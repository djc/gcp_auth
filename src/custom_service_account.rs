use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::{env, fmt};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE, Engine};
use bytes::Bytes;
use chrono::Utc;
use http_body_util::Full;
use hyper::header::CONTENT_TYPE;
use hyper::Request;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, instrument, Level};
use url::form_urlencoded;

use crate::types::{HttpClient, Signer, Token};
use crate::{Error, TokenProvider};

/// A custom service account containing credentials
///
/// Once initialized, a [`CustomServiceAccount`] can be converted into an [`AuthenticationManager`]
/// using the applicable `From` implementation.
///
/// [`AuthenticationManager`]: crate::AuthenticationManager
#[derive(Debug)]
pub struct CustomServiceAccount {
    client: HttpClient,
    credentials: ApplicationCredentials,
    signer: Signer,
    tokens: RwLock<HashMap<Vec<String>, Arc<Token>>>,
    subject: Option<String>,
}

impl CustomServiceAccount {
    /// Check `GOOGLE_APPLICATION_CREDENTIALS` environment variable for a path to JSON credentials
    pub fn from_env() -> Result<Option<Self>, Error> {
        debug!("check for GOOGLE_APPLICATION_CREDENTIALS env var");
        match ApplicationCredentials::from_env()? {
            Some(credentials) => Self::new(credentials, HttpClient::new()?).map(Some),
            None => Ok(None),
        }
    }

    /// Read service account credentials from the given JSON file
    pub fn from_file<T: AsRef<Path>>(path: T) -> Result<Self, Error> {
        Self::new(ApplicationCredentials::from_file(path)?, HttpClient::new()?)
    }

    /// Read service account credentials from the given JSON string
    pub fn from_json(s: &str) -> Result<Self, Error> {
        Self::new(ApplicationCredentials::from_str(s)?, HttpClient::new()?)
    }

    /// Set the `subject` to impersonate a user
    pub fn with_subject(mut self, subject: String) -> Self {
        self.subject = Some(subject);
        self
    }

    fn new(credentials: ApplicationCredentials, client: HttpClient) -> Result<Self, Error> {
        debug!(project = ?credentials.project_id, email = credentials.client_email, "found credentials");
        Ok(Self {
            client,
            signer: Signer::new(&credentials.private_key)?,
            credentials,
            tokens: RwLock::new(HashMap::new()),
            subject: None,
        })
    }

    #[instrument(level = Level::DEBUG, skip(self))]
    async fn fetch_token(&self, scopes: &[&str]) -> Result<Arc<Token>, Error> {
        let jwt =
            Claims::new(&self.credentials, scopes, self.subject.as_deref()).to_jwt(&self.signer)?;
        let body = Bytes::from(
            form_urlencoded::Serializer::new(String::new())
                .extend_pairs(&[("grant_type", GRANT_TYPE), ("assertion", jwt.as_str())])
                .finish()
                .into_bytes(),
        );

        let token = self
            .client
            .token(
                &|| {
                    Request::post(&self.credentials.token_uri)
                        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                        .body(Full::from(body.clone()))
                        .unwrap()
                },
                "CustomServiceAccount",
            )
            .await?;

        Ok(token)
    }

    /// The RSA PKCS1 SHA256 [`Signer`] used to sign JWT tokens
    pub fn signer(&self) -> &Signer {
        &self.signer
    }

    /// The project ID as found in the credentials
    pub fn project_id(&self) -> Option<&str> {
        self.credentials.project_id.as_deref()
    }

    /// The private key as found in the credentials
    pub fn private_key_pem(&self) -> &str {
        &self.credentials.private_key
    }
}

#[async_trait]
impl TokenProvider for CustomServiceAccount {
    async fn token(&self, scopes: &[&str]) -> Result<Arc<Token>, Error> {
        let key: Vec<_> = scopes.iter().map(|x| x.to_string()).collect();
        let token = self.tokens.read().await.get(&key).cloned();
        if let Some(token) = token {
            if !token.has_expired() {
                return Ok(token.clone());
            }

            let mut locked = self.tokens.write().await;
            let token = self.fetch_token(scopes).await?;
            locked.insert(key, token.clone());
            return Ok(token);
        }

        let mut locked = self.tokens.write().await;
        let token = self.fetch_token(scopes).await?;
        locked.insert(key, token.clone());
        return Ok(token);
    }

    async fn project_id(&self) -> Result<Arc<str>, Error> {
        match &self.credentials.project_id {
            Some(pid) => Ok(pid.clone()),
            None => Err(Error::Str("no project ID in application credentials")),
        }
    }
}

/// Permissions requested for a JWT.
/// See https://developers.google.com/identity/protocols/OAuth2ServiceAccount#authorizingrequests.
#[derive(Serialize, Debug)]
pub(crate) struct Claims<'a> {
    iss: &'a str,
    aud: &'a str,
    exp: i64,
    iat: i64,
    sub: Option<&'a str>,
    scope: String,
}

impl<'a> Claims<'a> {
    pub(crate) fn new(
        key: &'a ApplicationCredentials,
        scopes: &[&str],
        sub: Option<&'a str>,
    ) -> Self {
        let mut scope = String::with_capacity(16);
        for (i, s) in scopes.iter().enumerate() {
            if i != 0 {
                scope.push(' ');
            }

            scope.push_str(s);
        }

        let iat = Utc::now().timestamp();
        Claims {
            iss: &key.client_email,
            aud: &key.token_uri,
            exp: iat + 3600 - 5, // Max validity is 1h
            iat,
            sub,
            scope,
        }
    }

    pub(crate) fn to_jwt(&self, signer: &Signer) -> Result<String, Error> {
        let mut jwt = String::new();
        URL_SAFE.encode_string(GOOGLE_RS256_HEAD, &mut jwt);
        jwt.push('.');
        URL_SAFE.encode_string(&serde_json::to_string(self).unwrap(), &mut jwt);

        let signature = signer.sign(jwt.as_bytes())?;
        jwt.push('.');
        URL_SAFE.encode_string(&signature, &mut jwt);
        Ok(jwt)
    }
}

#[derive(Deserialize, Clone)]
pub(crate) struct ApplicationCredentials {
    /// project_id
    pub(crate) project_id: Option<Arc<str>>,
    /// private_key
    pub(crate) private_key: String,
    /// client_email
    pub(crate) client_email: String,
    /// token_uri
    pub(crate) token_uri: String,
}

impl ApplicationCredentials {
    fn from_env() -> Result<Option<Self>, Error> {
        env::var_os("GOOGLE_APPLICATION_CREDENTIALS")
            .map(|path| {
                debug!(
                    ?path,
                    "reading credentials file from GOOGLE_APPLICATION_CREDENTIALS env var"
                );
                Self::from_file(PathBuf::from(path))
            })
            .transpose()
    }

    fn from_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        let file = File::open(path.as_ref())
            .map_err(|err| Error::Io("failed to open application credentials file", err))?;
        serde_json::from_reader::<_, ApplicationCredentials>(file)
            .map_err(|err| Error::Json("failed to deserialize ApplicationCredentials", err))
    }
}

impl FromStr for ApplicationCredentials {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str::<ApplicationCredentials>(s)
            .map_err(|err| Error::Json("failed to deserialize ApplicationCredentials", err))
    }
}

impl fmt::Debug for ApplicationCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApplicationCredentials")
            .field("client_email", &self.client_email)
            .field("project_id", &self.project_id)
            .finish()
    }
}

pub(crate) const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const GOOGLE_RS256_HEAD: &str = r#"{"alg":"RS256","typ":"JWT"}"#;
