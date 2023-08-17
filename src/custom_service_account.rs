use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::authentication_manager::ServiceAccount;
use crate::error::Error;
use crate::types::{HyperClient, Signer, Token};
use crate::util::HyperExt;

/// A custom service account containing credentials
///
/// Once initialized, a [`CustomServiceAccount`] can be converted into an [`AuthenticationManager`]
/// using the applicable `From` implementation.
///
/// [`AuthenticationManager`]: crate::AuthenticationManager
#[derive(Debug)]
pub struct CustomServiceAccount {
    credentials: ApplicationCredentials,
    signer: Signer,
    tokens: RwLock<HashMap<Vec<String>, Token>>,
}

impl CustomServiceAccount {
    /// Check `GOOGLE_APPLICATION_CREDENTIALS` environment variable for a path to JSON credentials
    pub fn from_env() -> Result<Option<Self>, Error> {
        std::env::var_os("GOOGLE_APPLICATION_CREDENTIALS")
            .map(|path| {
                tracing::debug!(
                    "Reading credentials file from GOOGLE_APPLICATION_CREDENTIALS env var"
                );
                Self::from_file(PathBuf::from(path))
            })
            .transpose()
    }

    /// Read service account credentials from the given JSON file
    pub fn from_file<T: AsRef<Path>>(path: T) -> Result<Self, Error> {
        let file = std::fs::File::open(path.as_ref()).map_err(Error::CustomServiceAccountPath)?;
        match serde_json::from_reader::<_, ApplicationCredentials>(file) {
            Ok(credentials) => Self::new(credentials),
            Err(e) => Err(Error::CustomServiceAccountCredentials(e)),
        }
    }

    /// Read service account credentials from the given JSON string
    pub fn from_json(s: &str) -> Result<Self, Error> {
        match serde_json::from_str::<ApplicationCredentials>(s) {
            Ok(credentials) => Self::new(credentials),
            Err(e) => Err(Error::CustomServiceAccountCredentials(e)),
        }
    }

    fn new(credentials: ApplicationCredentials) -> Result<Self, Error> {
        Ok(Self {
            signer: Signer::new(&credentials.private_key)?,
            credentials,
            tokens: RwLock::new(HashMap::new()),
        })
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
impl ServiceAccount for CustomServiceAccount {
    async fn project_id(&self, _: &HyperClient) -> Result<String, Error> {
        match &self.credentials.project_id {
            Some(pid) => Ok(pid.clone()),
            None => Err(Error::ProjectIdNotFound),
        }
    }

    fn get_token(&self, scopes: &[&str]) -> Option<Token> {
        let key: Vec<_> = scopes.iter().map(|x| x.to_string()).collect();
        self.tokens.read().unwrap().get(&key).cloned()
    }

    #[tracing::instrument]
    async fn refresh_token(&self, client: &HyperClient, scopes: &[&str]) -> Result<Token, Error> {
        use crate::jwt::Claims;
        use crate::jwt::GRANT_TYPE;
        use hyper::header;
        use url::form_urlencoded;

        let jwt = Claims::new(
            &self.credentials.client_email,
            &self.credentials.token_uri,
            scopes,
            None,
        )
        .to_jwt(&self.signer)?;
        let rqbody = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&[("grant_type", GRANT_TYPE), ("assertion", jwt.as_str())])
            .finish();

        let mut retries = 0;
        let response = loop {
            let request = hyper::Request::post(&self.credentials.token_uri)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(hyper::Body::from(rqbody.clone()))
                .unwrap();

            tracing::debug!("requesting token from service account: {request:?}");
            let err = match client.request(request).await {
                // Early return when the request succeeds
                Ok(response) => break response,
                Err(err) => err,
            };

            tracing::warn!(
                "Failed to refresh token with GCP oauth2 token endpoint: {err}, trying again..."
            );
            retries += 1;
            if retries >= RETRY_COUNT {
                return Err(Error::OAuthConnectionError(err));
            }
        };

        let token = response.deserialize::<Token>().await?;

        let key = scopes.iter().map(|x| (*x).to_string()).collect();
        self.tokens.write().unwrap().insert(key, token.clone());
        Ok(token)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct ApplicationCredentials {
    pub(crate) r#type: Option<String>,
    /// project_id
    pub(crate) project_id: Option<String>,
    /// private_key_id
    pub(crate) private_key_id: Option<String>,
    /// private_key
    pub(crate) private_key: String,
    /// client_email
    pub(crate) client_email: String,
    /// client_id
    pub(crate) client_id: Option<String>,
    /// auth_uri
    pub(crate) auth_uri: Option<String>,
    /// token_uri
    pub(crate) token_uri: String,
    /// auth_provider_x509_cert_url
    pub(crate) auth_provider_x509_cert_url: Option<String>,
    /// client_x509_cert_url
    pub(crate) client_x509_cert_url: Option<String>,
}

impl fmt::Debug for ApplicationCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApplicationCredentials")
            .field("client_email", &self.client_email)
            .field("project_id", &self.project_id)
            .finish()
    }
}

/// How many times to attempt to fetch a token from the set credentials token endpoint.
const RETRY_COUNT: u8 = 5;
