use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::RwLock,
};

use async_trait::async_trait;
use hyper::{header, Body, Method, Request};
use serde::{Deserialize, Serialize};
use tokio::fs;

use crate::{
    authentication_manager::ServiceAccount, gcloud_authorized_user::DEFAULT_TOKEN_DURATION,
    types::HyperClient, util::HyperExt, Error, Signer, Token,
};

const DEFAULT_TOKEN_URI: &'static str = "https://oauth2.googleapis.com/token";

// Implementation referenced from
// https://github.com/golang/oauth2/blob/master/google/google.go#L158
// Currently not implementing external account credentials
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
enum FlexibleCredentialSource {
    ServiceAccount(ServiceAccountCredentials),
    AuthorizedUser(UserCredentials),
    ImpersonateServiceAccount(ImpersonateServiceAccountCredentials),
}

#[derive(Serialize, Debug)]
struct ServiceAccountCredentials {
    client_email: String,
    private_key: String,
    private_key_id: String,
    token_uri: Option<String>,
    audience: String,
    quota_project_id: Option<String>,
    #[serde(skip_serializing)]
    signer: Signer,
}

impl<'de> Deserialize<'de> for ServiceAccountCredentials {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ServiceAccountCredentialsDeserializer {
            client_email: String,
            private_key: String,
            private_key_id: String,
            token_uri: Option<String>,
            audience: String,
            quota_project_id: Option<String>,
        }

        let deserialized = ServiceAccountCredentialsDeserializer::deserialize(deserializer)?;

        let signer = Signer::new(&deserialized.private_key).map_err(|e| {
            serde::de::Error::custom(format!("failed to create signer from private key: {}", e))
        })?;

        Ok(ServiceAccountCredentials {
            client_email: deserialized.client_email,
            private_key: deserialized.private_key,
            private_key_id: deserialized.private_key_id,
            token_uri: deserialized.token_uri,
            audience: deserialized.audience,
            quota_project_id: deserialized.quota_project_id,
            signer,
        })
    }
}

impl ServiceAccountCredentials {
    async fn refresh_token(&self, client: &HyperClient, scopes: &[&str]) -> Result<Token, Error> {
        use crate::jwt::Claims;
        use crate::jwt::GRANT_TYPE;
        use url::form_urlencoded;

        let token_uri = self.token_uri.as_deref().unwrap_or(DEFAULT_TOKEN_URI);

        let jwt = Claims::new(&self.client_email, &token_uri, scopes, None).to_jwt(&self.signer)?;
        let rqbody = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&[("grant_type", GRANT_TYPE), ("assertion", jwt.as_str())])
            .finish();

        let mut retries = 0;
        let response = loop {
            let request = hyper::Request::post(token_uri)
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

        Ok(response.deserialize::<Token>().await?)
    }
}

// implementation to turn ServiceAccountCredentials into some kind of common config form.
// Needs optional `scopes` and optional `subject` user to impersonate.
// Replaces `token_url` with fallback.
// Refresh logic: https://github.com/golang/oauth2/blob/2e4a4e2bfb69ca7609cb423438c55caa131431c1/jwt/jwt.go#L101

#[derive(Serialize, Deserialize, Debug, Clone)]
struct UserCredentials {
    client_id: String,
    client_secret: String,
    auth_uri: Option<String>,
    token_uri: Option<String>,
    refresh_token: String,
    quota_project_id: Option<String>,
}

impl UserCredentials {
    const DEFAULT_TOKEN_GCP_URI: &'static str = "https://accounts.google.com/o/oauth2/token";

    fn build_token_request(&self) -> Request<Body> {
        #[derive(Serialize, Debug)]
        struct RefreshRequest<'a> {
            client_id: &'a str,
            client_secret: &'a str,
            grant_type: &'a str,
            refresh_token: &'a str,
        }

        Request::builder()
            .method(Method::POST)
            .uri(Self::DEFAULT_TOKEN_GCP_URI)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&RefreshRequest {
                    client_id: &self.client_id,
                    client_secret: &self.client_secret,
                    grant_type: "refresh_token",
                    refresh_token: &self.refresh_token,
                })
                .unwrap(),
            ))
            .unwrap()
    }

    async fn refresh_token(&self, client: &HyperClient) -> Result<Token, Error> {
        let mut retries = 0;
        let response = loop {
            let req = self.build_token_request();

            let err = match client.request(req).await {
                // Early return when the request succeeds
                Ok(response) => break response,
                Err(err) => err,
            };

            tracing::warn!(
                "Failed to get token from GCP oauth2 token endpoint: {err}, trying again..."
            );
            retries += 1;
            if retries >= RETRY_COUNT {
                return Err(Error::OAuthConnectionError(err));
            }
        };

        Ok(response.deserialize().await.map_err(Into::<Error>::into)?)
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct ImpersonateServiceAccountCredentials {
    // Either an untagged enum or this
    service_account_impersonation_url: String,
    source_credentials: Box<FlexibleCredentialSource>,
    delegates: Vec<String>,
}

impl ImpersonateServiceAccountCredentials {
    async fn refresh_with_token(
        &self,
        client: &HyperClient,
        scopes: &[&str],
        source_token: &Token,
    ) -> Result<Token, Error> {
        // Then we do a request to get the impersonated token
        let lifetime_seconds = DEFAULT_TOKEN_DURATION.whole_seconds().to_string();
        #[derive(Serialize, Clone)]
        // https://github.com/golang/oauth2/blob/a835fc4358f6852f50c4c5c33fddcd1adade5b0a/google/internal/externalaccount/impersonate.go#L21
        struct AccessTokenRequest {
            lifetime: String,
            #[serde(skip_serializing_if = "Vec::is_empty")]
            scope: Vec<String>,
            #[serde(skip_serializing_if = "Vec::is_empty")]
            delegates: Vec<String>,
        }

        let request = AccessTokenRequest {
            lifetime: lifetime_seconds,
            scope: scopes.iter().map(|s| s.to_string()).collect(),
            delegates: self.delegates.clone(),
        };
        let rqbody =
            serde_json::to_string(&request).expect("access token request failed to serialize");

        let token_uri = self.service_account_impersonation_url.as_str();

        let mut retries = 0;
        let response = loop {
            let request = hyper::Request::post(token_uri)
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", source_token.as_str()),
                )
                .header(header::CONTENT_TYPE, "application/json")
                .body(hyper::Body::from(rqbody.clone()))
                .unwrap();

            tracing::debug!("requesting impersonation token from service account: {request:?}");
            let err = match client.request(request).await {
                // Early return when the request succeeds
                Ok(response) => break response,
                Err(err) => err,
            };

            tracing::warn!(
                        "Failed to refresh impersonation token with service token endpoint {token_uri}: {err}, trying again..."
                    );
            retries += 1;
            if retries >= RETRY_COUNT {
                return Err(Error::OAuthConnectionError(err));
            }
        };

        Ok(response.deserialize::<Token>().await?)
    }
}

#[derive(Debug)]
pub(crate) struct FlexibleCredentials {
    tokens: RwLock<HashMap<Vec<String>, Token>>,
    credentials: FlexibleCredentialSource,
    project_id: Option<String>,
}

impl From<FlexibleCredentialSource> for FlexibleCredentials {
    fn from(creds: FlexibleCredentialSource) -> Self {
        let pid = creds.project_id();
        FlexibleCredentials {
            tokens: RwLock::new(HashMap::new()),
            credentials: creds,
            project_id: pid,
        }
    }
}

impl FlexibleCredentialSource {
    fn project_id(&self) -> Option<String> {
        return match self {
            FlexibleCredentialSource::ServiceAccount(sac) => sac.quota_project_id.clone(),
            FlexibleCredentialSource::AuthorizedUser(auc) => auc.quota_project_id.clone(),
            FlexibleCredentialSource::ImpersonateServiceAccount(isc) => {
                isc.source_credentials.project_id()
            }
        };
    }

    #[tracing::instrument]
    async fn refresh_token(&self, client: &HyperClient, scopes: &[&str]) -> Result<Token, Error> {
        let token = match self {
            FlexibleCredentialSource::ServiceAccount(creds) => {
                creds.refresh_token(client, scopes).await?
            }
            FlexibleCredentialSource::AuthorizedUser(creds) => creds.refresh_token(client).await?,
            FlexibleCredentialSource::ImpersonateServiceAccount(isc) => {
                // We don't account for nested impersonation, otherwise we would need async recursion which
                // gets messy
                let source_token = match isc.source_credentials.as_ref() {
                    FlexibleCredentialSource::ServiceAccount(sac) => {
                        sac.refresh_token(client, scopes).await?
                    }
                    FlexibleCredentialSource::AuthorizedUser(auc) => {
                        auc.refresh_token(client).await?
                    }
                    _ => return Err(Error::NestedImpersonation),
                };

                isc.refresh_with_token(client, scopes, &source_token)
                    .await?
            }
        };
        Ok(token)
    }
}

#[async_trait]
impl ServiceAccount for FlexibleCredentials {
    async fn project_id(&self, _hc: &HyperClient) -> Result<String, Error> {
        match &self.project_id {
            Some(project_id) => Ok(project_id.clone()),
            None => Err(Error::ProjectIdNotFound),
        }
    }

    fn get_token(&self, scopes: &[&str]) -> Option<Token> {
        let mut key: Vec<_> = scopes.iter().map(|x| x.to_string()).collect();
        key.sort();
        self.tokens.read().unwrap().get(&key).cloned()
    }

    #[tracing::instrument]
    async fn refresh_token(&self, client: &HyperClient, scopes: &[&str]) -> Result<Token, Error> {
        let token = self.credentials.refresh_token(client, scopes).await?;
        let mut key: Vec<_> = scopes.iter().map(|x| x.to_string()).collect();
        key.sort();
        self.tokens.write().unwrap().insert(key, token.clone());

        Ok(token)
    }
}

impl FlexibleCredentials {
    const USER_CREDENTIALS_PATH: &'static str =
        ".config/gcloud/application_default_credentials.json";

    pub(crate) async fn from_env() -> Result<Option<Self>, Error> {
        let creds_path = std::env::var_os("GOOGLE_APPLICATION_CREDENTIALS");
        if let Some(path) = creds_path {
            tracing::debug!("Reading credentials file from GOOGLE_APPLICATION_CREDENTIALS env var");
            let creds = Self::from_file(PathBuf::from(path)).await?;
            Ok(Some(creds))
        } else {
            Ok(None)
        }
    }

    /// Read service account credentials from the given JSON file
    async fn from_file<T: AsRef<Path>>(path: T) -> Result<Self, Error> {
        let creds_string = fs::read_to_string(&path)
            .await
            .map_err(Error::UserProfilePath)?;

        match serde_json::from_str::<FlexibleCredentialSource>(&creds_string) {
            Ok(credentials) => Ok(credentials.into()),
            Err(e) => Err(Error::CustomServiceAccountCredentials(e)),
        }
    }

    pub(crate) async fn from_default_credentials() -> Result<Self, Error> {
        tracing::debug!("Loading user credentials file");
        let mut home = dirs_next::home_dir().ok_or(Error::NoHomeDir)?;
        home.push(Self::USER_CREDENTIALS_PATH);
        Self::from_file(home).await
    }
}

/// How many times to attempt to fetch a token from the set credentials token endpoint.
const RETRY_COUNT: u8 = 5;
