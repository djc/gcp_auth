use std::fs;
use std::sync::Arc;
use std::sync::RwLock;

use async_trait::async_trait;
use hyper::body::Body;
use hyper::header::CONTENT_TYPE;
use hyper::{Method, Request};
use serde::{Deserialize, Serialize};
use tracing::{instrument, Level};

use crate::authentication_manager::ServiceAccount;
use crate::error::Error;
use crate::types::{HttpClient, Token};

#[derive(Debug)]
pub(crate) struct ConfigDefaultCredentials {
    client: HttpClient,
    token: RwLock<Arc<Token>>,
    credentials: UserCredentials,
}

impl ConfigDefaultCredentials {
    pub(crate) async fn new(client: &HttpClient) -> Result<Self, Error> {
        tracing::debug!("Loading user credentials file");
        let mut home = home::home_dir().ok_or(Error::NoHomeDir)?;
        home.push(USER_CREDENTIALS_PATH);

        let file = fs::File::open(home).map_err(Error::UserProfilePath)?;
        let credentials = serde_json::from_reader::<_, UserCredentials>(file)
            .map_err(Error::UserProfileFormat)?;

        Ok(Self {
            client: client.clone(),
            token: RwLock::new(Self::get_token(&credentials, client).await?),
            credentials,
        })
    }

    #[instrument(level = Level::DEBUG)]
    async fn get_token(cred: &UserCredentials, client: &HttpClient) -> Result<Arc<Token>, Error> {
        client
            .token(
                &|| {
                    Request::builder()
                        .method(Method::POST)
                        .uri(DEFAULT_TOKEN_GCP_URI)
                        .header(CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            serde_json::to_string(&RefreshRequest {
                                client_id: &cred.client_id,
                                client_secret: &cred.client_secret,
                                grant_type: "refresh_token",
                                refresh_token: &cred.refresh_token,
                            })
                            .unwrap(),
                        ))
                        .unwrap()
                },
                "ConfigDefaultCredentials",
            )
            .await
    }
}

#[async_trait]
impl ServiceAccount for ConfigDefaultCredentials {
    async fn project_id(&self) -> Result<Arc<str>, Error> {
        self.credentials
            .quota_project_id
            .clone()
            .ok_or(Error::NoProjectId)
    }

    fn get_token(&self, _scopes: &[&str]) -> Option<Arc<Token>> {
        Some(self.token.read().unwrap().clone())
    }

    async fn refresh_token(&self, _scopes: &[&str]) -> Result<Arc<Token>, Error> {
        let token = Self::get_token(&self.credentials, &self.client).await?;
        *self.token.write().unwrap() = token.clone();
        Ok(token)
    }
}

#[derive(Serialize, Debug)]
struct RefreshRequest<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    grant_type: &'a str,
    refresh_token: &'a str,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct UserCredentials {
    /// Client id
    pub(crate) client_id: String,
    /// Client secret
    pub(crate) client_secret: String,
    /// Project ID
    pub(crate) quota_project_id: Option<Arc<str>>,
    /// Refresh Token
    pub(crate) refresh_token: String,
    /// Type
    pub(crate) r#type: String,
}

const DEFAULT_TOKEN_GCP_URI: &str = "https://accounts.google.com/o/oauth2/token";
const USER_CREDENTIALS_PATH: &str = ".config/gcloud/application_default_credentials.json";
