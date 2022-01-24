use std::fs;
use std::sync::RwLock;

use async_trait::async_trait;
use hyper::body::Body;
use hyper::{Method, Request};
use serde::{Deserialize, Serialize};

use crate::authentication_manager::ServiceAccount;
use crate::error::Error;
use crate::types::{HyperClient, Token};
use crate::util::HyperExt;

#[derive(Debug)]
pub(crate) struct DefaultAuthorizedUser {
    token: RwLock<Token>,
}

impl DefaultAuthorizedUser {
    const DEFAULT_TOKEN_GCP_URI: &'static str = "https://accounts.google.com/o/oauth2/token";
    const USER_CREDENTIALS_PATH: &'static str =
        ".config/gcloud/application_default_credentials.json";

    pub(crate) async fn new(client: &HyperClient) -> Result<Self, Error> {
        let token = RwLock::new(Self::get_token(client).await?);
        Ok(Self { token })
    }

    fn build_token_request<T: serde::Serialize>(json: &T) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(Self::DEFAULT_TOKEN_GCP_URI)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(json).unwrap()))
            .unwrap()
    }

    async fn get_token(client: &HyperClient) -> Result<Token, Error> {
        log::debug!("Loading user credentials file");
        let mut home = dirs_next::home_dir().ok_or(Error::NoHomeDir)?;
        home.push(Self::USER_CREDENTIALS_PATH);

        let file = fs::File::open(home).map_err(Error::UserProfilePath)?;
        let cred = serde_json::from_reader::<_, UserCredentials>(file)
            .map_err(Error::UserProfileFormat)?;

        let req = Self::build_token_request(&RefreshRequest {
            client_id: cred.client_id,
            client_secret: cred.client_secret,
            grant_type: "refresh_token".to_string(),
            refresh_token: cred.refresh_token,
        });

        let token = client
            .request(req)
            .await
            .map_err(Error::OAuthConnectionError)?
            .deserialize()
            .await?;
        Ok(token)
    }
}

#[async_trait]
impl ServiceAccount for DefaultAuthorizedUser {
    async fn project_id(&self, _: &HyperClient) -> Result<String, Error> {
        Err(Error::NoProjectId)
    }

    fn get_token(&self, _scopes: &[&str]) -> Option<Token> {
        Some(self.token.read().unwrap().clone())
    }

    async fn refresh_token(&self, client: &HyperClient, _scopes: &[&str]) -> Result<Token, Error> {
        let token = Self::get_token(client).await?;
        *self.token.write().unwrap() = token.clone();
        Ok(token)
    }
}

#[derive(Serialize, Debug)]
struct RefreshRequest {
    client_id: String,
    client_secret: String,
    grant_type: String,
    refresh_token: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct UserCredentials {
    /// Client id
    pub(crate) client_id: String,
    /// Client secret
    pub(crate) client_secret: String,
    /// Refresh Token
    pub(crate) refresh_token: String,
    /// Type
    pub(crate) r#type: String,
}
