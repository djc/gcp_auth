use crate::prelude::*;
use tokio::fs;
use hyper::body::Body;
use hyper::Method;
use crate::authentication_manager::ServiceAccount;

#[derive(Debug)]
pub struct DefaultAuthorizedUser {
    token: Token,
}

impl DefaultAuthorizedUser {
    const DEFAULT_TOKEN_GCP_URI: &'static str = "https://accounts.google.com/o/oauth2/token";
    const USER_CREDENTIALS_PATH: &'static str = "/.config/gcloud/application_default_credentials.json";
    
    pub async fn new(client: &HyperClient) -> Result<Self, GCPAuthError> {
        let token = Self::get_token(client).await?;
        Ok(Self { token })
    }

    fn build_token_request<T: serde::Serialize>(json: &T) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(Self::DEFAULT_TOKEN_GCP_URI)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(json).unwrap())).unwrap()
    }

    async fn get_token(client: &HyperClient) -> Result<Token, GCPAuthError> {
        log::debug!("Loading user credentials file");
        let home = dirs::home_dir().ok_or(GCPAuthError::NoHomeDir)?;
        let cred = UserCredentials::from_file(home.display().to_string() + Self::USER_CREDENTIALS_PATH).await?;
        let req = Self::build_token_request(&RerfeshRequest {
            client_id: cred.client_id,
            client_secret: cred.client_secret,
            grant_type: "refresh_token".to_string(),
            refresh_token: cred.refresh_token,
        });
        let token = client.request(req).await.map_err(GCPAuthError::OAuthConnectionError)?.deserialize().await?;
        Ok(token)
    }
}

#[async_trait]
impl ServiceAccount for DefaultAuthorizedUser {
    fn get_token(&self, _scopes: &[&str]) -> Option<Token> {
        Some(self.token.clone())
    }

    async fn refresh_token(&mut self, client: &HyperClient, _scopes: &[&str]) -> Result<(), GCPAuthError> {
        let token = Self::get_token(client).await?;
        self.token = token;
        Ok(())
    }
}

#[derive(Serialize, Debug)]
struct RerfeshRequest {
    client_id: String,
    client_secret: String,
    grant_type: String,
    refresh_token: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct UserCredentials {
    /// Client id
    pub client_id: String,
    /// Client secret
    pub client_secret: String,
    /// Refresh Token
    pub refresh_token: String,
    /// Type
    pub r#type: String,
}

impl UserCredentials {
    async fn from_file<T: AsRef<Path>>(path: T) -> Result<UserCredentials, GCPAuthError> {
        let content = fs::read_to_string(path).await.map_err(GCPAuthError::UserProfilePath)?;
        Ok(serde_json::from_str(&content).map_err(GCPAuthError::UserProfileFormat)?)
    }
}
