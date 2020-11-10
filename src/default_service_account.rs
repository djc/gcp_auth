use crate::authentication_manager::ServiceAccount;
use crate::prelude::*;
use hyper::body::Body;
use hyper::Method;
use std::sync::Mutex;

#[derive(Debug)]
pub struct DefaultServiceAccount {
    token: Mutex<Token>,
}

impl DefaultServiceAccount {
    const DEFAULT_TOKEN_GCP_URI: &'static str = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

    pub async fn new(client: &HyperClient) -> Result<Self, Error> {
        let token = Mutex::new(Self::get_token(client).await?);
        Ok(Self { token })
    }

    fn build_token_request() -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(Self::DEFAULT_TOKEN_GCP_URI)
            .header("Metadata-Flavor", "Google")
            .body(Body::empty())
            .unwrap()
    }

    async fn get_token(client: &HyperClient) -> Result<Token, Error> {
        log::debug!("Getting token from GCP instance metadata server");
        let req = Self::build_token_request();
        let token = client
            .request(req)
            .await
            .map_err(Error::ConnectionError)?
            .deserialize()
            .await?;
        Ok(token)
    }
}

#[async_trait]
impl ServiceAccount for DefaultServiceAccount {
    fn get_token(&self, _scopes: &[&str]) -> Option<Token> {
        Some(self.token.lock().unwrap().clone())
    }

    async fn refresh_token(&self, client: &HyperClient, _scopes: &[&str]) -> Result<Token, Error> {
        let token = Self::get_token(client).await?;
        *self.token.lock().unwrap() = token.clone();
        Ok(token)
    }
}
