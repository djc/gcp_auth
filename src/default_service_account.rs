use crate::prelude::*;
use crate::authentication_manager::ServiceAccount;
use hyper::body::Body;
use hyper::Method;

#[derive(Debug)]
pub struct DefaultServiceAccount {
    token: Token,
}

impl DefaultServiceAccount {
    const DEFAULT_TOKEN_GCP_URI: &'static str = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

    pub async fn new(client: &HyperClient) -> Result<Self, GCPAuthError> {
        let token = Self::get_token(client).await?;
        Ok(Self { token })
    }

    fn build_token_request() -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(Self::DEFAULT_TOKEN_GCP_URI)
            .header("Metadata-Flavor", "Google")
            .body(Body::empty()).unwrap()
    }

    async fn get_token(client: &HyperClient) -> Result<Token, GCPAuthError> {
        log::debug!("Getting token from GCP instance metadata server");
        let req = Self::build_token_request();
        let resp = client.request(req).await.map_err(GCPAuthError::MetadataConnectionError)?;
        if resp.status().is_success() {
            let body = hyper::body::aggregate(resp).await.map_err(GCPAuthError::MetadataConnectionError)?;
            let bytes = body.bytes();
            let token = serde_json::from_slice(bytes).map_err(GCPAuthError::MetadataParsingError)?;
            return Ok(token);
        }
        Err(GCPAuthError::MetadataServerUnavailable)
    }
}

#[async_trait]
impl ServiceAccount for DefaultServiceAccount {
    fn get_token(&self, _scopes: &[&str]) -> Option<Token> {
        if self.token.has_expired() {
            return None;
        }
        Some(self.token.clone())
    }

    async fn refresh_token(&mut self, client: &HyperClient, _scopes: &[&str]) -> Result<(), GCPAuthError> {
        let token = Self::get_token(client).await?;
        self.token = token;
        Ok(())
    }
}