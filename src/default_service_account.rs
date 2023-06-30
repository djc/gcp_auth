use std::str;
use std::sync::RwLock;

use async_trait::async_trait;
use hyper::body::Body;
use hyper::{Method, Request};

use crate::authentication_manager::ServiceAccount;
use crate::error::Error;
use crate::types::{HyperClient, Token};
use crate::util::HyperExt;

#[derive(Debug)]
pub(crate) struct MetadataServiceAccount {
    token: RwLock<Token>,
}

impl MetadataServiceAccount {
    const DEFAULT_PROJECT_ID_GCP_URI: &'static str =
        "http://metadata.google.internal/computeMetadata/v1/project/project-id";
    const DEFAULT_TOKEN_GCP_URI: &'static str = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

    pub(crate) async fn new(client: &HyperClient) -> Result<Self, Error> {
        let token = RwLock::new(Self::get_token(client).await?);
        Ok(Self { token })
    }

    fn build_token_request(uri: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("Metadata-Flavor", "Google")
            .body(Body::empty())
            .unwrap()
    }

    #[tracing::instrument]
    async fn get_token(client: &HyperClient) -> Result<Token, Error> {
        let mut retries = 0;
        tracing::debug!("Getting token from GCP instance metadata server");
        let response = loop {
            let req = Self::build_token_request(Self::DEFAULT_TOKEN_GCP_URI);

            let err = match client.request(req).await {
                // Early return when the request succeeds
                Ok(response) => break response,
                Err(err) => err,
            };

            tracing::warn!(
                "Failed to get token from GCP instance metadata server: {err}, trying again..."
            );
            retries += 1;
            if retries >= RETRY_COUNT {
                return Err(Error::ConnectionError(err));
            }
        };

        response.deserialize().await.map_err(Into::into)
    }
}

#[async_trait]
impl ServiceAccount for MetadataServiceAccount {
    async fn project_id(&self, client: &HyperClient) -> Result<String, Error> {
        tracing::debug!("Getting project ID from GCP instance metadata server");
        let req = Self::build_token_request(Self::DEFAULT_PROJECT_ID_GCP_URI);
        let rsp = client.request(req).await.map_err(Error::ConnectionError)?;

        let (_, body) = rsp.into_parts();
        let body = hyper::body::to_bytes(body)
            .await
            .map_err(Error::ConnectionError)?;
        match str::from_utf8(&body) {
            Ok(s) => Ok(s.to_owned()),
            Err(_) => Err(Error::ProjectIdNonUtf8),
        }
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

/// How many times to attempt to fetch a token from the GCP metadata server.
const RETRY_COUNT: u8 = 5;
