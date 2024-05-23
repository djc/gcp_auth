use std::str;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use hyper::body::Body;
use hyper::{Method, Request};
use tracing::{instrument, Level};

use crate::authentication_manager::ServiceAccount;
use crate::error::Error;
use crate::types::{HyperClient, Token, HyperExt};

#[derive(Debug)]
pub(crate) struct MetadataServiceAccount {
    client: HyperClient,
    token: RwLock<Arc<Token>>,
}

impl MetadataServiceAccount {
    // https://cloud.google.com/compute/docs/metadata/predefined-metadata-keys
    const DEFAULT_PROJECT_ID_GCP_URI: &'static str =
        "http://metadata.google.internal/computeMetadata/v1/project/project-id";
    const DEFAULT_TOKEN_GCP_URI: &'static str = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

    pub(crate) async fn new(client: &HyperClient) -> Result<Self, Error> {
        let token = RwLock::new(Self::get_token(client).await?);
        Ok(Self {
            client: client.clone(),
            token,
        })
    }

    fn build_token_request(uri: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("Metadata-Flavor", "Google")
            .body(Body::empty())
            .unwrap()
    }

    #[instrument(level = Level::DEBUG)]
    async fn get_token(client: &HyperClient) -> Result<Arc<Token>, Error> {
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

        match response.deserialize::<Token>().await {
            Ok(token) => Ok(Arc::new(token)),
            Err(e) => Err(e.into()),
        }
    }
}

#[async_trait]
impl ServiceAccount for MetadataServiceAccount {
    async fn project_id(&self) -> Result<Arc<str>, Error> {
        tracing::debug!("Getting project ID from GCP instance metadata server");
        let req = Self::build_token_request(Self::DEFAULT_PROJECT_ID_GCP_URI);
        let rsp = self
            .client
            .request(req)
            .await
            .map_err(Error::ConnectionError)?;

        let (_, body) = rsp.into_parts();
        let body = hyper::body::to_bytes(body)
            .await
            .map_err(Error::ConnectionError)?;
        match str::from_utf8(&body) {
            Ok(s) => Ok(Arc::from(s)),
            Err(_) => Err(Error::ProjectIdNonUtf8),
        }
    }

    fn get_token(&self, _scopes: &[&str]) -> Option<Arc<Token>> {
        Some(self.token.read().unwrap().clone())
    }

    async fn refresh_token(&self, _scopes: &[&str]) -> Result<Arc<Token>, Error> {
        let token = Self::get_token(&self.client).await?;
        *self.token.write().unwrap() = token.clone();
        Ok(token)
    }
}

/// How many times to attempt to fetch a token from the GCP metadata server.
const RETRY_COUNT: u8 = 5;
