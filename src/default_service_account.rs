use std::str;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use hyper::body::Body;
use hyper::{Method, Request};
use tracing::{instrument, Level};

use crate::authentication_manager::ServiceAccount;
use crate::error::Error;
use crate::types::{HttpClient, Token};

#[derive(Debug)]
pub(crate) struct MetadataServiceAccount {
    client: HttpClient,
    token: RwLock<Arc<Token>>,
}

impl MetadataServiceAccount {
    pub(crate) async fn new(client: &HttpClient) -> Result<Self, Error> {
        let token = RwLock::new(Self::get_token(client).await?);
        Ok(Self {
            client: client.clone(),
            token,
        })
    }

    #[instrument(level = Level::DEBUG)]
    async fn get_token(client: &HttpClient) -> Result<Arc<Token>, Error> {
        client
            .token(
                &|| metadata_request(DEFAULT_TOKEN_GCP_URI),
                "ConfigDefaultCredentials",
            )
            .await
    }
}

#[async_trait]
impl ServiceAccount for MetadataServiceAccount {
    async fn token(&self, _scopes: &[&str]) -> Option<Arc<Token>> {
        Some(self.token.read().unwrap().clone())
    }

    async fn project_id(&self) -> Result<Arc<str>, Error> {
        tracing::debug!("Getting project ID from GCP instance metadata server");
        let req = metadata_request(DEFAULT_PROJECT_ID_GCP_URI);
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

    async fn refresh_token(&self, _scopes: &[&str]) -> Result<Arc<Token>, Error> {
        let token = Self::get_token(&self.client).await?;
        *self.token.write().unwrap() = token.clone();
        Ok(token)
    }
}

fn metadata_request(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("Metadata-Flavor", "Google")
        .body(Body::empty())
        .unwrap()
}

// https://cloud.google.com/compute/docs/metadata/predefined-metadata-keys
const DEFAULT_PROJECT_ID_GCP_URI: &str =
    "http://metadata.google.internal/computeMetadata/v1/project/project-id";
const DEFAULT_TOKEN_GCP_URI: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
