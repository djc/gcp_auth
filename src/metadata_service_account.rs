use std::str;
use std::sync::Arc;

use async_trait::async_trait;
use hyper::body::Body;
use hyper::{Method, Request};
use tokio::sync::RwLock;
use tracing::{instrument, Level};

use crate::types::{HttpClient, Token};
use crate::{Error, TokenProvider};

#[derive(Debug)]
pub(crate) struct MetadataServiceAccount {
    client: HttpClient,
    project_id: Arc<str>,
    token: RwLock<Arc<Token>>,
}

impl MetadataServiceAccount {
    pub(crate) async fn new(client: &HttpClient) -> Result<Self, Error> {
        let token = RwLock::new(Self::fetch_token(client).await?);

        tracing::debug!("getting project ID from GCP instance metadata server");
        let req = metadata_request(DEFAULT_PROJECT_ID_GCP_URI);
        let rsp = client
            .request(req, "MetadataServiceAccount")
            .await
            .map_err(Error::ConnectionError)?;
        if !rsp.status().is_success() {
            return Err(Error::ProjectIdNotFound);
        }

        let (_, body) = rsp.into_parts();
        let body = hyper::body::to_bytes(body)
            .await
            .map_err(Error::ConnectionError)?;
        let project_id = match str::from_utf8(&body) {
            Ok(s) if !s.is_empty() => Arc::from(s),
            Ok(_) => return Err(Error::NoProjectId),
            Err(_) => return Err(Error::ProjectIdNonUtf8),
        };

        Ok(Self {
            client: client.clone(),
            project_id,
            token,
        })
    }

    #[instrument(level = Level::DEBUG, skip(client))]
    async fn fetch_token(client: &HttpClient) -> Result<Arc<Token>, Error> {
        client
            .token(
                &|| metadata_request(DEFAULT_TOKEN_GCP_URI),
                "MetadataServiceAccount",
            )
            .await
    }
}

#[async_trait]
impl TokenProvider for MetadataServiceAccount {
    async fn token(&self, _scopes: &[&str]) -> Result<Arc<Token>, Error> {
        let token = self.token.read().await.clone();
        if !token.has_expired() {
            return Ok(token);
        }

        let mut locked = self.token.write().await;
        let token = Self::fetch_token(&self.client).await?;
        *locked = token.clone();
        Ok(token)
    }

    async fn project_id(&self) -> Result<Arc<str>, Error> {
        Ok(self.project_id.clone())
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
