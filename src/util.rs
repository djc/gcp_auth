use crate::prelude::*;
use serde::de;

#[async_trait]
pub trait HyperExt {
    async fn deserialize<T>(self) -> Result<T, GCPAuthError>
        where T: de::DeserializeOwned;
}

#[async_trait]
impl HyperExt for hyper::Response<hyper::body::Body> {
    async fn deserialize<T>(self) -> Result<T, GCPAuthError>
        where T: de::DeserializeOwned,
    {
        if !self.status().is_success() {
            log::error!("Server responded with error");
            return  Err(GCPAuthError::ServerUnavailable);
        }
        let (_, body) = self.into_parts();
        let body = hyper::body::to_bytes(body).await.map_err(GCPAuthError::ConnectionError)?;
        let token = serde_json::from_slice(&body).map_err(GCPAuthError::ParsingError)?;

        Ok(token)
    }
}

