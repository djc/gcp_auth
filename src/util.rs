use async_trait::async_trait;
use serde::de;

use crate::error::Error;

#[async_trait]
pub(crate) trait HyperExt {
    async fn deserialize<T>(self) -> Result<T, Error>
    where
        T: de::DeserializeOwned;
}

#[async_trait]
impl HyperExt for hyper::Response<hyper::body::Body> {
    async fn deserialize<T>(self) -> Result<T, Error>
    where
        T: de::DeserializeOwned,
    {
        if !self.status().is_success() {
            log::error!("Server responded with error");
            return Err(Error::ServerUnavailable);
        }
        let (_, body) = self.into_parts();
        let body = hyper::body::to_bytes(body)
            .await
            .map_err(Error::ConnectionError)?;
        let token = serde_json::from_slice(&body).map_err(Error::ParsingError)?;

        Ok(token)
    }
}
