use std::sync::Arc;
use std::time::Duration;
use std::{fmt, io};

use chrono::{DateTime, Utc};
use hyper::body::{Body, Bytes};
use hyper::{Client, Request, Response};
use hyper_rustls::HttpsConnectorBuilder;
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use serde::{Deserialize, Deserializer};

use crate::Error;

#[derive(Clone, Debug)]
pub(crate) struct HttpClient {
    inner: Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>,
}

impl HttpClient {
    pub(crate) fn new() -> Result<Self, Error> {
        #[cfg(feature = "webpki-roots")]
        let https = HttpsConnectorBuilder::new().with_webpki_roots();
        #[cfg(not(feature = "webpki-roots"))]
        let https = HttpsConnectorBuilder::new().with_native_roots()?;

        Ok(Self {
            inner: Client::builder().build::<_, Body>(https.https_or_http().enable_http2().build()),
        })
    }

    pub(crate) async fn token(
        &self,
        request: &impl Fn() -> Request<Body>,
        provider: &'static str,
    ) -> Result<Arc<Token>, Error> {
        let mut retries = 0;
        let body = loop {
            let err = match self.try_token(request, provider).await {
                // Early return when the request succeeds
                Ok(body) => break body,
                Err(err) => err,
            };

            tracing::warn!(
                ?err,
                provider,
                retries,
                "failed to refresh token, trying again..."
            );

            retries += 1;
            if retries >= RETRY_COUNT {
                return Err(err);
            }
        };

        serde_json::from_slice(&body).map_err(Error::ParsingError)
    }

    async fn try_token(
        &self,
        request: &impl Fn() -> Request<Body>,
        provider: &'static str,
    ) -> Result<Bytes, Error> {
        let req = request();
        tracing::debug!(?req, provider, "requesting token");
        let (parts, body) = self.inner.request(req).await?.into_parts();
        let body = hyper::body::to_bytes(body)
            .await
            .map_err(Error::ConnectionError)?;

        if !parts.status.is_success() {
            let error = format!(
                "Server responded with error {}: {}",
                parts.status,
                String::from_utf8_lossy(body.as_ref())
            );
            tracing::error!("{}", error);
            return Err(Error::ServerUnavailable(error));
        }

        Ok(body)
    }

    pub(crate) async fn request(&self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        self.inner.request(req).await
    }
}

/// Represents an access token that can be used as a bearer token in HTTP requests
///
/// Tokens should not be cached, the [`AuthenticationManager`] handles the correct caching
/// already.
///
/// The token does not implement [`Display`] to avoid accidentally printing the token in log
/// files, likewise [`Debug`] does not expose the token value itself which is only available
/// using the [Token::`as_str`] method.
///
/// [`AuthenticationManager`]: crate::AuthenticationManager
/// [`Display`]: fmt::Display
/// Token data as returned by the server
///
/// https://cloud.google.com/iam/docs/reference/sts/rest/v1/TopLevel/token#response-body
#[derive(Clone, Deserialize)]
pub struct Token {
    access_token: String,
    #[serde(
        deserialize_with = "deserialize_time",
        rename(deserialize = "expires_in")
    )]
    expires_at: DateTime<Utc>,
}

impl Token {
    pub(crate) fn from_string(access_token: String, expires_in: Duration) -> Self {
        Token {
            access_token,
            expires_at: Utc::now() + expires_in,
        }
    }

    /// Define if the token has has_expired
    ///
    /// This takes an additional 30s margin to ensure the token can still be reasonably used
    /// instead of expiring right after having checked.
    ///
    /// Note:
    /// The official Python implementation uses 20s and states it should be no more than 30s.
    /// The official Go implementation uses 10s (0s for the metadata server).
    /// The docs state, the metadata server caches tokens until 5 minutes before expiry.
    /// We use 20s to be on the safe side.
    pub fn has_expired(&self) -> bool {
        self.expires_at - Duration::from_secs(20) <= Utc::now()
    }

    /// Get str representation of the token.
    pub fn as_str(&self) -> &str {
        &self.access_token
    }

    /// Get expiry of token, if available
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Token")
            .field("access_token", &"****")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// An RSA PKCS1 SHA256 signer
pub struct Signer {
    key: RsaKeyPair,
    rng: SystemRandom,
}

impl Signer {
    pub(crate) fn new(pem_pkcs8: &str) -> Result<Self, Error> {
        let key = match rustls_pemfile::private_key(&mut pem_pkcs8.as_bytes()) {
            Ok(Some(key)) => key,
            Ok(None) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "No private key found in PEM",
                )
                .into())
            }
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Error reading key from PEM",
                )
                .into())
            }
        };

        Ok(Signer {
            key: RsaKeyPair::from_pkcs8(key.secret_der()).map_err(|_| Error::SignerInit)?,
            rng: SystemRandom::new(),
        })
    }

    /// Sign the input message and return the signature
    pub fn sign(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        let mut signature = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(&RSA_PKCS1_SHA256, &self.rng, input, &mut signature)
            .map_err(|_| Error::SignerFailed)?;
        Ok(signature)
    }
}

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signer").finish()
    }
}

fn deserialize_time<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
where
    D: Deserializer<'de>,
{
    let seconds_from_now: u64 = Deserialize::deserialize(deserializer)?;
    Ok(Utc::now() + Duration::from_secs(seconds_from_now))
}

/// How many times to attempt to fetch a token from the set credentials token endpoint.
const RETRY_COUNT: u8 = 5;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_with_time() {
        let s = r#"{"access_token":"abc123","expires_in":100}"#;
        let token: Token = serde_json::from_str(s).unwrap();
        let expires = Utc::now() + Duration::from_secs(100);

        assert_eq!(token.as_str(), "abc123");

        // Testing time is always racy, give it 1s leeway.
        let expires_at = token.expires_at();
        assert!(expires_at < expires + Duration::from_secs(1));
        assert!(expires_at > expires - Duration::from_secs(1));
    }
}
