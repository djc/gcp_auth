use std::fs::File;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{env, fmt};

use bytes::Buf;
use chrono::{DateTime, Utc};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::Request;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use serde::{Deserialize, Deserializer};
use tracing::{debug, warn};

use crate::Error;

#[derive(Clone, Debug)]
pub(crate) struct HttpClient {
    inner: Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Full<Bytes>,
    >,
}

impl HttpClient {
    pub(crate) fn new() -> Result<Self, Error> {
        #[cfg(feature = "webpki-roots")]
        let https = HttpsConnectorBuilder::new().with_webpki_roots();
        #[cfg(not(feature = "webpki-roots"))]
        let https = HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|err| {
                Error::Io("failed to load native TLS root certificates for HTTPS", err)
            })?;

        Ok(Self {
            inner: Client::builder(TokioExecutor::new())
                .build(https.https_or_http().enable_http2().build()),
        })
    }

    pub(crate) async fn token(
        &self,
        request: &impl Fn() -> Request<Full<Bytes>>,
        provider: &'static str,
    ) -> Result<Arc<Token>, Error> {
        let mut retries = 0;
        let body = loop {
            let err = match self.request(request(), provider).await {
                // Early return when the request succeeds
                Ok(body) => break body,
                Err(err) => err,
            };

            warn!(
                ?err,
                provider, retries, "failed to refresh token, trying again..."
            );

            retries += 1;
            if retries >= RETRY_COUNT {
                return Err(err);
            }
        };

        serde_json::from_slice(&body)
            .map_err(|err| Error::Json("failed to deserialize token from response", err))
    }

    pub(crate) async fn request(
        &self,
        req: Request<Full<Bytes>>,
        provider: &'static str,
    ) -> Result<Bytes, Error> {
        debug!(url = ?req.uri(), provider, "requesting token");
        let (parts, body) = self
            .inner
            .request(req)
            .await
            .map_err(|err| Error::Other("HTTP request failed", Box::new(err)))?
            .into_parts();

        let mut body = body
            .collect()
            .await
            .map_err(|err| Error::Http("failed to read HTTP response body", err))?
            .aggregate();

        let body = body.copy_to_bytes(body.remaining());
        if !parts.status.is_success() {
            let body = String::from_utf8_lossy(body.as_ref());
            warn!(%body, status = ?parts.status, "token request failed");
            return Err(Error::Str("token request failed"));
        }

        Ok(body)
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
                return Err(Error::Str(
                    "no private key found in credentials private key data",
                ))
            }
            Err(err) => {
                return Err(Error::Io(
                    "failed to read credentials private key data",
                    err,
                ))
            }
        };

        Ok(Signer {
            key: RsaKeyPair::from_pkcs8(key.secret_der())
                .map_err(|_| Error::Str("invalid private key in credentials"))?,
            rng: SystemRandom::new(),
        })
    }

    /// Sign the input message and return the signature
    pub fn sign(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        let mut signature = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(&RSA_PKCS1_SHA256, &self.rng, input, &mut signature)
            .map_err(|_| Error::Str("failed to sign with credentials key"))?;
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

#[derive(Deserialize)]
pub(crate) struct ServiceAccountKey {
    /// project_id
    pub(crate) project_id: Option<Arc<str>>,
    /// private_key
    pub(crate) private_key: String,
    /// client_email
    pub(crate) client_email: String,
    /// token_uri
    pub(crate) token_uri: String,
}

impl ServiceAccountKey {
    pub(crate) fn from_env() -> Result<Option<Self>, Error> {
        env::var_os("GOOGLE_APPLICATION_CREDENTIALS")
            .map(|path| {
                debug!(
                    ?path,
                    "reading credentials file from GOOGLE_APPLICATION_CREDENTIALS env var"
                );
                Self::from_file(&path)
            })
            .transpose()
    }

    pub(crate) fn from_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        let file = File::open(path.as_ref())
            .map_err(|err| Error::Io("failed to open application credentials file", err))?;
        serde_json::from_reader(file)
            .map_err(|err| Error::Json("failed to deserialize ApplicationCredentials", err))
    }
}

impl FromStr for ServiceAccountKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
            .map_err(|err| Error::Json("failed to deserialize ApplicationCredentials", err))
    }
}

impl fmt::Debug for ServiceAccountKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApplicationCredentials")
            .field("client_email", &self.client_email)
            .field("project_id", &self.project_id)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
pub(crate) struct AuthorizedUserRefreshToken {
    /// Client id
    pub(crate) client_id: String,
    /// Client secret
    pub(crate) client_secret: String,
    /// Project ID
    pub(crate) quota_project_id: Option<Arc<str>>,
    /// Refresh Token
    pub(crate) refresh_token: String,
}

impl AuthorizedUserRefreshToken {
    pub(crate) fn from_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        let file = File::open(path.as_ref())
            .map_err(|err| Error::Io("failed to open application credentials file", err))?;
        serde_json::from_reader(file)
            .map_err(|err| Error::Json("failed to deserialize ApplicationCredentials", err))
    }
}

impl fmt::Debug for AuthorizedUserRefreshToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserCredentials")
            .field("client_id", &self.client_id)
            .field("quota_project_id", &self.quota_project_id)
            .finish_non_exhaustive()
    }
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
