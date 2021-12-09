use std::fmt;
use std::sync::Arc;

use serde::Deserializer;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

/// Represents an access token. All access tokens are Bearer tokens.
///
/// Tokens should not be cached, the [`AuthenticationManager`] handles the correct caching
/// already.  Tokens are cheap to clone.
///
/// The token does not implement [`Display`] to avoid accidentally printing the token in log
/// files, likewise [`Debug`] does not expose the token value itself which is only available
/// using the [Token::`as_str`] method.
///
/// [`AuthenticationManager`]: crate::AuthenticationManager
/// [`Display`]: fmt::Display
/// [`Debug`]: fmt::Debug
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct Token {
    #[serde(flatten)]
    inner: Arc<InnerToken>,
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Token")
            .field("access_token", &"****")
            .field("expires_at", &self.inner.expires_at)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
struct InnerToken {
    access_token: String,
    #[serde(
        default,
        deserialize_with = "deserialize_time",
        rename(deserialize = "expires_in")
    )]
    expires_at: Option<OffsetDateTime>,
}

impl Token {
    /// Define if the token has has_expired
    ///
    /// This takes an additional 30s margin to ensure the token can still be reasonably used
    /// instead of expiring right after having checked.
    pub fn has_expired(&self) -> bool {
        self.inner
            .expires_at
            .map(|expiration_time| {
                expiration_time - Duration::seconds(30) <= OffsetDateTime::now_utc()
            })
            .unwrap_or(false)
    }

    /// Get str representation of the token.
    pub fn as_str(&self) -> &str {
        &self.inner.access_token
    }

    /// Get expiry of token, if available
    pub fn expires_at(&self) -> Option<OffsetDateTime> {
        self.inner.expires_at
    }
}

fn deserialize_time<'de, D>(deserializer: D) -> Result<Option<OffsetDateTime>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<i64> = Deserialize::deserialize(deserializer)?;
    let s =
        s.map(|seconds_from_now| OffsetDateTime::now_utc() + Duration::seconds(seconds_from_now));
    Ok(s)
}

pub(crate) type HyperClient =
    hyper::Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialise() {
        let token = Token {
            inner: Arc::new(InnerToken {
                access_token: "abc123".to_string(),
                expires_at: Some(OffsetDateTime::from_unix_timestamp(123).unwrap()),
            }),
        };
        let s = serde_json::to_string(&token).unwrap();

        assert_eq!(
            s,
            r#"{"access_token":"abc123","expires_at":[1970,1,0,2,3,0,0,0,0]}"#
        );
    }

    #[test]
    fn test_deserialise_with_time() {
        let s = r#"{"access_token":"abc123","expires_in":100}"#;
        let token: Token = serde_json::from_str(s).unwrap();
        let expires = OffsetDateTime::now_utc() + Duration::seconds(100);

        assert_eq!(token.as_str(), "abc123");

        // Testing time is always racy, give it 1s leeway.
        let expires_at = token.expires_at().unwrap();
        assert!(expires_at < expires + Duration::seconds(1));
        assert!(expires_at > expires - Duration::seconds(1));
    }

    #[test]
    fn test_deserialise_no_time() {
        let s = r#"{"access_token":"abc123"}"#;
        let token: Token = serde_json::from_str(s).unwrap();

        assert_eq!(token.as_str(), "abc123");
        assert!(token.expires_at().is_none());
    }
}
