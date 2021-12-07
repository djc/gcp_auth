use std::fmt;

use serde::Deserializer;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

/// Represents an access token. All access tokens are Bearer tokens.
///
/// Tokens cannot be cached.
///
/// The token does not implement [`Display`] to avoid accidentally printing the token in log
/// files, likewise [`Debug`] does not expose the token value itself which is only available
/// using the [Token::`as_str`] method.
///
/// [`Display`]: fmt::Display
/// [`Debug`]: fmt::Debug
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct Token {
    access_token: String,
    #[serde(
        default,
        deserialize_with = "deserialize_time",
        rename(deserialize = "expires_in")
    )]
    expires_at: Option<OffsetDateTime>,
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Token")
            .field("access_token", &"****")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Token {
    /// Define if the token has has_expired
    pub fn has_expired(&self) -> bool {
        self.expires_at
            .map(|expiration_time| {
                expiration_time - Duration::seconds(30) <= OffsetDateTime::now_utc()
            })
            .unwrap_or(false)
    }

    /// Get str representation of the token.
    pub fn as_str(&self) -> &str {
        &self.access_token
    }

    /// Get expiry of token, if available
    pub fn expires_at(&self) -> Option<OffsetDateTime> {
        self.expires_at
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
