use chrono::{DateTime, Utc};
use serde::{Deserializer};
use serde::{Deserialize, Serialize};

/// Represents an access token. All access tokens are Bearer tokens.
/// Token cannot be cached.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct Token {
    access_token: String,
    #[serde(
        deserialize_with = "deserialize_time",
        rename(deserialize = "expires_in")
    )]
    expires_at: Option<DateTime<Utc>>,
}

impl Token {
    pub(crate) fn has_expired(&self) -> bool {
        self.expires_at
            .map(|expiration_time| expiration_time - chrono::Duration::minutes(1) <= Utc::now())
            .unwrap_or(false)
    }

    /// Get str representation of the token.
    pub fn as_str(&self) -> &str {
        &self.access_token
    }
}

fn deserialize_time<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<i64> = Deserialize::deserialize(deserializer)?;
    let s = s.map(|seconds_from_now| Utc::now() + chrono::Duration::seconds(seconds_from_now));
    Ok(s)
}

pub type HyperClient = hyper::Client<hyper_tls::HttpsConnector<hyper::client::HttpConnector>>;
