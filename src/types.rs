use std::io::BufReader;
use std::sync::Arc;
use std::{fmt, io};

use hyper::Client;
use hyper_rustls::HttpsConnectorBuilder;
use ring::{
    rand::SystemRandom,
    signature::{RsaKeyPair, RSA_PKCS1_SHA256},
};
use serde::Deserializer;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::{
    custom_service_account::ApplicationCredentials, default_authorized_user::UserCredentials, Error,
};

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

impl Token {
    pub(crate) fn from_string(access_token: String, expires_in: Duration) -> Self {
        Token {
            inner: Arc::new(InnerToken {
                access_token,
                expires_at: OffsetDateTime::now_utc() + expires_in,
            }),
        }
    }
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
        deserialize_with = "deserialize_time",
        rename(deserialize = "expires_in")
    )]
    expires_at: OffsetDateTime,
}

impl Token {
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
        self.inner.expires_at - Duration::seconds(20) <= OffsetDateTime::now_utc()
    }

    /// Get str representation of the token.
    pub fn as_str(&self) -> &str {
        &self.inner.access_token
    }

    /// Get expiry of token, if available
    pub fn expires_at(&self) -> OffsetDateTime {
        self.inner.expires_at
    }
}

/// An RSA PKCS1 SHA256 signer
pub struct Signer {
    key: RsaKeyPair,
    rng: SystemRandom,
}

impl Signer {
    pub(crate) fn new(pem_pkcs8: &str) -> Result<Self, Error> {
        let private_keys = rustls_pemfile::pkcs8_private_keys(&mut pem_pkcs8.as_bytes());

        let key = match private_keys {
            Ok(mut keys) if !keys.is_empty() => {
                keys.truncate(1);
                keys.remove(0)
            }
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Not enough private keys in PEM",
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
            key: RsaKeyPair::from_pkcs8(&key).map_err(|_| Error::SignerInit)?,
            rng: SystemRandom::new(),
        })
    }

    /// Sign the input message and return the signature
    pub fn sign(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        let mut signature = vec![0; self.key.public_modulus_len()];
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

fn deserialize_time<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
where
    D: Deserializer<'de>,
{
    let seconds_from_now: i64 = Deserialize::deserialize(deserializer)?;
    Ok(OffsetDateTime::now_utc() + Duration::seconds(seconds_from_now))
}

pub(crate) fn client() -> HyperClient {
    #[cfg(feature = "webpki-roots")]
    let https = HttpsConnectorBuilder::new().with_webpki_roots();
    #[cfg(not(feature = "webpki-roots"))]
    let https = HttpsConnectorBuilder::new().with_native_roots();

    Client::builder().build::<_, hyper::Body>(https.https_or_http().enable_http2().build())
}

pub(crate) type HyperClient =
    hyper::Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>;

// Implementation referenced from
// https://github.com/golang/oauth2/blob/a835fc4358f6852f50c4c5c33fddcd1adade5b0a/google/google.go#L158
// Currently not implementing external account credentials
// Currently not implementing impersonating service accounts (coming soon !)
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum CredentialSource {
    // This credential parses the `key.json` file created when running
    // `gcloud iam service-accounts keys create key.json --iam-account=SA_NAME@PROJECT_ID.iam.gserviceaccount.com`
    ServiceAccount(ApplicationCredentials),
    // This credential parses the `~/.config/gcloud/application_default_credentials.json` file
    // created when running `gcloud auth application-default login`
    AuthorizedUser(UserCredentials),
}

impl CredentialSource {
    const USER_CREDENTIALS_PATH: &'static str =
        ".config/gcloud/application_default_credentials.json";

    pub(crate) async fn from_env() -> Result<Option<Self>, Error> {
        let creds_path = std::env::var_os("GOOGLE_APPLICATION_CREDENTIALS");
        let Some(path) = creds_path else { return Ok(None); };
        tracing::debug!("Reading credentials file from GOOGLE_APPLICATION_CREDENTIALS env var");
        let file = std::fs::File::open(path).map_err(Error::CustomServiceAccountPath)?;

        serde_json::from_reader::<_, CredentialSource>(BufReader::new(file))
            .map_err(Error::CustomServiceAccountCredentials)
            .map(Some)
    }

    pub(crate) async fn from_default_credentials() -> Result<Self, Error> {
        tracing::debug!("Loading user credentials file");
        let mut home = dirs_next::home_dir().ok_or(Error::NoHomeDir)?;
        home.push(Self::USER_CREDENTIALS_PATH);

        let file = std::fs::File::open(home).map_err(Error::CustomServiceAccountPath)?;

        serde_json::from_reader::<_, CredentialSource>(BufReader::new(file))
            .map_err(Error::CustomServiceAccountCredentials)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        authentication_manager::ServiceAccount, default_authorized_user::ConfigDefaultCredentials,
        CustomServiceAccount,
    };

    use super::*;

    #[test]
    fn test_serialise() {
        let token = Token {
            inner: Arc::new(InnerToken {
                access_token: "abc123".to_string(),
                expires_at: OffsetDateTime::from_unix_timestamp(123).unwrap(),
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
        let expires_at = token.expires_at();
        assert!(expires_at < expires + Duration::seconds(1));
        assert!(expires_at > expires - Duration::seconds(1));
    }

    #[tokio::test]
    async fn test_parse_application_default_credentials() {
        let test_creds = r#"{
            "client_id": "***id***.apps.googleusercontent.com",
            "client_secret": "***secret***",
            "quota_project_id": "test_project",
            "refresh_token": "***refresh***",
            "type": "authorized_user"
        }"#;

        let cred_source: CredentialSource =
            serde_json::from_str(test_creds).expect("Valid creds to parse");

        assert!(matches!(cred_source, CredentialSource::AuthorizedUser(_)));

        // Can't test converting this into a service account because it requires actually getting a key
    }

    #[tokio::test]
    async fn test_parse_service_account_key() {
        // Don't worry, even though the key is a real private_key, it's not used for anything
        let test_creds = r#" {
            "type": "service_account",
            "project_id": "test_project",
            "private_key_id": "***key_id***",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5M5y3WwsRk8NX\npF9fKaZukNspot9Ecmk1PAkupcHLKVhalwPxU4sMNWXgM9H2LTWSvvyOT//rDQpn\n3SGYri/lMhzb4lI8h10E7k6zyFQUPujxkXFBkMOzhIDUgtiiht0WvIw6M8nbaPqI\nxn/aYmPsFhvJfKCthYAt2UUz+D3enI9QjCuhic8iSMnvKT8m0QkOG2eALYGUaLF1\ngRkbV4BiBUGZfXfNEBdux3Wf4kNUau32LA0XotomlvNvf1oH77v5Hc1R/KMMIk5F\nJWVBuAr4jwkN9hwtOozpJ/52wSpddxsZuj+0nP1a3f0UyvrmMnuwszardPK39BoH\nJ+5+HZM3AgMBAAECggEADrHZrXK73hkrVrjkGFjlq8Ayo4sYzAWH84Ff+SONzODq\n8cUpuuw2DDHwc2mpLy9HIO2mfGQ8mhneyX7yO3sWscjYIVpDzCmxZ8LA2+L5SOH0\n+bXglqM14/iPgE0hg0PQJw2u0q9pRM9/kXquilVkOEdIzSPmW95L3Vdv9j+sKQ2A\nOL23l4dsaG4+i1lWRBKiGsLh1kB9FRnm4BzcOxd3WGooy7L1/jo9BoYRss1YABls\nmmyZ9f7r28zjclhpOBkE3OXX0zNbp4yIu1O1Bt9X2p87EOuYqlFA5eEvDbiTPZbk\n6wKEX3BPUkeIo8OaGvsGhHCWx0lv/sDPw/UofycOgQKBgQD4BD059aXEV13Byc5D\nh8LQSejjeM/Vx+YeCFI66biaIOvUs+unyxkH+qxXTuW6AgOgcvrJo93xkyAZ9SeR\nc6Vj9g5mZ5vqSJz5Hg8h8iZBAYtf40qWq0pHcmUIm2Z9LvrG5ZFHU5EEcCtLyBVS\nAv+pLLLf3OsAkJuuqTAgygBbOwKBgQC/KcBa9sUg2u9qIpq020UOW/n4KFWhSJ8h\ngXqqmjOnPqmDc5AnYg1ZdYdqSSgdiK8lJpRL/S2UjYUQp3H+56z0eK/b1iKM51n+\n6D80nIxWeKJ+n7VKI7cBXwc/KokaXgkz0It2UEZSlhPUMImnYcOvGIZ7cMr3Q6mf\n6FwD15UQNQKBgQDyAsDz454DvvS/+noJL1qMAPL9tI+pncwQljIXRqVZ0LIO9hoH\nu4kLXjH5aAWGwhxj3o6VYA9cgSIb8jrQFbbXmexnRMbBkGWMOSavCykE2cr0oEfS\nSgbLPPcVtP4HPWZ72tsubH7fg8zbv7v+MOrkW7eX9mxiOrmPb4yFElfSrQKBgA7y\nMLvr91WuSHG/6uChFDEfN9gTLz7A8tAn03NrQwace5xveKHbpLeN3NyOg7hra2Y4\nMfgO/3VR60l2Dg+kBX3HwdgqUeE6ZWrstaRjaQWJwQqtafs196T/zQ0/QiDxoT6P\n25eQhy8F1N8OPHT9y9Lw0/LqyrOycpyyCh+yx1DRAoGAJ/6dlhyQnwSfMAe3mfRC\noiBQG6FkyoeXHHYcoQ/0cSzwp0BwBlar1Z28P7KTGcUNqV+YfK9nF47eoLaTLCmG\nG5du0Ds6m2Eg0sOBBqXHnw6R1PC878tgT/XokNxIsVlF5qRz88q7Rn0J1lzB7+Tl\n2HSAcyIUcmr0gxlhRmC2Jq4=\n-----END PRIVATE KEY-----\n",
            "client_email": "test_account@test.iam.gserviceaccount.com",
            "client_id": "***id***",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test_account%40test.iam.gserviceaccount.com",
            "universe_domain": "googleapis.com"
        }"#;

        let cred_source: CredentialSource =
            serde_json::from_str(test_creds).expect("Valid creds to parse");

        assert!(matches!(cred_source, CredentialSource::ServiceAccount(_)));

        let client = client();

        let creds: Box<dyn ServiceAccount> = match cred_source {
            CredentialSource::ServiceAccount(creds) => {
                let service_account =
                    CustomServiceAccount::new(creds).expect("Valid creds to parse");

                Box::new(service_account)
            }
            CredentialSource::AuthorizedUser(creds) => {
                let service_account =
                    ConfigDefaultCredentials::from_user_credentials(creds, &client)
                        .await
                        .expect("Valid creds to parse");
                Box::new(service_account)
            }
        };

        assert_eq!(
            creds
                .project_id(&client)
                .await
                .expect("Project ID to be present"),
            "test_project".to_string(),
            "Project ID should be parsed"
        );
    }

    #[tokio::test]
    async fn test_additional_service_account_keys() {
        // Using test cases from https://github.com/golang/oauth2/blob/a835fc4358f6852f50c4c5c33fddcd1adade5b0a/google/google_test.go#L40
        // We have to use a real private key because we validate private keys on parsing as well.
        let k1 = r#"{
            "private_key_id": "268f54e43a1af97cfc71731688434f45aca15c8b",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5M5y3WwsRk8NX\npF9fKaZukNspot9Ecmk1PAkupcHLKVhalwPxU4sMNWXgM9H2LTWSvvyOT//rDQpn\n3SGYri/lMhzb4lI8h10E7k6zyFQUPujxkXFBkMOzhIDUgtiiht0WvIw6M8nbaPqI\nxn/aYmPsFhvJfKCthYAt2UUz+D3enI9QjCuhic8iSMnvKT8m0QkOG2eALYGUaLF1\ngRkbV4BiBUGZfXfNEBdux3Wf4kNUau32LA0XotomlvNvf1oH77v5Hc1R/KMMIk5F\nJWVBuAr4jwkN9hwtOozpJ/52wSpddxsZuj+0nP1a3f0UyvrmMnuwszardPK39BoH\nJ+5+HZM3AgMBAAECggEADrHZrXK73hkrVrjkGFjlq8Ayo4sYzAWH84Ff+SONzODq\n8cUpuuw2DDHwc2mpLy9HIO2mfGQ8mhneyX7yO3sWscjYIVpDzCmxZ8LA2+L5SOH0\n+bXglqM14/iPgE0hg0PQJw2u0q9pRM9/kXquilVkOEdIzSPmW95L3Vdv9j+sKQ2A\nOL23l4dsaG4+i1lWRBKiGsLh1kB9FRnm4BzcOxd3WGooy7L1/jo9BoYRss1YABls\nmmyZ9f7r28zjclhpOBkE3OXX0zNbp4yIu1O1Bt9X2p87EOuYqlFA5eEvDbiTPZbk\n6wKEX3BPUkeIo8OaGvsGhHCWx0lv/sDPw/UofycOgQKBgQD4BD059aXEV13Byc5D\nh8LQSejjeM/Vx+YeCFI66biaIOvUs+unyxkH+qxXTuW6AgOgcvrJo93xkyAZ9SeR\nc6Vj9g5mZ5vqSJz5Hg8h8iZBAYtf40qWq0pHcmUIm2Z9LvrG5ZFHU5EEcCtLyBVS\nAv+pLLLf3OsAkJuuqTAgygBbOwKBgQC/KcBa9sUg2u9qIpq020UOW/n4KFWhSJ8h\ngXqqmjOnPqmDc5AnYg1ZdYdqSSgdiK8lJpRL/S2UjYUQp3H+56z0eK/b1iKM51n+\n6D80nIxWeKJ+n7VKI7cBXwc/KokaXgkz0It2UEZSlhPUMImnYcOvGIZ7cMr3Q6mf\n6FwD15UQNQKBgQDyAsDz454DvvS/+noJL1qMAPL9tI+pncwQljIXRqVZ0LIO9hoH\nu4kLXjH5aAWGwhxj3o6VYA9cgSIb8jrQFbbXmexnRMbBkGWMOSavCykE2cr0oEfS\nSgbLPPcVtP4HPWZ72tsubH7fg8zbv7v+MOrkW7eX9mxiOrmPb4yFElfSrQKBgA7y\nMLvr91WuSHG/6uChFDEfN9gTLz7A8tAn03NrQwace5xveKHbpLeN3NyOg7hra2Y4\nMfgO/3VR60l2Dg+kBX3HwdgqUeE6ZWrstaRjaQWJwQqtafs196T/zQ0/QiDxoT6P\n25eQhy8F1N8OPHT9y9Lw0/LqyrOycpyyCh+yx1DRAoGAJ/6dlhyQnwSfMAe3mfRC\noiBQG6FkyoeXHHYcoQ/0cSzwp0BwBlar1Z28P7KTGcUNqV+YfK9nF47eoLaTLCmG\nG5du0Ds6m2Eg0sOBBqXHnw6R1PC878tgT/XokNxIsVlF5qRz88q7Rn0J1lzB7+Tl\n2HSAcyIUcmr0gxlhRmC2Jq4=\n-----END PRIVATE KEY-----\n",
            "client_email": "gopher@developer.gserviceaccount.com",
            "client_id": "gopher.apps.googleusercontent.com",
            "token_uri": "https://accounts.google.com/o/gophers/token",
            "type": "service_account",
            "audience": "https://testservice.googleapis.com/"
        }"#;

        let k3 = r#"{
            "private_key_id": "268f54e43a1af97cfc71731688434f45aca15c8b",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5M5y3WwsRk8NX\npF9fKaZukNspot9Ecmk1PAkupcHLKVhalwPxU4sMNWXgM9H2LTWSvvyOT//rDQpn\n3SGYri/lMhzb4lI8h10E7k6zyFQUPujxkXFBkMOzhIDUgtiiht0WvIw6M8nbaPqI\nxn/aYmPsFhvJfKCthYAt2UUz+D3enI9QjCuhic8iSMnvKT8m0QkOG2eALYGUaLF1\ngRkbV4BiBUGZfXfNEBdux3Wf4kNUau32LA0XotomlvNvf1oH77v5Hc1R/KMMIk5F\nJWVBuAr4jwkN9hwtOozpJ/52wSpddxsZuj+0nP1a3f0UyvrmMnuwszardPK39BoH\nJ+5+HZM3AgMBAAECggEADrHZrXK73hkrVrjkGFjlq8Ayo4sYzAWH84Ff+SONzODq\n8cUpuuw2DDHwc2mpLy9HIO2mfGQ8mhneyX7yO3sWscjYIVpDzCmxZ8LA2+L5SOH0\n+bXglqM14/iPgE0hg0PQJw2u0q9pRM9/kXquilVkOEdIzSPmW95L3Vdv9j+sKQ2A\nOL23l4dsaG4+i1lWRBKiGsLh1kB9FRnm4BzcOxd3WGooy7L1/jo9BoYRss1YABls\nmmyZ9f7r28zjclhpOBkE3OXX0zNbp4yIu1O1Bt9X2p87EOuYqlFA5eEvDbiTPZbk\n6wKEX3BPUkeIo8OaGvsGhHCWx0lv/sDPw/UofycOgQKBgQD4BD059aXEV13Byc5D\nh8LQSejjeM/Vx+YeCFI66biaIOvUs+unyxkH+qxXTuW6AgOgcvrJo93xkyAZ9SeR\nc6Vj9g5mZ5vqSJz5Hg8h8iZBAYtf40qWq0pHcmUIm2Z9LvrG5ZFHU5EEcCtLyBVS\nAv+pLLLf3OsAkJuuqTAgygBbOwKBgQC/KcBa9sUg2u9qIpq020UOW/n4KFWhSJ8h\ngXqqmjOnPqmDc5AnYg1ZdYdqSSgdiK8lJpRL/S2UjYUQp3H+56z0eK/b1iKM51n+\n6D80nIxWeKJ+n7VKI7cBXwc/KokaXgkz0It2UEZSlhPUMImnYcOvGIZ7cMr3Q6mf\n6FwD15UQNQKBgQDyAsDz454DvvS/+noJL1qMAPL9tI+pncwQljIXRqVZ0LIO9hoH\nu4kLXjH5aAWGwhxj3o6VYA9cgSIb8jrQFbbXmexnRMbBkGWMOSavCykE2cr0oEfS\nSgbLPPcVtP4HPWZ72tsubH7fg8zbv7v+MOrkW7eX9mxiOrmPb4yFElfSrQKBgA7y\nMLvr91WuSHG/6uChFDEfN9gTLz7A8tAn03NrQwace5xveKHbpLeN3NyOg7hra2Y4\nMfgO/3VR60l2Dg+kBX3HwdgqUeE6ZWrstaRjaQWJwQqtafs196T/zQ0/QiDxoT6P\n25eQhy8F1N8OPHT9y9Lw0/LqyrOycpyyCh+yx1DRAoGAJ/6dlhyQnwSfMAe3mfRC\noiBQG6FkyoeXHHYcoQ/0cSzwp0BwBlar1Z28P7KTGcUNqV+YfK9nF47eoLaTLCmG\nG5du0Ds6m2Eg0sOBBqXHnw6R1PC878tgT/XokNxIsVlF5qRz88q7Rn0J1lzB7+Tl\n2HSAcyIUcmr0gxlhRmC2Jq4=\n-----END PRIVATE KEY-----\n",
            "client_email": "gopher@developer.gserviceaccount.com",
            "client_id": "gopher.apps.googleusercontent.com",
            "token_uri": "https://accounts.google.com/o/gophers/token",
            "type": "service_account"
        }"#;

        let client = client();
        for key in [k1, k3] {
            let cred_source: CredentialSource =
                serde_json::from_str(key).expect("Valid creds to parse");

            assert!(matches!(cred_source, CredentialSource::ServiceAccount(_)));

            let creds: Box<dyn ServiceAccount> = match cred_source {
                CredentialSource::ServiceAccount(creds) => {
                    let service_account =
                        CustomServiceAccount::new(creds).expect("Valid creds to parse");

                    Box::new(service_account)
                }
                CredentialSource::AuthorizedUser(creds) => {
                    let service_account =
                        ConfigDefaultCredentials::from_user_credentials(creds, &client)
                            .await
                            .expect("Valid creds to parse");
                    Box::new(service_account)
                }
            };

            assert!(
                matches!(
                    creds
                        .project_id(&client)
                        .await
                        .expect_err("Project ID to not be present"),
                    crate::Error::ProjectIdNotFound,
                ),
                "Project id should not be found here",
            );
        }
    }
}
