//! Copyright (c) 2016 Google Inc (lewinb@google.com).

use std::io;

use crate::custom_service_account::ApplicationCredentials;
use crate::prelude::*;
use rustls::{
    self,
    internal::pemfile,
    sign::{self, SigningKey},
    PrivateKey,
};
use serde::Serialize;

pub const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const GOOGLE_RS256_HEAD: &str = r#"{"alg":"RS256","typ":"JWT"}"#;

/// Encodes s as Base64
fn append_base64<T: AsRef<[u8]> + ?Sized>(s: &T, out: &mut String) {
    base64::encode_config_buf(s, base64::URL_SAFE, out)
}

/// Decode a PKCS8 formatted RSA key.
fn decode_rsa_key(pem_pkcs8: &str) -> Result<PrivateKey, io::Error> {
    let private_keys = pemfile::pkcs8_private_keys(&mut pem_pkcs8.as_bytes());

    match private_keys {
        Ok(mut keys) if !keys.is_empty() => {
            keys.truncate(1);
            Ok(keys.remove(0))
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Not enough private keys in PEM",
        )),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Error reading key from PEM",
        )),
    }
}

/// Permissions requested for a JWT.
/// See https://developers.google.com/identity/protocols/OAuth2ServiceAccount#authorizingrequests.
#[derive(Serialize, Debug)]
pub struct Claims<'a> {
    iss: &'a str,
    aud: &'a str,
    exp: i64,
    iat: i64,
    subject: Option<&'a str>,
    scope: String,
}

impl<'a> Claims<'a> {
    pub fn new<T>(key: &'a ApplicationCredentials, scopes: &[T], subject: Option<&'a str>) -> Self
    where
        T: std::string::ToString,
    {
        let iat = chrono::Utc::now().timestamp();
        let expiry = iat + 3600 - 5; // Max validity is 1h.

        let scope: String = scopes
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        Claims {
            iss: &key.client_email,
            aud: &key.token_uri,
            exp: expiry,
            iat,
            subject,
            scope,
        }
    }
}

/// A JSON Web Token ready for signing.
pub(crate) struct JWTSigner {
    signer: Box<dyn rustls::sign::Signer>,
}

impl JWTSigner {
    pub fn new(private_key: &str) -> Result<Self, GCPAuthError> {
        let key = decode_rsa_key(private_key)?;
        let signing_key = sign::RSASigningKey::new(&key)
            .map_err(|_| GCPAuthError::SignerInit)?;
        let signer = signing_key
            .choose_scheme(&[rustls::SignatureScheme::RSA_PKCS1_SHA256])
            .ok_or_else(|| GCPAuthError::SignerSchemeError)?;
        Ok(JWTSigner { signer })
    }

    pub fn sign_claims(&self, claims: &Claims) -> Result<String, rustls::TLSError> {
        let mut jwt_head = Self::encode_claims(claims);
        let signature = self.signer.sign(jwt_head.as_bytes())?;
        jwt_head.push_str(".");
        append_base64(&signature, &mut jwt_head);
        Ok(jwt_head)
    }

    /// Encodes the first two parts (header and claims) to base64 and assembles them into a form
    /// ready to be signed.
    fn encode_claims(claims: &Claims) -> String {
        let mut head = String::new();
        append_base64(GOOGLE_RS256_HEAD, &mut head);
        head.push_str(".");
        append_base64(&serde_json::to_string(&claims).unwrap(), &mut head);
        head
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::read_service_account_key;
    use hyper_rustls::HttpsConnector;

    // Valid but deactivated key.
    const TEST_PRIVATE_KEY_PATH: &'static str = "examples/Sanguine-69411a0c0eea.json";

    // Uncomment this test to verify that we can successfully obtain tokens.
    //#[tokio::test]
    #[allow(dead_code)]
    async fn test_service_account_e2e() {
        let key = read_service_account_key(TEST_PRIVATE_KEY_PATH)
            .await
            .unwrap();
        let acc = ServiceAccountFlow::new(ServiceAccountFlowOpts { key, subject: None }).unwrap();
        let https = HttpsConnector::new();
        let client = hyper::Client::builder()
            .keep_alive(false)
            .build::<_, hyper::Body>(https);
        println!(
            "{:?}",
            acc.token(&client, &["https://www.googleapis.com/auth/pubsub"])
                .await
        );
    }

    #[tokio::test]
    async fn test_jwt_initialize_claims() {
        let key = read_service_account_key(TEST_PRIVATE_KEY_PATH)
            .await
            .unwrap();
        let scopes = vec!["scope1", "scope2", "scope3"];
        let claims = Claims::new(&key, &scopes, None);

        assert_eq!(
            claims.iss,
            "oauth2-public-test@sanguine-rhythm-105020.iam.gserviceaccount.com".to_string()
        );
        assert_eq!(claims.scope, "scope1 scope2 scope3".to_string());
        assert_eq!(
            claims.aud,
            "https://accounts.google.com/o/oauth2/token".to_string()
        );
        assert!(claims.exp > 1000000000);
        assert!(claims.iat < claims.exp);
        assert_eq!(claims.exp - claims.iat, 3595);
    }

    #[tokio::test]
    async fn test_jwt_sign() {
        let key = read_service_account_key(TEST_PRIVATE_KEY_PATH)
            .await
            .unwrap();
        let scopes = vec!["scope1", "scope2", "scope3"];
        let signer = JWTSigner::new(&key.private_key).unwrap();
        let claims = Claims::new(&key, &scopes, None);
        let signature = signer.sign_claims(&claims);

        assert!(signature.is_ok());

        let signature = signature.unwrap();
        assert_eq!(
            signature.split(".").nth(0).unwrap(),
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
        );
    }
}
