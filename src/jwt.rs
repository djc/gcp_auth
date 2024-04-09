//! Copyright (c) 2016 Google Inc (lewinb@google.com).

use base64::{engine::general_purpose::URL_SAFE, Engine};
use chrono::Utc;
use serde::Serialize;

use crate::custom_service_account::ApplicationCredentials;
use crate::error::Error;
use crate::types::Signer;

pub(crate) const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const GOOGLE_RS256_HEAD: &str = r#"{"alg":"RS256","typ":"JWT"}"#;

/// Permissions requested for a JWT.
/// See https://developers.google.com/identity/protocols/OAuth2ServiceAccount#authorizingrequests.
#[derive(Serialize, Debug)]
pub(crate) struct Claims<'a> {
    iss: &'a str,
    aud: &'a str,
    exp: i64,
    iat: i64,
    sub: Option<&'a str>,
    scope: String,
}

impl<'a> Claims<'a> {
    pub(crate) fn new<T>(
        key: &'a ApplicationCredentials,
        scopes: &[T],
        sub: Option<&'a str>,
    ) -> Self
    where
        T: std::string::ToString,
    {
        let iat = Utc::now().timestamp();
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
            sub,
            scope,
        }
    }

    pub(crate) fn to_jwt(&self, signer: &Signer) -> Result<String, Error> {
        let mut jwt = String::new();
        URL_SAFE.encode_string(GOOGLE_RS256_HEAD, &mut jwt);
        jwt.push('.');
        URL_SAFE.encode_string(&serde_json::to_string(self).unwrap(), &mut jwt);

        let signature = signer.sign(jwt.as_bytes())?;
        jwt.push('.');
        URL_SAFE.encode_string(&signature, &mut jwt);
        Ok(jwt)
    }
}
