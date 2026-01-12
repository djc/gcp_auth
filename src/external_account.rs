//! External account credentials for Workload Identity Federation
//!
//! This module implements authentication using external identity providers
//! (e.g., GitHub Actions OIDC, AWS, Azure) via GCP Workload Identity Federation.
//!
//! See: https://google.aip.dev/auth/4117

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::Full;
use hyper::header::CONTENT_TYPE;
use hyper::Request;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, instrument, Level};
use url::form_urlencoded;

use crate::types::{ExternalAccountCredentials, HttpClient, Token};
use crate::{Error, TokenProvider};

/// Provider for external account credentials (Workload Identity Federation)
#[derive(Debug)]
pub struct ExternalAccount {
    client: HttpClient,
    credentials: ExternalAccountCredentials,
    tokens: RwLock<HashMap<Vec<String>, Arc<Token>>>,
}

impl ExternalAccount {
    /// Create from credentials
    pub(crate) fn new(
        credentials: ExternalAccountCredentials,
        client: HttpClient,
    ) -> Result<Self, Error> {
        debug!(
            audience = %credentials.audience,
            token_url = %credentials.token_url,
            "creating ExternalAccount provider"
        );
        Ok(Self {
            client,
            credentials,
            tokens: RwLock::new(HashMap::new()),
        })
    }

    /// Read the subject token from the credential source
    async fn read_subject_token(&self) -> Result<String, Error> {
        let source = &self.credentials.credential_source;

        // Read from file
        if let Some(file_path) = &source.file {
            debug!(path = %file_path, "reading subject token from file");
            let token = tokio::fs::read_to_string(file_path)
                .await
                .map_err(|err| Error::Io("failed to read subject token file", err))?;
            return self.extract_token(token.trim().to_string());
        }

        // Read from URL
        if let Some(url) = &source.url {
            debug!(url = %url, "fetching subject token from URL");
            let mut req_builder = Request::get(url);

            // Add headers if specified
            if let Some(headers) = &source.headers {
                for (key, value) in headers {
                    req_builder = req_builder.header(key.as_str(), value.as_str());
                }
            }

            let request = req_builder
                .body(Full::from(Bytes::new()))
                .map_err(|_| Error::Str("failed to build subject token request"))?;

            let body = self.client.request(request, "ExternalAccount").await?;
            let token = String::from_utf8_lossy(&body).to_string();
            return self.extract_token(token);
        }

        Err(Error::Str(
            "external account credential_source must have 'file' or 'url'",
        ))
    }

    /// Extract token from response based on format specification
    fn extract_token(&self, response: String) -> Result<String, Error> {
        let format = &self.credentials.credential_source.format;

        match format {
            Some(f) if f.format_type == "json" => {
                let field_name = f
                    .subject_token_field_name
                    .as_deref()
                    .unwrap_or("access_token");
                let json: serde_json::Value = serde_json::from_str(&response)
                    .map_err(|err| Error::Json("failed to parse subject token response", err))?;
                json.get(field_name)
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .ok_or(Error::Str("subject_token_field_name not found in response"))
            }
            // Default to text format
            _ => Ok(response),
        }
    }

    /// Exchange subject token for a GCP access token via STS
    #[instrument(level = Level::DEBUG, skip(self, subject_token))]
    async fn exchange_token(
        &self,
        subject_token: &str,
        scopes: &[&str],
    ) -> Result<Arc<Token>, Error> {
        let scope = scopes.join(" ");

        let body = Bytes::from(
            form_urlencoded::Serializer::new(String::new())
                .extend_pairs(&[
                    (
                        "grant_type",
                        "urn:ietf:params:oauth:grant-type:token-exchange",
                    ),
                    ("audience", &self.credentials.audience),
                    ("subject_token", subject_token),
                    ("subject_token_type", &self.credentials.subject_token_type),
                    (
                        "requested_token_type",
                        "urn:ietf:params:oauth:token-type:access_token",
                    ),
                    ("scope", &scope),
                ])
                .finish()
                .into_bytes(),
        );

        let response_body = self
            .client
            .request(
                Request::post(&self.credentials.token_url)
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Full::from(body))
                    .unwrap(),
                "ExternalAccount/STS",
            )
            .await?;

        let sts_response: StsTokenResponse = serde_json::from_slice(&response_body)
            .map_err(|err| Error::Json("failed to parse STS response", err))?;

        let expires_in = std::time::Duration::from_secs(sts_response.expires_in.unwrap_or(3600));
        let token = Arc::new(Token::from_string(sts_response.access_token, expires_in));

        // If service account impersonation is configured, use the STS token to get an impersonated token
        if let Some(impersonation_url) = &self.credentials.service_account_impersonation_url {
            return self
                .impersonate_service_account(impersonation_url, &token, scopes)
                .await;
        }

        Ok(token)
    }

    /// Use the federated token to impersonate a service account
    #[instrument(level = Level::DEBUG, skip(self, federated_token))]
    async fn impersonate_service_account(
        &self,
        impersonation_url: &str,
        federated_token: &Token,
        scopes: &[&str],
    ) -> Result<Arc<Token>, Error> {
        debug!(url = %impersonation_url, "impersonating service account");

        let body = serde_json::json!({
            "scope": scopes,
            "lifetime": "3600s"
        });

        let body_bytes = Bytes::from(serde_json::to_vec(&body).unwrap());

        let response_body = self
            .client
            .request(
                Request::post(impersonation_url)
                    .header(CONTENT_TYPE, "application/json")
                    .header(
                        "Authorization",
                        format!("Bearer {}", federated_token.as_str()),
                    )
                    .body(Full::from(body_bytes))
                    .unwrap(),
                "ExternalAccount/Impersonate",
            )
            .await?;

        let response: ImpersonatedTokenResponse = serde_json::from_slice(&response_body)
            .map_err(|err| Error::Json("failed to parse impersonation response", err))?;

        // Parse the expireTime to calculate duration
        let expires_in = response
            .expire_time
            .parse::<chrono::DateTime<chrono::Utc>>()
            .map(|t| {
                let duration = t - chrono::Utc::now();
                std::time::Duration::from_secs(duration.num_seconds().max(0) as u64)
            })
            .unwrap_or(std::time::Duration::from_secs(3600));

        Ok(Arc::new(Token::from_string(
            response.access_token,
            expires_in,
        )))
    }

    #[instrument(level = Level::DEBUG, skip(self))]
    async fn fetch_token(&self, scopes: &[&str]) -> Result<Arc<Token>, Error> {
        let subject_token = self.read_subject_token().await?;
        self.exchange_token(&subject_token, scopes).await
    }
}

#[async_trait]
impl TokenProvider for ExternalAccount {
    async fn token(&self, scopes: &[&str]) -> Result<Arc<Token>, Error> {
        let key: Vec<_> = scopes.iter().map(|x| x.to_string()).collect();

        // Fast path: check with read lock
        if let Some(token) = self.tokens.read().await.get(&key).cloned() {
            if !token.has_expired() {
                return Ok(token);
            }
        }

        // Slow path: acquire write lock and double-check
        let mut locked = self.tokens.write().await;
        if let Some(token) = locked.get(&key) {
            if !token.has_expired() {
                return Ok(token.clone());
            }
        }

        let token = self.fetch_token(scopes).await?;
        locked.insert(key, token.clone());
        Ok(token)
    }

    async fn project_id(&self) -> Result<Arc<str>, Error> {
        // External accounts typically don't have a project ID in the credentials
        // The quota_project_id can be used if available
        match &self.credentials.quota_project_id {
            Some(pid) => Ok(pid.clone()),
            None => Err(Error::Str("no project ID in external account credentials")),
        }
    }
}

/// Response from STS token exchange
#[derive(Deserialize)]
struct StsTokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    token_type: Option<String>,
}

/// Response from service account impersonation
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImpersonatedTokenResponse {
    access_token: String,
    expire_time: String,
}
