//! GCP auth provides authentication using service accounts Google Cloud Platform (GCP)
//!
//! GCP auth is a simple, minimal authentication library for Google Cloud Platform (GCP)
//! providing authentication using service accounts. Once authenticated, the service
//! account can be used to acquire bearer tokens for use in authenticating against GCP
//! services.
//!
//! The library supports the following methods of retrieving tokens:
//!
//! 1. Reading custom service account credentials from the path pointed to by the
//!    `GOOGLE_APPLICATION_CREDENTIALS` environment variable. Alternatively, custom service
//!    account credentials can be read from a JSON file or string.
//! 2. Look for credentials in `.config/gcloud/application_default_credentials.json`;
//!    if found, use these credentials to request refresh tokens. This file can be created
//!    by invoking `gcloud auth application-default login`.
//! 3. Use the default service account by retrieving a token from the metadata server.
//! 4. Retrieving a token from the `gcloud` CLI tool, if it is available on the `PATH`.
//!
//! For more details, see [`provider()`].
//!
//! A [`TokenProvider`] handles caching tokens for their lifetime; it will not make a request if
//! an appropriate token is already cached. Therefore, the caller should not cache tokens.
//!
//! ## Simple usage
//!
//! The default way to use this library is to select the appropriate token provider using
//! [`provider()`]. It will find the appropriate authentication method and use it to retrieve
//! tokens.
//!
//! ```rust,no_run
//! # async fn get_token() -> Result<(), gcp_auth::Error> {
//! let provider = gcp_auth::provider().await?;
//! let scopes = &["https://www.googleapis.com/auth/cloud-platform"];
//! let token = provider.token(scopes).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Supplying service account credentials
//!
//! When running outside of GCP (for example, on a development machine), it can be useful to supply
//! service account credentials. The first method checked by [`provider()`] is to
//! read a path to a file containing JSON credentials in the `GOOGLE_APPLICATION_CREDENTIALS`
//! environment variable. However, you may also supply a custom path to read credentials from, or
//! a `&str` containing the credentials. In both of these cases, you should create a
//! [`CustomServiceAccount`] directly using one of its associated functions:
//!
//! ```rust,no_run
//! # use std::path::PathBuf;
//! #
//! # async fn get_token() -> Result<(), gcp_auth::Error> {
//! use gcp_auth::{CustomServiceAccount, TokenProvider};
//!
//! // `credentials_path` variable is the path for the credentials `.json` file.
//! let credentials_path = PathBuf::from("service-account.json");
//! let service_account = CustomServiceAccount::from_file(credentials_path)?;
//! let scopes = &["https://www.googleapis.com/auth/cloud-platform"];
//! let token = service_account.token(scopes).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Getting tokens in multi-thread or async environments
//!
//! Using a `OnceCell` makes it easy to reuse the [`AuthenticationManager`] across different
//! threads or async tasks.
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use tokio::sync::OnceCell;
//! use gcp_auth::TokenProvider;
//!
//! static TOKEN_PROVIDER: OnceCell<Arc<dyn TokenProvider>> = OnceCell::const_new();
//!
//! async fn token_provider() -> &'static Arc<dyn TokenProvider> {
//!     TOKEN_PROVIDER
//!         .get_or_init(|| async {
//!             gcp_auth::provider()
//!                 .await
//!                 .expect("unable to initialize token provider")
//!         })
//!         .await
//! }
//! ```

#![deny(missing_docs)]
#![deny(warnings)]
#![deny(unreachable_pub)]
#![allow(clippy::pedantic)]

use std::sync::Arc;

use async_trait::async_trait;
use tracing::{instrument, Level};

mod custom_service_account;
pub use custom_service_account::CustomServiceAccount;

mod default_authorized_user;
use default_authorized_user::ConfigDefaultCredentials;

mod default_service_account;
use default_service_account::MetadataServiceAccount;

mod error;
pub use error::Error;

mod gcloud_authorized_user;
use gcloud_authorized_user::GCloudAuthorizedUser;

mod types;
use types::HttpClient;
pub use types::{Signer, Token};

/// Finds a service account provider to get authentication tokens from
///
/// Tries the following approaches, in order:
///
/// 1. Check if the `GOOGLE_APPLICATION_CREDENTIALS` environment variable if set;
///    if so, use a custom service account as the token source.
/// 2. Look for credentials in `.config/gcloud/application_default_credentials.json`;
///    if found, use these credentials to request refresh tokens.
/// 3. Send a HTTP request to the internal metadata server to retrieve a token;
///    if it succeeds, use the default service account as the token source.
/// 4. Check if the `gcloud` tool is available on the `PATH`; if so, use the
///    `gcloud auth print-access-token` command as the token source.
#[instrument(level = Level::DEBUG)]
pub async fn provider() -> Result<Arc<dyn TokenProvider>, Error> {
    tracing::debug!("Initializing gcp_auth");
    if let Some(provider) = CustomServiceAccount::from_env()? {
        return Ok(Arc::new(provider));
    }

    let client = HttpClient::new()?;
    let default_user_error = match ConfigDefaultCredentials::new(&client).await {
        Ok(provider) => {
            tracing::debug!("Using ConfigDefaultCredentials");
            return Ok(Arc::new(provider));
        }
        Err(e) => e,
    };

    let default_service_error = match MetadataServiceAccount::new(&client).await {
        Ok(provider) => {
            tracing::debug!("Using MetadataServiceAccount");
            return Ok(Arc::new(provider));
        }
        Err(e) => e,
    };

    let gcloud_error = match GCloudAuthorizedUser::new().await {
        Ok(provider) => {
            tracing::debug!("Using GCloudAuthorizedUser");
            return Ok(Arc::new(provider));
        }
        Err(e) => e,
    };

    Err(Error::NoAuthMethod(
        Box::new(gcloud_error),
        Box::new(default_service_error),
        Box::new(default_user_error),
    ))
}

/// A trait for an authentication context that can provide tokens
#[async_trait]
pub trait TokenProvider: Send + Sync {
    /// Get a valid token for the given scopes
    ///
    /// Tokens are cached until they expire, so this method will only fetch a fresh token once
    /// the current token (for the given scopes) has expired.
    async fn token(&self, scopes: &[&str]) -> Result<Arc<Token>, Error>;

    /// Get the project ID for the authentication context
    async fn project_id(&self) -> Result<Arc<str>, Error>;
}
