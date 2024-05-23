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
//! For more details, see [`AuthenticationManager::new()`].
//!
//! The `AuthenticationManager` handles caching tokens for their lifetime; it will not make a request if
//! an appropriate token is already cached. Therefore, the caller should not cache tokens.
//!
//! ## Simple usage
//!
//! The default way to use this library is to get instantiate an [`AuthenticationManager`]. It will
//! find the appropriate authentication method and use it to retrieve tokens.
//!
//! ```rust,no_run
//! # async fn get_token() -> Result<(), gcp_auth::Error> {
//! use gcp_auth::AuthenticationManager;
//!
//! let authentication_manager = AuthenticationManager::new().await?;
//! let scopes = &["https://www.googleapis.com/auth/cloud-platform"];
//! let token = authentication_manager.get_token(scopes).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Supplying service account credentials
//!
//! When running outside of GCP (for example, on a development machine), it can be useful to supply
//! service account credentials. The first method checked by [`AuthenticationManager::new()`] is to
//! read a path to a file containing JSON credentials in the `GOOGLE_APPLICATION_CREDENTIALS`
//! environment variable. However, you may also supply a custom path to read credentials from, or
//! a `&str` containing the credentials. In both of these cases, you should create a
//! [`CustomServiceAccount`] directly using one of its associated functions:
//!
//! ```rust,no_run
//! # use std::path::PathBuf;
//! #
//! # async fn get_token() -> Result<(), gcp_auth::Error> {
//! use gcp_auth::{AuthenticationManager, CustomServiceAccount};
//!
//! // `credentials_path` variable is the path for the credentials `.json` file.
//! let credentials_path = PathBuf::from("service-account.json");
//! let service_account = CustomServiceAccount::from_file(credentials_path)?;
//! let authentication_manager = AuthenticationManager::try_from(service_account)?;
//! let scopes = &["https://www.googleapis.com/auth/cloud-platform"];
//! let token = authentication_manager.get_token(scopes).await?;
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
//! use gcp_auth::AuthenticationManager;
//! use tokio::sync::OnceCell;
//!
//! static AUTH_MANAGER: OnceCell<AuthenticationManager> = OnceCell::const_new();
//!
//! async fn authentication_manager() -> &'static AuthenticationManager {
//!     AUTH_MANAGER
//!         .get_or_init(|| async {
//!             AuthenticationManager::new()
//!                 .await
//!                 .expect("unable to initialize authentication manager")
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

mod authentication_manager;
mod custom_service_account;
mod default_authorized_user;
mod default_service_account;
mod error;
mod gcloud_authorized_user;
mod types;

pub use authentication_manager::AuthenticationManager;
pub use custom_service_account::CustomServiceAccount;
pub use error::Error;
pub use types::{Signer, Token};

#[async_trait]
pub(crate) trait TokenProvider: Send + Sync {
    async fn token(&self, scopes: &[&str]) -> Result<Arc<Token>, Error>;
    async fn project_id(&self) -> Result<Arc<str>, Error>;
}
