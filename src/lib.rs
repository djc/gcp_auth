//! GCP auth provides authentication using service accounts Google Cloud Platform (GCP)
//! 
//! The library can be used in two ways:
//! 
//! - Invoking the library inside GCP environment fetches the default service account for the service and
//! the application is authenticated using that particular account
//! - Providing a path to service account JSON configuration file using GOOGLE_APPLICATION_CREDENTIALS environment
//! variable. The service account configuration file can be downloaded in the IAM service when displaying service account detail.
//! The downloaded JSON file should be provided without any further modification.
//! 
//! The tokens are single-use and as such they shouldn't be cached and for each use a new token should be requested.
//! Library handles token caching for their lifetime and so it won't make a request if a token with appropriate scope
//! is available.
//! 
//! # Default service account
//! 
//! When running inside GCP the library can be asked directly without any further configuration to provide a Bearer token
//! for the current service account of the service.
//! 
//! ```async
//! let authentication_manager = gcp_auth::init().await?;
//! let token = authentication_manager.get_token().await?;
//! ```
//! 
//! # Custom service account
//! 
//! When running outside of GCP e.g on development laptop to allow finer granularity for permission a
//! custom service account can be used. To use a custom service account a configuration file containing key
//! has to be downloaded in IAM service for the service account you intend to use. The configuration file has to
//! be available to the application at run time. The path to the configuration file is specified by 
//! `GOOGLE_APPLICATION_CREDENTIALS` environment variable.
//! 
//! ```async
//! // GOOGLE_APPLICATION_CREDENTIALS environtment variable is set-up
//! let authentication_manager = gcp_auth::init().await?;
//! let token = authentication_manager.get_token().await?;
//! ```

#![deny(missing_docs)]
#![deny(warnings)]
#![allow(clippy::pedantic)]

mod error;
mod authentication_manager;
mod jwt;
mod types;
mod default_service_account;
mod custom_service_account;
mod prelude {
    pub(crate) use {
        crate::types::HyperClient, crate::types::Token,
        serde::Deserialize, serde::Serialize, std::collections::HashMap,
        std::path::Path, crate::error::GCPAuthError, hyper::Request, bytes::buf::Buf, async_trait::async_trait
    };
}
pub use authentication_manager::AuthenticationManager;
pub use types::Token;
pub use error::GCPAuthError;

use hyper::Client;
use hyper_tls::HttpsConnector;
use tokio::sync::Mutex;

/// Initialize GCP authentication
/// 
/// Returns `AuthenticationManager` which can be used to obtain tokens
pub async fn init() -> Result<AuthenticationManager, GCPAuthError> {
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);
    let default = default_service_account::DefaultServiceAccount::new(&client).await;
    if let Ok(service_account) = default {
        return Ok(AuthenticationManager {
            client: client.clone(),
            service_account: Mutex::new(Box::new(service_account)),
        });
    }
    let custom = custom_service_account::CustomServiceAccount::new().await;
    if let Ok(service_account) = custom {
        return Ok(AuthenticationManager {
            client,
            service_account: Mutex::new(Box::new(service_account)),
        });
    }
    Err(GCPAuthError::NoAuthMethod(Box::new(custom.unwrap_err()), Box::new(default.unwrap_err())))
}
