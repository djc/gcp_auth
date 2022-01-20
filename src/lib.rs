//! GCP auth provides authentication using service accounts Google Cloud Platform (GCP)
//!
//! The library looks for authentication methods in the following order:
//!
//! 1. Path to service account JSON configuration file using GOOGLE_APPLICATION_CREDENTIALS environment
//! variable. The service account configuration file can be downloaded in the IAM service when displaying service account detail.
//! The downloaded JSON file should be provided without any further modification.
//! 2. Invoking the library inside GCP environment fetches the default service account for the service and
//! the application is authenticated using that particular account
//! 3. Application default credentials. Local user authentication for development purposes created using `gcloud auth` application.
//! 4. If none of the above can be used an error occurs
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
//! // GOOGLE_APPLICATION_CREDENTIALS environment variable is set-up
//! let authentication_manager = gcp_auth::init().await?;
//! let token = authentication_manager.get_token().await?;
//! ```
//! You may instantiate `authentication_manager` from a credentials file path using the method `from_credentials_file`:
//!
//! ```async
//! // `credentials_path` variable is the path for the credentials `.json` file.
//! let authentication_manager = gcp_auth::from_credentials_file(credentials_path).await?;
//! let token = authentication_manager.get_token().await?;
//! ```
//!
//! # Local user authentication
//! This authentication method allows developers to authenticate again GCP services when developing locally.
//! The method is intended only for development. Credentials can be set-up using `gcloud auth` utility.
//! Credentials are read from file `~/.config/gcloud/application_default_credentials.json`.
//!
//! # FAQ
//!
//! ## Does library support windows?
//!
//! No

#![deny(missing_docs)]
#![deny(warnings)]
#![deny(unreachable_pub)]
#![allow(clippy::pedantic)]

mod authentication_manager;
mod custom_service_account;
mod default_authorized_user;
mod default_service_account;
mod error;
mod gcloud_authorized_user;
mod jwt;
mod types;
mod util;

use custom_service_account::CustomServiceAccount;

pub use authentication_manager::AuthenticationManager;
pub use error::Error;
pub use types::Token;

use std::path::Path;

use hyper::Client;
use hyper_rustls::HttpsConnectorBuilder;

/// Initialize GCP authentication based on a credentials file
///
/// Returns `AuthenticationManager` which can be used to obtain tokens
pub async fn from_credentials_file<T: AsRef<Path>>(
    path: T,
) -> Result<AuthenticationManager, Error> {
    get_authentication_manager(Some(path.as_ref())).await
}

async fn get_authentication_manager(
    credential_path: Option<&Path>,
) -> Result<AuthenticationManager, Error> {
    #[cfg(feature = "webpki-roots")]
    let https = HttpsConnectorBuilder::new().with_webpki_roots();
    #[cfg(not(feature = "webpki-roots"))]
    let https = HttpsConnectorBuilder::new().with_native_roots();

    let client =
        Client::builder().build::<_, hyper::Body>(https.https_or_http().enable_http2().build());

    let custom = match credential_path {
        Some(path) => CustomServiceAccount::from_file(path).await,
        None => match std::env::var("GOOGLE_APPLICATION_CREDENTIALS") {
            Ok(path) => CustomServiceAccount::from_file(Path::new(&path)).await,
            Err(_) => Err(Error::ApplicationProfileMissing),
        },
    };

    if let Ok(service_account) = custom {
        return Ok(AuthenticationManager::new(
            client,
            Box::new(service_account),
        ));
    }
    let gcloud = gcloud_authorized_user::GCloudAuthorizedUser::new().await;
    if let Ok(service_account) = gcloud {
        return Ok(AuthenticationManager::new(
            client.clone(),
            Box::new(service_account),
        ));
    }
    let default = default_service_account::DefaultServiceAccount::new(&client).await;
    if let Ok(service_account) = default {
        return Ok(AuthenticationManager::new(
            client.clone(),
            Box::new(service_account),
        ));
    }
    let user = default_authorized_user::DefaultAuthorizedUser::new(&client).await;
    if let Ok(user_account) = user {
        return Ok(AuthenticationManager::new(client, Box::new(user_account)));
    }
    Err(Error::NoAuthMethod(
        Box::new(custom.unwrap_err()),
        Box::new(gcloud.unwrap_err()),
        Box::new(default.unwrap_err()),
        Box::new(user.unwrap_err()),
    ))
}
/// Initialize GCP authentication
///
/// Returns `AuthenticationManager` which can be used to obtain tokens
pub async fn init() -> Result<AuthenticationManager, Error> {
    get_authentication_manager(None).await
}
