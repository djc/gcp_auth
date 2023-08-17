use thiserror::Error;
/// Enumerates all possible errors returned by this library.
#[derive(Error, Debug)]
pub enum Error {
    /// No available authentication method was discovered
    ///
    /// Application can authenticate against GCP using:
    ///
    /// - Default service account - available inside GCP platform using GCP Instance Metadata server
    /// - GCloud authorized user - retrieved using `gcloud auth` command
    ///
    /// All authentication methods have been tested and none succeeded.
    /// Service account file can be downloaded from GCP in json format.
    #[error("No available authentication method was discovered")]
    NoAuthMethod(Box<Error>, Box<Error>, Box<Error>),

    /// Error in underlying RustTLS library.
    /// Might signal problem with establishing secure connection using trusted certificates
    #[error("TLS error")]
    TlsError(#[source] rustls::Error),

    /// Error when establishing connection to OAuth server
    #[error("Could not establish connection with OAuth server")]
    OAuthConnectionError(#[source] hyper::Error),

    /// Wrong path to custom service account credentials provided
    ///
    /// By default, the custom service account credentials are parsed from the path pointed to by the
    /// `GOOGLE_APPLICATION_CREDENTIALS` environment variable.
    #[error("Invalid path to custom service account")]
    CustomServiceAccountPath(#[source] std::io::Error),

    /// Failed to parse the application credentials provided
    ///
    /// By default, the custom service account credentials are parsed from the path pointed to by the
    /// `GOOGLE_APPLICATION_CREDENTIALS` environment variable or `~/.config/gcloud/application_default_credentials.json`
    #[error("Application profile provided in `GOOGLE_APPLICATION_CREDENTIALS` was not parsable")]
    CustomServiceAccountCredentials(#[source] serde_json::error::Error),

    /// Default user profile not found
    ///
    /// User can authenticate locally during development using `gcloud auth login` which results in creating
    /// `~/.config/gcloud/application_default_credentials.json` which couldn't be find on the machine
    #[error("User authentication profile not found")]
    UserProfilePath(#[source] std::io::Error),

    /// Wrong format of user profile
    #[error("User profile was not parsable")]
    UserProfileFormat(#[source] serde_json::error::Error),

    /// Could not connect to  server
    #[error("Could not establish connection with server")]
    ConnectionError(#[source] hyper::Error),

    /// Could not parse response from server
    #[error("Could not parse server response")]
    ParsingError(#[source] serde_json::error::Error),

    /// Could not connect to server
    #[error("Server unavailable: {0}")]
    ServerUnavailable(String),

    /// Could not sign requested message
    #[error("Could not sign")]
    SignerFailed,

    /// Could not initialize signer
    #[error("Couldn't initialize signer")]
    SignerInit,

    /// Could not find Home directory in the environment
    #[error("Home directory not found")]
    NoHomeDir,

    /// Project ID not supported for current authentication method
    #[error("Project ID not supported for current authentication method")]
    NoProjectId,

    /// Project ID not found through current authentication method
    #[error("Project ID not found through current authentication method")]
    ProjectIdNotFound,

    /// Project ID is invalid UTF-8
    #[error("Project ID is invalid UTF-8")]
    ProjectIdNonUtf8,

    /// GCloud executable not found
    #[error("GCloud executable not found in $PATH")]
    GCloudNotFound,

    /// GCloud returned an error status
    #[error("GCloud returned a non OK status")]
    GCloudError,

    /// GCloud output couldn't be parsed
    #[error("Failed to parse output of GCloud")]
    GCloudParseError,

    /// Currently, nested service account impersonation is not supported
    #[error("Nested impersonation is not supported")]
    NestedImpersonation,

    /// Represents all other cases of `std::io::Error`.
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}
