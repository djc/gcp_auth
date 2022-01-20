use thiserror::Error;
/// Enumerates all possible errors returned by this library.
#[derive(Error, Debug)]
pub enum Error {
    /// No available authentication method was discovered
    ///
    /// Application can authenticate against GCP using:
    ///
    /// - Default service account - available inside GCP platform using GCP Instance Metadata server
    /// - Service account file - provided using `GOOGLE_APPLICATION_CREDENTIALS` with path
    /// - GCloud authorized user - retrieved using `gcloud auth` command
    ///
    /// All authentication methods have been tested and none succeeded.
    /// Service account file can be downloaded from GCP in json format.
    #[error("No available authentication method was discovered")]
    NoAuthMethod(Box<Error>, Box<Error>, Box<Error>, Box<Error>),

    /// Error in underlying RustTLS library.
    /// Might signal problem with establishing secure connection using trusted certificates
    #[error("TLS error")]
    TLSError(#[source] rustls::Error),

    /// Error when establishing connection to OAuth server
    #[error("Could not establish connection with OAuth server")]
    OAuthConnectionError(#[source] hyper::Error),

    /// Error when parsing response from OAuth server
    #[error("Could not parse OAuth server response")]
    OAuthParsingError(#[source] serde_json::error::Error),

    /// Variable `GOOGLE_APPLICATION_CREDENTIALS` could not be found in the current environment
    ///
    /// GOOGLE_APPLICATION_CREDENTIALS is used for providing path to json file with applications credentials.
    /// File can be downloaded in GCP Console when creating service account.
    #[error("Path to custom auth credentials was not provided in `GOOGLE_APPLICATION_CREDENTIALS` env variable")]
    ApplicationProfileMissing,

    /// Wrong path to custom application profile credentials provided
    ///
    /// Path has to be defined using `GOOGLE_APPLICATION_CREDENTIALS` environment variable
    #[error("Environment variable `GOOGLE_APPLICATION_CREDENTIALS` contains invalid path to application profile file")]
    ApplicationProfilePath(#[source] std::io::Error),

    /// Wrong format of custom application profile
    ///
    /// Application profile is downloaded from GCP console and is stored in filesystem on the server.
    /// Full path is passed to library by setting `GOOGLE_APPLICATION_CREDENTIALS` variable with path as a value.
    #[error("Application profile provided in `GOOGLE_APPLICATION_CREDENTIALS` was not parsable")]
    ApplicationProfileFormat(#[source] serde_json::error::Error),

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

    /// Could not determine signer scheme
    #[error("Couldn't choose signing scheme")]
    SignerSchemeError,

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

    /// Represents all other cases of `std::io::Error`.
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}
