# GCP Auth
[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![MIT licensed][mit-badge]][mit-url]

[crates-badge]: https://img.shields.io/crates/v/gcp_auth.svg
[crates-url]: https://crates.io/crates/gcp_auth
[docs-badge]: https://docs.rs/gcp_auth/badge.svg
[docs-url]: https://docs.rs/gcp_auth
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: LICENSE

GCP Auth is a simple, minimal authentication library for Google Cloud Platform (GCP) providing authentication using
services accounts that are used to issues Bearer tokens that can be used to authenticate against GCP services.

Library implements two authenticatiom methods:

1. Default service accounts - can be used inside GCP
2. Custom service account - provided using environenment variable
3. Local user authetincation - for development purposes only, using `gcloud auth` application

Tokens should not be cached in the application and before every use a new token should be request. The GCP auth library decides
if there is available token with appropriate scope or if a new token should be generated.

## Default Service Account

When running inside GCP the library can be asked directly without any further configuration to provide a Bearer token
for the current service account of the service.

```rust
let authentication_manager = gcp_auth::init().await?;
let token = authentication_manager.get_token().await?;
```

## Custom Service Account

When running outside of GCP e.g on development laptop to allow finer granularity for permission a
custom service account can be used. To use a custom service account a configuration file containing key
has to be downloaded in IAM service for the service account you intend to use. The configuration file has to
be available to the application at run time. The path to the configuration file is specified by 
`GOOGLE_APPLICATION_CREDENTIALS` environment variable.

```rust
// GOOGLE_APPLICATION_CREDENTIALS environtment variable is set-up
let authentication_manager = gcp_auth::init().await?;
let token = authentication_manager.get_token().await?;
```

## Local user authentication
This authentication method allows developers to authenticate again GCP ices when developign locally.
The method is intended only for development. Credentials can be set-up g `gcloud auth` utility.
Credentials are read from file `~/.config/gcloud/ication_default_credentials.json`.

## FAQ

### Does library support windows?

No

# License
Parts of implementatino have been sourced from [yup-oauth2](https://github.com/dermesser/yup-oauth2)

Licensed under [MIT license](http://opensource.org/licenses/MIT).