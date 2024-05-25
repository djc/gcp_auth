#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();

    let token_provider = gcp_auth::provider().await?;
    let _token = token_provider
        .token(&["https://www.googleapis.com/auth/cloud-platform"])
        .await?;
    Ok(())
}
