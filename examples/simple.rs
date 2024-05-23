#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let token_provider = gcp_auth::provider().await?;
    let _token = token_provider
        .token(&["https://www.googleapis.com/auth/cloud-platform"])
        .await?;
    Ok(())
}
