#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let authentication_manager = gcp_auth::init().await?;
    let _token = authentication_manager.get_token(&["https://www.googleapis.com/auth/cloud-platform"]).await?;
    Ok(())
}
