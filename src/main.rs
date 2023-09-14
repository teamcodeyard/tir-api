use clap::Parser;
use mongodb::{options::ClientOptions, Client};

use tir_api::config::Config;
use tir_api::http;
use tir_api::knowledge;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // This returns an error if the `.env` file doesn't exist, but that's not what we want
    // since we're not going to use a `.env` file if we deploy this application.
    dotenv::dotenv().ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tir_api=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Parse our configuration from the environment.
    // This will exit with a help message if something is wrong.
    let config = Config::parse();

    let client_options = ClientOptions::parse(&config.database_url).await?;

    // Get a handle to the deployment.
    let client = Client::with_options(client_options)?;
    let db: mongodb::Database = client.database(&config.database_name);

    knowledge::build(&config, &db).await;

    // Finally, we spin up our API.
    http::serve(config, db).await?;

    Ok(())
}
