use axum::{ routing::{ get, post }, http::StatusCode, response::IntoResponse, Json, Router };
use clap::Parser;
use mongodb::{ Client, options::ClientOptions };

use tir_api::config::Config;
use tir_api::http;
use tir_api::knowledge;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // This returns an error if the `.env` file doesn't exist, but that's not what we want
    // since we're not going to use a `.env` file if we deploy this application.
    dotenv::dotenv().ok();

    // Initialize the logger.
    env_logger::init();

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
