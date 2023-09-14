#[derive(clap::Parser)]
pub struct Config {
    /// The connection URL for the Mongo database this application should use.
    #[arg(long, env)]
    pub database_url: String,

    #[arg(long, env)]
    pub database_name: String,

    #[arg(long, env)]
    pub roadmap_file_path: String,

    #[arg(long, env)]
    pub openai_sk: String,
}
