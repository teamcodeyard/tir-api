#[derive(clap::Parser)]
pub struct Config {
    /// The connection URL for the Mongo database this application should use.
    #[clap(long, env)]
    pub database_url: String,
 
    #[clap(long, env)]
    pub database_name: String,
}
