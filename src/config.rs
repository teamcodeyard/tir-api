#[derive(clap::Parser)]
pub struct Config {
    /// The connection URL for the Mongo database this application should use.
    #[clap(long, env)]
    pub database_url: String,
 
    #[clap(long, env)]
    pub database_name: String,

    #[clap(long, env)]
    pub roadmap_file_path: String,
    
    #[clap(long, env)]
    pub openai_sk: String,

}
