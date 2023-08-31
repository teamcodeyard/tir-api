use mongodb::{ self, Database };
use crate::config::Config;
use tirengine::{ GPT, Thematic };

pub async fn build(config: &Config, db: &Database) {
    let contents = std::fs::read_to_string(config.roadmap_file_path.clone()).unwrap();
    let mut thematics: Vec<Thematic> = serde_yaml::from_str(&contents).expect("Failed to parse YAML");

    let gpt = GPT::new(config.openai_sk.clone());
    for thematic in &mut thematics {
        let result = gpt.generate_knowledge(thematic).await.unwrap();
        println!("{:?}",thematic);
    }
    

}
