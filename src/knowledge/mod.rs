use mongodb::{ self, Database };
use crate::config::Config;
use tirengine::{ GPT, Thematic };
use mongodb::bson::doc;
use indicatif::ProgressBar;

pub async fn build(config: &Config, db: &Database) {
    let collection = db.collection::<Thematic>("thematics");
    let count_result = collection.count_documents(doc! {}, None).await.unwrap();
    if count_result > 0 {
        println!("Database already seeded!");
        return;
    }
    println!("!Build knowledge!");
    let contents = std::fs::read_to_string(config.roadmap_file_path.clone()).unwrap();
    let mut thematics: Vec<Thematic> = serde_yaml
        ::from_str(&contents)
        .expect("Failed to parse YAML");
  
    let bar = ProgressBar::new(thematics.len() as _);
    let gpt = GPT::new(config.openai_sk.clone());
    for thematic in &mut thematics {
        gpt.generate_knowledge(thematic).await.unwrap();
        bar.inc(1);
    }
    collection.insert_many(thematics, None).await.unwrap();
    bar.finish();
    println!("Database seed success!");
}
