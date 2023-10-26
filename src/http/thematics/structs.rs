use super::{DBCollectable, ObjectId};
use serde::{de, Deserializer};
use tirengine::Topic;

impl DBCollectable for Thematic {
    fn get_collection_name() -> &'static str {
        "thematics"
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct Thematic {
    #[serde(deserialize_with = "inline_object_id")]
    pub _id: String,
    pub title: String,
    pub topics: Vec<Topic>,
}

fn inline_object_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let id: ObjectId = de::Deserialize::deserialize(deserializer)?;
    Ok(id.to_hex())
}
