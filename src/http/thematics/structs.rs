use super::{DBCollectable, ObjectId};
use tirengine::{ Topic };

impl DBCollectable for Thematic {
    fn get_collection_name() -> &'static str {
        "thematics"
    }
}


#[derive(serde::Deserialize, serde::Serialize)]
pub struct Thematic {
    pub _id: ObjectId,
    pub title: String,
    pub topics: Vec<Topic>,
}