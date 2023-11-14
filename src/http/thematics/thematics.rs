use super::structs::Thematic;
use super::structs::CreateThematicRequest;
use super::ServerError;
use crate::http::extractors::DatabaseCollection;
use crate::http::ApiContext;
use anyhow::Result;
use axum::routing::get;
use axum::{ Json, Router };
use futures::stream::TryStreamExt;
use mongodb::Database;

pub fn router() -> Router<ApiContext> {
    Router::new().route("/api/thematics", get(list_thematics).post(add_thematic))
}

pub async fn create_indexes(_db: &Database) {}

async fn list_thematics(DatabaseCollection(
    thematic_collection,
): DatabaseCollection<Thematic>) -> Result<Json<Vec<Thematic>>, ServerError> {
    Ok(Json(thematic_collection.find(None, None).await?.try_collect().await?))
}

#[axum::debug_handler(state = ApiContext)]
async fn add_thematic(
    DatabaseCollection(thematic_collection): DatabaseCollection<tirengine::Thematic>,
    Json(req): Json<CreateThematicRequest>
) -> Result<Json<Thematic>, ServerError> {
    let result = thematic_collection.insert_one(
        tirengine::Thematic {
            title: req.title.clone(),
            topics: vec![],
        },
        None
    ).await?;

    Ok(
        Json(Thematic {
            _id: result.inserted_id.as_object_id().unwrap().to_hex(),
            title: req.title,
            topics: vec![],
        })
    )
}

impl crate::http::thematics::DBCollectable for tirengine::Thematic {
    fn get_collection_name() -> &'static str {
        "thematics"
    }
}
