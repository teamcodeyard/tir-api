use crate::http::ApiContext;
use super::ServerError;
use axum::routing::get;
use axum::{ Json, Router };
use anyhow::Result;
use mongodb::{ Database };
use crate::http::extractors::DatabaseCollection;
use futures::stream::StreamExt;
use super::structs::Thematic;

pub fn router() -> Router<ApiContext> {
    Router::new().route("/api/thematics", get(list_thematics))
}

pub async fn create_indexes(_db: &Database) {}

async fn list_thematics(DatabaseCollection(
    thematic_collection,
): DatabaseCollection<Thematic>) -> Result<Json<serde_json::Value>, ServerError> {
    let mut cursor = thematic_collection.find(None, None).await?;
    let mut result = vec! {};
    while let Some(doc) = cursor.next().await {
        let thematic = doc.unwrap();
        result.push(
            serde_json::json!({
            "id": thematic._id.to_hex(),
            "title": thematic.title,
            "topic": thematic.topics
        })
        );
    }
    Ok(Json(serde_json::Value::Array(result)))
}
