use crate::http::ApiContext;
use super::ServerError;
use axum::routing::get;
use axum::{ Json, Router };
use anyhow::Result;
use mongodb::Database;
use crate::http::extractors::DatabaseCollection;
use futures::stream::TryStreamExt;
use super::structs::Thematic;

pub fn router() -> Router<ApiContext> {
    Router::new().route("/api/thematics", get(list_thematics))
}

pub async fn create_indexes(_db: &Database) {}

async fn list_thematics(
    DatabaseCollection(thematic_collection): DatabaseCollection<Thematic>,
) -> Result<Json<Vec<Thematic>>, ServerError> {
    let cursor = thematic_collection.find(None, None).await?;
    let result = cursor.try_collect().await?;
    Ok(Json(result))
}
