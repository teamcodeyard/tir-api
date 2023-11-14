use crate::http::users::structs::{ User, UserRole };
use super::structs::Thematic;
use super::structs::{ CreateThematicRequest, UpdateThematicRequest };
use super::ServerError;
use crate::http::extractors::DatabaseCollection;
use crate::http::ApiContext;
use anyhow::Result;
use axum::routing::{ get, patch };
use axum::{ Json, Router };
use futures::stream::TryStreamExt;
use mongodb::{ Database, bson::{ doc, oid::ObjectId } };
use axum::extract::Path;

pub fn router() -> Router<ApiContext> {
    Router::new()
        .route("/api/thematics", get(list_thematics).post(add_thematic))
        .route("/api/thematics/:id", patch(update_thematic))
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

#[axum::debug_handler(state = ApiContext)]
async fn update_thematic(
    authorized_user: User,
    DatabaseCollection(thematic_collection): DatabaseCollection<Thematic>,
    Path(thematic_id_param): Path<String>,
    Json(req): Json<UpdateThematicRequest>
) -> Result<Json<Thematic>, ServerError> {
    if authorized_user.role != UserRole::SUPERVISOR {
        return Err(ServerError::Forbidden(String::from("You don't have role to this action")));
    }
    let thematic_id = ObjectId::parse_str(&thematic_id_param).unwrap();
    thematic_collection.update_one(
        doc! { "_id": thematic_id },
        doc! { "$set": { "title": &req.title.clone() } },
        Option::None
    ).await?;

    let thematic = thematic_collection
        .find_one(doc! { "_id": thematic_id }, Option::None).await?
        .ok_or_else({
            || ServerError::UnprocessableEntity(String::from("Unknown thematic"))
        })?;
    Ok(
        Json(Thematic {
            _id: thematic._id,
            title: thematic.title,
            topics: thematic.topics,
        })
    )
}

impl crate::http::thematics::DBCollectable for tirengine::Thematic {
    fn get_collection_name() -> &'static str {
        "thematics"
    }
}
