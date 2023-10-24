use crate::http::users::structs::{ User, UserRequest, UserRole, UpdateUserRequest };
use crate::http::extractors::{ DBCollectable, DatabaseCollection };
use crate::http::ApiContext;
use crate::utils::spawn_blocking_with_tracing;
use super::{ ValidatedJson, validate_password_match, generate_new_api_key };
use super::ServerError;
use super::utils::compute_password_hash;
use axum::routing::{ post, get, put };
use axum::{ extract::State, Json, Router };
use anyhow::Result;
use mongodb::{ Database, IndexModel, bson::{ doc, oid::ObjectId }, options::IndexOptions };

pub fn router() -> Router<ApiContext> {
    // By having each module responsible for setting up its own routing,
    // it makes the root module a lot cleaner.
    Router::new()
        .route("/api/users", post(create_user))
        .route("/api/users/me", get(get_user))
        .route("/api/users/login", post(login_user))
        .route("/api/users/:id", put(update_user))
}

pub async fn create_indexes(db: &Database) {
    let options = IndexOptions::builder().unique(true).build();
    let model = IndexModel::builder()
        .keys(doc! { "email": 1 })
        .options(options)
        .build();
    db.collection::<User>(User::get_collection_name())
        .create_index(model, None).await
        .expect("error creating index!");
}

async fn create_user(
    State(ctx): State<ApiContext>,
    DatabaseCollection(user_collection): DatabaseCollection<User>,
    ValidatedJson(req): ValidatedJson<UserRequest>
) -> Result<Json<serde_json::Value>, ServerError> {
    let hashed_password = spawn_blocking_with_tracing(move ||
        compute_password_hash(req.password)
    ).await.map_err(|e| ServerError::InternalError(e.into()))??;
    let result = user_collection
        .insert_one(
            User {
                _id: Some(ObjectId::new()),
                email: req.email.clone(),
                password: hashed_password,
                api_keys: vec![],
                role: UserRole::MEMBER,
                bio: Option::None,
                full_name: Option::None,
            },
            None
        ).await
        .map_err(|_err| {
            println!("{:?}", _err);
            ServerError::BadRequest("E-mail already exists".to_string())
        })?;
    let inserted_id = result.inserted_id.as_object_id().unwrap().to_hex();
    let token = generate_new_api_key(&inserted_id, ctx).await?;
    let bson_id = ObjectId::parse_str(&inserted_id).unwrap();
    user_collection.update_one(
        doc! { "_id": bson_id },
        doc! { "$push": {"api_keys": &token} },
        None
    ).await?;
    Ok(
        Json(
            serde_json::json!( {
        "id": inserted_id,
        "email": req.email,
        "apiKey": token,
        "role": UserRole::MEMBER
    })
        )
    )
}

async fn get_user(authorized_user: User) -> Result<Json<serde_json::Value>, ServerError> {
    let id = authorized_user._id.unwrap().to_hex();
    Ok(
        Json(
            serde_json::json!({
        "email": authorized_user.email,
        "id": id,
        "role": authorized_user.role
    })
        )
    )
}

async fn login_user(
    State(ctx): State<ApiContext>,
    DatabaseCollection(user_collection): DatabaseCollection<User>,
    ValidatedJson(req): ValidatedJson<UserRequest>
) -> Result<Json<serde_json::Value>, ServerError> {
    let user = user_collection
        .find_one(doc! { "email": req.email }, Option::None).await?
        .ok_or_else({
            || ServerError::UnprocessableEntity(String::from("Invalid e-mail or password"))
        })?;

    validate_password_match(user.password, req.password).await?;

    let user_id = user._id.unwrap();
    let token = generate_new_api_key(&user_id.to_hex().to_string(), ctx).await?;
    user_collection.update_one(
        doc! { "_id": user_id },
        doc! { "$push": {"api_keys": &token} },
        None
    ).await?;

    Ok(
        Json(
            serde_json::json!({
        "email": user.email,
        "id": user._id.unwrap().to_hex(),
        "apiKey": token,
        "role": user.role
    })
        )
    )
}

async fn update_user(
    authorized_user: User,
    DatabaseCollection(user_collection): DatabaseCollection<User>,
    ValidatedJson(req): ValidatedJson<UpdateUserRequest>
) -> Result<Json<serde_json::Value>, ServerError> {
    user_collection.update_one(
        doc! { "_id": authorized_user._id },
        doc! { "$set": {"bio": &req.bio, "full_name": &req.full_name, "email": &req.email} },
        Option::None
    ).await?;

    let user = user_collection
        .find_one(doc! { "_id": authorized_user._id }, Option::None).await?
        .unwrap();

    Ok(
        Json(
            serde_json::json!( {
        "id": user._id.unwrap().to_hex().to_string(),
        "email": user.email,
        "role": user.role,
        "bio": user.bio,
        "full_name": user.full_name
    })
        )
    )
}
