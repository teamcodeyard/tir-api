use crate::http::users::structs::{ User, UserRequest, Claim };
use crate::http::extractors::{ DBCollectable, DatabaseCollection };
use crate::http::ApiContext;
use crate::utils::spawn_blocking_with_tracing;
use super::ValidatedJson;
use super::ServerError;
use super::utils::compute_password_hash;
use axum::routing::{ post, get };
use axum::{ extract::State, Json, Router };
use time;
use time::Duration;
use anyhow::Result;
use mongodb::{ Database, IndexModel, bson::{ doc, oid::ObjectId }, options::IndexOptions };
use argon2::{ Argon2, PasswordHash, PasswordVerifier };
use jsonwebtoken::encode;
use jsonwebtoken::{ EncodingKey, Header };
use anyhow::Context;

pub fn router() -> Router<ApiContext> {
    // By having each module responsible for setting up its own routing,
    // it makes the root module a lot cleaner.
    Router::new()
        .route("/api/users", post(create_user))
        .route("/api/users/me", get(get_user))
        .route("/api/users/login", post(login_user))
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
            },
            None
        ).await
        .map_err(|_err| {
            println!("{:?}", _err);
            ServerError::BadRequest("E-mail already exists".to_string())
        })?;
    let inserted_id = result.inserted_id.as_object_id().unwrap().to_hex();
    let session_length: Duration = Duration::days(7);
    let claim = Claim {
        sub: inserted_id.clone(),
        iat: time::OffsetDateTime::now_utc().unix_timestamp(),
        exp: (time::OffsetDateTime::now_utc() + session_length).unix_timestamp(),
    };
    let token = encode(
        &Header::default(),
        &claim,
        &EncodingKey::from_secret(ctx.config.jwt_secret.as_ref())
    ).unwrap();

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
    })
        )
    )
}

async fn get_user(authorized_user: User) -> Result<Json<serde_json::Value>, ServerError> {
    let id = authorized_user._id.unwrap().to_hex();
    Ok(Json(serde_json::json!({
        "email": authorized_user.email,
        "id": id 
    })))
}

async fn login_user(
    DatabaseCollection(user_collection): DatabaseCollection<User>,
    ValidatedJson(req): ValidatedJson<UserRequest>
) -> Result<Json<serde_json::Value>, ServerError> {
    let user = user_collection
        .find_one(doc! { "email": req.email }, Option::None).await?
        .ok_or_else({
            || ServerError::UnprocessableEntity(String::from("Invalid e-mail or password"))
        })?;

    crate::utils
        ::spawn_blocking_with_tracing(move || {
            let expected_password_hash = PasswordHash::new(&user.password)?;
            Argon2::default().verify_password(req.password.as_bytes(), &expected_password_hash)
        }).await
        .context("unexpected error happened during password hashing")?
        .map_err(|_| ServerError::UnprocessableEntity(String::from("Invalid e-mail or password")))?;

    Ok(
        Json(
            serde_json::json!({
        "email": user.email,
        "id": user._id.unwrap().to_hex() 
    })
        )
    )
}