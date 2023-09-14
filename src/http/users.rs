use std::borrow::Cow;

use argon2::{password_hash::SaltString, Algorithm, Argon2, Params, PasswordHasher, Version};
use axum::routing::post;
use axum::{Json, Router};
use mongodb::bson::doc;
use validator::{Validate, ValidationError};

use crate::http::extractors::{DBCollectable, DatabaseCollection};
use crate::http::ApiContext;
use crate::utils::spawn_blocking_with_tracing;

use super::validation::{ServerError, ValidatedJson};

const SPECIAL_CHARS: &str = "!@#$%^&*()-=_+{}[]:;<>,.?";

pub(crate) fn router() -> Router<ApiContext> {
    // By having each module responsible for setting up its own routing,
    // it makes the root module a lot cleaner.
    Router::new().route("/api/users", post(create_user))
}

#[derive(serde::Deserialize, Validate)]
struct UserRequest {
    #[validate(email)]
    email: String,
    #[validate(custom = "validate_password")]
    password: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct User {
    email: String,
    password: String,
}

impl DBCollectable for User {
    fn get_collection_name() -> &'static str {
        "users"
    }
}

async fn create_user(
    DatabaseCollection(user_collection): DatabaseCollection<User>,
    ValidatedJson(req): ValidatedJson<UserRequest>,
) -> Result<Json<serde_json::Value>, ServerError> {
    let hashed_password = spawn_blocking_with_tracing(move || compute_password_hash(req.password))
        .await
        .map_err(|e| ServerError::InternalError(e.into()))??;
    let result = user_collection
        .insert_one(
            User {
                email: req.email.clone(),
                password: hashed_password,
            },
            None,
        )
        .await?;

    Ok(Json(serde_json::json!( {
        "id": result.inserted_id.as_object_id().unwrap().to_hex(),
        "email": req.email,
    })))
}

fn compute_password_hash(password: String) -> Result<String, anyhow::Error> {
    let salt = SaltString::generate(&mut rand::thread_rng());
    let password_hash = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(15000, 2, 1, None).unwrap(),
    )
    .hash_password(password.as_bytes(), &salt)?
    .to_string();
    Ok(password_hash)
}

fn validate_password(password: &str) -> Result<(), ValidationError> {
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
    let has_special = password.chars().any(|c| SPECIAL_CHARS.contains(c));

    if has_digit && has_uppercase && has_special && password.len() > 9 {
        return Ok(());
    }
    let mut err = ValidationError::new("UNPROCESSABLE_ENTITY");
    err.message = Some(
        Cow::from(
            "The password must be at least 10 characters, must contain numeric characters, minimum 1 uppercase letter [A-Z] and minimum 1 special character"
        )
    );
    Err(err)
}
