use std::borrow::Cow;

use argon2::{
    password_hash::SaltString,
    Algorithm,
    Argon2,
    Params,
    PasswordHasher,
    Version,
    PasswordHash,
    PasswordVerifier,
};
use axum::http::request::Parts;
use axum::routing::{ post, get };
use axum::{
    async_trait,
    extract::State,
    extract::{ FromRef, FromRequestParts },
    http::{ HeaderName, HeaderValue },
    Json,
    Router,
};
use jsonwebtoken::{ decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation };
use mongodb::{ Database, IndexModel, bson::{ doc, oid::ObjectId }, options::IndexOptions };
use serde::{ Deserialize, Serialize };
use time;
use time::Duration;
use validator::{ Validate, ValidationError };

use crate::config::Config;
use crate::http::extractors::{ DBCollectable, DatabaseCollection };
use crate::http::ApiContext;
use crate::utils::spawn_blocking_with_tracing;
use anyhow::{Result, Context};
use super::validation::{ ServerError, ValidatedJson };

const SPECIAL_CHARS: &str = "!@#$%^&*()-=_+{}[]:;<>,.?";

pub(crate) fn router() -> Router<ApiContext> {
    // By having each module responsible for setting up its own routing,
    // it makes the root module a lot cleaner.
    Router::new()
        .route("/api/users", post(create_user))
        .route("/api/users/me", get(get_user))
        .route("/api/users/login", post(login_user))
}

pub(crate) async fn create_indexes(db: &Database) {
    let options = IndexOptions::builder().unique(true).build();
    let model = IndexModel::builder()
        .keys(doc! { "email": 1 })
        .options(options)
        .build();
    db.collection::<User>(User::get_collection_name())
        .create_index(model, None).await
        .expect("error creating index!");
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
    _id: Option<ObjectId>,
    email: String,
    password: String,
    api_keys: Vec<String>,
}
#[derive(Debug, Serialize, Deserialize)]
struct Claim {
    sub: String,
    iat: i64,
    exp: i64,
}

impl DBCollectable for User {
    fn get_collection_name() -> &'static str {
        "users"
    }
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
                _id: Option::None,
                email: req.email.clone(),
                password: hashed_password,
                api_keys: vec![],
            },
            None
        ).await
        .map_err(|err| ServerError::BadRequest("E-mail already exists".to_string()))?;
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

async fn get_user(
    State(ctx): State<ApiContext>,
    DatabaseCollection(user_collection): DatabaseCollection<User>,
    authorized_user: User
) -> Result<Json<serde_json::Value>, ServerError> {
    let id = authorized_user._id.unwrap().to_hex();
    Ok(Json(serde_json::json!({
        "email": authorized_user.email,
        "id": id 
    })))
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

    crate::utils
        ::spawn_blocking_with_tracing(move || {
            let expected_password_hash = PasswordHash::new(&user.password)?;
            Argon2::default().verify_password(req.password.as_bytes(), &expected_password_hash)
        }).await
        .context("unexpected error happened during password hashing")?
        .map_err(|_| ServerError::UnprocessableEntity(String::from("Invalid e-mail or password")))?;

    Ok(Json(serde_json::json!({
        "email": user.email,
        "id": user._id.unwrap().to_hex() 
    })))
}

fn compute_password_hash(password: String) -> Result<String, anyhow::Error> {
    let salt = SaltString::generate(&mut rand::thread_rng());
    let password_hash = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(15000, 2, 1, None).unwrap()
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

const X_ACCESS_TOKEN: HeaderName = HeaderName::from_static("x-access-token");

#[async_trait]
impl<S> FromRequestParts<S> for User where S: Send + Sync, ApiContext: FromRef<S> {
    type Rejection = ServerError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let Some(access_token) = parts.headers.get(X_ACCESS_TOKEN) {
            let app_state = ApiContext::from_ref(state);
            let id = User::from_authorization(&app_state.config, access_token)?;
            let DatabaseCollection(mut user_collection) =
                DatabaseCollection::<User>::from_request_parts(parts, state).await?;
            let user_result = user_collection.find_one(doc! { "_id": id }, None).await?;
            Ok(user_result.unwrap())
        } else {
            Err(ServerError::Unauthorized(String::from("unauthorized")))
        }
    }
}

impl User {
    fn from_authorization(
        ctx: &Config,
        auth_header: &HeaderValue
    ) -> Result<ObjectId, ServerError> {
        let token = auth_header.to_str().map_err(|_| {
            tracing::debug!("Authorization header is not UTF-8");
            ServerError::Unauthorized(String::from("Missing x-access-token header variable"))
        })?;

        let decoding = DecodingKey::from_secret(ctx.jwt_secret.as_bytes());
        let validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        let TokenData { claims, .. } = jsonwebtoken
            ::decode::<Claim>(token, &decoding, &validation)
            .map_err(|_| ServerError::Unauthorized(String::from("Invalid token")))?;

        if claims.exp < time::OffsetDateTime::now_utc().unix_timestamp() {
            tracing::debug!("token expired");
            return Err(ServerError::Unauthorized(String::from("Token expired")));
        }

        Ok(ObjectId::parse_str(&claims.sub).unwrap())
    }
}
