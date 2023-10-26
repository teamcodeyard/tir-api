use super::structs::{ User, Claim };
use super::DatabaseCollection;
use super::doc;
use super::ServerError;
use super::ApiContext;
use jsonwebtoken::{ EncodingKey, Header };
use jsonwebtoken::encode;
use time::Duration;
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
use axum::{ async_trait, http::HeaderName, extract::{ FromRef, FromRequestParts } };
use regex::Regex;
use validator::ValidationError;
use std::borrow::Cow;
use axum::http::request::Parts;
use anyhow::Context;

const SPECIAL_CHARS: &str = "!@#$%^&*()-=_+{}[]:;<>,.?";

pub(crate) fn compute_password_hash(password: String) -> Result<String, anyhow::Error> {
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

pub fn validate_password(password: &str) -> Result<(), ValidationError> {
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
    let has_special = password.chars().any(|c| SPECIAL_CHARS.contains(c));

    if has_digit && has_uppercase && has_special && password.len() > 9 {
        return Ok(());
    }
    let mut err = ValidationError::new("BAD_REQUEST");
    err.message = Some(
        Cow::from(
            "The password must be at least 10 characters, must contain numeric characters, minimum 1 uppercase letter [A-Z] and minimum 1 special character"
        )
    );
    Err(err)
}

pub async fn validate_password_match(
    password: String,
    req_password: String
) -> Result<(), ServerError> {
    crate::utils
        ::spawn_blocking_with_tracing(move || {
            let expected_password_hash = PasswordHash::new(&password)?;
            Argon2::default().verify_password(req_password.as_bytes(), &expected_password_hash)
        }).await
        .context("unexpected error happened during password hashing")?
        .map_err(|_| ServerError::UnprocessableEntity(String::from("Invalid e-mail or password")))?;
    Ok(())
}

pub fn validate_email(email: &str) -> Result<(), ValidationError> {
    let regex = Regex::new(r"^([a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$").unwrap();
    let is_valid = regex.is_match(email);
    if is_valid {
        return Ok(());
    }
    let mut err = ValidationError::new("BAD_REQUEST");
    err.message = Some(Cow::from("Invalid e-mail address"));
    Err(err)
}

pub async fn generate_new_api_key(
    inserted_id: &String,
    ctx: ApiContext
) -> Result<String, ServerError> {
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
    Ok(token)
}

const X_ACCESS_TOKEN: HeaderName = HeaderName::from_static("x-access-token");

#[async_trait]
impl<S> FromRequestParts<S> for User where S: Send + Sync, ApiContext: FromRef<S> {
    type Rejection = ServerError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let Some(access_token) = parts.headers.get(X_ACCESS_TOKEN) {
            let app_state = ApiContext::from_ref(state);
            let id = User::from_authorization(&app_state.config, access_token)?;
            let DatabaseCollection(user_collection) =
                DatabaseCollection::<User>::from_request_parts(parts, state).await?;
            let user_result = user_collection.find_one(doc! { "_id": id }, None).await?;
            Ok(user_result.unwrap())
        } else {
            Err(ServerError::Unauthorized(String::from("unauthorized")))
        }
    }
}
