use super::structs::User;
use super::DatabaseCollection;
use super::doc;
use super::ServerError;
use super::ApiContext;
use argon2::{ password_hash::SaltString, Algorithm, Argon2, Params, PasswordHasher, Version };
use axum::{ async_trait, http::HeaderName, extract::{ FromRef, FromRequestParts } };
use validator::ValidationError;
use std::borrow::Cow;
use axum::http::request::Parts;

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
            let DatabaseCollection(user_collection) =
                DatabaseCollection::<User>::from_request_parts(parts, state).await?;
            let user_result = user_collection.find_one(doc! { "_id": id }, None).await?;
            Ok(user_result.unwrap())
        } else {
            Err(ServerError::Unauthorized(String::from("unauthorized")))
        }
    }
}