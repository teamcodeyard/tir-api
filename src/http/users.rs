use std::borrow::Cow;

use crate::http::ApiContext;
use axum::extract::State;
use axum::routing::post;
use axum::response::IntoResponse;
use axum::{ Json, Router };
use validator::{ Validate, ValidationError };

use super::validation::ValidatedJson;

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
    #[validate(length(min = 10), custom = "validate_password")]
    password: String,
}

fn validate_password(password: &str) -> Result<(), ValidationError> {
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
    let has_special = password.chars().any(|c| SPECIAL_CHARS.contains(c));

    if has_digit && has_uppercase && has_special {
        return Ok(());
    }
    let mut err = ValidationError::new("UNPROCESSABLE_ENTITY");
    err.message = Some(
        Cow::from(
            "The password must be at least 10 characters, must contain numeric characters, minimum 1 uppercase letter [A-Z] and minimum 1 special character"
        )
    );
    return Err(err);
}

#[derive(serde::Serialize, serde::Deserialize)]
struct User {
    email: String,
}

async fn create_user(
    ctx: State<ApiContext>,
    ValidatedJson(req): ValidatedJson<UserRequest>
) -> impl IntoResponse {
    Json(User {
        email: req.email.to_string(),
    })
}
