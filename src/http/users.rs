use crate::http::{ ApiContext };
use anyhow::Context;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::{ get, post };
use axum::{ Json, Router };

pub(crate) fn router() -> Router<ApiContext> {
    // By having each module responsible for setting up its own routing,
    // it makes the root module a lot cleaner.
    Router::new().route("/api/users", post(create_user))
}

#[derive(serde::Deserialize)]
struct NewUser {
    email: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct User {
    email: String,
}

// https://realworld-docs.netlify.app/docs/specs/backend-specs/endpoints#registration
async fn create_user(ctx: State<ApiContext>, Json(req): Json<NewUser>) -> impl IntoResponse {
    Json(User {
        email: req.email.to_string()
    })
}
 