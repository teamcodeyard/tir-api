use axum::async_trait;
use axum::extract::rejection::JsonRejection;
use axum::extract::FromRequest;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::de::DeserializeOwned;
use thiserror::Error;
use validator::Validate;

#[derive(Debug, Clone, Copy, Default)]
pub struct ValidatedJson<T>(pub T);

#[async_trait]
impl<T, S, B> FromRequest<S, B> for ValidatedJson<T>
where
    T: DeserializeOwned + Validate,
    S: Send + Sync,
    Json<T>: FromRequest<S, B, Rejection = JsonRejection>,
    B: Send + 'static,
{
    type Rejection = ServerError;

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state).await?;
        value.validate()?;
        Ok(ValidatedJson(value))
    }
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error(transparent)]
    ValidationError(#[from] validator::ValidationErrors),

    #[error(transparent)]
    AxumJsonRejection(#[from] JsonRejection),

    #[error(transparent)]
    MongoError(#[from] mongodb::error::Error),

    #[error("internal server error occurred")]
    InternalError(#[from] anyhow::Error),

    #[error("mongodb error occurred")]
    BadRequest(String),

    #[error("access denied")]
    Unauthorized(String),
    
    #[error("Unprocessable entity")]
    UnprocessableEntity(String)
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        (
            match self {
                ServerError::ValidationError(err) => {
                    // TODO: Remove the unwraps, and try to find a good way of doing this..
                    let field_errors = err.field_errors();
                    let field_error = field_errors.iter().next().unwrap();
                    let (_, err_values) = field_error;
                    let err_value = err_values.first().unwrap();
                    let err_json = Json(
                        serde_json::json!({"code": 400, "type": err_value.code, "message": err_value.message })
                    );
                    (StatusCode::BAD_REQUEST, err_json)
                }
                ServerError::AxumJsonRejection(_) => {
                    let err_json = Json(serde_json::json!({"code": 400, "type": "BAD_REQUEST", "message": "invalid JSON"}));
                    (StatusCode::BAD_REQUEST, err_json)
                }
                ServerError::MongoError(err) => {
                    // Just log the DB error, but don't send in the response.
                    tracing::error!("Mongo error: {err}");
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                        "code": 500, "type": "INTERNAL_SERVER_ERROR", "message": "an internal server error occurred"
                    })))
                },
                ServerError::BadRequest(err_message)  => {
                    // Just log the error, but don't send in the response.
                    tracing::error!("Bad request error: {err_message}");
                    (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                        "code": 400, "type": "BAD_REQUEST", "message": err_message
                    })))
                },
                ServerError::Unauthorized(err_message)  => {
                    // Just log the error, but don't send in the response.
                    tracing::error!("Unauthorized request error: {err_message}");
                    (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                        "code": 401, "type": "UNAUTHORIZED", "message": err_message
                    })))
                },
                ServerError::InternalError(err) => {
                    // Just log the error, but don't send in the response.
                    tracing::error!("internal error: {err}");
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                        "code": 500, "type": "INTERNAL_SERVER_ERROR", "message": "an internal server error occurred"
                    })))
                },
                ServerError::UnprocessableEntity(error_message) => {
                    // Just log the error, but don't send in the response.
                    tracing::error!("unprocessable entity: {error_message}");
                    (StatusCode::UNPROCESSABLE_ENTITY, Json(serde_json::json!({
                        "code": 422, "type": "UNPROCESSABLE_ENTITY", "message": error_message
                    })))
                },
                
            }
        ).into_response()
    }
}
