use axum::extract::rejection::JsonRejection;
use axum::extract::FromRequest;
use axum::http::{ Request, StatusCode };
use axum::response::{ IntoResponse, Response };
use axum::Json;
use serde_json::json;
use validator::Validate;
use axum::async_trait;
use serde::de::DeserializeOwned;
use thiserror::Error;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ValidatedJson<T>(pub T);

#[async_trait]
impl<T, S, B> FromRequest<S, B>
    for ValidatedJson<T>
    where
        T: DeserializeOwned + Validate,
        S: Send + Sync,
        Json<T>: FromRequest<S, B, Rejection = JsonRejection>,
        B: Send + 'static
{
    type Rejection = ServerError;

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state).await?;
        value.validate()?;
        Ok(ValidatedJson(value))
    }
}

#[derive(Debug, Error)]
pub(crate) enum ServerError {
    #[error(transparent)] ValidationError(#[from] validator::ValidationErrors),

    #[error(transparent)] AxumFormRejection(#[from] JsonRejection),
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        (
            match self {
                ServerError::ValidationError(err) => {
                    let field_errors = err.field_errors();
                    let field_error = field_errors.iter().next().unwrap();
                    let (_, err_values) = field_error;
                    let err_value = err_values.first().unwrap();
                    let err_json = Json(
                        serde_json::json!({"code": 400, "type": err_value.code, "message": err_value.message})
                    );
                    (StatusCode::BAD_REQUEST, err_json)
                }
                ServerError::AxumFormRejection(_) => {
                    let err_json = Json(serde_json::json!({}));
                    (StatusCode::BAD_REQUEST, err_json)
                }
            }
        ).into_response()
    }
}
