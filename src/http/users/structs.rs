use super::ServerError;
use super::validate_password;
use super::DBCollectable;
use super::Config;
use serde::{ Deserialize, Serialize };
use mongodb::bson::oid::ObjectId;
use validator::Validate;
use axum::http::HeaderValue;
use jsonwebtoken::{ DecodingKey, TokenData, Validation };

#[derive(serde::Deserialize, Validate)]
pub(crate) struct UserRequest {
    #[validate(email)]
    pub(crate) email: String,
    #[validate(custom = "validate_password")]
    pub(crate) password: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct User {
    pub(crate) _id: Option<ObjectId>,
    pub(crate) email: String,
    pub(crate) password: String,
    pub(crate) api_keys: Vec<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Claim {
    pub(crate) sub: String,
    pub(crate) iat: i64,
    pub(crate) exp: i64,
}

impl DBCollectable for User {
    fn get_collection_name() -> &'static str {
        "users"
    }
}


impl User {
    pub(crate) fn from_authorization(
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
