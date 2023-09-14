use crate::http::validation::ServerError;
use crate::http::ApiContext;
use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use mongodb;
use mongodb::Collection;

pub trait DBCollectable {
    fn get_collection_name() -> &'static str;
}

pub struct DatabaseCollection<T>(pub Collection<T>);

#[async_trait]
impl<S, T: DBCollectable> FromRequestParts<S> for DatabaseCollection<T>
where
    S: Send + Sync,
    ApiContext: FromRef<S>,
{
    type Rejection = ServerError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let ApiContext { db, .. } = ApiContext::from_ref(state);
        let conn = db.collection::<T>(T::get_collection_name());
        Ok(Self(conn))
    }
}
