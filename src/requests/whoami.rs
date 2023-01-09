use axum::response::{IntoResponse, Response};
use axum::{
    http::{StatusCode},
    Json
};

use crate::requests::misc::prisma;
use crate::requests::misc::data_types::*;

pub async fn whoami(Json(payload): Json<UserID>) -> Response {
    if let Ok(db) = prisma::new_client().await {
        if let Ok(user) = db
            .user_data()
            .find_unique(prisma::user_data::id::equals(payload.id))
            .exec()
            .await
        {
            match user {
                Some(data) => Json(WhoAmI {
                    id: payload.id,
                    username: data.username,
                })
                .into_response(),

                None => StatusCode::NOT_FOUND.into_response(),
            }
        } else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    } else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
}