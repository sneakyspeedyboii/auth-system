
use axum::response::{IntoResponse, Response};
use axum::{
    http::StatusCode,
};
use axum_extra::extract::cookie::{PrivateCookieJar, SameSite};

use crate::requests::misc::prisma;

pub async fn logout(jar: PrivateCookieJar) -> Response {
    match jar.get("session_token") {
        Some(mut cookie) => {
            if let Ok(db) = prisma::new_client().await {
                if let Ok(user) = db
                    .cookie_tokens()
                    .find_unique(prisma::cookie_tokens::token::equals(
                        jar.get("session_token").unwrap().value().to_string(),
                    ))
                    .exec()
                    .await
                {
                    match user {
                        Some(data) => {
                            if let Ok(_) = db
                                .cookie_tokens()
                                .delete(prisma::cookie_tokens::token::equals(data.token))
                                .exec()
                                .await
                            {
                                cookie.set_same_site(SameSite::None);
                                let new_jar = jar.remove(cookie);
                                return (StatusCode::OK, new_jar).into_response();
                            } else {
                                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                            }
                        }
                        None => {
                            cookie.set_same_site(SameSite::None);
                            let new_jar = jar.remove(cookie);
                            return (StatusCode::UNAUTHORIZED, new_jar).into_response();
                        }
                    }
                } else {
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            } else {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
        None => return StatusCode::NOT_FOUND.into_response(),
    }
}