use argon2::password_hash::{PasswordVerifier};
use argon2::Argon2;
use axum::response::{IntoResponse, Response};
use axum::{
    http::{StatusCode},
    Json
};
use axum_extra::extract::cookie::{Cookie, PrivateCookieJar, SameSite};

use crate::requests::misc::prisma;
use crate::requests::misc::data_types::*;

pub async fn login(jar: PrivateCookieJar, Json(payload): Json<Credentials>) -> Response {
    let username = payload.username.to_lowercase().trim().to_string();

    match jar.get("session_token") {
        Some(mut cookie) => {
            let new_jar = jar.remove(cookie.clone());
            if let Ok(db) = prisma::new_client().await {
                if let Ok(user) = db
                    .cookie_tokens()
                    .find_unique(prisma::cookie_tokens::token::equals(
                        cookie.value().to_string(),
                    ))
                    .exec()
                    .await
                {
                    match user {
                        Some(_) => {
                            return StatusCode::OK.into_response();
                        }
                        None => {


                            if let Ok(user) = db
                                .user_data()
                                .find_unique(prisma::user_data::username::equals(username.clone()))
                                .exec()
                                .await
                            {
                                match user {
                                    Some(data) => {
                                        let argon = Argon2::default();

                                        let stored_hashed =
                                            argon2::PasswordHash::new(&data.password).unwrap();

                                        if argon
                                            .verify_password(
                                                payload.password.as_bytes(),
                                                &stored_hashed,
                                            )
                                            .is_ok()
                                        {
                                            if let Ok(stored_cookies) = db
                                                .cookie_tokens()
                                                .find_unique(
                                                    prisma::cookie_tokens::username::equals(
                                                        username.clone(),
                                                    ),
                                                )
                                                .exec()
                                                .await
                                            {
                                                match stored_cookies {
                                                    Some(_) => {
                                                        if let Ok(_) = db
                                                                .cookie_tokens()
                                                                .delete(prisma::cookie_tokens::username::equals(
                                                                    username.clone(),
                                                                ))
                                                                .exec()
                                                                .await
                                                            {
                                                                let token = uuid::Uuid::new_v4().to_string();
                
                                                                if let Ok(_) = db
                                                                    .cookie_tokens()
                                                                    .create(
                                                                        data.id,
                                                                        data.username,
                                                                        token.clone(),
                                                                        vec![],
                                                                    )
                                                                    .exec()
                                                                    .await
                                                                {
                                                                    cookie.set_value(token);
                                                                    cookie.set_same_site(SameSite::None);
                                                                    cookie.set_path("/api");
                                                                    cookie.set_secure(true);
                                                                    cookie.set_http_only(true);
                                                                    
                
                                                                    return (StatusCode::OK, new_jar.add(cookie))
                                                                        .into_response();
                                                                } else {
                                                                    return StatusCode::INTERNAL_SERVER_ERROR
                                                                        .into_response();
                                                                }
                                                            } else {
                                                                return StatusCode::INTERNAL_SERVER_ERROR
                                                                    .into_response();
                                                            }
                                                    }
                                                    None => {
                                                        let token =
                                                            uuid::Uuid::new_v4().to_string();
                                                        if let Ok(_) = db
                                                            .cookie_tokens()
                                                            .create(
                                                                data.id,
                                                                data.username,
                                                                token.clone(),
                                                                vec![],
                                                            )
                                                            .exec()
                                                            .await
                                                        {
                                                            let mut cookie =
                                                                Cookie::new("session_token", token);
                                                            cookie.set_same_site(SameSite::None);
                                                            cookie.set_path("/api");
                                                            cookie.set_secure(true);
                                                            cookie.set_http_only(true);

                                                            return (
                                                                StatusCode::OK,
                                                                new_jar.add(cookie),
                                                            )
                                                                .into_response();
                                                        } else {
                                                            return (StatusCode::INTERNAL_SERVER_ERROR, new_jar).into_response();
                                                        }
                                                    }
                                                }
                                            } else {
                                                return (StatusCode::INTERNAL_SERVER_ERROR, new_jar).into_response();
                                            }
                                        } else {
                                            return (StatusCode::UNAUTHORIZED, new_jar).into_response(); 
                                        }
                                    }
                                    None => return (StatusCode::NOT_FOUND, new_jar).into_response(), //this one
                                }
                            } else {
                                return (StatusCode::INTERNAL_SERVER_ERROR, new_jar).into_response(); 
                            }
                        }
                    }
                } else {
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            } else {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
        None => {
            if let Ok(db) = prisma::new_client().await {
                if let Ok(user) = db
                    .user_data()
                    .find_unique(prisma::user_data::username::equals(username.clone()))
                    .exec()
                    .await
                {
                    match user {
                        Some(data) => {
                            let argon = Argon2::default();

                            let stored_hashed = argon2::PasswordHash::new(&data.password).unwrap();

                            if argon
                                .verify_password(payload.password.as_bytes(), &stored_hashed)
                                .is_ok()
                            {
                                if let Ok(stored_cookies) = db
                                    .cookie_tokens()
                                    .find_unique(prisma::cookie_tokens::username::equals(
                                        username.clone(),
                                    ))
                                    .exec()
                                    .await
                                {
                                    match stored_cookies {
                                        Some(_) => {
                                            if let Ok(_) = db
                                                .cookie_tokens()
                                                .delete(prisma::cookie_tokens::username::equals(
                                                    username.clone(),
                                                ))
                                                .exec()
                                                .await
                                            {
                                                let token = uuid::Uuid::new_v4().to_string();

                                                if let Ok(_) = db
                                                    .cookie_tokens()
                                                    .create(
                                                        data.id,
                                                        data.username,
                                                        token.clone(),
                                                        vec![],
                                                    )
                                                    .exec()
                                                    .await
                                                {
                                                    let mut cookie =
                                                        Cookie::new("session_token", token);
                                                    cookie.set_same_site(SameSite::None);
                                                    cookie.set_path("/api");
                                                    cookie.set_secure(true);
                                                    cookie.set_http_only(true);

                                                    return (StatusCode::OK, jar.add(cookie))
                                                        .into_response();
                                                } else {
                                                    return StatusCode::INTERNAL_SERVER_ERROR
                                                        .into_response();
                                                }
                                            } else {
                                                return StatusCode::INTERNAL_SERVER_ERROR
                                                    .into_response();
                                            }
                                        }
                                        None => {
                                            let token = uuid::Uuid::new_v4().to_string();
                                            if let Ok(_) = db
                                                .cookie_tokens()
                                                .create(
                                                    data.id,
                                                    data.username,
                                                    token.clone(),
                                                    vec![],
                                                )
                                                .exec()
                                                .await
                                            {
                                                let mut cookie =
                                                    Cookie::new("session_token", token);
                                                cookie.set_same_site(SameSite::None);
                                                cookie.set_path("/api");
                                                cookie.set_secure(true);
                                                cookie.set_http_only(true);

                                                return (StatusCode::OK, jar.add(cookie))
                                                    .into_response();
                                            } else {
                                                return StatusCode::INTERNAL_SERVER_ERROR
                                                    .into_response();
                                            }
                                        }
                                    }
                                } else {
                                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                                }
                            } else {
                                return StatusCode::UNAUTHORIZED.into_response();
                            }
                        }
                        None => return StatusCode::NOT_FOUND.into_response(),
                    }
                } else {
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            } else {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    }
}