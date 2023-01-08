use argon2::password_hash::{rand_core::OsRng, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::FromRef;
use axum::response::{IntoResponse, Response};
use axum::{
    http::{header::HeaderName, Method, StatusCode},
    routing::{get, post},
    Json, Router,
};
use axum_extra::extract::cookie::{Cookie, Key, PrivateCookieJar, SameSite};
use axum_server::tls_rustls::RustlsConfig;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tower_http::cors::{AllowOrigin, CorsLayer};

mod prisma;

#[derive(Deserialize)]
struct Credentials {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    id: i32,
}

#[derive(Deserialize)]
struct UserID {
    id: i32,
}

#[derive(Serialize)]
struct WhoAmI {
    id: i32,
    username: String,
}

#[derive(Clone)]
struct AppState {
    key: Key,
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.clone()
    }
}

#[tokio::main]
async fn main() {
    let ip: String = "127.0.0.1".to_string();

    println!("Running on: {}", ip);

    let addr = format!("{}:28765", ip).parse::<SocketAddr>().unwrap();

    let state = AppState {
        key: Key::from(&std::fs::read("key").unwrap()),
    };

    let cors = CorsLayer::new()
        .allow_methods([Method::POST])
        .allow_origin(AllowOrigin::mirror_request())
        .allow_headers(vec![HeaderName::from_lowercase(b"content-type").unwrap()])
        .allow_credentials(true);

    let app = Router::new()
        .route("/api/login", post(login))
        .route("/api/register", post(register))
        .route("/api/whoami", post(whoami))
        .route("/api/authorize", get(authorize))
        .route("/api/logout", get(logout))
        .route("/api/test", get(test_route))
        .layer(cors)
        .with_state(state);

    let tls = RustlsConfig::from_pem_file("certs/fullchain.pem", "certs/privkey.pem")
        .await
        .unwrap();

    println!("Serving");
    axum::Server::bind(&addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap(); //Dev bind, without certs for local testing
                   // axum_server::bind_rustls(addr, tls).serve(app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();            //Production, with certs
}

async fn login(jar: PrivateCookieJar, Json(payload): Json<Credentials>) -> Response {
    let username = payload.username.to_lowercase().trim().to_string();

    match jar.get("session_token") {
        Some(mut cookie) => {
            let mut new_jar = jar.remove(cookie.clone());
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
                                                    Some(found) => {
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
                                        Some(found) => {
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

async fn authorize(jar: PrivateCookieJar) -> Response {
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
                            return (
                                StatusCode::OK,
                                Json(WhoAmI {
                                    id: data.id,
                                    username: data.username,
                                }),
                            )
                                .into_response()
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

async fn logout(jar: PrivateCookieJar) -> Response {
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

async fn register(Json(payload): Json<Credentials>) -> impl IntoResponse {
    let username = payload.username.to_lowercase().trim().to_string();

    if let Ok(db) = prisma::new_client().await {
        if let Ok(is_unique) = db
            .user_data()
            .find_unique(prisma::user_data::username::equals(username.clone()))
            .exec()
            .await
        {
            match is_unique {
                Some(_) => return StatusCode::CONFLICT.into_response(),
                None => {
                    let argon = Argon2::default();
                    let salt = SaltString::generate(&mut OsRng);

                    if let Ok(hashed_result) =
                        argon.hash_password(payload.password.as_bytes(), &salt)
                    {
                        match argon.verify_password(payload.password.as_bytes(), &hashed_result) {
                            Ok(_) => {
                                match db
                                    .user_data()
                                    .create(username.clone(), hashed_result.to_string(), vec![])
                                    .exec()
                                    .await
                                {
                                    Ok(db_stored_data) => {
                                        return (
                                            StatusCode::CREATED,
                                            Json(RegisterResponse {
                                                id: db_stored_data.id,
                                            }),
                                        )
                                            .into_response();
                                    }
                                    Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                                }
                            }
                            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                        }
                    } else {
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
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

async fn whoami(Json(payload): Json<UserID>) -> Response {
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

async fn test_route() -> String {
    format!("Hello User :) !")
}