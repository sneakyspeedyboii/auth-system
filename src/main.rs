use axum::extract::FromRef;
use axum::{
    http::{header::HeaderName, Method},
    routing::{get, post},
    Router,
};
use axum_extra::extract::cookie::Key;
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use tower_http::cors::{AllowOrigin, CorsLayer};

mod requests;
use crate::requests::{register::register, whoami::whoami, login::login, authorize::authorize, logout::logout};

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

    let _tls = RustlsConfig::from_pem_file("certs/fullchain.pem", "certs/privkey.pem").await.unwrap(); 

        

    println!("Serving");
    axum::Server::bind(&addr).serve(app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();                         //Dev bind, without certs for local testing

    // axum_server::bind_rustls(addr, tls).serve(app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();            //Production, with certs
}

async fn test_route() -> String {
    format!("Hello User :) !")
}