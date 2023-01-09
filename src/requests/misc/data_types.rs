use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub id: i32,
}

#[derive(Deserialize)]
pub struct UserID {
    pub id: i32,
}

#[derive(Serialize)]
pub struct WhoAmI {
    pub id: i32,
    pub username: String,
}