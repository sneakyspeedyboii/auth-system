use argon2::password_hash::{rand_core::OsRng, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::response::{IntoResponse};
use axum::{
    http::{StatusCode},
    Json,
};

use crate::requests::misc::prisma;
use crate::requests::misc::data_types::*;

pub async fn register(Json(payload): Json<Credentials>) -> impl IntoResponse {
    let username = payload.username.to_lowercase().trim().to_string();

    if let Ok(db) = prisma::new_client().await {
        if let Ok(is_unique) = db
            .user_data()
            .find_unique(prisma::user_data::username::equals(username.clone()))
            .exec()
            .await
        {
            match is_unique {
                
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
                },
                Some(_) => return StatusCode::CONFLICT.into_response()
            }
        } else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    } else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
}