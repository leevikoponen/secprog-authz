use argon2::{PasswordHasher as _, PasswordVerifier as _};
use hyper::{
    body::{Bytes, Incoming},
    header::HeaderValue,
    http::{Request, Response, StatusCode},
};
use serde_derive::{Deserialize, Serialize};

use crate::application::SharedState;

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

impl LoginForm {
    const BODY_LIMIT: usize = 512;
}

#[derive(Deserialize, Serialize)]
struct IdentityToken {
    user: i64,
}

pub async fn register(
    state: &SharedState,
    request: &mut Request<Incoming>,
) -> Result<Response<Bytes>, StatusCode> {
    let body = crate::extract::data(
        request,
        LoginForm::BODY_LIMIT,
        HeaderValue::from_static("text/json"),
    )
    .await?;

    let LoginForm { username, password } = serde_json::from_slice(&body)
        .ok()
        .ok_or(StatusCode::BAD_REQUEST)?;

    let hashed = state
        .authentication
        .schedule_task(move |hasher| {
            hasher
                .hash_password(password.as_bytes())
                .expect("password hasher configuration should be valid")
        })
        .await
        .to_string();

    let changed = state
        .persistence
        .schedule_task(move |database| database.create_new_account(&username, &hashed))
        .await
        .ok()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    if !changed {
        return Err(StatusCode::CONFLICT);
    }

    Ok(crate::reply::status(StatusCode::OK))
}

pub async fn login(
    state: &SharedState,
    request: &mut Request<Incoming>,
) -> Result<Response<Bytes>, StatusCode> {
    let body = crate::extract::data(
        request,
        LoginForm::BODY_LIMIT,
        HeaderValue::from_static("text/json"),
    )
    .await?;

    let LoginForm { username, password } = serde_json::from_slice(&body)
        .ok()
        .ok_or(StatusCode::BAD_REQUEST)?;

    let result = state
        .persistence
        .schedule_task(move |database| database.fetch_by_name(&username))
        .await
        .ok()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    // FIXME: not ideal but makes both cases take similar-ish amount of time
    let Some(found) = result else {
        state
            .authentication
            .schedule_task(move |hasher| hasher.hash_password(password.as_bytes()))
            .await
            .expect("password hasher configuration should be valid");

        return Err(StatusCode::UNAUTHORIZED);
    };

    state
        .authentication
        .schedule_task(move |hasher| hasher.verify_password(password.as_bytes(), &found.password))
        .await
        .ok()
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = state
        .verification
        .schedule_task(move |security| security.sign_jwt(&IdentityToken { user: found.id }))
        .await;

    Ok(crate::reply::data(
        StatusCode::OK,
        HeaderValue::from_static("text/plain"),
        Bytes::from(token),
    ))
}

pub async fn check(
    state: &SharedState,
    request: &Request<Incoming>,
) -> Result<Response<Bytes>, StatusCode> {
    let mut token = crate::extract::bearer(request)?;

    let IdentityToken { .. } = state
        .verification
        .schedule_task(move |security| security.verify_jwt(&mut token))
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;

    Ok(crate::reply::status(StatusCode::OK))
}
