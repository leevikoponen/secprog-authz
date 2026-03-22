use argon2::{Argon2, PasswordHasher as _};
use hyper::{
    body::{Bytes, Incoming},
    header::HeaderValue,
    http::{Request, Response, StatusCode},
};
use serde_derive::{Deserialize, Serialize};

use crate::{
    storage::{UserInfo, UserRepository},
    token::HmacSecurity,
    worker::OffThread,
};

const BODY_LIMIT: usize = 512;

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Deserialize, Serialize)]
struct IdentityToken {
    user: i64,
}

pub async fn register(
    persistence: &OffThread<UserRepository>,
    authentication: &OffThread<Argon2<'static>>,
    request: &mut Request<Incoming>,
) -> Result<Response<Bytes>, StatusCode> {
    let body =
        crate::extract::data(request, BODY_LIMIT, HeaderValue::from_static("text/json")).await?;

    let LoginForm { username, password } = serde_json::from_slice(&body)
        .ok()
        .ok_or(StatusCode::BAD_REQUEST)?;

    let hashed = authentication
        .schedule_task(move |hasher| hasher.hash_password(password.as_bytes()))
        .await
        .and_then(Result::ok)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
        .to_string();

    let changed = persistence
        .schedule_task(move |database| database.create_new_account(&username, &hashed))
        .await
        .and_then(Result::ok)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    if !changed {
        return Err(StatusCode::CONFLICT);
    }

    Ok(crate::reply::status(StatusCode::OK))
}

pub async fn login(
    persistence: &OffThread<UserRepository>,
    authentication: &OffThread<Argon2<'static>>,
    verification: &OffThread<HmacSecurity>,
    request: &mut Request<Incoming>,
) -> Result<Response<Bytes>, StatusCode> {
    let body =
        crate::extract::data(request, BODY_LIMIT, HeaderValue::from_static("text/json")).await?;

    let LoginForm { username, password } = serde_json::from_slice(&body)
        .ok()
        .ok_or(StatusCode::BAD_REQUEST)?;

    let hashed = authentication
        .schedule_task(move |hasher| hasher.hash_password(password.as_bytes()))
        .await
        .and_then(Result::ok)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let UserInfo { id, password } = persistence
        .schedule_task(move |database| database.fetch_by_name(&username))
        .await
        .and_then(Result::ok)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if password
        .hash
        .expect("stored password hash should contain output value")
        != hashed
            .hash
            .expect("freshly produced password hash should contain output value")
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token = verification
        .schedule_task(move |security| security.sign_jwt(&IdentityToken { user: id }))
        .await
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(crate::reply::data(
        StatusCode::OK,
        HeaderValue::from_static("text/plain"),
        Bytes::from(token),
    ))
}

pub async fn check(
    verification: &OffThread<HmacSecurity>,
    request: &Request<Incoming>,
) -> Result<Response<Bytes>, StatusCode> {
    let mut token = crate::extract::bearer(request)?;

    let IdentityToken { .. } = verification
        .schedule_task(move |security| security.verify_jwt(&mut token))
        .await
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    Ok(crate::reply::status(StatusCode::OK))
}
