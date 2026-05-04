use std::{sync::Arc, time::SystemTime};

use argon2::{PasswordHasher as _, PasswordVerifier as _, password_hash::SaltString};
use base64ct::{Base64Url, Encoding as _};
use hyper::{
    body::{Bytes, Incoming},
    header::HeaderValue,
    http::{Request, Response, StatusCode},
};
use rand::rngs::OsRng;
use secrecy::{ExposeSecret, SecretBox};
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{application::SharedState, crypto::HmacSecurity, storage::CodeExchange};

// none of our handlers should handle huge requests
const REASONABLE_BODY_LIMIT: usize = 512;

#[derive(Deserialize)]
struct LoginForm {
    username: Box<str>,
    password: SecretBox<str>,
    totp: Option<Box<str>>,
}

#[derive(Deserialize, Serialize)]
struct IdentityToken {
    user: i64,
}

#[derive(Deserialize)]
struct AuthorizeRequest<'source> {
    target: &'source str,
    state: Option<&'source str>,
    challenge: Option<&'source str>,
}

#[derive(Deserialize)]
struct TokenRequest<'source> {
    code: &'source str,
    state: Option<&'source str>,
    verifier: Option<&'source str>,
}

pub async fn register(
    state: &SharedState,
    request: &mut Request<Incoming>,
) -> Result<Response<Bytes>, StatusCode> {
    let body = crate::extract::data(
        request,
        REASONABLE_BODY_LIMIT,
        HeaderValue::from_static("text/json"),
    )
    .await?;

    let LoginForm {
        username, password, ..
    } = serde_json::from_slice(&body)
        .ok()
        .ok_or(StatusCode::BAD_REQUEST)?;

    let hashed = state
        .authentication
        .schedule_task(move |hasher| {
            hasher
                .hash_password(
                    password.expose_secret().as_bytes(),
                    &SaltString::generate(&mut OsRng),
                )
                .expect("password hasher configuration should be valid")
                .serialize()
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
        REASONABLE_BODY_LIMIT,
        HeaderValue::from_static("text/json"),
    )
    .await?;

    let LoginForm {
        username,
        password,
        totp,
    } = serde_json::from_slice(&body)
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
            .schedule_task(move |hasher| {
                hasher
                    .hash_password(
                        password.expose_secret().as_bytes(),
                        &SaltString::generate(&mut OsRng),
                    )
                    .expect("password hasher configuration should be valid")
                    .serialize()
            })
            .await;

        return Err(StatusCode::UNAUTHORIZED);
    };

    if let Some(security) = found
        .totp
        .as_ref()
        .map(ExposeSecret::expose_secret)
        .map(HmacSecurity::from_secret)
    {
        // FIXME: constant time equal even tough just tiny string of base 10 digits
        let code = totp.ok_or(StatusCode::FORBIDDEN)?;
        let correct = state
            .verification
            .schedule_task(move |_| security.verify_totp(SystemTime::now(), &code))
            .await;

        if !correct {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    state
        .authentication
        .schedule_task(move |hasher| {
            hasher.verify_password(
                password.expose_secret().as_bytes(),
                &found.password.password_hash(),
            )
        })
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

pub async fn authorize(
    context: &SharedState,
    request: &mut Request<Incoming>,
) -> Result<Response<Bytes>, StatusCode> {
    let mut token = crate::extract::bearer(request)?;
    let body = crate::extract::data(
        request,
        REASONABLE_BODY_LIMIT,
        HeaderValue::from_static("text/json"),
    )
    .await?;

    let IdentityToken { user } = context
        .verification
        .schedule_task(move |security| security.verify_jwt(&mut token))
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let allowed = Arc::clone(&context.allowed);
    let code = context
        .persistence
        .schedule_task(move |database| {
            let AuthorizeRequest {
                target,
                state,
                challenge,
            } = serde_json::from_slice(&body)
                .ok()
                .ok_or(StatusCode::BAD_REQUEST)?;

            if !target.parse().is_ok_and(|uri| allowed.contains(&uri)) {
                return Err(StatusCode::FORBIDDEN);
            }

            database
                .create_code_exchange(user, state, challenge)
                .ok()
                .ok_or(StatusCode::INTERNAL_SERVER_ERROR)
        })
        .await?;

    Ok(crate::reply::data(
        StatusCode::OK,
        HeaderValue::from_static("text/plain"),
        Bytes::from(code.into_boxed_bytes()),
    ))
}

pub async fn token(
    context: &SharedState,
    request: &mut Request<Incoming>,
) -> Result<Response<Bytes>, StatusCode> {
    let body = crate::extract::data(
        request,
        REASONABLE_BODY_LIMIT,
        HeaderValue::from_static("text/json"),
    )
    .await?;

    let user = context
        .persistence
        .schedule_task(move |database| {
            let TokenRequest {
                code,
                state,
                verifier,
            } = serde_json::from_slice(&body)
                .ok()
                .ok_or(StatusCode::BAD_REQUEST)?;

            let CodeExchange { user, challenge } = database
                .take_code_exchange(code, state)
                .ok()
                .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
                .ok_or(StatusCode::NOT_FOUND)?;

            let provided = verifier.map(|value| {
                // the actual size calculation is const so we could construct an array string
                // but unfortunately that's not how it's publicly exposed to us by the crate
                Base64Url::encode_string(&Sha256::new().chain_update(value.as_bytes()).finalize())
            });

            if provided.as_deref() != challenge.as_deref() {
                return Err(StatusCode::FORBIDDEN);
            }

            Ok(user)
        })
        .await?;

    let token = context
        .verification
        .schedule_task(move |security| security.sign_jwt(&IdentityToken { user }))
        .await;

    Ok(crate::reply::data(
        StatusCode::OK,
        HeaderValue::from_static("text/plain"),
        Bytes::from(token),
    ))
}
