use argon2::{Argon2, PasswordHash, PasswordHasher as _};
use hyper::{
    body::{Bytes, Incoming},
    header::{self, HeaderValue},
    http::{Method, Request, Response, StatusCode},
};
use rusqlite::{Connection, OptionalExtension as _};
use serde_derive::{Deserialize, Serialize};

use crate::{token::HmacSecurity, worker::OffThread};

mod extract;
mod reply;
mod runtime;
mod server;
mod token;
mod worker;

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

struct UserInfo {
    id: i64,
    password: PasswordHash,
}

fn main() -> anyhow::Result<()> {
    let database = Connection::open("app.sqlite3")?;
    database.execute_batch(
        "
        create table if not exists users (
            id integer primary key,
            username text unique not null,
            password_hash text not null
        ) strict;
        ",
    )?;

    let (persistence, _) = OffThread::spawn_single(database, 16);
    let (authentication, _) = OffThread::spawn_many(Argon2::default(), 2, 16);
    let (verification, _) = OffThread::spawn_many(HmacSecurity::generate_random(), 4, 16);

    runtime::initialize_environment(async |context, cancellation| {
        server::start_listening(
            context,
            cancellation,
            async move |mut request| match extract::route(&request) {
                (&Method::POST, "register") => {
                    register(&persistence, &authentication, &mut request)
                        .await
                        .unwrap_or_else(reply::status)
                }
                (&Method::POST, "login") => {
                    login(&persistence, &authentication, &verification, &mut request)
                        .await
                        .unwrap_or_else(reply::status)
                }
                (&Method::GET, "check") => check(&verification, &request)
                    .await
                    .unwrap_or_else(reply::status),
                _ => reply::status(StatusCode::NOT_FOUND),
            },
        )
    })
}

async fn register(
    persistence: &OffThread<Connection>,
    authentication: &OffThread<Argon2<'static>>,
    request: &mut Request<Incoming>,
) -> Result<Response<Bytes>, StatusCode> {
    let body = extract::data(request, BODY_LIMIT, HeaderValue::from_static("text/json")).await?;

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
        .schedule_task(move |database| {
            database.execute(
                "
                insert into users (username, password_hash)
                values (?1, ?2)
                ",
                [username, hashed],
            )
        })
        .await
        .and_then(Result::ok)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    if changed != 1 {
        return Err(StatusCode::CONFLICT);
    }

    Ok(reply::status(StatusCode::OK))
}

async fn login(
    persistence: &OffThread<Connection>,
    authentication: &OffThread<Argon2<'static>>,
    verification: &OffThread<HmacSecurity>,
    request: &mut Request<Incoming>,
) -> Result<Response<Bytes>, StatusCode> {
    let body = extract::data(request, BODY_LIMIT, HeaderValue::from_static("text/json")).await?;

    let LoginForm { username, password } = serde_json::from_slice(&body)
        .ok()
        .ok_or(StatusCode::BAD_REQUEST)?;

    let hashed = authentication
        .schedule_task(move |hasher| hasher.hash_password(password.as_bytes()))
        .await
        .and_then(Result::ok)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let UserInfo { id, password } =
        persistence
            .schedule_task(move |database| {
                database
                    .query_row(
                        "
                        select (id, password_hash) from users
                        where username = ?1
                        ",
                        [username],
                        |row| {
                            Ok(UserInfo {
                                id: row.get(0)?,
                                password: row.get_ref(1)?.as_str()?.parse().expect(
                                    "user database shouldn't contain invalid password hashes",
                                ),
                            })
                        },
                    )
                    .optional()
            })
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

    Ok(reply::data(
        StatusCode::OK,
        HeaderValue::from_static("text/plain"),
        Bytes::from(token),
    ))
}

async fn check(
    verification: &OffThread<HmacSecurity>,
    request: &Request<Incoming>,
) -> Result<Response<Bytes>, StatusCode> {
    let mut token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.as_bytes().strip_prefix(b"Bearer: "))
        .ok_or(StatusCode::UNAUTHORIZED)
        .map(Vec::from)
        .map(Vec::into_boxed_slice)?;

    let IdentityToken { .. } = verification
        .schedule_task(move |security| security.verify_jwt(&mut token))
        .await
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    Ok(reply::status(StatusCode::OK))
}
