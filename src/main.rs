use argon2::Argon2;
use hyper::{
    body::Bytes,
    header::HeaderValue,
    http::{Method, StatusCode},
};

use crate::{storage::UserRepository, token::HmacSecurity, worker::OffThread};

mod extract;
mod handler;
mod reply;
mod runtime;
mod server;
mod storage;
mod token;
mod worker;

fn main() -> anyhow::Result<()> {
    let frontend = std::fs::read("index.html").map(Bytes::from_owner)?;
    let database = UserRepository::initialize_from_env()?;

    let (persistence, _) = OffThread::spawn_single(database, 16);
    let (authentication, _) = OffThread::spawn_many(Argon2::default(), 2, 16);
    let (verification, _) = OffThread::spawn_many(HmacSecurity::generate_random(), 4, 16);

    runtime::initialize_environment(async |context, cancellation| {
        server::start_listening(
            context,
            cancellation,
            async move |mut request| match extract::route(&request) {
                (&Method::GET, "" | "index.html") => reply::data(
                    StatusCode::OK,
                    HeaderValue::from_static("text/html"),
                    frontend.clone(),
                ),
                (&Method::POST, "register") => {
                    handler::register(&persistence, &authentication, &mut request)
                        .await
                        .unwrap_or_else(reply::status)
                }
                (&Method::POST, "login") => {
                    handler::login(&persistence, &authentication, &verification, &mut request)
                        .await
                        .unwrap_or_else(reply::status)
                }
                (&Method::GET, "check") => handler::check(&verification, &request)
                    .await
                    .unwrap_or_else(reply::status),
                _ => reply::status(StatusCode::NOT_FOUND),
            },
        )
    })
}
