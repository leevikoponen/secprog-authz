use hyper::{
    header::HeaderValue,
    http::{Method, StatusCode},
};

mod application;
mod crypto;
mod extract;
mod handler;
mod reply;
mod server;
mod storage;
mod worker;

fn main() -> anyhow::Result<()> {
    application::initialize_runtime(async |context, cancellation| {
        let (state, workers) = application::prepare_state()?;

        server::start_listening(context.clone(), cancellation, async move |mut request| {
            match extract::route(&request) {
                (&Method::GET, "" | "index.html") => reply::data(
                    StatusCode::OK,
                    HeaderValue::from_static("text/html"),
                    state.page.clone(),
                ),
                (&Method::POST, "register") => handler::register(&state, &mut request)
                    .await
                    .unwrap_or_else(reply::status),
                (&Method::POST, "login") => handler::login(&state, &mut request)
                    .await
                    .unwrap_or_else(reply::status),
                (&Method::GET, "check") => handler::check(&state, &request)
                    .await
                    .unwrap_or_else(reply::status),
                (&Method::POST, "authorize") => handler::authorize(&state, &mut request)
                    .await
                    .unwrap_or_else(reply::status),
                (&Method::POST, "token") => handler::token(&state, &mut request)
                    .await
                    .unwrap_or_else(reply::status),
                _ => reply::status(StatusCode::NOT_FOUND),
            }
        })?;

        context.wait().await;
        workers.expect_join_success();

        Ok(())
    })
}
