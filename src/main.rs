use hyper::{body::Bytes, http::Response};

mod runtime;
mod server;

fn main() -> anyhow::Result<()> {
    runtime::initialize_environment(async |context, cancellation| {
        server::start_listening(context, cancellation, async move |_| {
            Response::new(Bytes::from_static(b"Hello, World!"))
        })
    })
}
