use std::{convert::Infallible, io::ErrorKind, net::Ipv6Addr};

use anyhow::Result;
use http_body_util::Full;
use hyper::{
    body::{Bytes, Incoming},
    http::{Request, Response},
    server::conn::http1::Builder,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpSocket};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::Instrument as _;

async fn accept_connections(
    context: TaskTracker,
    cancellation: CancellationToken,
    listener: TcpListener,
    handler: impl AsyncFn(Request<Incoming>) -> Response<Bytes> + Clone + 'static,
) {
    loop {
        let (stream, address) = match cancellation.run_until_cancelled(listener.accept()).await {
            Some(Ok(output)) => output,
            Some(Err(error)) => {
                tracing::error!("failed to accept connection: {error}");

                if error.kind() == ErrorKind::ConnectionAborted {
                    continue;
                }

                tracing::info!("stopping due to fatal error");
                return;
            }
            None => {
                tracing::info!("stopping due to cancellation");
                return;
            }
        };

        let cancellation = cancellation.clone();
        let handler = handler.clone();
        let future = async move {
            let mut connection =
                std::pin::pin!(Builder::new().timer(TokioTimer::new()).serve_connection(
                    TokioIo::new(stream),
                    hyper::service::service_fn(async |request| Ok::<_, Infallible>(
                        handler(request).await.map(Full::new)
                    )),
                ));

            let result =
                if let Some(result) = cancellation.run_until_cancelled(connection.as_mut()).await {
                    result
                } else {
                    tracing::info!("shutting down due to cancellation");

                    connection.as_mut().graceful_shutdown();
                    connection.await
                };

            if let Err(error) = result {
                if error.is_user() {
                    tracing::error!("service error: {error}");
                } else {
                    tracing::warn!("connection error: {error}");
                }
            }
        };

        context.spawn_local(future.instrument(tracing::info_span!("client", ?address)));
    }
}

pub fn start_listening(
    context: TaskTracker,
    cancellation: CancellationToken,
    handler: impl AsyncFn(Request<Incoming>) -> Response<Bytes> + Clone + 'static,
) -> Result<()> {
    let span = tracing::info_span!("server", address = tracing::field::Empty).entered();
    let listener = {
        let socket = TcpSocket::new_v6()?;
        socket.set_reuseaddr(true)?;
        socket.set_reuseport(true)?;
        socket.bind((Ipv6Addr::UNSPECIFIED, 8080).into())?;
        socket.listen(4096)?
    };

    match listener.local_addr() {
        Ok(address) => tracing::record_all!(span, ?address),
        Err(error) => tracing::warn!("failed to resolve address: {error}"),
    }

    context.clone().spawn_local(
        accept_connections(context, cancellation, listener, handler).in_current_span(),
    );

    tracing::info!("accepting requests");

    Ok(())
}
