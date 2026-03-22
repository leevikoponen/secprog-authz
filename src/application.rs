use std::{rc::Rc, thread::JoinHandle};

use anyhow::Result;
use argon2::Argon2;
use hyper::body::Bytes;
use tokio::{runtime::Builder, task::LocalSet};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing_subscriber::fmt::writer::{OptionalWriter, Tee};

use crate::{storage::UserRepository, token::HmacSecurity, worker::OffThread};

pub struct SharedState {
    pub page: Bytes,
    pub persistence: OffThread<UserRepository>,
    pub authentication: OffThread<Argon2<'static>>,
    pub verification: OffThread<HmacSecurity>,
}

#[must_use]
pub struct WorkerHandles {
    persistence: JoinHandle<()>,
    authentication: JoinHandle<()>,
    verification: JoinHandle<()>,
}

impl WorkerHandles {
    pub fn expect_join_success(self) {
        [self.persistence, self.authentication, self.verification]
            .into_iter()
            .try_for_each(JoinHandle::join)
            .expect("worker threads shouldn't panic unless it should propagate");
    }
}

pub fn prepare_state() -> Result<(Rc<SharedState>, WorkerHandles)> {
    let page = std::fs::read("index.html").map(Bytes::from_owner)?;
    let database = UserRepository::initialize_from_env()?;

    let persistence = OffThread::spawn_single(database, 16);
    let authentication = OffThread::spawn_many(Argon2::default(), 2, 16);
    let verification = OffThread::spawn_many(HmacSecurity::generate_random(), 4, 16);

    Ok((
        Rc::new(SharedState {
            page,
            persistence: persistence.0,
            authentication: authentication.0,
            verification: verification.0,
        }),
        WorkerHandles {
            persistence: persistence.1,
            authentication: authentication.1,
            verification: verification.1,
        },
    ))
}

pub fn initialize_runtime(
    application: impl AsyncFnOnce(TaskTracker, CancellationToken) -> Result<()>,
) -> Result<()> {
    let (handle, _thread) = tracing_appender::non_blocking(Tee::new(
        std::io::stderr(),
        std::env::var_os("LOG_DIRECTORY").map_or_else(OptionalWriter::none, |directory| {
            OptionalWriter::some(tracing_appender::rolling::daily(directory, "rolling.log"))
        }),
    ));

    tracing_subscriber::fmt()
        .with_writer(handle)
        .with_ansi(false)
        .with_target(false)
        .init();

    let runtime = Builder::new_current_thread().enable_all().build()?;
    let cancellation = CancellationToken::new();
    let context = TaskTracker::new();
    let tasks = LocalSet::new();

    tasks.spawn_local(context.track_future({
        let cancellation = cancellation.clone();
        let context = context.clone();

        async move {
            match tokio::signal::ctrl_c().await {
                Ok(()) => {
                    tracing::info!("initiating cancellation due to user interrupt");
                    cancellation.cancel();
                    context.close();
                }
                Err(error) => {
                    tracing::warn!("failed to enable graceful shutdown: {error}");
                }
            }
        }
    }));

    tasks.block_on(&runtime, application(context, cancellation))
}
