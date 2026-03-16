use anyhow::Result;
use tokio::{runtime::Builder, task::LocalSet};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing_subscriber::fmt::writer::{OptionalWriter, Tee};

pub fn initialize_environment(
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

    tasks.block_on(&runtime, async {
        application(context.clone(), cancellation).await?;

        context.wait().await;

        Ok(())
    })
}
