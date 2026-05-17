use std::{num::Wrapping, thread::JoinHandle};

use tokio::sync::{
    mpsc::{self, Sender},
    oneshot,
};

struct ActionCallback<T>(Box<dyn FnOnce(&mut T) + Send + 'static>);

pub struct OffThread<T>(Sender<ActionCallback<T>>);

impl<T: Send + 'static> OffThread<T> {
    /// Since I've chosen to assume that much of our server's time is going to
    /// be spent doing the relatively heavy cryptography, there's not much
    /// reason to use [`tokio`]'s much more complicated multi threaded task
    /// stealing executor.
    ///
    /// Thus we need a way to offload specific tasks to specific threads,
    /// leaving the main thread to do little beyond waiting for IO and
    /// coordinating minimal logic beyond steps.
    ///
    /// Building an abstraction around the concept of an actor that simply
    /// receives dynamic work callback tends to be the path of least resistance.
    pub fn spawn_single(mut state: T, buffer: usize) -> (Self, JoinHandle<()>) {
        let (sender, mut receiver) = mpsc::channel(buffer);
        let thread = std::thread::spawn(move || {
            while let Some(ActionCallback(action)) = receiver.blocking_recv() {
                action(&mut state);
            }
        });

        (Self(sender), thread)
    }
}

impl<T: Send + Clone + 'static> OffThread<T> {
    /// Of course even quite modest hardware setups tend to have many cores
    /// available, so some types of actors might work using multiple instances.
    ///
    /// The easiest way is to just have one thread doing something like a simple
    /// round robin dipatching loop, since a worker is probably related to
    /// similarly heavy tasks.
    ///
    /// Ideally this work shuffling thread would likely just fit on the main
    /// thread itself, but the interface would need to differ from the single
    /// threaded one so not really worth focusing on.
    pub fn spawn_many(state: T, count: usize, buffer: usize) -> (Self, JoinHandle<()>) {
        let (sender, mut receiver) = mpsc::channel(buffer);
        let thread = std::thread::spawn(move || {
            let workers = (0..count)
                .map(|_| Self::spawn_single(state.clone(), buffer))
                .collect::<Box<[_]>>();

            let mut offset = Wrapping(0usize);
            while let Some(task) = receiver.blocking_recv() {
                let (Self(sender), _) = &workers[offset.0 % workers.len()];

                sender
                    .blocking_send(task)
                    .expect("worker dispatch channels shouldn't disconnect");

                offset += 1;
            }

            for (sender, thread) in workers {
                drop(sender);

                thread
                    .join()
                    .expect("closed worker threads should finish successfully");
            }
        });

        (Self(sender), thread)
    }
}

impl<T> OffThread<T> {
    /// The given work callback can be then easily be wrapped to provide an
    /// interface more like just giving a function with associated data and
    /// having it magically be asynchronously executed on some other thread.
    pub async fn schedule_task<O: Send + 'static>(
        &self,
        action: impl FnOnce(&mut T) -> O + Send + 'static,
    ) -> O {
        let (sender, receiver) = oneshot::channel();
        let task = ActionCallback(Box::new(move |state| {
            let _ = sender.send(action(state));
        }));

        self.0
            .send(task)
            .await
            .expect("worker task channel shouldn't disconnect");

        receiver
            .await
            .expect("worker result channel shouldn't disconnect")
    }
}

impl<T> Clone for OffThread<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
