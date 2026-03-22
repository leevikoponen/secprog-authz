use std::{num::Wrapping, thread::JoinHandle};

use tokio::sync::{
    mpsc::{self, Sender},
    oneshot,
};

struct ActionCallback<T>(Box<dyn FnOnce(&mut T) + Send + 'static>);

pub struct OffThread<T>(Sender<ActionCallback<T>>);

impl<T: Send + 'static> OffThread<T> {
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
