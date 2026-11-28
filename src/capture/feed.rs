use super::{Capture, Frame, Stats};
use crate::error::YeyoError;
use std::panic;
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::thread::{self, JoinHandle};

// Bounded so a slow renderer applies back-pressure instead of growing memory;
// libpcap's kernel buffer absorbs short bursts.
const QUEUE_LEN: usize = 4096;

pub struct Feed {
    frames: Receiver<Frame>,
    worker: JoinHandle<Result<Stats, YeyoError>>,
    stop: super::Stop,
}

impl Capture {
    pub fn spawn(mut self) -> Feed {
        let stop = self.stopper();
        let (sender, frames) = mpsc::sync_channel(QUEUE_LEN);
        let worker = thread::spawn(move || {
            let pumped = pump(&mut self, &sender);
            // Flush the savefile even when reading failed, then report the first error.
            let flushed = self.finish();
            pumped?;
            flushed?;
            self.stats()
        });
        Feed {
            frames,
            worker,
            stop,
        }
    }
}

impl Feed {
    pub fn recv(&self) -> Option<Frame> {
        self.frames.recv().ok()
    }

    pub fn try_recv(&self) -> Result<Frame, TryRecvError> {
        self.frames.try_recv()
    }

    pub fn finish(self) -> Result<Stats, YeyoError> {
        self.stop.stop();
        // Dropping the receiver unblocks a worker waiting on a full queue.
        drop(self.frames);
        match self.worker.join() {
            Ok(result) => result,
            Err(payload) => panic::resume_unwind(payload),
        }
    }
}

fn pump(cap: &mut Capture, sender: &SyncSender<Frame>) -> Result<(), YeyoError> {
    while let Some(frame) = cap.next_frame()? {
        // The receiver is gone: the renderer quit.
        if sender.send(frame).is_err() {
            break;
        }
    }
    Ok(())
}
