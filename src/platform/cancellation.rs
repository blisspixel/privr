//! Cooperative cleanup cancellation. Signal callbacks never touch journals or files.

use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Default)]
pub struct Cancellation(Arc<AtomicBool>);

impl Cancellation {
    pub fn requested(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    pub(crate) fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

static ACTIVE: Mutex<Option<Cancellation>> = Mutex::new(None);
static INSTALLED: OnceLock<Result<(), String>> = OnceLock::new();

pub(crate) struct SignalGuard;

impl SignalGuard {
    pub(crate) fn begin() -> Result<(Self, Cancellation), String> {
        INSTALLED
            .get_or_init(|| {
                ctrlc::try_set_handler(|| {
                    let active = ACTIVE.lock().expect("cleanup signal state");
                    if let Some(cancellation) = active.as_ref() {
                        cancellation.cancel();
                    } else {
                        // Once cleanup ends, do not swallow termination while an MCP
                        // server is waiting for another request.
                        std::process::exit(130);
                    }
                })
                .map_err(|_| "Cannot install cleanup interruption handler".to_owned())
            })
            .clone()?;
        let mut active = ACTIVE
            .lock()
            .map_err(|_| "Cleanup signal state unavailable")?;
        if active.is_some() {
            return Err("Another cleanup is already running".to_owned());
        }
        let cancellation = Cancellation::default();
        *active = Some(cancellation.clone());
        Ok((Self, cancellation))
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        if let Ok(mut active) = ACTIVE.lock() {
            *active = None;
        }
    }
}
