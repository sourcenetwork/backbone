//! Background log parser for validator process output.

use std::{path::PathBuf, sync::Arc, time::Duration};

use tokio::sync::broadcast;

use super::events::LogEvent;

/// Tracks log output from a validator process and emits typed events.
#[derive(Debug)]
pub struct LogTracker {
    log_path: PathBuf,
    tx: broadcast::Sender<LogEvent>,
    latest_height: Arc<std::sync::atomic::AtomicU64>,
    errors: Arc<parking_lot::Mutex<Vec<LogEvent>>>,
    _handle: Option<tokio::task::JoinHandle<()>>,
}

impl LogTracker {
    /// Create a new log tracker for the given log file.
    pub fn new(log_path: PathBuf) -> Self {
        let (tx, _) = broadcast::channel(1024);
        let latest_height = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let errors = Arc::new(parking_lot::Mutex::new(Vec::new()));

        let tracker_tx = tx.clone();
        let tracker_path = log_path.clone();
        let tracker_height = latest_height.clone();
        let tracker_errors = errors.clone();

        let handle = tokio::spawn(async move {
            Self::run_parser(tracker_path, tracker_tx, tracker_height, tracker_errors).await;
        });

        Self {
            log_path,
            tx,
            latest_height,
            errors,
            _handle: Some(handle),
        }
    }

    /// Subscribe to log events.
    pub fn subscribe(&self) -> broadcast::Receiver<LogEvent> {
        self.tx.subscribe()
    }

    /// Get the latest block height seen in logs.
    pub fn latest_height(&self) -> u64 {
        self.latest_height
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get all error events collected so far.
    pub fn errors(&self) -> Vec<LogEvent> {
        self.errors.lock().clone()
    }

    /// Wait for a log line matching the given pattern, with timeout.
    pub async fn wait_for(&self, pattern: &str, timeout: Duration) -> eyre::Result<LogEvent> {
        let re = regex::Regex::new(pattern)?;
        let mut rx = self.subscribe();
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(eyre::eyre!("timeout waiting for pattern: {}", pattern));
                }
                event = rx.recv() => {
                    if let Ok(event) = event {
                        let matches = match &event {
                            LogEvent::BlockBuilt { height, .. } => re.is_match(&format!("block built height={}", height)),
                            LogEvent::BlockVerified { height, .. } => re.is_match(&format!("block verified height={}", height)),
                            LogEvent::Error { message, .. } => re.is_match(message),
                        };
                        if matches {
                            return Ok(event);
                        }
                    }
                }
            }
        }
    }

    /// Restart the log parser (e.g. after a node respawn).
    ///
    /// Aborts the old parser task, clears collected errors, and spawns
    /// a fresh parser on the same log file. Existing broadcast subscribers
    /// seamlessly receive events from the new process output.
    pub fn restart(&mut self) {
        if let Some(handle) = self._handle.take() {
            handle.abort();
        }
        self.errors.lock().clear();

        let tracker_tx = self.tx.clone();
        let tracker_path = self.log_path.clone();
        let tracker_height = self.latest_height.clone();
        let tracker_errors = self.errors.clone();

        let handle = tokio::spawn(async move {
            Self::run_parser(tracker_path, tracker_tx, tracker_height, tracker_errors).await;
        });
        self._handle = Some(handle);
    }

    /// Get the log file path.
    pub fn log_path(&self) -> &std::path::Path {
        &self.log_path
    }
}

impl Drop for LogTracker {
    fn drop(&mut self) {
        if let Some(handle) = self._handle.take() {
            handle.abort();
        }
    }
}

impl LogTracker {
    async fn run_parser(
        log_path: PathBuf,
        tx: broadcast::Sender<LogEvent>,
        latest_height: Arc<std::sync::atomic::AtomicU64>,
        errors: Arc<parking_lot::Mutex<Vec<LogEvent>>>,
    ) {
        use tokio::io::AsyncBufReadExt;

        let ansi_re = regex::Regex::new(r"\x1b\[[0-9;]*m").expect("valid ansi regex");
        let block_built_re =
            regex::Regex::new(r"built block.*height=(\d+).*txs=(\d+).*total_ms=(\d+)")
                .expect("valid regex");
        let block_verified_re =
            regex::Regex::new(r"verified block.*height=(\d+).*txs=(\d+).*total_ms=(\d+)")
                .expect("valid regex");
        let error_re = regex::Regex::new(r"\bERROR\b(.*)").expect("valid regex");

        // Wait for the file to appear.
        loop {
            if log_path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let file = match tokio::fs::File::open(&log_path).await {
            Ok(f) => f,
            Err(_) => return,
        };
        let reader = tokio::io::BufReader::new(file);
        let mut lines = reader.lines();

        loop {
            match lines.next_line().await {
                Ok(Some(raw_line)) => {
                    let line = ansi_re.replace_all(&raw_line, "");

                    if let Some(caps) = block_built_re.captures(&line) {
                        let height: u64 = caps[1].parse().unwrap_or(0);
                        let txs: u64 = caps[2].parse().unwrap_or(0);
                        let total_ms: u64 = caps[3].parse().unwrap_or(0);
                        latest_height.fetch_max(height, std::sync::atomic::Ordering::Relaxed);
                        let _ = tx.send(LogEvent::BlockBuilt {
                            height,
                            txs,
                            total_ms,
                        });
                    } else if let Some(caps) = block_verified_re.captures(&line) {
                        let height: u64 = caps[1].parse().unwrap_or(0);
                        let txs: u64 = caps[2].parse().unwrap_or(0);
                        let total_ms: u64 = caps[3].parse().unwrap_or(0);
                        latest_height.fetch_max(height, std::sync::atomic::Ordering::Relaxed);
                        let _ = tx.send(LogEvent::BlockVerified {
                            height,
                            txs,
                            total_ms,
                        });
                    } else if let Some(caps) = error_re.captures(&line) {
                        let message = caps[1].trim().to_string();
                        let event = LogEvent::Error {
                            level: "ERROR".to_string(),
                            message,
                        };
                        errors.lock().push(event.clone());
                        let _ = tx.send(event);
                    }
                }
                Ok(None) => {
                    // EOF — file may still be written to, poll again.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(_) => break,
            }
        }
    }
}
