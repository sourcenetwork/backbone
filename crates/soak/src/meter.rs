//! Disk and memory meter plus the write-budget governor.
//!
//! Every write grows the Merkle DAG on every node forever, so a soak has a
//! disk ceiling. Each sample writes `du.jsonl` and `rss.jsonl`, then the
//! governor turns the remaining budget into the op rate that would exhaust
//! it exactly at the deadline, clamped to `[floor, profile rate]`, and
//! raises the hard stop at 95% of the ceiling. Amplification is measured
//! live as mesh-wide bytes grown per executed op since the first sample.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eyre::{Result, WrapErr};
use serde_json::json;

use crate::executor::now_ms;
use crate::nodes::Nodes;

/// Rate that spends `remaining_bytes` over `remaining_secs` at
/// `bytes_per_op` (mesh-wide growth per executed op), clamped to
/// `[floor, ceiling_rate]`. A non-positive or unknown `bytes_per_op` means
/// nothing measured yet: full rate.
pub fn governed_rate(
    remaining_bytes: f64,
    bytes_per_op: f64,
    remaining_secs: f64,
    floor: f64,
    ceiling_rate: f64,
) -> f64 {
    if bytes_per_op.is_nan() || bytes_per_op <= 0.0 || remaining_secs <= 0.0 {
        return ceiling_rate;
    }
    let allowed = remaining_bytes.max(0.0) / (bytes_per_op * remaining_secs);
    allowed.clamp(floor.min(ceiling_rate), ceiling_rate)
}

/// Nearest-rank percentile of an unsorted sample; `None` when empty.
pub fn percentile(values: &[u64], p: f64) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = (p * sorted.len() as f64).ceil() as usize;
    Some(sorted[rank.clamp(1, sorted.len()) - 1])
}

pub struct MeterConfig {
    pub interval: Duration,
    pub ceiling_bytes: u64,
    pub floor_rate: f64,
    pub profile_rate: f64,
    /// Wall deadline of a `--secs` run; op-count runs derive one from the
    /// remaining ops at the profile rate.
    pub deadline: Option<Instant>,
    pub ops: usize,
}

pub struct Meter {
    cfg: MeterConfig,
    du: BufWriter<File>,
    rss: BufWriter<File>,
    budget: BufWriter<File>,
    /// (total bytes, op index) at the first sample.
    baseline: Option<(u64, u64)>,
    last_sample: Option<Instant>,
    last_rate_milli: u64,
    /// Governed op rate x1000, read by the workload loop.
    rate_milli: Arc<AtomicU64>,
    /// Hard stop, read by the workload loop.
    stop: Arc<AtomicBool>,
    op_index: Arc<AtomicU64>,
}

impl Meter {
    pub fn new(
        cfg: MeterConfig,
        run_dir: &Path,
        rate_milli: Arc<AtomicU64>,
        stop: Arc<AtomicBool>,
        op_index: Arc<AtomicU64>,
    ) -> Result<Self> {
        let open = |name: &str| -> Result<BufWriter<File>> {
            let path = run_dir.join(name);
            Ok(BufWriter::new(File::create(&path).wrap_err_with(|| {
                format!("creating {}", path.display())
            })?))
        };
        Ok(Self {
            du: open("du.jsonl")?,
            rss: open("rss.jsonl")?,
            budget: open("budget.jsonl")?,
            baseline: None,
            last_sample: None,
            last_rate_milli: (cfg.profile_rate * 1000.0) as u64,
            cfg,
            rate_milli,
            stop,
            op_index,
        })
    }

    /// Sample if the interval elapsed (always on the first call).
    pub async fn maybe_sample(&mut self, nodes: &Nodes) -> Result<()> {
        if self
            .last_sample
            .is_some_and(|t| t.elapsed() < self.cfg.interval)
        {
            return Ok(());
        }
        self.sample(nodes).await
    }

    // ponytail: `du` and `ps` run synchronously on the task the workload
    // shares, stalling op dispatch for the sample's duration (ms now,
    // seconds near a 120 GiB ceiling); move to spawn_blocking when it shows.
    pub async fn sample(&mut self, nodes: &Nodes) -> Result<()> {
        self.last_sample = Some(Instant::now());
        let wall = now_ms();
        let op_index = self.op_index.load(Ordering::Relaxed);
        let mut total = 0u64;
        for i in 0..nodes.len() {
            let name = nodes.name(i);
            let bytes = du_bytes(&nodes.rootdir(i))?;
            total += bytes;
            let line =
                json!({"wall_ts_ms": wall, "op_index": op_index, "node": name, "bytes": bytes});
            serde_json::to_writer(&mut self.du, &line)?;
            self.du.write_all(b"\n")?;
            let pid = nodes.pid(i);
            let rss = nodes.rss_bytes(i).await;
            if pid.is_some() || rss.is_some() {
                let line = json!({
                    "wall_ts_ms": wall, "op_index": op_index, "node": name, "pid": pid,
                    "rss_bytes": rss,
                });
                serde_json::to_writer(&mut self.rss, &line)?;
                self.rss.write_all(b"\n")?;
            }
        }
        self.du.flush()?;
        self.rss.flush()?;

        let (base_bytes, base_op) = *self.baseline.get_or_insert((total, op_index));
        let bytes_per_op = if op_index > base_op {
            total.saturating_sub(base_bytes) as f64 / (op_index - base_op) as f64
        } else {
            0.0
        };
        let remaining_secs = match self.cfg.deadline {
            Some(d) => d.saturating_duration_since(Instant::now()).as_secs_f64(),
            None => self.cfg.ops.saturating_sub(op_index as usize) as f64 / self.cfg.profile_rate,
        };
        let remaining = self.cfg.ceiling_bytes as f64 - total as f64;
        let rate = governed_rate(
            remaining,
            bytes_per_op,
            remaining_secs,
            self.cfg.floor_rate,
            self.cfg.profile_rate,
        );
        let rate_milli = (rate * 1000.0) as u64;
        self.rate_milli.store(rate_milli, Ordering::Relaxed);
        let hard_stop = total as f64 >= 0.95 * self.cfg.ceiling_bytes as f64;
        if hard_stop && !self.stop.swap(true, Ordering::Relaxed) {
            println!(
                "budget: hard stop, {} of {} bytes used (95% ceiling)",
                total, self.cfg.ceiling_bytes
            );
        }
        if rate_milli != self.last_rate_milli {
            println!(
                "budget: {:.1}% of ceiling used, {:.0} bytes/op, rate {:.2} -> {:.2} ops/s",
                100.0 * total as f64 / self.cfg.ceiling_bytes as f64,
                bytes_per_op,
                self.last_rate_milli as f64 / 1000.0,
                rate
            );
            self.last_rate_milli = rate_milli;
        }
        let line = json!({
            "wall_ts_ms": wall, "op_index": op_index, "total_bytes": total,
            "ceiling_bytes": self.cfg.ceiling_bytes, "bytes_per_op": bytes_per_op,
            "remaining_secs": remaining_secs, "rate": rate, "hard_stop": hard_stop,
        });
        serde_json::to_writer(&mut self.budget, &line)?;
        self.budget.write_all(b"\n")?;
        self.budget.flush()?;
        Ok(())
    }
}

fn du_bytes(path: &Path) -> Result<u64> {
    let out = Command::new("du")
        .args(["-sk"])
        .arg(path)
        .output()
        .wrap_err("running du")?;
    let text = String::from_utf8_lossy(&out.stdout);
    let kb: u64 = text
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Ok(kb * 1024)
}

pub fn rss_bytes(pid: u32) -> Option<u64> {
    let out = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u64>()
        .ok()
        .map(|kb| kb * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plenty_of_budget_runs_at_profile_rate() {
        // 100 MiB left, 3 KiB per op, one hour: could do ~9 ops/s.
        assert_eq!(governed_rate(100e6, 3000.0, 3600.0, 0.5, 5.0), 5.0);
    }

    #[test]
    fn tight_budget_scales_the_rate_down() {
        // 10 MB left, 5 KB per op, 1000s: 2 ops/s spends it exactly.
        let r = governed_rate(10e6, 5000.0, 1000.0, 0.5, 5.0);
        assert!((r - 2.0).abs() < 1e-9, "{r}");
    }

    #[test]
    fn never_below_the_floor() {
        assert_eq!(governed_rate(1.0, 5000.0, 1000.0, 0.5, 5.0), 0.5);
        assert_eq!(governed_rate(0.0, 5000.0, 1000.0, 0.5, 5.0), 0.5);
    }

    #[test]
    fn unmeasured_amplification_means_full_rate() {
        assert_eq!(governed_rate(10e6, 0.0, 1000.0, 0.5, 5.0), 5.0);
        assert_eq!(governed_rate(10e6, f64::NAN, 1000.0, 0.5, 5.0), 5.0);
    }

    #[test]
    fn percentiles_nearest_rank() {
        let v = [50, 10, 40, 20, 30];
        assert_eq!(percentile(&v, 0.5), Some(30));
        assert_eq!(percentile(&v, 0.95), Some(50));
        assert_eq!(percentile(&v, 0.0), Some(10));
        assert_eq!(percentile(&[], 0.5), None);
    }
}
