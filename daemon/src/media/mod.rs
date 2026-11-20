//! Media integration: PipeWire audio activity detection and MPRIS control
//!
//! [FR-016] A stream counts as active only while it is RUNNING with its peak
//! above the configured threshold across the configured window. Capture-side
//! and communication-class streams are excluded.
//!
//! [FR-018] Every probe is timeout-bounded. A failed or missing probe holds
//! the last known activity state and logs one persistent warning instead of
//! fabricating a stop/start edge pair. The monitor runs under a supervisor so
//! a task death is visible and the monitor restarts.

use std::collections::{HashMap, HashSet};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Duration bound on one probe subprocess. [FR-018]
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Poll period. Two samples fit inside the default 200 ms window, and a state
/// change settles well inside NFR-001's one-second bound. [NFR-001]
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Delay before the supervisor restarts a monitor task that died. [FR-018]
const SUPERVISOR_RESTART_DELAY: Duration = Duration::from_secs(1);

/// Upper bound on simultaneous stream taps.
///
/// Each tap is one `parec` subprocess, so the bound keeps a stream flood from
/// exhausting subprocesses. Existing taps and the first RUNNING candidates are
/// preferred when the bound is reached. [FR-016]
const MAX_TAPS: usize = 4;

/// Largest block read from one tap per poll. A 48 kHz stereo s16 stream
/// produces about 19 KB per 100 ms poll, so this drains the pipe with headroom.
const TAP_READ_BYTES: usize = 32 * 1024;

/// Duration bound on one tap read. [FR-018]
const TAP_READ_TIMEOUT: Duration = Duration::from_millis(20);

/// Sample rate the tap requests from `parec`. [FR-016]
const TAP_SAMPLE_RATE: u32 = 48_000;

/// Channel count the tap requests from `parec`. [FR-016]
const TAP_CHANNELS: u32 = 2;

/// Media state event
#[allow(dead_code)] // Fields describe the source in logs.
#[derive(Debug, Clone)]
pub enum MediaEvent {
    /// Local audio activity started
    AudioStarted { stream_name: String },
    /// Local audio activity stopped
    AudioStopped { stream_name: String },
    /// MPRIS player state changed. MPRIS is a secondary signal and never
    /// triggers a handoff on its own. [FR-016]
    PlayerStateChanged { player_name: String, playing: bool },
}

/// Runtime knobs for the activity monitor, read from config.toml. [FR-016]
#[derive(Debug, Clone, Copy)]
pub struct MediaSettings {
    /// Minimum peak in dBFS for a stream to count as active.
    pub threshold_dbfs: f32,
    /// Time the peak must stay above the threshold.
    pub window: Duration,
    /// Bound on one probe. [FR-018]
    pub probe_timeout: Duration,
}

impl Default for MediaSettings {
    fn default() -> Self {
        Self {
            threshold_dbfs: -60.0,
            window: Duration::from_millis(200),
            probe_timeout: PROBE_TIMEOUT,
        }
    }
}

/// One PipeWire playback stream as reported by `pactl list sink-inputs`.
#[derive(Debug, Clone, PartialEq)]
pub struct StreamSample {
    /// Sink-input index, the handle the peak tap records. [FR-016]
    pub index: u32,
    pub state_running: bool,
    pub corked: bool,
    pub muted: bool,
    /// Largest channel gain as a linear factor; 1.0 is unity (0 dBFS).
    /// Diagnostic only: activity is decided by the measured peak.
    pub volume: f32,
    pub media_class: String,
    pub media_role: String,
}

impl Default for StreamSample {
    fn default() -> Self {
        Self {
            index: 0,
            state_running: false,
            corked: false,
            muted: false,
            volume: 1.0,
            media_class: String::new(),
            media_role: String::new(),
        }
    }
}

impl StreamSample {
    /// Linear gain expressed in dBFS. Unity gain is 0 dBFS.
    pub fn gain_dbfs(&self) -> f32 {
        if self.volume <= 0.0 {
            f32::NEG_INFINITY
        } else {
            20.0 * self.volume.log10()
        }
    }

    /// True when this sample is a playback stream that may count as media.
    ///
    /// Capture-side sources and communication-class roles are never media
    /// activity. [FR-016]
    pub fn is_media_stream(&self) -> bool {
        let class = self.media_class.to_ascii_lowercase();
        let capture = class.contains("/input")
            || class.contains("capture")
            || class.contains("source");
        let role = self.media_role.to_ascii_lowercase();
        let communication = role.contains("communication")
            || role.contains("phone")
            || role.contains("voice");
        !capture && !communication
    }

    /// Cheap prefilter that decides which streams get a peak tap.
    ///
    /// This never decides activity on its own; the verdict comes from the peak
    /// the tap measures. Capture-side sources and communication-class roles
    /// are never media activity. [FR-016]
    pub fn is_tap_candidate(&self) -> bool {
        self.state_running && !self.corked && !self.muted && self.is_media_stream()
    }

    /// True when a tapped stream's true peak is at or above the threshold.
    ///
    /// [FR-016] The session gain is not a dBFS ceiling: a digitally-silent
    /// stream at unity gain stays inactive, and a stream whose peak clears the
    /// threshold is active regardless of its gain.
    pub fn is_active_with_peak(&self, peak_dbfs: f32, threshold_dbfs: f32) -> bool {
        self.is_tap_candidate() && peak_dbfs >= threshold_dbfs
    }
}

/// Tracks how long the peak has stayed above the threshold. [FR-016]
#[derive(Debug, Default)]
struct ActivityWindow {
    above_since: Option<Instant>,
}

impl ActivityWindow {
    /// Returns true once the active condition has held for at least `window`.
    fn update(&mut self, above_threshold: bool, now: Instant, window: Duration) -> bool {
        if !above_threshold {
            self.above_since = None;
            return false;
        }
        let since = *self.above_since.get_or_insert(now);
        now.duration_since(since) >= window
    }
}

/// Environment override for the activity probe command.
///
/// [NFR-001] A test harness points this at a script that emits synthetic
/// `pactl list sink-inputs` text, so the timed one-second settling check can
/// drive the monitor without a real audio graph.
const PROBE_COMMAND_ENV: &str = "SEUIL_MEDIA_PROBE";

/// Environment override for the stream tap command.
///
/// [NFR-001] When set, the monitor spawns this script instead of `parec` and
/// passes the stream index as its argument. The script must keep writing raw
/// little-endian s16 samples to stdout while the stream is tapped, so the same
/// monitor logic runs for silent-tab, game-audio, and communication-class
/// scenarios without a real audio graph.
const TAP_COMMAND_ENV: &str = "SEUIL_MEDIA_TAP";

/// Why the activity probe produced no result. [FR-018]
#[derive(Debug)]
enum ProbeFailure {
    MissingTool(&'static str),
    TimedOut(Duration),
    Failed(String),
}

impl std::fmt::Display for ProbeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingTool(tool) => write!(f, "{tool} is not installed"),
            Self::TimedOut(limit) => write!(f, "the activity probe did not answer within {limit:?}"),
            Self::Failed(message) => write!(f, "{message}"),
        }
    }
}

/// Starts the supervised media monitor.
///
/// [FR-018] The inner monitor task runs under this supervisor. A death is
/// logged at error level and the monitor restarts after a short delay; the
/// last activity edge is not replayed on restart.
pub fn monitor_pipewire(tx: mpsc::Sender<MediaEvent>, settings: MediaSettings) {
    tokio::spawn(async move {
        // [FR-018] The last activity verdict survives a monitor restart so a
        // death cannot fabricate a duplicate start or stop edge.
        let last_active = Arc::new(AtomicBool::new(false));
        loop {
            let handle = tokio::spawn(run_monitor(
                tx.clone(),
                settings,
                last_active.clone(),
            ));
            match handle.await {
                Ok(true) => break,
                Ok(false) => warn!("The media monitor stopped; restarting it"),
                Err(error) if error.is_panic() => {
                    error!("The media monitor panicked; restarting it")
                }
                Err(error) => {
                    error!("The media monitor task failed ({error}); restarting it")
                }
            }
            if tx.is_closed() {
                break;
            }
            tokio::time::sleep(SUPERVISOR_RESTART_DELAY).await;
        }
        debug!("Media monitor supervisor stopped");
    });
}

/// One monitor run. Returns true when the event receiver closed.
async fn run_monitor(
    tx: mpsc::Sender<MediaEvent>,
    settings: MediaSettings,
    last_active: Arc<AtomicBool>,
) -> bool {
    info!(
        threshold_dbfs = settings.threshold_dbfs,
        window_ms = settings.window.as_millis(),
        "Starting the PipeWire activity monitor"
    );

    let mut window = ActivityWindow::default();
    let mut taps = TapPool::new();
    let mut probe_healthy = true;

    loop {
        let sampled_at = Instant::now();
        match evaluate_activity(&mut taps, &settings).await {
            Ok(above) => {
                if !probe_healthy {
                    info!("The PipeWire activity probe recovered");
                    probe_healthy = true;
                }
                let active = window.update(above, sampled_at, settings.window);
                if active != last_active.load(Ordering::Relaxed) {
                    last_active.store(active, Ordering::Relaxed);
                    let event = if active {
                        MediaEvent::AudioStarted {
                            stream_name: "pipewire".into(),
                        }
                    } else {
                        MediaEvent::AudioStopped {
                            stream_name: "pipewire".into(),
                        }
                    };
                    if tx.send(event).await.is_err() {
                        return true;
                    }
                }
            }
            Err(failure) => {
                // [FR-018] Hold the last known state. The window is frozen, not
                // reset, so a recovered probe cannot turn one continuous state
                // into a stop/start edge pair.
                if probe_healthy {
                    probe_healthy = false;
                    warn!(
                        reason = %failure,
                        "The PipeWire activity probe failed; holding the last known state"
                    );
                }
            }
        }

        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Lists the streams, then measures the true peak of each tapped stream.
///
/// [FR-016] The activity verdict is peak-based: a stream counts only when its
/// measured peak stays above the threshold across the window.
async fn evaluate_activity(
    taps: &mut TapPool,
    settings: &MediaSettings,
) -> std::result::Result<bool, ProbeFailure> {
    let streams = probe_sink_inputs(settings.probe_timeout).await?;
    taps.is_active(&streams, settings).await
}

/// Runs the activity probe with a timeout. [FR-018]
async fn probe_sink_inputs(
    timeout: Duration,
) -> std::result::Result<Vec<StreamSample>, ProbeFailure> {
    let mut command = match std::env::var(PROBE_COMMAND_ENV) {
        Ok(path) if !path.trim().is_empty() => {
            let mut command = tokio::process::Command::new(path);
            command.arg("sink-inputs");
            command
        }
        _ => {
            let mut command = tokio::process::Command::new("pactl");
            command.args(["list", "sink-inputs"]);
            command
        }
    };
    let output = tokio::time::timeout(timeout, command.output())
        .await
        .map_err(|_| ProbeFailure::TimedOut(timeout))?
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => ProbeFailure::MissingTool("pactl"),
            _ => ProbeFailure::Failed(error.to_string()),
        })?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    let lowered = stderr.to_ascii_lowercase();
    // PipeWire can be down while pactl still exits zero; treat a connection
    // failure as an unhealthy probe rather than an empty stream list.
    if !output.status.success()
        || lowered.contains("connection failure")
        || lowered.contains("failed to connect")
    {
        let reason = if stderr.trim().is_empty() {
            format!("pactl exited with {}", output.status)
        } else {
            stderr.trim().to_string()
        };
        return Err(ProbeFailure::Failed(reason));
    }

    Ok(parse_sink_inputs(&String::from_utf8_lossy(&output.stdout)))
}

/// Parses the text form of `pactl list sink-inputs`.
fn parse_sink_inputs(text: &str) -> Vec<StreamSample> {
    let mut samples = Vec::new();
    let mut current: Option<StreamSample> = None;

    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("Sink Input #") {
            if let Some(sample) = current.take() {
                samples.push(sample);
            }
            current = Some(StreamSample {
                index: value.trim().parse().unwrap_or(0),
                ..StreamSample::default()
            });
            continue;
        }
        let Some(sample) = current.as_mut() else {
            continue;
        };

        if let Some(value) = trimmed.strip_prefix("State:") {
            sample.state_running = value.trim().eq_ignore_ascii_case("RUNNING");
        } else if let Some(value) = trimmed.strip_prefix("Corked:") {
            sample.corked = value.trim().eq_ignore_ascii_case("yes");
        } else if let Some(value) = trimmed.strip_prefix("Mute:") {
            sample.muted = value.trim().eq_ignore_ascii_case("yes");
        } else if let Some(value) = trimmed.strip_prefix("Volume:") {
            if let Some(volume) = parse_volume(value) {
                sample.volume = volume;
            }
        } else if let Some(value) = trimmed.strip_prefix("media.class =") {
            sample.media_class = unquote(value);
        } else if let Some(value) = trimmed.strip_prefix("media.role =") {
            sample.media_role = unquote(value);
        }
    }

    if let Some(sample) = current {
        samples.push(sample);
    }
    samples
}

/// Reads the largest channel percentage from a `Volume:` line as a factor.
fn parse_volume(value: &str) -> Option<f32> {
    let mut loudest: Option<f32> = None;
    for token in value.split_whitespace() {
        if let Some(percent) = token.strip_suffix('%')
            && let Ok(percent) = percent.parse::<f32>()
        {
            let gain = percent / 100.0;
            loudest = Some(loudest.map_or(gain, |current| current.max(gain)));
        }
    }
    loudest
}

/// Strips the surrounding quotes from a pactl property value.
fn unquote(value: &str) -> String {
    value.trim().trim_matches('"').to_string()
}

/// Owns the live peak taps and reconciles them with the stream listing.
///
/// [FR-016] One tap records one playback stream. Taps open for the first
/// RUNNING candidates up to [`MAX_TAPS`], survive across polls, and close when
/// their stream leaves the listing or stops being a candidate.
struct TapPool {
    taps: HashMap<u32, StreamTap>,
    cap_logged: bool,
}

impl TapPool {
    fn new() -> Self {
        Self {
            taps: HashMap::new(),
            cap_logged: false,
        }
    }

    /// Reconciles taps with the listing and returns whether any tapped stream
    /// is currently above the configured peak threshold. [FR-016]
    async fn is_active(
        &mut self,
        streams: &[StreamSample],
        settings: &MediaSettings,
    ) -> std::result::Result<bool, ProbeFailure> {
        let candidates: Vec<&StreamSample> = streams
            .iter()
            .filter(|stream| stream.is_tap_candidate())
            .collect();
        let candidate_indices: HashSet<u32> =
            candidates.iter().map(|stream| stream.index).collect();

        // Existing taps stay while their stream is still a candidate; the rest
        // are killed and dropped so no subprocess outlives its stream.
        self.taps.retain(|index, tap| {
            if candidate_indices.contains(index) {
                true
            } else {
                tap.close();
                false
            }
        });

        // Fill the remaining slots in listing order, so already-tapped streams
        // and the first RUNNING candidates win under a flood.
        for stream in &candidates {
            if self.taps.len() >= MAX_TAPS {
                break;
            }
            if let std::collections::hash_map::Entry::Vacant(entry) = self.taps.entry(stream.index)
            {
                entry.insert(StreamTap::spawn(stream)?);
            }
        }

        let capped = candidates.len() > self.taps.len();
        if capped {
            if !self.cap_logged {
                debug!(
                    max_taps = MAX_TAPS,
                    candidates = candidates.len(),
                    "Tap limit reached; extra playback streams are not measured"
                );
                self.cap_logged = true;
            }
        } else {
            self.cap_logged = false;
        }

        let indices: Vec<u32> = self.taps.keys().copied().collect();
        let mut above = false;
        for index in indices {
            let peak = match self.taps.get_mut(&index) {
                Some(tap) => tap.sample_peak_dbfs().await,
                None => continue,
            };
            match peak {
                Ok(peak) => {
                    if let Some(stream) = streams.iter().find(|stream| stream.index == index) {
                        above |= stream.is_active_with_peak(peak, settings.threshold_dbfs);
                    }
                }
                Err(failure) => {
                    // [FR-018] A failing tap holds the last known state. Drop it
                    // so the next tick can respawn it and recover.
                    if let Some(mut tap) = self.taps.remove(&index) {
                        tap.close();
                    }
                    return Err(failure);
                }
            }
        }
        Ok(above)
    }
}

/// One live `parec` tap over a playback stream.
struct StreamTap {
    index: u32,
    child: tokio::process::Child,
    stdout: Option<tokio::process::ChildStdout>,
    read_buf: Vec<u8>,
    /// Bytes that did not complete an s16 sample on the previous read.
    pending: Vec<u8>,
}

impl StreamTap {
    /// Spawns a tap for `stream` and starts reading its raw samples. [FR-016]
    fn spawn(stream: &StreamSample) -> std::result::Result<Self, ProbeFailure> {
        let (mut command, tool) = tap_command(stream.index);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => ProbeFailure::MissingTool(tool),
            _ => ProbeFailure::Failed(error.to_string()),
        })?;
        let stdout = child.stdout.take();
        debug!(
            stream_index = stream.index,
            gain_dbfs = stream.gain_dbfs(),
            "Opened a stream tap"
        );
        Ok(Self {
            index: stream.index,
            child,
            stdout,
            read_buf: vec![0u8; TAP_READ_BYTES],
            pending: Vec::new(),
        })
    }

    /// Reads the samples that arrived since the last poll and returns their
    /// peak in dBFS. [FR-016]
    async fn sample_peak_dbfs(&mut self) -> std::result::Result<f32, ProbeFailure> {
        let Some(stdout) = self.stdout.as_mut() else {
            return Err(ProbeFailure::Failed(
                "the stream tap has no output pipe".into(),
            ));
        };
        let read =
            match tokio::time::timeout(TAP_READ_TIMEOUT, stdout.read(&mut self.read_buf)).await {
                Ok(Ok(0)) => {
                    return Err(ProbeFailure::Failed(format!(
                        "the stream tap for #{} closed its output",
                        self.index
                    )));
                }
                Ok(Ok(read)) => read,
                Ok(Err(error)) => return Err(ProbeFailure::Failed(error.to_string())),
                // No samples within the budget is silence, not a failure.
                Err(_) => 0,
            };
        self.pending.extend_from_slice(&self.read_buf[..read]);
        let complete = self.pending.len() - self.pending.len() % 2;
        let peak = peak_dbfs(&self.pending[..complete]);
        self.pending.drain(..complete);
        Ok(peak)
    }

    /// Stops the tap. `kill_on_drop` covers the drop path; this closes early.
    fn close(&mut self) {
        self.stdout.take();
        if let Err(error) = self.child.start_kill() {
            debug!(
                stream_index = self.index,
                %error,
                "Could not stop the stream tap"
            );
        }
    }
}

/// Builds the tap command for one stream index and names the tool for errors.
///
/// `SEUIL_MEDIA_TAP` replaces `parec` for the test harness. [NFR-001]
fn tap_command(index: u32) -> (tokio::process::Command, &'static str) {
    match std::env::var(TAP_COMMAND_ENV) {
        Ok(path) if !path.trim().is_empty() => {
            let mut command = tokio::process::Command::new(path);
            command.arg(index.to_string());
            (command, "the stream tap command")
        }
        _ => {
            let mut command = tokio::process::Command::new("parec");
            command.args([
                format!("--monitor-stream={index}"),
                "--raw".to_string(),
                "--format=s16le".to_string(),
                format!("--rate={TAP_SAMPLE_RATE}"),
                format!("--channels={TAP_CHANNELS}"),
            ]);
            (command, "parec")
        }
    }
}

/// Peak amplitude of little-endian signed 16-bit samples as dBFS.
///
/// Full scale is 0 dBFS and digital silence is `-inf` dBFS. [FR-016]
fn peak_dbfs(samples_le: &[u8]) -> f32 {
    let peak = samples_le
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u32::from(i16::from_le_bytes(*pair).unsigned_abs()))
        .max()
        .unwrap_or(0);
    if peak == 0 {
        f32::NEG_INFINITY
    } else {
        20.0 * (peak as f32 / 32768.0).log10()
    }
}

/// Control MPRIS media players
pub struct MprisController;

/// Result of a pause request across every MPRIS player. [FR-019]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PauseOutcome {
    pub attempted: usize,
    pub failed: usize,
}

impl PauseOutcome {
    /// True when every player that was asked to pause accepted it.
    pub fn succeeded(&self) -> bool {
        self.failed == 0
    }
}

impl MprisController {
    /// Pause all active MPRIS players.
    ///
    /// [FR-019] The caller gets a per-player failure count so a release reply
    /// can report a pause that did not take effect instead of claiming success.
    pub async fn pause_all() -> Result<PauseOutcome> {
        info!("Pausing all MPRIS players");

        let players = mpris::PlayerFinder::new()
            .map_err(|e| anyhow::anyhow!("Failed to find MPRIS players: {}", e))?;

        let all_players = players
            .find_all()
            .map_err(|e| anyhow::anyhow!("Failed to enumerate MPRIS players: {}", e))?;

        let mut outcome = PauseOutcome {
            attempted: all_players.len(),
            failed: 0,
        };
        for player in &all_players {
            match player.pause() {
                Ok(()) => debug!("Paused MPRIS player: {}", player.identity()),
                Err(e) => {
                    outcome.failed += 1;
                    warn!("Failed to pause {}: {}", player.identity(), e);
                }
            }
        }

        if outcome.failed > 0 {
            warn!(
                attempted = outcome.attempted,
                failed = outcome.failed,
                "Some MPRIS players did not pause"
            );
        }
        Ok(outcome)
    }

    /// Resume all paused MPRIS players
    #[allow(dead_code)] // Symmetric helper for future resume-on-return flows.
    pub async fn resume_all() -> Result<()> {
        info!("Resuming all MPRIS players");

        let players = mpris::PlayerFinder::new()
            .map_err(|e| anyhow::anyhow!("Failed to find MPRIS players: {}", e))?;

        let all_players = players
            .find_all()
            .map_err(|e| anyhow::anyhow!("Failed to enumerate MPRIS players: {}", e))?;

        for player in &all_players {
            match player.play() {
                Ok(()) => debug!("Resumed MPRIS player: {}", player.identity()),
                Err(e) => warn!("Failed to resume {}: {}", player.identity(), e),
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(state_running: bool, muted: bool, volume: f32) -> StreamSample {
        StreamSample {
            index: 1,
            state_running,
            muted,
            volume,
            media_class: "Stream/Output/Audio".into(),
            media_role: "Music".into(),
            ..StreamSample::default()
        }
    }

    #[test]
    fn muted_stream_is_not_active() {
        let muted = sample(true, true, 1.0);
        assert!(!muted.is_tap_candidate());
        assert!(!muted.is_active_with_peak(0.0, -60.0));
    }

    #[test]
    fn silent_peak_is_not_active() {
        // [FR-016] Unity session gain does not make a digitally-silent stream
        // active; the measured peak decides.
        let stream = sample(true, false, 1.0);
        assert!(stream.is_tap_candidate());
        assert!(!stream.is_active_with_peak(f32::NEG_INFINITY, -60.0));
        assert!(!stream.is_active_with_peak(-61.0, -60.0));
        assert!(stream.is_active_with_peak(-60.0, -60.0));
        assert!(stream.is_active_with_peak(-6.0, -60.0));
    }

    #[test]
    fn tap_candidates_require_a_playable_stream() {
        // [FR-016] The cheap gates decide which streams get a tap, not activity.
        let running = sample(true, false, 1.0);
        assert!(running.is_tap_candidate());
        let corked = StreamSample {
            corked: true,
            ..running.clone()
        };
        let paused = StreamSample {
            state_running: false,
            ..running.clone()
        };
        assert!(!corked.is_tap_candidate());
        assert!(!paused.is_tap_candidate());
    }

    #[test]
    fn peak_is_measured_from_raw_s16le_samples() {
        // [FR-016] Digital silence, full scale, and half scale in dBFS.
        assert_eq!(peak_dbfs(&[0, 0, 0, 0]), f32::NEG_INFINITY);
        // 0x7fff is full scale and -32768 is also full scale.
        assert!(peak_dbfs(&[0xff, 0x7f]).abs() < 0.001);
        assert!(peak_dbfs(&[0x00, 0x80, 0x00, 0x00]).abs() < 0.001);
        // 0x4000 is half scale, about -6.02 dBFS.
        assert!((peak_dbfs(&[0x00, 0x40]) + 6.02).abs() < 0.05);
    }

    #[test]
    fn capture_and_communication_streams_are_excluded() {
        let capture = StreamSample {
            media_class: "Stream/Input/Audio".into(),
            ..sample(true, false, 1.0)
        };
        let communication = StreamSample {
            media_role: "Communication".into(),
            ..sample(true, false, 1.0)
        };
        assert!(!capture.is_media_stream());
        assert!(!communication.is_media_stream());
        assert!(sample(true, false, 1.0).is_media_stream());
    }

    #[test]
    fn activity_needs_the_whole_window() {
        let start = Instant::now();
        let window = Duration::from_millis(200);
        let mut activity = ActivityWindow::default();
        assert!(!activity.update(true, start, window));
        assert!(!activity.update(true, start + Duration::from_millis(100), window));
        assert!(activity.update(true, start + window, window));
    }

    #[test]
    fn a_dip_resets_the_activity_window() {
        let start = Instant::now();
        let window = Duration::from_millis(200);
        let mut activity = ActivityWindow::default();
        assert!(!activity.update(true, start, window));
        assert!(!activity.update(false, start + Duration::from_millis(100), window));
        assert!(!activity.update(true, start + Duration::from_millis(150), window));
    }

    #[test]
    fn parses_sink_inputs_with_class_and_role() {
        let text = "\
Sink Input #12
\tState: RUNNING
\tCorked: no
\tMute: no
\tVolume: front-left: 65536 / 100% / 0.00 dB,   front-right: 32768 / 50% / -6.02 dB
\tProperties:
\t\tmedia.class = \"Stream/Output/Audio\"
\t\tmedia.role = \"Game\"
";
        let samples = parse_sink_inputs(text);
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].index, 12);
        assert!(samples[0].state_running);
        assert!(!samples[0].muted);
        assert!((samples[0].volume - 1.0).abs() < f32::EPSILON);
        assert_eq!(samples[0].media_class, "Stream/Output/Audio");
        assert_eq!(samples[0].media_role, "Game");
    }
}
