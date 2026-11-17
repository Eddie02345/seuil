//! Media integration: PipeWire audio stream detection and MPRIS control

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Media state event
#[allow(dead_code)] // Fields describe the source in logs.
#[derive(Debug, Clone)]
pub enum MediaEvent {
    /// Local audio stream started
    AudioStarted { stream_name: String },
    /// Local audio stream stopped/paused
    AudioStopped { stream_name: String },
    /// MPRIS player state changed
    PlayerStateChanged { player_name: String, playing: bool },
}

/// Monitor local playback through PipeWire stream state and MPRIS status.
///
/// Browsers keep a sink-input open (and in Chromium/Electron, `Corked: no`)
/// while a tab is paused. The monitor therefore combines MPRIS (`playerctl`)
/// with `pactl list sink-inputs`: MPRIS players (and browsers whose playback is
/// governed by MPRIS) trigger playback when `playerctl` reports `Playing`,
/// while non-MPRIS apps (games, voice calls, CLI audio) trigger playback via
/// `Corked: no` / `State: RUNNING` in `pactl`.
///
/// Instead of spawning subprocesses every 750ms while idle, we listen to
/// `playerctl -a --follow status` and `pactl subscribe` events (with a 100ms
/// debounce and a 10s safety fallback tick).
pub async fn monitor_pipewire(tx: mpsc::Sender<MediaEvent>) -> Result<()> {
    info!("Starting PipeWire audio stream monitor");

    let (wake_tx, mut wake_rx) = mpsc::channel::<()>(16);
    spawn_playerctl_watcher(wake_tx.clone());
    spawn_pactl_watcher(wake_tx);

    tokio::spawn(async move {
        let mut last_playing = false;

        loop {
            let mpris = check_mpris_state().await;
            let pipewire_playing =
                check_audio_playing(&mpris.inactive_players, mpris.available).await;
            let playing = mpris.any_playing || pipewire_playing;

            if playing != last_playing {
                last_playing = playing;
                let source = if mpris.any_playing {
                    "mpris"
                } else {
                    "pipewire"
                };
                let event = if playing {
                    MediaEvent::AudioStarted {
                        stream_name: source.to_string(),
                    }
                } else {
                    MediaEvent::AudioStopped {
                        stream_name: source.to_string(),
                    }
                };

                if tx.send(event).await.is_err() {
                    warn!("Media event receiver dropped");
                    break;
                }
            }

            // Wait for an MPRIS or PipeWire sink-input event, or re-verify on a
            // 10s safety interval if no events arrive.
            let _ = tokio::time::timeout(
                tokio::time::Duration::from_secs(10),
                wake_rx.recv(),
            )
            .await;

            // Coalesce bursts of sink-input/MPRIS events within a 100ms window.
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            while wake_rx.try_recv().is_ok() {}
        }
    });

    Ok(())
}

fn spawn_playerctl_watcher(wake_tx: mpsc::Sender<()>) {
    use tokio::io::{AsyncBufReadExt, BufReader};

    tokio::spawn(async move {
        loop {
            let child = tokio::process::Command::new("playerctl")
                .args(["-a", "--follow", "status"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn();

            match child {
                Ok(mut child) => {
                    if let Some(stdout) = child.stdout.take() {
                        let mut lines = BufReader::new(stdout).lines();
                        while let Ok(Some(_)) = lines.next_line().await {
                            let _ = wake_tx.try_send(());
                        }
                    }
                    let _ = child.wait().await;
                }
                Err(e) => {
                    debug!("Could not spawn playerctl --follow: {e}");
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    });
}

fn spawn_pactl_watcher(wake_tx: mpsc::Sender<()>) {
    use tokio::io::{AsyncBufReadExt, BufReader};

    tokio::spawn(async move {
        loop {
            let child = tokio::process::Command::new("pactl")
                .arg("subscribe")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn();

            match child {
                Ok(mut child) => {
                    if let Some(stdout) = child.stdout.take() {
                        let mut lines = BufReader::new(stdout).lines();
                        while let Ok(Some(line)) = lines.next_line().await {
                            if line.contains("sink-input") {
                                let _ = wake_tx.try_send(());
                            }
                        }
                    }
                    let _ = child.wait().await;
                }
                Err(e) => {
                    debug!("Could not spawn pactl subscribe: {e}");
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    });
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct MprisSnapshot {
    pub available: bool,
    pub any_playing: bool,
    pub inactive_players: Vec<String>,
}

/// Known browser/MPRIS-managed binaries and app names that keep PipeWire streams
/// uncorked (`Corked: no`) while paused or idle; their playback is tracked by MPRIS.
const MPRIS_MANAGED_APPS: &[&str] = &[
    "chromium",
    "chrome",
    "google-chrome",
    "brave",
    "vivaldi",
    "opera",
    "microsoft-edge",
    "firefox",
    "librewolf",
    "waterfox",
    "zen",
    "floorp",
    "youtube-music",
    "spotify",
];

/// True when at least one PipeWire/PulseAudio sink-input is actively playing and unmuted.
async fn check_audio_playing(inactive_mpris_players: &[String], mpris_available: bool) -> bool {
    let output = tokio::process::Command::new("pactl")
        .args(["list", "sink-inputs"])
        .output()
        .await;

    match output {
        Ok(out) => parse_pactl_sink_inputs_playing(
            &String::from_utf8_lossy(&out.stdout),
            inactive_mpris_players,
            mpris_available,
        ),
        Err(_) => false,
    }
}

pub(crate) fn parse_pactl_sink_inputs_playing(
    stdout: &str,
    inactive_mpris_players: &[String],
    mpris_available: bool,
) -> bool {
    stdout.split("Sink Input #").skip(1).any(|block| {
        let muted = block.lines().any(|line| line.trim() == "Mute: yes");
        if muted {
            return false;
        }
        if block.lines().any(|line| line.trim() == "State: RUNNING") {
            return true;
        }
        if !mpris_available {
            return false;
        }
        let uncorked = block.lines().any(|line| line.trim() == "Corked: no");
        uncorked && !block_is_mpris_managed_or_inactive(block, inactive_mpris_players)
    })
}

fn matches_app_name(value: &str, candidate: &str) -> bool {
    if value == candidate {
        return true;
    }
    if candidate.chars().all(|c| c.is_ascii_alphanumeric()) {
        value
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|token| token == candidate)
    } else {
        value.contains(candidate)
    }
}

fn block_is_mpris_managed_or_inactive(block: &str, inactive_mpris_players: &[String]) -> bool {
    for line in block.lines() {
        let trimmed = line.trim();
        for key in [
            "application.name =",
            "node.name =",
            "application.process.binary =",
            "application.icon_name =",
        ] {
            if let Some(rest) = trimmed.strip_prefix(key) {
                let value = rest.trim().trim_matches('"').to_ascii_lowercase();
                if value.is_empty() {
                    continue;
                }
                if MPRIS_MANAGED_APPS
                    .iter()
                    .any(|app| matches_app_name(&value, app))
                {
                    return true;
                }
                if inactive_mpris_players.iter().any(|player| {
                    matches_app_name(&value, player)
                        || (player.len() >= 3 && matches_app_name(player, &value))
                }) {
                    return true;
                }
            }
        }
    }
    false
}

/// Queries all MPRIS players (`playerctl -a --format '{{playerName}}|{{status}}' status`).
async fn check_mpris_state() -> MprisSnapshot {
    let output = tokio::process::Command::new("playerctl")
        .args(["-a", "--format", "{{playerName}}|{{status}}", "status"])
        .output()
        .await;

    match output {
        Ok(out) => {
            if out.status.success() {
                parse_playerctl_status(&String::from_utf8_lossy(&out.stdout))
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                if stderr.contains("No players found") {
                    MprisSnapshot {
                        available: true,
                        ..Default::default()
                    }
                } else {
                    MprisSnapshot::default()
                }
            }
        }
        Err(_) => MprisSnapshot::default(),
    }
}

pub(crate) fn parse_playerctl_status(stdout: &str) -> MprisSnapshot {
    let mut playing_players = Vec::new();
    let mut inactive_players = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((player, status)) = line.split_once('|') {
            let player = player.trim().to_ascii_lowercase();
            let status = status.trim();
            if status == "Playing" {
                if !playing_players.contains(&player) {
                    playing_players.push(player);
                }
            } else if !player.is_empty() && !inactive_players.contains(&player) {
                inactive_players.push(player);
            }
        } else if line == "Playing" {
            playing_players.push(String::new());
        }
    }

    inactive_players.retain(|p| !playing_players.contains(p));

    MprisSnapshot {
        available: true,
        any_playing: !playing_players.is_empty(),
        inactive_players,
    }
}

/// Control MPRIS media players
pub struct MprisController;

impl MprisController {
    /// Pause all active MPRIS players
    pub async fn pause_all() -> Result<()> {
        info!("Pausing all MPRIS players");

        let players = mpris::PlayerFinder::new()
            .map_err(|e| anyhow::anyhow!("Failed to find MPRIS players: {}", e))?;

        let all_players = players
            .find_all()
            .map_err(|e| anyhow::anyhow!("Failed to enumerate MPRIS players: {}", e))?;

        for player in &all_players {
            match player.pause() {
                Ok(()) => debug!("Paused MPRIS player: {}", player.identity()),
                Err(e) => warn!("Failed to pause {}: {}", player.identity(), e),
            }
        }

        Ok(())
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
    use super::{parse_pactl_sink_inputs_playing, parse_playerctl_status};

    #[test]
    fn ignores_pipewire_uncorked_idle_browser_streams() {
        // Chromium/Electron apps keep `Corked: no` while paused; MPRIS tracks
        // their real playback state, so pactl must not lock `playing = true`.
        let mpris = parse_playerctl_status("chromium|Paused\nfirefox|Paused\n");
        assert!(!mpris.any_playing);
        assert_eq!(mpris.inactive_players, vec!["chromium", "firefox"]);

        let sample = "\
Sink Input #249
\tDriver: PipeWire
\tCorked: no
\tMute: no
\tProperties:
\t\tapplication.name = \"Chromium\"
\t\tapplication.process.binary = \"youtube-music\"
\t\tnode.name = \"Chromium\"
";
        assert!(!parse_pactl_sink_inputs_playing(
            sample,
            &mpris.inactive_players,
            true,
        ));
        assert!(!parse_pactl_sink_inputs_playing(sample, &[], true));
    }

    #[test]
    fn detects_pipewire_uncorked_non_mpris_stream_even_with_paused_browser() {
        let mpris = parse_playerctl_status("chromium|Paused\nfirefox|Paused\n");

        let sample = "\
Sink Input #249
\tDriver: PipeWire
\tCorked: no
\tMute: no
\tProperties:
\t\tapplication.name = \"Chromium\"
\t\tnode.name = \"Chromium\"

Sink Input #512
\tDriver: PipeWire
\tCorked: no
\tMute: no
\tProperties:
\t\tapplication.name = \"Discord\"
\t\tnode.name = \"WEBRTC VoiceEngine\"
";
        assert!(parse_pactl_sink_inputs_playing(
            sample,
            &mpris.inactive_players,
            true,
        ));
    }

    #[test]
    fn word_boundary_matching_does_not_suppress_zenith_with_zen() {
        let sample = "\
Sink Input #700
\tDriver: PipeWire
\tCorked: no
\tMute: no
\tProperties:
\t\tapplication.name = \"Zenith\"
\t\tapplication.process.binary = \"zenith-game\"
";
        assert!(parse_pactl_sink_inputs_playing(sample, &[], true));
    }

    #[test]
    fn unknown_mpris_state_requires_running_stream() {
        let uncorked_only = "\
Sink Input #701
\tDriver: PipeWire
\tCorked: no
\tMute: no
\tProperties:
\t\tapplication.name = \"CustomPlayer\"
";
        assert!(!parse_pactl_sink_inputs_playing(uncorked_only, &[], false));

        let running = "\
Sink Input #702
\tState: RUNNING
\tCorked: no
\tMute: no
\tProperties:
\t\tapplication.name = \"CustomPlayer\"
";
        assert!(parse_pactl_sink_inputs_playing(running, &[], false));
    }

    #[test]
    fn ignores_corked_or_muted_streams() {
        let corked = "\
Sink Input #72
\tDriver: PipeWire
\tCorked: yes
\tMute: no
";
        assert!(!parse_pactl_sink_inputs_playing(corked, &[], true));

        let muted = "\
Sink Input #73
\tState: RUNNING
\tMute: yes
";
        assert!(!parse_pactl_sink_inputs_playing(muted, &[], true));
    }

    #[test]
    fn detects_pulseaudio_running_stream() {
        let pulse = "\
Sink Input #1
\tState: RUNNING
\tMute: no
";
        assert!(parse_pactl_sink_inputs_playing(pulse, &[], true));
    }
}
