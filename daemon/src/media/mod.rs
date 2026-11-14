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
/// Browsers keep a sink-input open while a tab is paused, so a non-empty
/// `pactl list sink-inputs` does not mean audio is playing. The monitor
/// therefore requires a `RUNNING` sink-input, or an MPRIS player reporting
/// `Playing`. That makes play inside an already-open tab produce a fresh
/// `AudioStarted` edge.
pub async fn monitor_pipewire(tx: mpsc::Sender<MediaEvent>) -> Result<()> {
    info!("Starting PipeWire audio stream monitor");

    tokio::spawn(async move {
        let mut last_playing = false;

        loop {
            let pipewire_playing = check_audio_playing().await;
            let mpris_playing = check_mpris_playing().await;
            let playing = pipewire_playing || mpris_playing;

            if playing != last_playing {
                last_playing = playing;
                let source = if mpris_playing {
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

            tokio::time::sleep(tokio::time::Duration::from_millis(750)).await;
        }
    });

    Ok(())
}

/// True when at least one PipeWire sink-input is in the `RUNNING` state.
async fn check_audio_playing() -> bool {
    let output = tokio::process::Command::new("pactl")
        .args(["list", "sink-inputs"])
        .output()
        .await;

    match output {
        Ok(out) => String::from_utf8_lossy(&out.stdout)
            .lines()
            .any(|line| line.trim() == "State: RUNNING"),
        Err(_) => false,
    }
}

/// True when any MPRIS player reports `Playing` (`playerctl -a status`).
async fn check_mpris_playing() -> bool {
    let output = tokio::process::Command::new("playerctl")
        .args(["-a", "status"])
        .output()
        .await;

    match output {
        Ok(out) => String::from_utf8_lossy(&out.stdout)
            .lines()
            .any(|line| line.trim() == "Playing"),
        Err(_) => false,
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
