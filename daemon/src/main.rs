//! Seuil: pass Galaxy Buds audio between a Samsung phone and Linux over
//! Samsung Continuity (`mcfds`), BLE 0x0075 advertisements, and an L2CAP CoC.
//! for Galaxy Buds Auto Switch (Dynamic Stream Handoff)
//!
//! Implements:
//! - BLE Manufacturer Specific Data advertising/scanning (Company ID 0x0075)
//! - CONTINUITY_MSG_SPP RFCOMM communication
//! - Galaxy Buds Core SPP control (SET_SEAMLESS_CONNECTION)
//! - PipeWire + MPRIS media state integration
//! - Auto Switch handoff state machine

mod auth;
mod ble;
mod buds;
mod config;
mod doctor;
mod handoff;
mod media;
mod protocol;
mod rfcomm;
mod sdp;
mod setup;

use anyhow::{Context, Result};
use bluer::Adapter;
use clap::Parser;
use futures::StreamExt;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use handoff::{DevicePriority, HandoffAction, HandoffConfig, HandoffStateMachine};
use protocol::AudioState;

#[derive(Parser, Debug)]
#[command(name = "seuil")]
#[command(about = "Pass Galaxy Buds audio between a Samsung phone and Linux")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Phone Bluetooth MAC address
    #[arg(long, default_value = "")]
    phone: String,

    /// Galaxy Buds Bluetooth MAC address
    #[arg(long, default_value = "")]
    buds: String,

    /// Bluetooth adapter name (default: hci0)
    #[arg(long, default_value = "hci0", global = true)]
    adapter: String,

    /// Enable debug logging
    #[arg(short, long, global = true)]
    debug: bool,

    /// Dry-run mode (scan and log only, no handoff actions)
    #[arg(long)]
    dry_run: bool,

    /// Disable auto-switch (monitoring only)
    #[arg(long)]
    monitor_only: bool,

    /// Samsung account fingerprint (hex) used to derive the MCF advertisement keys.
    ///
    /// Advertise only this identity; the phone ignores payloads it cannot decode.
    #[arg(long)]
    account_fingerprint: Option<String>,

    /// Sign in with a Samsung account, enroll this device, and print the account key
    #[arg(long)]
    auth_login: bool,

    /// Refresh stored Samsung tokens and certificate without a browser login
    #[arg(long)]
    auth_refresh: bool,

    /// Samsung account auth server host (regional)
    #[arg(long, default_value = "eu-auth2.samsungosp.com", global = true)]
    auth_server: String,

    /// Local Bluetooth address to enroll (default: adapter sysfs address)
    #[arg(long, global = true)]
    bt_address: Option<String>,
}

/// Top-level subcommands. The daemon runs when none is given.
#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Interactive setup: enroll, pick phone and Buds, install the service
    Setup {
        /// Re-run Samsung account enrollment
        #[arg(long)]
        reauth: bool,
        /// Install the optional BlueZ experimental drop-in under /etc (uses sudo)
        #[arg(long)]
        install_bluez_dropin: bool,
    },

    /// Check runtime dependencies and state without changing anything
    Doctor,

    /// Receive the ms-app:// OAuth callback from the browser
    #[command(hide = true)]
    AuthCallback {
        /// Callback URL handed over by the desktop entry
        url: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut cli = Cli::parse();
    init_logging(&cli);

    if let Some(Commands::Doctor) = cli.command.as_ref() {
        std::process::exit(doctor::run(&cli).await);
    }
    if let Some(Commands::Setup {
        reauth,
        install_bluez_dropin,
    }) = cli.command.as_ref()
    {
        return setup::run(&cli, *reauth, *install_bluez_dropin).await;
    }
    if let Some(Commands::AuthCallback { url }) = cli.command.as_ref() {
        return auth::browser::send_callback(url).await;
    }
    let file_config = config::load_strict()?;
    // [FR-010] Timing keys land in config.toml with these defaults.
    let handoff_dwell = file_config.handoff_dwell();
    let backoff_start = file_config.backoff_start();
    let backoff_cap = file_config.backoff_cap();
    let peer_limit = file_config.peer_limit();
    let channel_timeouts = ble::coc_session::ChannelTimeouts {
        keepalive: file_config.keepalive_timeout(),
        frame: file_config.frame_timeout(),
    };
    if cli.phone.is_empty() {
        cli.phone = file_config
            .phone_mac
            .clone()
            .or_else(|| config::discover_phone(auth::Credentials::load().ok().flatten().as_ref()))
            .unwrap_or_default();
    }
    if cli.buds.is_empty() {
        cli.buds = file_config.buds_mac.clone().unwrap_or_default();
    }
    if cli.adapter == "hci0"
        && let Some(adapter) = file_config.adapter.clone() {
            cli.adapter = adapter;
        }
    let discover_buds = file_config.discover;

    if cli.auth_login || cli.auth_refresh {
        return run_auth(&cli).await;
    }
    if cli.phone.is_empty() {
        anyhow::bail!(
            "no phone address: set phone_mac in ~/.config/seuil/config.toml, enroll with \
             --auth-login, or pass --phone"
        );
    }

    info!("seuil starting");
    info!(
        "Phone: {}, Buds: {}, Adapter: {}",
        cli.phone, cli.buds, cli.adapter
    );

    // Get Bluetooth adapter
    // [FR-003] Wait for BlueZ instead of exiting when the unit beats bluetoothd.
    let (session, adapter) = acquire_startup_adapter(&cli.adapter).await?;
    let adapter = Arc::new(adapter);

    info!("Bluetooth adapter {} powered on", cli.adapter);

    // Discover the Buds by name when neither the flag nor the config names them.
    if cli.buds.is_empty() && discover_buds {
        cli.buds = discover_buds_address(&adapter).await.unwrap_or_default();
    }
    if cli.buds.is_empty() {
        anyhow::bail!(
            "no Buds address: set buds_mac in ~/.config/seuil/config.toml or pass --buds"
        );
    }
    info!("Using Buds address {}", cli.buds);
    spawn_device_name_sync(
        cli.auth_server.clone(),
        cli.adapter.clone(),
        cli.bt_address.clone(),
    );

    // Register SDP record
    sdp::register_sdp_record().await?;

    // Query phone SDP records. [FR-004] `sdptool` is absent from SteamOS
    // bluez-utils: a missing tool or a failed query disables only the
    // SDP-dependent check and never aborts startup.
    let phone_sdp = match sdp::query_remote_sdp(&cli.phone).await {
        Ok(records) => Some(records),
        Err(error) => {
            if doctor::command_available("sdptool") {
                warn!("SDP query failed; continuing without the phone SDP check: {error:#}");
            } else {
                warn!(
                    "`sdptool` is not installed; skipping the phone SDP check. This is normal \
                     on SteamOS, where bluez-utils ships no sdptool"
                );
            }
            None
        }
    };
    if let Some(records) = &phone_sdp {
        if records.iter().any(|record| record.is_continuity) {
            info!("CONTINUITY_MSG_SPP found on phone SDP records");
        } else {
            warn!("CONTINUITY_MSG_SPP NOT found on phone - phone may need Samsung MCF app running");
        }
    }

    // Create event channels
    let (ble_tx, mut ble_rx) = mpsc::channel::<ble::BleAdvEvent>(64);
    let (rfcomm_tx, mut rfcomm_rx) = mpsc::channel::<rfcomm::RfcommEvent>(64);
    let (spp_tx, spp_rx) = mpsc::channel::<rfcomm::SppCommand>(8);
    let (media_tx, mut media_rx) = mpsc::channel::<media::MediaEvent>(32);

    // [FR-013] SPP carries Buds opcodes over an RFCOMM Profile1 handler.
    match cli.buds.parse::<bluer::Address>() {
        Ok(buds) => {
            let spp_session = session.clone();
            tokio::spawn(async move {
                rfcomm::run_buds_spp(spp_session, buds, spp_rx, rfcomm_tx).await;
            });
        }
        Err(_) => warn!(
            address = %cli.buds,
            "Buds address is invalid; SPP opcodes are disabled"
        ),
    }

    // Account identity used by the scanner, the advertiser, and the dial guard.
    let fingerprint = account_fingerprint(&cli);
    let refresh_keys = ble::scanning_keys(fingerprint.as_deref());

    // Initialized handoff state machine
    let config = HandoffConfig {
        phone_address: cli.phone.clone(),
        buds_address: cli.buds.clone(),
        auto_switch_enabled: !cli.monitor_only,
        priority: DevicePriority::PhoneWins,
    };
    let state_machine = Arc::new(tokio::sync::Mutex::new(HandoffStateMachine::new(config)));

    // [FR-014] Command channels keyed by peer address. Map access is a short
    // synchronous lock so no await ever runs with one held.
    let command_channels: CommandChannels = Arc::new(std::sync::Mutex::new(HashMap::new()));
    let channel_tasks: ChannelTasks = Arc::new(std::sync::Mutex::new(HashMap::new()));
    let inflight_dials: Arc<std::sync::Mutex<HashSet<String>>> =
        Arc::new(std::sync::Mutex::new(HashSet::new()));
    // Incoming Auto Switch traffic from the phone's command channels.
    let (command_in_tx, mut command_in_rx) =
        mpsc::channel::<(String, ble::coc_session::IncomingCommand)>(16);
    // Buds address bytes for the Auto Switch request body.
    let buds_address = match ble::coc_session::parse_address(&cli.buds) {
        Ok(address) => Some(address),
        Err(e) => {
            warn!("Buds address {:?} is invalid; Auto Switch requests disabled: {e}", cli.buds);
            None
        }
    };
    let switch_state = Arc::new(tokio::sync::Mutex::new(SwitchState::default()));
    let local_playback = Arc::new(AtomicBool::new(false));

    // Supervised transport sessions: scan, advertiser, and Buds ownership watch.
    let mut transport = TransportSessions::new(
        adapter,
        ble_tx,
        fingerprint,
        peer_limit,
        buds_address,
        command_channels.clone(),
        channel_tasks.clone(),
        local_playback.clone(),
        switch_state.clone(),
    );
    transport.start().await?;

    // [FR-009] Suspend/resume and adapter-power supervision.
    let mut lifecycle_rx =
        start_lifecycle_supervisor(cli.adapter.clone(), transport.adapter.clone());

    let dial_attempts: Arc<std::sync::Mutex<HashMap<String, DialAttempt>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));

    let dial = DialContext {
        channels: command_channels.clone(),
        channel_tasks,
        inflight: inflight_dials,
        attempts: dial_attempts,
        incoming: command_in_tx.clone(),
        buds_address,
        local_playback: local_playback.clone(),
        switch_state: switch_state.clone(),
        timeouts: channel_timeouts,
        peer_limit,
        backoff_start,
        backoff_cap,
        dwell: handoff_dwell,
        handshake_failures: Arc::new(AtomicU32::new(0)),
    };

    // Last peer that advertised a CoC PSM, used to retry the authenticated
    // channel without waiting for a fresh advertisement.
    let mut last_coc_target: Option<(ble::BleAdvEvent, u16)> = None;
    let mut lifecycle_enabled = true;
    // [FR-009] Tracks whether the transport sessions are up, so a logind resume
    // and an adapter power-on for the same wake start them (and redial) once.
    let mut transport_active = true;
    // A one-second tick lets the per-peer backoff schedule dial attempts at
    // 1 s, 2 s, 4 s, and so on; the dial gate rejects early ticks. [FR-010]
    let mut reconnect_timer = tokio::time::interval(Duration::from_secs(1));
    reconnect_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    reconnect_timer.tick().await;

    // [FR-023] Refresh expiring tokens in the background without user action.
    spawn_token_refresh(cli.auth_server.clone(), cli.adapter.clone(), cli.bt_address.clone());

    // Start media monitor
    // [FR-016] Threshold and window come from config.toml; the monitor is
    // supervised and restarts itself if the task dies. [FR-018]
    media::monitor_pipewire(
        media_tx,
        media::MediaSettings {
            threshold_dbfs: file_config.media_threshold_dbfs(),
            window: file_config.media_window(),
            ..media::MediaSettings::default()
        },
    );

    // Main event loop
    info!("Entering main event loop");

    loop {
        tokio::select! {
            lifecycle = lifecycle_rx.recv(), if lifecycle_enabled => {
                let Some(lifecycle) = lifecycle else {
                    warn!("Lifecycle supervisor stopped; suspend teardown is disabled");
                    lifecycle_enabled = false;
                    continue;
                };
                match lifecycle {
                    LifecycleEvent::Suspend | LifecycleEvent::PoweredOff => {
                        if transport_active {
                            info!("Transport teardown requested");
                            transport.stop().await;
                            transport_active = false;
                        }
                        lock_or_recover(&dial.attempts).clear();
                    }
                    LifecycleEvent::Resume | LifecycleEvent::PoweredOn => {
                        // A wake fires once even when logind and the adapter
                        // both report it.
                        if transport_active {
                            continue;
                        }
                        if restart_transport_with_backoff(&mut transport).await {
                            transport_active = true;
                            if let Some((event, psm)) = last_coc_target.clone()
                                // [FR-009] Exactly one redial attempt follows a
                                // wake, and only for an authentic phone
                                // advertisement.
                                && dial_authentic(&event, &cli.phone, &refresh_keys)
                            {
                                maybe_connect_coc(
                                    transport.adapter.clone(),
                                    &event,
                                    psm,
                                    &dial,
                                )
                                .await;
                            }
                        }
                    }
                    LifecycleEvent::AdapterLost => {
                        if transport_active {
                            warn!("Bluetooth adapter lost; tearing down transport sessions");
                            transport.stop().await;
                            transport_active = false;
                        }
                        lock_or_recover(&dial.attempts).clear();
                    }
                    LifecycleEvent::AdapterAvailable(adapter) => {
                        info!("Bluetooth adapter available again; re-initializing transport");
                        transport.replace_adapter(adapter);
                        if restart_transport_with_backoff(&mut transport).await {
                            transport_active = true;
                            if let Some((event, psm)) = last_coc_target.clone()
                                && dial_authentic(&event, &cli.phone, &refresh_keys)
                            {
                                maybe_connect_coc(
                                    transport.adapter.clone(),
                                    &event,
                                    psm,
                                    &dial,
                                )
                                .await;
                            }
                        }
                    }
                }
            }
            Some(ble_event) = ble_rx.recv() => {
                let action = {
                    let mut sm = state_machine.lock().await;
                    sm.on_ble_event(&ble_event)
                };
                // [FR-017] The phone reports the call ended when its audio
                // state goes idle; the Buds reporting a disconnect also ends
                // the call. A call guard is never cleared by a timed lock.
                let call_ended = (ble_event.audio_state == AudioState::Idle
                    && ble_event.address.eq_ignore_ascii_case(&cli.phone))
                    || (ble_event.audio_state == AudioState::Disconnected
                        && ble_event.address.eq_ignore_ascii_case(&cli.buds));
                if call_ended {
                    let mut state = switch_state.lock().await;
                    if state.call.call_active() {
                        state.call.call_ended();
                        info!("Phone call ended; media-reason handoffs are allowed again");
                    }
                }
                // Release the state-machine lock before the handoff work runs.
                if let Some(action) = action {
                    handle_action(
                        action,
                        &cli.dry_run,
                        &spp_tx,
                        &transport.adapter,
                        buds_address,
                    )
                    .await;
                }
                if let Some(psm) = ble_event.coc_psm {
                    // [FR-011] Pair and dial only the configured phone, and
                    // only after the account checksum validates.
                    if !ble_event.address.eq_ignore_ascii_case(&cli.phone) {
                        warn!(
                            address = %ble_event.address,
                            "Ignoring a CoC advertisement from an unconfigured address"
                        );
                    } else if !ble::advertisement_checksum_matches(&ble_event.raw_data, &refresh_keys) {
                        warn!(
                            address = %ble_event.address,
                            "Ignoring a phone advertisement whose checksum does not match the account"
                        );
                    } else {
                        last_coc_target = Some((ble_event.clone(), psm));
                        maybe_connect_coc(
                            transport.adapter.clone(),
                            &ble_event,
                            psm,
                            &dial,
                        )
                        .await;
                    }
                }
            }
            Some(rfcomm_event) = rfcomm_rx.recv() => {
                let action = {
                    let mut sm = state_machine.lock().await;
                    sm.on_rfcomm_event(&rfcomm_event)
                };
                if let Some(action) = action {
                    handle_action(
                        action,
                        &cli.dry_run,
                        &spp_tx,
                        &transport.adapter,
                        buds_address,
                    )
                    .await;
                }
            }
            Some((peer, incoming)) = command_in_rx.recv() => {
                if let Some(buds_address) = buds_address {
                    handle_incoming_command(
                        &transport.adapter,
                        buds_address,
                        &peer,
                        incoming,
                        &command_channels,
                        &switch_state,
                    )
                    .await;
                }
            }
            _ = reconnect_timer.tick() => {
                // Re-establish a dropped command channel. Never dial from a
                // cached PSM: read the phone's current advertisement first so a
                // restarted mcfds server or a rotated address is picked up.
                let attempt_allowed = last_coc_target.as_ref().is_none_or(|(event, _)| {
                    dial_allowed(
                        lock_or_recover(&dial.attempts).get(&event.address),
                        Instant::now(),
                    )
                });
                if let Some((event, cached_psm)) = last_coc_target.clone()
                    && !lock_or_recover(&command_channels).contains_key(&event.address)
                    && dial_authentic(&event, &cli.phone, &refresh_keys)
                    && attempt_allowed
                {
                    let fresh_psm = match event.address.parse::<bluer::Address>() {
                        Ok(address) => {
                            ble::read_phone_coc_psm(&transport.adapter, &address, &refresh_keys)
                                .await
                        }
                        Err(_) => None,
                    };
                    match fresh_psm {
                        Some(psm) => {
                            if psm != cached_psm {
                                info!(
                                    address = %event.address,
                                    cached = cached_psm,
                                    fresh = psm,
                                    "Refreshed the CoC PSM from the current advertisement"
                                );
                            }
                            last_coc_target = Some((event.clone(), psm));
                            info!(
                                address = %event.address,
                                psm,
                                "Retrying the authenticated command channel"
                            );
                            maybe_connect_coc(
                                transport.adapter.clone(),
                                &event,
                                psm,
                                &dial,
                            )
                            .await;
                        }
                        None => debug!(
                            address = %event.address,
                            "No current phone advertisement yet; skipping the L2CAP dial"
                        ),
                    }
                }
            }
            Some(media_event) = media_rx.recv() => {
                // Mirror the local audio state into the MCF advertisement.
                let audio_state = match &media_event {
                    media::MediaEvent::AudioStarted { .. } => Some(AudioState::Streaming),
                    media::MediaEvent::AudioStopped { .. } => Some(AudioState::Idle),
                    media::MediaEvent::PlayerStateChanged { playing, .. } => Some(
                        if *playing {
                            AudioState::Streaming
                        } else {
                            AudioState::Idle
                        },
                    ),
                };
                if let Some(state) = audio_state {
                    // Track playback even while advertising is torn down.
                    local_playback.store(
                        matches!(state, AudioState::Streaming),
                        Ordering::Relaxed,
                    );
                    if let Some(tx) = transport.advertiser_sender() {
                        let _ = tx.try_send(ble::AdvUpdate::Audio(state));
                    }
                }
                // Ask the phone to hand the Buds over when Linux starts playing.
                if is_playback_start(&media_event)
                    && let Some(buds_address) = buds_address {
                        request_buds_switch(
                            &transport.adapter,
                            buds_address,
                            &command_channels,
                            &switch_state,
                            handoff_dwell,
                        )
                        .await;
                    }
                let action = {
                    let mut sm = state_machine.lock().await;
                    match &media_event {
                        media::MediaEvent::AudioStarted { .. } => sm.on_local_media_start(),
                        media::MediaEvent::AudioStopped { .. } => sm.on_local_media_stop(),
                        media::MediaEvent::PlayerStateChanged { playing: false, .. } => {
                            sm.on_local_media_stop()
                        }
                        _ => None,
                    }
                };
                if let Some(action) = action {
                    handle_action(
                        action,
                        &cli.dry_run,
                        &spp_tx,
                        &transport.adapter,
                        buds_address,
                    )
                    .await;
                }
            }
            else => {
                info!("All event channels closed, exiting");
                break;
            }
        }
    }

    Ok(())
}

fn init_logging(cli: &Cli) {
    let filter = if cli.debug {
        EnvFilter::new("debug")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

async fn run_auth(cli: &Cli) -> Result<()> {
    let stored = auth::Credentials::load()?;
    if cli.auth_refresh && stored.is_none() {
        anyhow::bail!("no stored Samsung credentials; run --auth-login first");
    }

    let mut oauth = match &stored {
        Some(stored) => auth::SamsungOAuth::from_credentials(stored)?,
        None => auth::SamsungOAuth::new(&cli.auth_server)?,
    };

    let address = match cli.bt_address.clone() {
        Some(address) => Some(address),
        None => read_adapter_address(&cli.adapter).await.or_else(|| {
            stored
                .as_ref()
                .map(|stored| stored.bt_address.clone())
                .filter(|address| !address.is_empty())
        }),
    };
    let Some(address) = address else {
        anyhow::bail!(
            "could not read the address of {}; pass --bt-address XX:XX:XX:XX:XX:XX, \
             for example `seuil setup --bt-address XX:XX:XX:XX:XX:XX`",
            cli.adapter
        );
    };
    oauth.set_bt_address(&address)?;
    if cli.auth_refresh
        && let Some(previous) = stored
            .as_ref()
            .filter(|stored| !stored.bt_address.is_empty())
        && auth::normalize_bt_address(&previous.bt_address)?
            != auth::normalize_bt_address(&address)?
    {
        anyhow::bail!(
            "the Bluetooth identity changed; re-enroll with --auth-login or remove {}",
            auth::credentials_path().display()
        );
    }

    if cli.auth_login {
        let entry = oauth.get_entry_point().await?;
        let svc_param = oauth.build_svc_param(&entry)?;
        let url = oauth.authorize_url(&entry, &svc_param)?;
        let callback = oauth.interactive_login(&url).await?;
        oauth.authenticate(&callback).await?;
    }

    oauth.get_service_token().await?;

    let registration = if let Some(stored) = stored.as_ref().filter(|stored| {
        cli.auth_refresh
            || (!stored.registration_id.is_empty()
                && oauth.user_id() == Some(stored.user_id.as_str()))
    }) {
        let current = auth::DeviceRegistration {
            registration_id: stored.registration_id.clone(),
            cloud_token: stored.cloud_token.clone(),
            expires_at: stored.cloud_expires,
        };
        if current.registration_id.is_empty() || current.cloud_token.is_empty() {
            oauth.register_device().await?
        } else if current.expires_at <= unix_now() + 120 {
            oauth.renew_cloud_token(&current).await?
        } else {
            current
        }
    } else {
        oauth.register_device().await?
    };
    oauth.set_registration(&registration);

    let bundle = oauth.enroll_certificate(&registration).await?;
    oauth.credentials(&bundle).save()?;

    if cli.auth_login || cli.auth_refresh {
        // [FR-021] The account key stays out of stdout; it is written to the
        // encrypted credential store above.
        println!("Account key: stored in the credential envelope (redacted)");
        println!(
            "Enrolled device: {} ({})",
            bundle.this_device.bt_address, bundle.this_device.device_name
        );
        println!("User fingerprint: redacted");
        println!("Certificate revision: {}", bundle.revision);
        println!("Peer devices: {}", bundle.devices.len());
        println!(
            "Credentials saved to {}",
            auth::credentials_path().display()
        );
    } else {
        info!(
            device_name = %bundle.this_device.device_name,
            revision = bundle.revision,
            "Synced local device name with Samsung Continuity certificate"
        );
    }
    Ok(())
}

/// Checks in the background whether the enrolled Samsung certificate's
/// `device_name` differs from `auth::local_device_name()`, and refreshes the
/// certificate automatically when it does.
fn spawn_device_name_sync(
    auth_server: String,
    adapter: String,
    bt_address: Option<String>,
) {
    let Ok(Some(stored)) = auth::Credentials::load() else {
        return;
    };
    if stored.refresh_token.is_empty() {
        return;
    }
    let desired = auth::local_device_name();
    if stored.device_name == desired {
        return;
    }
    tokio::spawn(async move {
        // [FR-023] Name both identities before a re-enroll changes the enrolled
        // device identity, so the switch is visible in the log.
        warn!(
            current = %stored.device_name,
            desired = %desired,
            "Resolved device name differs from the enrolled certificate; re-enrolling this \
             device identity in the background"
        );
        let refresh_cli = Cli {
            command: None,
            phone: String::new(),
            buds: String::new(),
            adapter,
            debug: false,
            dry_run: false,
            monitor_only: false,
            account_fingerprint: None,
            auth_login: false,
            auth_refresh: false,
            auth_server,
            bt_address,
        };
        if let Err(error) = run_auth(&refresh_cli).await {
            warn!("Could not auto-sync device name with Samsung Cloud: {error:#}");
        }
    });
}

/// Background token refresh window and retry bounds. [FR-023]
const TOKEN_REFRESH_MARGIN_SECS: i64 = 120;
const TOKEN_REFRESH_CHECK: Duration = Duration::from_secs(30);
const MAX_TOKEN_REFRESH_ATTEMPTS: u32 = 3;
/// Handshake failures before the daemon tells the user to re-enroll.
const MAX_HANDSHAKE_FAILURES: u32 = 3;

/// Whether an access token has entered the refresh margin.
fn token_needs_refresh(expires_at: i64, now: i64) -> bool {
    expires_at != 0 && expires_at <= now + TOKEN_REFRESH_MARGIN_SECS
}

/// Refreshes an expiring service token at runtime.
///
/// [FR-023] Runs the existing refresh path without user action, persists the
/// refreshed store, and escalates after bounded failures instead of retrying
/// forever.
fn spawn_token_refresh(auth_server: String, adapter: String, bt_address: Option<String>) {
    tokio::spawn(async move {
        let mut failures = 0u32;
        loop {
            tokio::time::sleep(TOKEN_REFRESH_CHECK).await;
            let credentials = match auth::Credentials::load() {
                Ok(Some(credentials)) => credentials,
                Ok(None) => continue,
                Err(error) => {
                    warn!("Could not read credentials for token refresh: {error}");
                    continue;
                }
            };
            if credentials.refresh_token.is_empty() {
                continue;
            }
            if !token_needs_refresh(credentials.access_expires, unix_now()) {
                failures = 0;
                continue;
            }
            info!("Service token entered the refresh margin; refreshing");
            let refresh_cli = Cli {
                command: None,
                phone: String::new(),
                buds: String::new(),
                adapter: adapter.clone(),
                debug: false,
                dry_run: false,
                monitor_only: false,
                account_fingerprint: None,
                auth_login: false,
                auth_refresh: true,
                auth_server: auth_server.clone(),
                bt_address: bt_address.clone(),
            };
            match run_auth(&refresh_cli).await {
                Ok(()) => {
                    failures = 0;
                    info!("Service token refreshed and persisted");
                }
                Err(error) => {
                    failures += 1;
                    warn!(
                        attempt = failures,
                        "Service token refresh failed: {error:#}"
                    );
                    if failures >= MAX_TOKEN_REFRESH_ATTEMPTS {
                        error!(
                            attempts = failures,
                            "Samsung credentials could not be refreshed; rerun `seuil setup \
                             --reauth` to re-enroll this device"
                        );
                        return;
                    }
                    tokio::time::sleep(Duration::from_secs(30 * u64::from(failures))).await;
                }
            }
        }
    });
}

async fn read_adapter_address(adapter: &str) -> Option<String> {
    // Try sysfs first
    let path = format!("/sys/class/bluetooth/{adapter}/address");
    if let Ok(address) = std::fs::read_to_string(&path) {
        let address = address.trim().to_string();
        if !address.is_empty() {
            return Some(address);
        }
    }

    // BlueZ exposes the adapter address even when sysfs does not.
    if let Ok(session) = bluer::Session::new().await
        && let Ok(adapter) = session.adapter(adapter)
        && let Ok(address) = adapter.address().await
    {
        return Some(address.to_string());
    }

    // Fallback to hciconfig
    if let Ok(output) = std::process::Command::new("hciconfig")
        .arg(adapter)
        .output()
        && output.status.success()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("BD Address")
                && let Some(addr) = line.split_whitespace().nth(2)
            {
                return Some(addr.to_string());
            }
        }
    }

    tracing::debug!(adapter, "Could not read adapter address");
    None
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or_default()
}

/// Account fingerprint from the CLI override, else from stored credentials.
///
/// Never log the fingerprint itself: it is the account identity.
fn account_fingerprint(cli: &Cli) -> Option<Vec<u8>> {
    if let Some(hex_fingerprint) = cli.account_fingerprint.as_deref() {
        match hex::decode(hex_fingerprint) {
            Ok(fingerprint) if !fingerprint.is_empty() => return Some(fingerprint),
            Ok(_) => warn!("Empty --account-fingerprint, ignoring it"),
            Err(e) => warn!("Invalid --account-fingerprint ({}), ignoring it", e),
        }
    }

    match auth::Credentials::load() {
        Ok(Some(credentials)) if !credentials.user_fingerprint.is_empty() => {
            match hex::decode(&credentials.user_fingerprint) {
                Ok(fingerprint) if !fingerprint.is_empty() => Some(fingerprint),
                Ok(_) => {
                    warn!("Stored account fingerprint is empty");
                    None
                }
                Err(e) => {
                    warn!("Stored account fingerprint is not valid hex: {}", e);
                    None
                }
            }
        }
        Ok(_) => None,
        Err(e) => {
            warn!("Could not load Samsung credentials: {}", e);
            None
        }
    }
}

/// Upper bound on the account handshake exchange.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound on one BLE pairing attempt, so a hung pair cannot accumulate.
const PAIR_TIMEOUT: Duration = Duration::from_secs(10);

/// Credentials the Continuity account handshake needs, reloaded per attempt.
#[derive(Clone)]
struct HandshakeCredentials {
    account_key: [u8; 32],
    bt_address: [u8; 6],
    revision: u32,
}

/// Loads the enrolled account key, Bluetooth address, and certificate revision.
fn handshake_credentials() -> Option<HandshakeCredentials> {
    let credentials = match auth::Credentials::load() {
        Ok(Some(credentials)) => credentials,
        Ok(None) => return None,
        Err(e) => {
            warn!("Could not load Samsung credentials for the handshake: {e}");
            return None;
        }
    };
    let Some(account_key) = credentials.account_key() else {
        warn!("Stored Samsung account key is missing or invalid");
        return None;
    };
    let bt_address = match credentials.bt_address_bytes() {
        Ok(address) => address,
        Err(e) => {
            warn!("Stored Bluetooth address is invalid: {e}");
            return None;
        }
    };
    Some(HandshakeCredentials {
        account_key,
        bt_address,
        revision: credentials.revision,
    })
}

/// Per-peer CoC dial state: failures drive the exponential backoff.
#[derive(Debug, Clone, Copy, Default)]
struct DialAttempt {
    /// Consecutive failed or unconfirmed attempts.
    failures: u32,
    /// Earliest instant the next attempt may start.
    next_allowed: Option<Instant>,
}

/// Whether a CoC connect attempt to a peer may start now.
///
/// [FR-010] Replacement for the flat retry interval: the delay comes from
/// [`dial_backoff`] and is stored on the peer's [`DialAttempt`].
fn dial_allowed(attempt: Option<&DialAttempt>, now: Instant) -> bool {
    attempt
        .and_then(|attempt| attempt.next_allowed)
        .is_none_or(|next_allowed| now >= next_allowed)
}

/// Exponential delay for repeated connect failures: `start`, doubling to `cap`.
///
/// [FR-010] The sequence is 1 s, 2 s, 4 s, and so on, staying at the cap.
fn dial_backoff(failures: u32, start: Duration, cap: Duration) -> Duration {
    let start = start.max(Duration::from_millis(1));
    let cap = cap.max(start);
    let mut delay = start;
    for _ in 0..failures {
        delay = (delay * 2).min(cap);
        if delay >= cap {
            break;
        }
    }
    delay.min(cap)
}

/// Upper bound on one A2DP pull attempt and the retry budget on a granted
/// media switch. [FR-019]
const A2DP_PULL_ATTEMPTS: u32 = 3;
const A2DP_PULL_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
const A2DP_PULL_RETRY_DELAY: Duration = Duration::from_millis(500);

/// A2DP Sink profile UUID (`0000110b-...`), the audio link the Buds use.
const A2DP_SINK_UUID: &str = "0000110b-0000-1000-8000-00805f9b34fb";

/// Handsfree profile UUID (`0000111e-...`), disconnected on a call handoff.
const HFP_UUID: &str = "0000111e-0000-1000-8000-00805f9b34fb";

/// Handoff bookkeeping between local playback and the phone's requests.
#[derive(Default)]
struct SwitchState {
    /// When a handoff was last requested, for the dwell gate.
    last_request: Option<Instant>,
    /// Call policy: HFP calls block media-reason requests only. [FR-017]
    call: handoff::CallGuard,
}

impl SwitchState {
    /// True when the dwell since the last handoff request has elapsed.
    ///
    /// [FR-010] A request inside the dwell is suppressed and logged as
    /// dwell-blocked; one at or past the dwell proceeds.
    fn dwell_elapsed(&self, now: Instant, dwell: Duration) -> bool {
        self.last_request
            .is_none_or(|requested| now.duration_since(requested) >= dwell)
    }

    /// Whether a handoff request of `reason` may proceed now.
    ///
    /// [FR-017] A media-reason request is suppressed during an HFP call; a
    /// call-reason request always proceeds during a call.
    fn may_request(&self, now: Instant, dwell: Duration, reason: handoff::SwitchReason) -> bool {
        if reason == handoff::SwitchReason::Media && self.call.blocks_media() {
            info!("Ignoring local playback start: an HFP call owns the Buds");
            return false;
        }
        if !self.dwell_elapsed(now, dwell) {
            info!(
                dwell = ?dwell,
                "Ignoring local playback start: the handoff dwell has not elapsed (dwell-blocked)"
            );
            return false;
        }
        true
    }
}

/// True when a media event starts local playback.
///
/// [FR-016] Only the peak-window verdict starts a handoff. MPRIS state is a
/// secondary signal and never triggers on its own.
fn is_playback_start(event: &media::MediaEvent) -> bool {
    matches!(event, media::MediaEvent::AudioStarted { .. })
}

/// Asks the phone to hand the Buds to this PC.
///
/// Skipped while the handoff dwell has not elapsed and while a phone call
/// session owns the Buds.
async fn request_buds_switch(
    adapter: &Arc<Adapter>,
    buds_address: [u8; 6],
    channels: &CommandChannels,
    state: &Arc<tokio::sync::Mutex<SwitchState>>,
    dwell: Duration,
) {
    let now = Instant::now();
    {
        let mut state = state.lock().await;
        if !state.may_request(now, dwell, handoff::SwitchReason::Media) {
            return;
        }
        // [FR-010] Record the request timestamp so the dwell applies to the
        // next trigger.
        state.last_request = Some(now);
    }

    let buds_string = format_address(buds_address);
    // Do not gate on the local `Connected` property: BlueZ keeps reporting a
    // partial link after the phone takes the Buds, which blocked every later
    // request. The phone decides whether to switch, so always ask.
    let Ok(device_address) = buds_string.parse::<bluer::Address>() else {
        warn!(address = %buds_string, "Could not parse the Buds address for a switch request");
        return;
    };
    if adapter.device(device_address).is_err() {
        warn!(address = %buds_string, "Could not resolve the Buds device for a switch request");
        return;
    }

    let request = ble::coc_session::CommandRequest::BudsSwitch {
        adv_id: ble::coc_session::advertisement_id(buds_address),
        address: buds_address,
        reason: ble::coc_session::REASON_MEDIA,
    };
    let senders: Vec<_> = lock_or_recover(channels).values().cloned().collect();
    if senders.is_empty() {
        info!("Local playback started, but no authenticated phone channel is open");
        return;
    }
    for sender in senders {
        info!(address = %buds_string, "Requesting Buds handoff from the phone (reason: media)");
        if sender.send(request.clone()).await.is_err() {
            warn!("Command channel closed while sending the switch request");
        }
    }
}

/// Formats a six-byte Bluetooth address for BlueZ calls.
fn format_address(address: [u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        address[0], address[1], address[2], address[3], address[4], address[5]
    )
}

/// Pauses local MPRIS playback and reports whether it took effect. [FR-019]
async fn pause_media_verified() -> bool {
    match media::MprisController::pause_all().await {
        Ok(outcome) if outcome.succeeded() => {
            debug!(
                attempted = outcome.attempted,
                "Local MPRIS playback paused for the handoff"
            );
            true
        }
        Ok(outcome) => {
            warn!(
                attempted = outcome.attempted,
                failed = outcome.failed,
                "MPRIS pause failed for some players"
            );
            false
        }
        Err(error) => {
            error!("Failed to pause MPRIS players: {error}");
            false
        }
    }
}

/// Disconnects the Buds A2DP and HFP profiles.
///
/// [FR-019] Returns true only when every profile disconnect completed, so a
/// release reply can report a partial teardown.
async fn teardown_buds_profiles(adapter: &Arc<Adapter>, buds_address: [u8; 6]) -> bool {
    let buds_string = format_address(buds_address);
    let Ok(device_address) = buds_string.parse::<bluer::Address>() else {
        warn!(
            address = %buds_string,
            "Could not parse the Buds address during profile teardown"
        );
        return false;
    };
    let Ok(device) = adapter.device(device_address) else {
        warn!(
            address = %buds_string,
            "Could not resolve the Buds device during profile teardown"
        );
        return false;
    };

    let mut complete = true;
    for profile in [A2DP_SINK_UUID, HFP_UUID] {
        let Ok(uuid) = uuid::Uuid::parse_str(profile) else {
            complete = false;
            continue;
        };
        match device.disconnect_profile(&uuid).await {
            Ok(()) => debug!(profile = %uuid, "Disconnected the Buds profile"),
            Err(error) => {
                complete = false;
                warn!(profile = %uuid, "Could not disconnect the Buds profile: {error}");
            }
        }
    }
    complete
}

/// Pulls the Buds A2DP link to Linux with bounded retries. [FR-019]
async fn pull_a2dp(adapter: &Arc<Adapter>, buds_address: [u8; 6]) {
    let buds_string = format_address(buds_address);
    let Ok(device_address) = buds_string.parse::<bluer::Address>() else {
        warn!(
            address = %buds_string,
            "Could not parse the Buds address after a granted handoff"
        );
        return;
    };
    let Ok(device) = adapter.device(device_address) else {
        warn!(
            address = %buds_string,
            "Could not resolve the Buds device after a granted handoff"
        );
        return;
    };
    let Ok(uuid) = uuid::Uuid::parse_str(A2DP_SINK_UUID) else {
        return;
    };

    info!(address = %buds_string, "Pulling the Buds A2DP link to Linux");
    for attempt in 1..=A2DP_PULL_ATTEMPTS {
        match tokio::time::timeout(A2DP_PULL_ATTEMPT_TIMEOUT, device.connect_profile(&uuid)).await {
            Ok(Ok(())) => {
                info!(address = %buds_string, attempt, "Pulled the Buds A2DP link to Linux");
                return;
            }
            Ok(Err(error)) => warn!(
                address = %buds_string,
                attempt,
                "Could not connect the A2DP profile: {error}"
            ),
            Err(_) => warn!(
                address = %buds_string,
                attempt,
                "The A2DP connect timed out"
            ),
        }
        if attempt < A2DP_PULL_ATTEMPTS {
            tokio::time::sleep(A2DP_PULL_RETRY_DELAY).await;
        }
    }
    warn!(
        address = %buds_string,
        attempts = A2DP_PULL_ATTEMPTS,
        "Giving up on the Buds A2DP pull"
    );
}

/// Applies Auto Switch traffic from the phone.
async fn handle_incoming_command(
    adapter: &Arc<Adapter>,
    buds_address: [u8; 6],
    peer: &str,
    incoming: ble::coc_session::IncomingCommand,
    channels: &CommandChannels,
    state: &Arc<tokio::sync::Mutex<SwitchState>>,
) {
    match incoming {
        ble::coc_session::IncomingCommand::BudsSwitchRequest {
            adv_id,
            address,
            reason,
        } => {
            info!(
                peer = %peer,
                adv_id,
                reason,
                address = %hex::encode(address),
                "Phone requested a Buds handoff"
            );
            // [FR-019] Verify the local pause and finish the Buds teardown
            // before the phone is told the handoff succeeded.
            let paused = pause_media_verified().await;
            let torn_down = teardown_buds_profiles(adapter, buds_address).await;

            {
                let now = Instant::now();
                let mut state = state.lock().await;
                state.last_request = Some(now);
                if handoff::SwitchReason::from_byte(reason) == handoff::SwitchReason::Call {
                    // [FR-017] Enter the call state on the phone's call-reason
                    // request; the phone's idle advertisement ends it.
                    state.call.call_started();
                    info!(
                        "Phone call owns the Buds; media-reason handoffs are suppressed until \
                         the call ends"
                    );
                }
            }

            if !paused {
                warn!("Local playback did not pause; answering the phone with a failure result");
            }
            if !torn_down {
                warn!(
                    "Buds profile teardown was incomplete; answering the phone with a failure \
                     result"
                );
            }
            // [FR-019] The reply reflects a failed pause or teardown.
            let response = ble::coc_session::CommandRequest::SwitchResponse {
                result: u8::from(paused && torn_down),
                adv_id,
                address,
            };
            let sender = lock_or_recover(channels).get(peer).cloned();
            if let Some(sender) = sender
                && sender.send(response).await.is_err()
            {
                warn!("Command channel closed while acknowledging the handoff");
            }
        }
        ble::coc_session::IncomingCommand::BudsSwitchResponse {
            result,
            adv_id,
            address,
        } => {
            info!(
                peer = %peer,
                result,
                adv_id,
                address = %hex::encode(address),
                "Phone answered the Buds handoff request"
            );
            let reason = {
                let mut state = state.lock().await;
                state.call.on_response(adv_id, address, Instant::now())
            };
            if result != 1 {
                warn!(result, "Phone rejected the Buds handoff request");
                return;
            }
            // [FR-019] A call-reason grant leaves the media links alone.
            if reason == handoff::SwitchReason::Call {
                info!("Call-reason switch granted; not pulling A2DP to Linux");
                return;
            }
            pull_a2dp(adapter, buds_address).await;
        }
    }
}

/// Command senders keyed by peer address.
///
/// The lock is synchronous and only held for map access, so no await ever runs
/// with it held. [FR-014]
type CommandChannels =
    Arc<std::sync::Mutex<HashMap<String, mpsc::Sender<ble::coc_session::CommandRequest>>>>;

/// Join handles for command-channel tasks, aborted on teardown. [FR-009]
type ChannelTasks = Arc<std::sync::Mutex<HashMap<String, JoinHandle<()>>>>;

/// Locks a map, recovering from a poisoned mutex rather than panicking.
fn lock_or_recover<T>(map: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match map.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Whether an event is an authentic advertisement from the configured phone.
///
/// [FR-011] Both the address and the account checksum must match before the
/// daemon pairs or dials.
fn dial_authentic(
    event: &ble::BleAdvEvent,
    phone: &str,
    keys: &auth::ble_keys::BleKeyDerivation,
) -> bool {
    event.address.eq_ignore_ascii_case(phone.trim())
        && ble::advertisement_checksum_matches(&event.raw_data, keys)
}

/// Removes a channel's map entries when its task ends, including on abort.
struct ChannelEntryGuard {
    address: String,
    channels: CommandChannels,
    tasks: ChannelTasks,
}

impl Drop for ChannelEntryGuard {
    fn drop(&mut self) {
        lock_or_recover(&self.channels).remove(&self.address);
        lock_or_recover(&self.tasks).remove(&self.address);
    }
}

/// Removes the in-flight marker when a dial attempt ends.
struct InflightGuard {
    address: String,
    inflight: Arc<std::sync::Mutex<HashSet<String>>>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        lock_or_recover(&self.inflight).remove(&self.address);
    }
}

/// Runtime knobs for the CoC channel manager.
#[derive(Clone)]
struct DialContext {
    channels: CommandChannels,
    channel_tasks: ChannelTasks,
    inflight: Arc<std::sync::Mutex<HashSet<String>>>,
    /// Per-peer dial state; the dial task clears it after a successful handshake.
    attempts: Arc<std::sync::Mutex<HashMap<String, DialAttempt>>>,
    incoming: mpsc::Sender<(String, ble::coc_session::IncomingCommand)>,
    buds_address: Option<[u8; 6]>,
    local_playback: Arc<AtomicBool>,
    switch_state: Arc<tokio::sync::Mutex<SwitchState>>,
    timeouts: ble::coc_session::ChannelTimeouts,
    peer_limit: usize,
    backoff_start: Duration,
    backoff_cap: Duration,
    dwell: Duration,
    handshake_failures: Arc<std::sync::atomic::AtomicU32>,
}

/// Connect to a peer that advertised a CoC PSM.
///
/// Skips the attempt when a channel is already open or an attempt is in flight,
/// and applies the exponential connect backoff. The connect runs in its own
/// task so a slow or unreachable peer cannot stall the event loop. After a
/// successful handshake the channel task owns its map entry and the dial task
/// clears the peer's failure count. Credentials are reloaded per attempt, so a
/// re-enrollment applies without a restart.
async fn maybe_connect_coc(
    adapter: Arc<Adapter>,
    event: &ble::BleAdvEvent,
    psm: u16,
    ctx: &DialContext,
) {
    let address = event.address.clone();
    {
        if lock_or_recover(&ctx.channels).contains_key(&address) {
            lock_or_recover(&ctx.attempts).remove(&address);
            return;
        }
        // [FR-014] A hung attempt does not accumulate duplicates.
        if lock_or_recover(&ctx.inflight).contains(&address) {
            debug!(%address, "CoC connect already in flight; skipping the duplicate");
            return;
        }
    }

    let now = Instant::now();
    let previous = lock_or_recover(&ctx.attempts)
        .get(&address)
        .copied()
        .unwrap_or_default();
    if !dial_allowed(Some(&previous), now) {
        debug!(%address, "CoC connect is still backing off");
        return;
    }

    // [FR-010] The delay grows on each failure: start, doubling to the cap.
    let delay = dial_backoff(previous.failures, ctx.backoff_start, ctx.backoff_cap);
    {
        let mut attempts = lock_or_recover(&ctx.attempts);
        if attempts.len() >= ctx.peer_limit {
            attempts.clear();
        }
        attempts.insert(
            address.clone(),
            DialAttempt {
                failures: previous.failures.saturating_add(1),
                next_allowed: Some(now + delay),
            },
        );
    }
    lock_or_recover(&ctx.inflight).insert(address.clone());
    let inflight_guard = InflightGuard {
        address: address.clone(),
        inflight: ctx.inflight.clone(),
    };

    let address_type = event.address_type;
    let ctx = ctx.clone();
    tokio::spawn(async move {
        let _inflight = inflight_guard;
        // Reload the credential store when preparing each attempt, so a key
        // replaced by re-enrollment is used on the next attempt without a
        // daemon restart.
        let credentials = handshake_credentials();

        let Ok(peer_address) = address.parse::<bluer::Address>() else {
            error!(address = %address, "Could not parse the phone address; skipping the dial");
            return;
        };

        // Try to pair/bond with the device first. The timeout bounds a hung
        // pairing request.
        info!(address = %address, "Attempting BLE pairing");
        match adapter.device(peer_address) {
            Ok(device) => match tokio::time::timeout(PAIR_TIMEOUT, device.pair()).await {
                Ok(Ok(())) => info!(address = %address, "BLE pairing successful"),
                Ok(Err(error)) => warn!(address = %address, "BLE pairing failed: {error}"),
                Err(_) => warn!(
                    address = %address,
                    timeout = ?PAIR_TIMEOUT,
                    "BLE pairing timed out"
                ),
            },
            Err(error) => warn!(
                address = %address,
                "Could not resolve the phone device for pairing: {error}"
            ),
        }

        let mut channel = match ble::l2cap::connect_l2cap_coc(&address, address_type, psm).await {
            Ok(channel) => channel,
            Err(error) => {
                warn!(address = %address, psm, "BLE L2CAP CoC connect failed: {error:#}");
                return;
            }
        };
        info!(address = %address, psm, "BLE L2CAP CoC ready");

        let session_key = match credentials {
            Some(credentials) => {
                let handshake = match auth::handshake::AuthHandshake::new(
                    credentials.account_key,
                    credentials.bt_address,
                    credentials.revision,
                ) {
                    Ok(handshake) => handshake,
                    Err(error) => {
                        warn!(address = %address, "Could not start the Continuity handshake: {error}");
                        return;
                    }
                };
                match handshake
                    .authenticate(&mut channel.stream, HANDSHAKE_TIMEOUT)
                    .await
                {
                    Ok(session_key) => {
                        ctx.handshake_failures.store(0, Ordering::Relaxed);
                        // [FR-010] A successful handshake ends the peer's
                        // failure streak, so a later drop redials from a clean
                        // count instead of the stale one.
                        lock_or_recover(&ctx.attempts).remove(&address);
                        info!(address = %address, "Continuity account handshake complete");
                        session_key
                    }
                    Err(error) => {
                        // [FR-023] Bound the retries and escalate visibly when
                        // the certificate is likely rotated.
                        let failures =
                            ctx.handshake_failures.fetch_add(1, Ordering::Relaxed) + 1;
                        warn!(
                            address = %address,
                            attempts = failures,
                            "Continuity account handshake failed: {error}"
                        );
                        if failures >= MAX_HANDSHAKE_FAILURES {
                            error!(
                                address = %address,
                                attempts = failures,
                                "Continuity handshake keeps failing; the stored certificate may \
                                 have rotated. Rerun `seuil setup --reauth`"
                            );
                        }
                        return;
                    }
                }
            }
            None => {
                warn!(address = %address, "L2CAP channel opened without authentication");
                return;
            }
        };

        // Hand the authenticated stream to the command-channel task. It sends
        // the ready event immediately so the phone routes Auto Switch requests
        // to this PC, then serves requests and responses.
        //
        // [FR-014] The sender is inserted before the task spawns, and the task
        // owns both map entries, so an immediate close leaves no stale sender.
        let (out_tx, out_rx) = mpsc::channel(8);
        {
            let mut channels = lock_or_recover(&ctx.channels);
            if channels.len() >= ctx.peer_limit {
                warn!(
                    limit = ctx.peer_limit,
                    "Command-channel map is at its cap; skipping a new peer"
                );
                return;
            }
            channels.insert(address.clone(), out_tx);
        }
        let guard = ChannelEntryGuard {
            address: address.clone(),
            channels: ctx.channels.clone(),
            tasks: ctx.channel_tasks.clone(),
        };
        let peer = address.clone();
        let incoming = ctx.incoming.clone();
        let timeouts = ctx.timeouts;
        let task = tokio::spawn(async move {
            let _guard = guard;
            if let Err(error) = ble::coc_session::run_command_channel(
                channel.stream,
                session_key,
                peer.clone(),
                out_rx,
                incoming,
                timeouts,
            )
            .await
            {
                warn!(address = %peer, "Command channel ended: {error:#}");
            }
        });
        lock_or_recover(&ctx.channel_tasks).insert(address, task);

        // Catch up when playback already started before the channel opened: the
        // media event is edge-based, so without this the first handoff after a
        // daemon start would be skipped.
        if let Some(buds_address) = ctx.buds_address
            && ctx.local_playback.load(Ordering::Relaxed) {
                request_buds_switch(
                    &adapter,
                    buds_address,
                    &ctx.channels,
                    &ctx.switch_state,
                    ctx.dwell,
                )
                .await;
            }
    });
}

/// Watches the Buds' BlueZ device and mirrors its connection state into the
/// advertisement. While this PC owns the Buds the type 3 AD record carries the
/// Buds' advertisement id; when they leave, the record is cleared so the phone
/// does not keep targeting this PC.
async fn watch_buds_ownership(
    adapter: Arc<Adapter>,
    buds_address: bluer::Address,
    adv_id: u16,
    tx: mpsc::Sender<ble::AdvUpdate>,
    local_playback: Arc<std::sync::atomic::AtomicBool>,
    switch_state: Arc<tokio::sync::Mutex<SwitchState>>,
) {
    use futures::StreamExt;

    let mut last: Option<bool> = None;
    loop {
        let device = match adapter.device(buds_address) {
            Ok(device) => device,
            Err(error) => {
                warn!(%buds_address, "Could not resolve the Buds device: {error}");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        let connected = device.is_connected().await.unwrap_or(false);
        if last != Some(connected) {
            last = Some(connected);
            let buds = connected.then_some(ble::BudsAdRecord {
                adv_id,
                flags: ble::BUDS_AD_FLAGS_CONNECTED,
            });
            info!(%buds_address, connected, "Buds ownership changed; updating the advertisement");
            if !connected {
                release_local_playback(&local_playback, &switch_state).await;
            }
            if tx.send(ble::AdvUpdate::Buds(buds)).await.is_err() {
                return;
            }
        }

        let mut events = match device.events().await {
            Ok(events) => events,
            Err(error) => {
                warn!(%buds_address, "Could not watch the Buds device: {error}");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        while let Some(event) = events.next().await {
            if let bluer::DeviceEvent::PropertyChanged(bluer::DeviceProperty::Connected(connected)) =
                event
            {
                if last == Some(connected) {
                    continue;
                }
                last = Some(connected);
                let buds = connected.then_some(ble::BudsAdRecord {
                    adv_id,
                    flags: ble::BUDS_AD_FLAGS_CONNECTED,
                });
                info!(%buds_address, connected, "Buds ownership changed; updating the advertisement");
                if !connected {
                    release_local_playback(&local_playback, &switch_state).await;
                }
                if tx.send(ble::AdvUpdate::Buds(buds)).await.is_err() {
                    return;
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// Pauses local playback after the Buds leave this PC, so the next local play
/// produces a clean `AudioStarted` edge and the dwell gate applies.
async fn release_local_playback(
    local_playback: &Arc<std::sync::atomic::AtomicBool>,
    switch_state: &Arc<tokio::sync::Mutex<SwitchState>>,
) {
    if local_playback.swap(false, Ordering::Relaxed) {
        info!("Buds left Linux; pausing local media to reset the playback edge");
        if let Err(error) = media::MprisController::pause_all().await {
            warn!("Could not pause MPRIS players after the Buds left: {error}");
        }
    }
    // [FR-010] The yield folds into the dwell timestamp instead of a separate
    // cooldown constant.
    switch_state.lock().await.last_request = Some(Instant::now());
}

/// Finds a paired BlueZ device whose name mentions the Buds.
async fn discover_buds_address(adapter: &Arc<Adapter>) -> Option<String> {
    let addresses = adapter.device_addresses().await.ok()?;
    for address in addresses {
        let Ok(device) = adapter.device(address) else {
            continue;
        };
        let name = device.name().await.ok().flatten().unwrap_or_default();
        if name.to_ascii_lowercase().contains("buds") {
            info!(%address, name, "Discovered the Buds from BlueZ");
            return Some(address.to_string());
        }
    }
    warn!("No BlueZ device with \"Buds\" in its name; set buds_mac in config.toml");
    None
}

/// Lifecycle signal for the session supervisor.
#[derive(Debug)]
enum LifecycleEvent {
    /// logind is preparing to suspend.
    Suspend,
    /// logind finished resuming.
    Resume,
    /// The adapter reported `Powered=false`.
    PoweredOff,
    /// The adapter reported `Powered=true`.
    PoweredOn,
    /// The D-Bus adapter watch died (bluetoothd restart or adapter removal).
    AdapterLost,
    /// A replacement adapter was acquired after a bus restart.
    AdapterAvailable(Arc<Adapter>),
}

/// Re-acquires the Bluetooth session and adapter after a bluetoothd restart.
///
/// [FR-023] Used by the supervisor's capped-backoff loop, which keeps the
/// recovery inside NFR-004's 60-second bound.
async fn reacquire_adapter(name: &str) -> Result<Arc<Adapter>> {
    let (_, adapter) = open_adapter(name).await?;
    Ok(Arc::new(adapter))
}

/// Opens a Bluetooth session and powers the named adapter on.
async fn open_adapter(name: &str) -> Result<(bluer::Session, Adapter)> {
    let session = bluer::Session::new()
        .await
        .context("open a Bluetooth session")?;
    let adapter = session
        .adapter(name)
        .with_context(|| format!("resolve Bluetooth adapter {name}"))?;
    adapter
        .set_powered(true)
        .await
        .context("power the Bluetooth adapter on")?;
    Ok((session, adapter))
}

/// Acquires the Bluetooth session and adapter at startup, waiting for BlueZ.
///
/// [FR-003] A unit that starts before bluetoothd retries the session, adapter
/// resolution, and power-on with the supervisor's capped backoff (1 s doubling
/// to 60 s) instead of exiting on the first failure. The loop stays inside
/// NFR-004's 60-second bound and then returns the last error so the unit's
/// `Restart=on-failure` continues the wait.
async fn acquire_startup_adapter(name: &str) -> Result<(bluer::Session, Adapter)> {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut delay = Duration::from_secs(1);
    loop {
        match open_adapter(name).await {
            Ok(adapter) => return Ok(adapter),
            Err(error) => {
                if Instant::now() >= deadline {
                    error!("Bluetooth adapter {name} did not become available within 60 s");
                    return Err(error.context(format!(
                        "Bluetooth adapter {name} did not become available within 60 s"
                    )));
                }
                warn!("Bluetooth is not ready yet ({error:#}); retrying in {delay:?}");
            }
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(60));
    }
}

/// Watches logind `PrepareForSleep` and the adapter `Powered` property.
///
/// [FR-009] A failed logind or adapter watch degrades with a warning instead of
/// stopping the daemon.
fn start_lifecycle_supervisor(
    adapter_name: String,
    adapter: Arc<Adapter>,
) -> mpsc::Receiver<LifecycleEvent> {
    let (tx, rx) = mpsc::channel(8);

    // logind: PrepareForSleep(true) precedes suspend, (false) follows resume.
    let sleep_tx = tx.clone();
    tokio::spawn(async move {
        let connection = match zbus::Connection::system().await {
            Ok(connection) => connection,
            Err(error) => {
                warn!("logind is unavailable; suspend teardown is disabled: {error}");
                return;
            }
        };
        let rule = match zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .interface("org.freedesktop.login1.Manager")
            .and_then(|builder| builder.member("PrepareForSleep"))
        {
            Ok(builder) => builder.build(),
            Err(error) => {
                warn!("Could not build the logind sleep match rule: {error}");
                return;
            }
        };
        let mut stream =
            match zbus::MessageStream::for_match_rule(rule, &connection, Some(8)).await {
                Ok(stream) => stream,
                Err(error) => {
                    warn!("Could not watch logind PrepareForSleep: {error}");
                    return;
                }
            };
        while let Some(message) = stream.next().await {
            let start = match message
                .and_then(|message| message.body().deserialize::<(bool,)>())
            {
                Ok((start,)) => start,
                Err(error) => {
                    warn!("Ignoring a malformed logind sleep signal: {error}");
                    continue;
                }
            };
            let event = if start {
                LifecycleEvent::Suspend
            } else {
                LifecycleEvent::Resume
            };
            if sleep_tx.send(event).await.is_err() {
                return;
            }
        }
    });

    // Adapter power and bus watcher.
    tokio::spawn(async move {
        let mut current = adapter;
        loop {
            match current.events().await {
                Ok(mut events) => {
                    while let Some(event) = events.next().await {
                        if let bluer::AdapterEvent::PropertyChanged(
                            bluer::AdapterProperty::Powered(powered),
                        ) = event
                        {
                            let lifecycle = if powered {
                                LifecycleEvent::PoweredOn
                            } else {
                                LifecycleEvent::PoweredOff
                            };
                            if tx.send(lifecycle).await.is_err() {
                                return;
                            }
                        }
                    }
                    warn!("Adapter event stream ended; re-acquiring the Bluetooth session");
                }
                Err(error) => warn!("Could not watch the adapter power state: {error}"),
            }

            if tx.send(LifecycleEvent::AdapterLost).await.is_err() {
                return;
            }

            let mut delay = Duration::from_secs(1);
            loop {
                tokio::time::sleep(delay).await;
                match reacquire_adapter(&adapter_name).await {
                    Ok(adapter) => {
                        info!("Bluetooth session re-acquired");
                        if tx
                            .send(LifecycleEvent::AdapterAvailable(adapter.clone()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                        current = adapter;
                        break;
                    }
                    Err(error) => {
                        warn!(
                            "Bluetooth re-acquisition failed ({error:#}); retrying in {delay:?}"
                        );
                        delay = (delay * 2).min(Duration::from_secs(60));
                    }
                }
            }
        }
    });

    rx
}

/// Supervised transport sessions: scan, advertiser, and ownership watch.
///
/// [FR-009] Each start bumps the epoch and first tears down any leftover
/// session, so repeated sleep/wake cycles converge to exactly one of each.
struct TransportSessions {
    adapter: Arc<Adapter>,
    ble_tx: mpsc::Sender<ble::BleAdvEvent>,
    fingerprint: Option<Vec<u8>>,
    peer_limit: usize,
    buds_address: Option<[u8; 6]>,
    channels: CommandChannels,
    channel_tasks: ChannelTasks,
    local_playback: Arc<AtomicBool>,
    switch_state: Arc<tokio::sync::Mutex<SwitchState>>,
    epoch: u64,
    scan: Option<JoinHandle<()>>,
    advertiser: Option<(JoinHandle<()>, mpsc::Sender<ble::AdvUpdate>)>,
    ownership: Option<JoinHandle<()>>,
}

impl TransportSessions {
    #[allow(clippy::too_many_arguments)]
    fn new(
        adapter: Arc<Adapter>,
        ble_tx: mpsc::Sender<ble::BleAdvEvent>,
        fingerprint: Option<Vec<u8>>,
        peer_limit: usize,
        buds_address: Option<[u8; 6]>,
        channels: CommandChannels,
        channel_tasks: ChannelTasks,
        local_playback: Arc<AtomicBool>,
        switch_state: Arc<tokio::sync::Mutex<SwitchState>>,
    ) -> Self {
        Self {
            adapter,
            ble_tx,
            fingerprint,
            peer_limit,
            buds_address,
            channels,
            channel_tasks,
            local_playback,
            switch_state,
            epoch: 0,
            scan: None,
            advertiser: None,
            ownership: None,
        }
    }

    /// Sender for audio and Buds advertisement updates, when advertising runs.
    fn advertiser_sender(&self) -> Option<mpsc::Sender<ble::AdvUpdate>> {
        self.advertiser.as_ref().map(|(_, sender)| sender.clone())
    }

    /// Replaces the adapter after a Bluetooth session re-acquisition.
    fn replace_adapter(&mut self, adapter: Arc<Adapter>) {
        self.adapter = adapter;
    }

    /// Starts exactly one scan, advertiser, and ownership watcher.
    async fn start(&mut self) -> Result<()> {
        self.stop().await;
        self.epoch = self.epoch.wrapping_add(1);
        let keys = ble::scanning_keys(self.fingerprint.as_deref());
        self.scan = Some(
            ble::start_ble_scan(
                self.adapter.clone(),
                self.ble_tx.clone(),
                keys,
                self.peer_limit,
            )
            .await?,
        );
        self.advertiser = self.spawn_advertiser();
        self.ownership = self.spawn_ownership();
        info!(epoch = self.epoch, "Transport sessions started");
        Ok(())
    }

    /// Registers the MCF advertisement for the enrolled account.
    fn spawn_advertiser(&self) -> Option<(JoinHandle<()>, mpsc::Sender<ble::AdvUpdate>)> {
        let fingerprint = self.fingerprint.clone()?;
        let key_derivation = auth::ble_keys::BleKeyDerivation::new(fingerprint);
        let (tx, rx) = mpsc::channel::<ble::AdvUpdate>(8);
        let adapter = self.adapter.clone();
        let epoch = self.epoch;
        let task = tokio::spawn(async move {
            if let Err(error) = ble::advertiser_task(adapter, key_derivation, rx).await {
                error!(epoch, "BLE advertiser stopped: {error:#}");
            }
        });
        Some((task, tx))
    }

    /// Mirrors Buds ownership into the advertisement's type 3 record.
    fn spawn_ownership(&self) -> Option<JoinHandle<()>> {
        let buds_address = self.buds_address?;
        let tx = self.advertiser_sender()?;
        let adapter = self.adapter.clone();
        let playback = self.local_playback.clone();
        let state = self.switch_state.clone();
        let epoch = self.epoch;
        let buds_string = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            buds_address[0],
            buds_address[1],
            buds_address[2],
            buds_address[3],
            buds_address[4],
            buds_address[5]
        );
        Some(tokio::spawn(async move {
            let Ok(buds_device) = buds_string.parse() else {
                warn!(
                    %buds_string,
                    epoch,
                    "Could not parse the Buds address for ownership tracking"
                );
                return;
            };
            watch_buds_ownership(
                adapter,
                buds_device,
                ble::coc_session::advertisement_id(buds_address),
                tx,
                playback,
                state,
            )
            .await;
        }))
    }

    /// Tears down every session and command channel.
    async fn stop(&mut self) {
        if let Some(task) = self.scan.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some((task, _)) = self.advertiser.take() {
            // Abort-and-join drops the advertisement handle, which unregisters
            // the advertisement before a restart.
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = self.ownership.take() {
            task.abort();
            let _ = task.await;
        }
        // The aborted scan task dropped its discovery stream, which stops the
        // BlueZ discovery session before a restart re-applies the filter.

        let tasks: Vec<JoinHandle<()>> = lock_or_recover(&self.channel_tasks)
            .drain()
            .map(|(_, task)| task)
            .collect();
        lock_or_recover(&self.channels).clear();
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
    }
}

/// Restarts the transport sessions with capped backoff for up to 60 seconds.
///
/// [FR-009] Keeps the recovery inside NFR-004's bound after a wake or a
/// bluetoothd restart even when the first restart attempt races BlueZ.
async fn restart_transport_with_backoff(transport: &mut TransportSessions) -> bool {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut delay = Duration::from_secs(1);
    loop {
        match transport.start().await {
            Ok(()) => return true,
            Err(error) => {
                warn!("Could not start the transport sessions ({error:#}); retrying in {delay:?}");
            }
        }
        if Instant::now() >= deadline {
            error!("Transport sessions did not restart within 60 s");
            return false;
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(60));
    }
}

async fn handle_action(
    action: HandoffAction,
    dry_run: &bool,
    spp: &mpsc::Sender<rfcomm::SppCommand>,
    adapter: &Arc<Adapter>,
    buds_address: Option<[u8; 6]>,
) {
    if *dry_run {
        info!("[DRY RUN] Would execute action: {:?}", action);
        return;
    }

    match action {
        HandoffAction::YieldToPhone => {
            info!("=== HANDOFF: Yielding to Phone ===");
            // [FR-019] Verify the pause and complete the Buds profile teardown
            // before the phone is told the Buds are free.
            let paused = pause_media_verified().await;
            if !paused {
                warn!("Local playback did not pause cleanly; releasing the Buds anyway");
            }
            match buds_address {
                Some(address) => {
                    if teardown_buds_profiles(adapter, address).await {
                        debug!("Buds A2DP and HFP links released");
                    } else {
                        warn!("Buds profile teardown was incomplete");
                    }
                }
                None => warn!("No Buds address is configured; cannot release the local audio links"),
            }
            // [FR-013] The yield path delivers SET_SEAMLESS_CONNECTION over SPP.
            send_seamless(spp, true).await;
            info!("Phone should now connect to Buds");
        }
        HandoffAction::ClaimBuds => {
            info!("=== HANDOFF: Linux requested the Buds ===");
            debug!("The phone's BudsSwitchResponse triggers the A2DP pull to Linux");
        }
        HandoffAction::PhoneReady => {
            info!("Phone is ready for Linux to take over");
            // Connect A2DP
        }
        HandoffAction::SetSeamless(enable) => {
            info!("Setting seamless connection on Buds: {}", enable);
            send_seamless(spp, enable).await;
        }
        HandoffAction::SendHandoffCommand(data) => {
            // [FR-013] Phone-directed commands stay on the BLE CoC; SPP carries
            // Buds opcodes only, so this payload is not written to the Buds.
            debug!(
                bytes = data.len(),
                "Phone-directed handoff command stays on the BLE CoC"
            );
        }
    }
}

/// Sends one SET_SEAMLESS_CONNECTION opcode to the Buds over SPP.
async fn send_seamless(spp: &mpsc::Sender<rfcomm::SppCommand>, enable: bool) {
    if spp
        .send(rfcomm::SppCommand::SetSeamlessConnection { enable })
        .await
        .is_err()
    {
        warn!("The Buds SPP session is not running; SET_SEAMLESS_CONNECTION was dropped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_attempt_is_allowed() {
        assert!(dial_allowed(None, Instant::now()));
    }

    #[test]
    fn attempt_before_the_backoff_is_rejected() {
        let now = Instant::now();
        let start = Duration::from_secs(1);
        let cap = Duration::from_secs(60);
        let attempt = DialAttempt {
            failures: 1,
            next_allowed: Some(now + dial_backoff(1, start, cap)),
        };
        assert!(!dial_allowed(Some(&attempt), now));
    }

    #[test]
    fn attempt_after_the_backoff_is_allowed() {
        let now = Instant::now();
        let attempt = DialAttempt {
            failures: 1,
            next_allowed: Some(now - Duration::from_millis(1)),
        };
        assert!(dial_allowed(Some(&attempt), now));
    }

    #[test]
    fn backoff_doubles_from_one_second_to_the_cap() {
        let start = Duration::from_secs(1);
        let cap = Duration::from_secs(60);
        assert_eq!(dial_backoff(0, start, cap), Duration::from_secs(1));
        assert_eq!(dial_backoff(1, start, cap), Duration::from_secs(2));
        assert_eq!(dial_backoff(2, start, cap), Duration::from_secs(4));
        assert_eq!(dial_backoff(3, start, cap), Duration::from_secs(8));
        assert_eq!(dial_backoff(10, start, cap), Duration::from_secs(60));
        assert_eq!(dial_backoff(100, start, cap), Duration::from_secs(60));
    }

    #[test]
    fn dwell_suppresses_requests_inside_the_window() {
        let now = Instant::now();
        let dwell = Duration::from_secs(10);
        let state = SwitchState {
            last_request: Some(now - Duration::from_secs(5)),
            call: handoff::CallGuard::default(),
        };
        assert!(!state.dwell_elapsed(now, dwell));
        assert!(!state.may_request(now, dwell, handoff::SwitchReason::Media));
    }

    #[test]
    fn dwell_allows_requests_at_or_past_the_window() {
        let now = Instant::now();
        let dwell = Duration::from_secs(10);
        let state = SwitchState {
            last_request: Some(now - dwell),
            call: handoff::CallGuard::default(),
        };
        assert!(state.dwell_elapsed(now, dwell));
        assert!(state.may_request(now, dwell, handoff::SwitchReason::Media));
    }

    #[test]
    fn an_hfp_call_blocks_media_requests_but_not_call_requests() {
        let now = Instant::now();
        let dwell = Duration::from_secs(10);
        let mut state = SwitchState {
            last_request: Some(now - dwell),
            call: handoff::CallGuard::default(),
        };
        state.call.call_started();
        assert!(!state.may_request(now, dwell, handoff::SwitchReason::Media));
        assert!(state.may_request(now, dwell, handoff::SwitchReason::Call));
    }

    #[test]
    fn a_media_response_does_not_clear_a_call_guard() {
        let now = Instant::now();
        let mut state = SwitchState {
            last_request: Some(now - Duration::from_secs(10)),
            call: handoff::CallGuard::default(),
        };
        state.call.call_started();
        state.call.expect_call_response(0x1234, [1, 2, 3, 4, 5, 6], now);
        assert_eq!(
            state.call.on_response(0x5678, [1, 2, 3, 4, 5, 6], now),
            handoff::SwitchReason::Media
        );
        assert!(!state.may_request(now, Duration::from_secs(10), handoff::SwitchReason::Media));
    }
}
