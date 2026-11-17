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
mod handoff;
mod media;
mod protocol;
mod rfcomm;
mod sdp;
mod setup;

use anyhow::Result;
use bluer::Adapter;
use clap::Parser;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
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
    },

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

    if let Some(Commands::Setup { reauth }) = cli.command.as_ref() {
        return setup::run(&cli, *reauth).await;
    }
    if let Some(Commands::AuthCallback { url }) = cli.command.as_ref() {
        return auth::browser::send_callback(url).await;
    }
    let file_config = config::load();
    if cli.phone.is_empty() {
        cli.phone = file_config
            .phone_mac
            .or_else(|| config::discover_phone(auth::Credentials::load().ok().flatten().as_ref()))
            .unwrap_or_default();
    }
    if cli.buds.is_empty() {
        cli.buds = file_config.buds_mac.unwrap_or_default();
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
    let session = bluer::Session::new().await?;
    let adapter = session.adapter(&cli.adapter)?;
    adapter.set_powered(true).await?;
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

    // Only probe legacy Classic SDP records when --debug is enabled; One UI 6+
    // uses BLE L2CAP CoC exclusively, and sdptool adds ~1s of startup latency.
    if cli.debug {
        sdp::register_sdp_record().await?;
        let phone_sdp = sdp::query_remote_sdp(&cli.phone).await?;
        let continuity_found = phone_sdp.iter().any(|r| r.is_continuity);
        if continuity_found {
            info!("CONTINUITY_MSG_SPP found on phone SDP records");
        } else {
            debug!("CONTINUITY_MSG_SPP not found on phone SDP records (using BLE L2CAP CoC)");
        }
    }

    // Create event channels
    let (ble_tx, mut ble_rx) = mpsc::channel::<ble::BleAdvEvent>(64);
    let (_rfcomm_tx, mut rfcomm_rx) = mpsc::channel::<rfcomm::RfcommEvent>(64);
    let (media_tx, mut media_rx) = mpsc::channel::<media::MediaEvent>(32);

    // Start BLE scanner with the scan-side keys so phone advertisements can be
    // deobfuscated and their CoC PSM read.
    let fingerprint = account_fingerprint(&cli);
    let scan_keys = ble::scanning_keys(fingerprint.as_deref());
    let refresh_keys = scan_keys.clone();
    ble::start_ble_scan(adapter.clone(), ble_tx, scan_keys).await?;

    // Start the MCF advertiser with the enrolled account identity.
    let mut advertise_state_tx: Option<mpsc::Sender<ble::AdvUpdate>> = None;
    match fingerprint {
        Some(fingerprint) => {
            let key_derivation = auth::ble_keys::BleKeyDerivation::new(fingerprint);
            let (tx, rx) = mpsc::channel::<ble::AdvUpdate>(8);
            let advertise_adapter = adapter.clone();
            tokio::spawn(async move {
                if let Err(e) = ble::advertiser_task(advertise_adapter, key_derivation, rx).await {
                    error!("BLE advertiser stopped: {e:#}");
                }
            });
            advertise_state_tx = Some(tx);
        }
        None => warn!("No Samsung account fingerprint available, BLE advertiser disabled"),
    }

    // Start media monitor
    media::monitor_pipewire(media_tx).await?;

    // Initialize handoff state machine
    let config = HandoffConfig {
        phone_address: cli.phone.clone(),
        buds_address: cli.buds.clone(),
        auto_switch_enabled: !cli.monitor_only,
        priority: DevicePriority::PhoneWins,
    };
    let state_machine = Arc::new(tokio::sync::Mutex::new(HandoffStateMachine::new(config)));

    // Active command channels over authenticated BLE L2CAP CoC, keyed by peer
    // address. The stream itself lives in the command-channel task.
    let command_channels: Arc<
        tokio::sync::Mutex<HashMap<String, mpsc::Sender<ble::coc_session::CommandRequest>>>,
    > = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
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
    let local_playback = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Mirror Buds ownership into the advertisement's type 3 AD record so the
    // phone can map this PC to the Buds and target it for a handoff. A
    // disconnect that we did not initiate pauses local media, resets the
    // playback edge, and arms the yield cooldown.
    if let (Some(advertise_tx), Some(address)) = (advertise_state_tx.clone(), buds_address) {
        let watcher_adapter = adapter.clone();
        let buds_string = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            address[0], address[1], address[2], address[3], address[4], address[5]
        );
        let adv_id = ble::coc_session::advertisement_id(address);
        let playback = local_playback.clone();
        let state = switch_state.clone();
        let sm = state_machine.clone();
        tokio::spawn(async move {
            let Ok(buds_device) = buds_string.parse() else {
                warn!(%buds_string, "Could not parse the Buds address for ownership tracking");
                return;
            };
            watch_buds_ownership(
                watcher_adapter,
                buds_device,
                adv_id,
                advertise_tx,
                playback,
                state,
                sm,
            )
            .await;
        });
    }
    let mut l2cap_attempts: HashMap<String, Instant> = HashMap::new();
    // Last peer that advertised a CoC PSM, used to retry the authenticated
    // channel without waiting for a fresh advertisement.
    let mut last_coc_target: Option<(ble::BleAdvEvent, u16)> = None;
    let mut reconnect_timer = tokio::time::interval(Duration::from_secs(15));
    reconnect_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    reconnect_timer.tick().await;

    // Main event loop
    info!("Entering main event loop");

    loop {
        tokio::select! {
            Some(ble_event) = ble_rx.recv() => {
                if ble_event.address.eq_ignore_ascii_case(&cli.buds) {
                    switch_state.lock().await.last_connect_failure = None;
                }
                if ble_event.address.eq_ignore_ascii_case(&cli.phone) {
                    let is_ble_call = ble_event.context.is_some_and(|ctx| ctx.device_state == 2);
                    if is_ble_call {
                        let currently_playing =
                            local_playback.load(std::sync::atomic::Ordering::Relaxed);
                        switch_state
                            .lock()
                            .await
                            .mark_call_started(Instant::now(), currently_playing);
                    }
                    let phone_now_idle = ble_event.audio_state == AudioState::Idle
                        && ble_event.context.is_some_and(|ctx| ctx.device_state == 0);
                    let should_resume = if phone_now_idle {
                        switch_state.lock().await.on_phone_call_ended()
                    } else {
                        false
                    };
                    if should_resume {
                        info!("Phone call ended; resuming local media and requesting Buds back");
                        if let Some(buds_address) = buds_address {
                            request_buds_switch(
                                &adapter,
                                buds_address,
                                &command_channels,
                                &*switch_state.lock().await,
                            )
                            .await;
                        }
                        if let Err(e) = media::MprisController::resume_all().await {
                            warn!("Could not resume MPRIS players after phone call: {e}");
                        }
                    }
                }
                let mut sm = state_machine.lock().await;
                if let Some(action) = sm.on_ble_event(&ble_event) {
                    handle_action(
                        action,
                        &cli.dry_run,
                        &adapter,
                        buds_address,
                        &switch_state,
                        &local_playback,
                        &advertise_state_tx,
                        &mut sm,
                    )
                    .await;
                }
                drop(sm);
                if let Some(psm) = ble_event.coc_psm {
                    last_coc_target = Some((ble_event.clone(), psm));
                    maybe_connect_coc(
                        adapter.clone(),
                        &ble_event,
                        psm,
                        &command_channels,
                        &mut l2cap_attempts,
                        command_in_tx.clone(),
                        buds_address,
                        local_playback.clone(),
                        switch_state.clone(),
                    )
                    .await;
                }
            }
            Some(rfcomm_event) = rfcomm_rx.recv() => {
                let mut sm = state_machine.lock().await;
                if let Some(action) = sm.on_rfcomm_event(&rfcomm_event) {
                    handle_action(
                        action,
                        &cli.dry_run,
                        &adapter,
                        buds_address,
                        &switch_state,
                        &local_playback,
                        &advertise_state_tx,
                        &mut sm,
                    )
                    .await;
                }
            }
            Some((peer, incoming)) = command_in_rx.recv() => {
                if let Some(buds_address) = buds_address {
                    handle_incoming_command(
                        &adapter,
                        buds_address,
                        &peer,
                        incoming,
                        &command_channels,
                        &mut *switch_state.lock().await,
                        &state_machine,
                        &local_playback,
                        &advertise_state_tx,
                    )
                    .await;
                }
            }
            _ = reconnect_timer.tick() => {
                // Re-establish a dropped command channel. Never dial from a
                // cached PSM: read the phone's current advertisement first so a
                // restarted mcfds server or a rotated address is picked up.
                if let Some((event, cached_psm)) = last_coc_target.clone()
                    && !command_channels.lock().await.contains_key(&event.address) {
                        let fresh_psm = match event.address.parse::<bluer::Address>() {
                            Ok(address) => {
                                ble::read_phone_coc_psm(&adapter, &address, &refresh_keys).await
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
                                    adapter.clone(),
                                    &event,
                                    psm,
                                    &command_channels,
                                    &mut l2cap_attempts,
                                    command_in_tx.clone(),
                                    buds_address,
                                    local_playback.clone(),
                                    switch_state.clone(),
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
                if let Some(tx) = &advertise_state_tx {
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
                        local_playback.store(
                            matches!(state, AudioState::Streaming),
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        let _ = tx.try_send(ble::AdvUpdate::Audio(state));
                    }
                }
                let playback_allowed = if is_playback_start(&media_event) {
                    switch_state.lock().await.may_request(Instant::now())
                } else {
                    true
                };
                if !playback_allowed {
                    continue;
                }
                // Ask the phone to hand the Buds over when Linux starts playing.
                if is_playback_start(&media_event)
                    && let Some(buds_address) = buds_address {
                        request_buds_switch(
                            &adapter,
                            buds_address,
                            &command_channels,
                            &*switch_state.lock().await,
                        )
                        .await;
                    }
                let mut sm = state_machine.lock().await;
                let action = match &media_event {
                    media::MediaEvent::AudioStarted { .. } => sm.on_local_media_start(),
                    media::MediaEvent::AudioStopped { .. } => sm.on_local_media_stop(),
                    media::MediaEvent::PlayerStateChanged { playing: false, .. } => {
                        sm.on_local_media_stop()
                    }
                    _ => None,
                };
                if let Some(action) = action {
                    handle_action(
                        action,
                        &cli.dry_run,
                        &adapter,
                        buds_address,
                        &switch_state,
                        &local_playback,
                        &advertise_state_tx,
                        &mut sm,
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
        println!("Account key: {}", hex::encode(bundle.account_key));
        println!(
            "Enrolled device: {} ({})",
            bundle.this_device.bt_address, bundle.this_device.device_name
        );
        println!("User fingerprint: {}", bundle.user_fingerprint);
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
        info!(
            current = %stored.device_name,
            desired = %desired,
            "Device name changed; refreshing Samsung Continuity certificate in background"
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

/// Delay before retrying a failed CoC connect to the same peer.
const COC_RETRY_INTERVAL: Duration = Duration::from_secs(30);

/// Upper bound on the account handshake exchange.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

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

/// Whether a CoC connect attempt to a peer may start now: the last attempt, if
/// any, must be older than [`COC_RETRY_INTERVAL`]. The channel-present check is
/// done by the caller against the open-channel map.
fn attempt_allowed(last_attempt: Option<Instant>, now: Instant) -> bool {
    last_attempt.is_none_or(|attempt| now.duration_since(attempt) >= COC_RETRY_INTERVAL)
}

/// Cooldown after yielding the Buds to the phone. Suppresses a local playback
/// start (for example a notification sound) from immediately stealing them back.
const YIELD_COOLDOWN: Duration = Duration::from_secs(5);

/// Cooldown after failing to connect the Buds A2DP profile (for example when
/// the Buds are asleep inside the closed charging case).
const CONNECT_FAILURE_COOLDOWN: Duration = Duration::from_secs(45);

/// Upper bound on an active call session guard. A reason-2 handoff marks the
/// session as a phone call; the guard clears on the phone's response and this
/// timeout protects against a lost response.
const CALL_GUARD: Duration = Duration::from_secs(30 * 60);

/// Window within which a direct HFP disconnect while local media was playing is
/// correlated with a subsequent phone `AudioState::Call` advertisement.
const CALL_YIELD_CORRELATION: Duration = Duration::from_secs(15);

/// A2DP Sink profile UUID (`0000110b-...`), the audio link the Buds use.
const A2DP_SINK_UUID: &str = "0000110b-0000-1000-8000-00805f9b34fb";

/// Handsfree profile UUID (`0000111e-...`), disconnected on a call handoff.
const HFP_UUID: &str = "0000111e-0000-1000-8000-00805f9b34fb";

/// Handoff bookkeeping between local playback and the phone's requests.
#[derive(Default)]
struct SwitchState {
    /// When the Buds were last yielded to the phone.
    last_yield: Option<Instant>,
    /// While set in the future, a phone call owns the Buds and local playback
    /// starts are ignored.
    call_active_until: Option<Instant>,
    /// When the last A2DP connect attempt to the Buds failed (e.g. Buds in case).
    last_connect_failure: Option<Instant>,
    /// When local playback was paused due to the Buds leaving Linux.
    was_playing_on_yield: Option<Instant>,
    /// Whether the phone is currently in a voice/video call.
    phone_in_call: bool,
    /// Whether Linux playback should be resumed when the phone call ends.
    resume_after_call: bool,
}

impl SwitchState {
    /// True when the phone call session currently owns the Buds.
    fn call_active(&self, now: Instant) -> bool {
        self.call_active_until
            .is_some_and(|until| now < until)
    }

    /// Records that a phone call started and remembers whether Linux was
    /// playing media when the call interrupted it.
    fn mark_call_started(&mut self, now: Instant, currently_playing: bool) {
        let recently_yielded_playing = self
            .was_playing_on_yield
            .is_some_and(|t| now.duration_since(t) <= CALL_YIELD_CORRELATION);
        if currently_playing || recently_yielded_playing {
            self.resume_after_call = true;
        }
        self.phone_in_call = true;
        self.call_active_until = Some(now + CALL_GUARD);
    }

    /// Clears call state when the phone returns to `AudioState::Idle` and
    /// returns `true` when local media should be resumed and the Buds reclaimed.
    fn on_phone_call_ended(&mut self) -> bool {
        if !self.phone_in_call {
            return false;
        }
        self.phone_in_call = false;
        self.call_active_until = None;
        self.was_playing_on_yield = None;
        if self.resume_after_call {
            self.resume_after_call = false;
            self.last_yield = None;
            return true;
        }
        false
    }

    /// True when a local playback start may ask for the Buds.
    fn may_request(&self, now: Instant) -> bool {
        if self.call_active(now) {
            info!("Ignoring local playback start: a phone call session owns the Buds");
            return false;
        }
        if self
            .last_yield
            .is_some_and(|yielded| now.duration_since(yielded) < YIELD_COOLDOWN)
        {
            info!("Ignoring local playback start: within the yield cooldown");
            return false;
        }
        if self
            .last_connect_failure
            .is_some_and(|failed| now.duration_since(failed) < CONNECT_FAILURE_COOLDOWN)
        {
            info!("Ignoring local playback start: Buds appear unreachable (in case or offline)");
            return false;
        }
        true
    }
}

/// Disconnects A2DP and HFP profiles from the Buds so the phone can claim them.
async fn disconnect_buds_profiles(adapter: &Arc<Adapter>, buds_address: [u8; 6]) {
    let buds_string = format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        buds_address[0],
        buds_address[1],
        buds_address[2],
        buds_address[3],
        buds_address[4],
        buds_address[5]
    );
    if let Ok(device) = adapter.device(buds_string.parse().unwrap()) {
        for uuid in [A2DP_SINK_UUID, HFP_UUID] {
            let Ok(uuid) = uuid::Uuid::parse_str(uuid) else {
                continue;
            };
            if let Err(error) = device.disconnect_profile(&uuid).await {
                debug!(
                    profile = %uuid,
                    "Could not disconnect Buds profile: {error}"
                );
            }
        }
    }
}

/// True when a media event starts local playback.
fn is_playback_start(event: &media::MediaEvent) -> bool {
    matches!(
        event,
        media::MediaEvent::AudioStarted { .. }
            | media::MediaEvent::PlayerStateChanged { playing: true, .. }
    )
}

/// Asks the phone to hand the Buds to this PC.
///
/// Skipped when the Buds are already connected to Linux, during the yield
/// cooldown, and while a phone call session owns them.
async fn request_buds_switch(
    adapter: &Arc<Adapter>,
    buds_address: [u8; 6],
    channels: &Arc<
        tokio::sync::Mutex<HashMap<String, mpsc::Sender<ble::coc_session::CommandRequest>>>,
    >,
    state: &SwitchState,
) {
    if !state.may_request(Instant::now()) {
        return;
    }

    let buds_string = format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        buds_address[0],
        buds_address[1],
        buds_address[2],
        buds_address[3],
        buds_address[4],
        buds_address[5]
    );
    // Do not gate on the local `Connected` property: BlueZ keeps reporting a
    // partial link after the phone takes the Buds, which blocked every later
    // request. The phone decides whether to switch, so always ask.
    if adapter.device(buds_string.parse().unwrap()).is_err() {
        warn!(address = %buds_string, "Could not resolve the Buds device for a switch request");
        return;
    }

    let request = ble::coc_session::CommandRequest::BudsSwitch {
        adv_id: ble::coc_session::advertisement_id(buds_address),
        address: buds_address,
        reason: ble::coc_session::REASON_MEDIA,
    };
    let senders: Vec<_> = channels.lock().await.values().cloned().collect();
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

/// Applies Auto Switch traffic from the phone.
#[allow(clippy::too_many_arguments)]
async fn handle_incoming_command(
    adapter: &Arc<Adapter>,
    buds_address: [u8; 6],
    peer: &str,
    incoming: ble::coc_session::IncomingCommand,
    channels: &Arc<
        tokio::sync::Mutex<HashMap<String, mpsc::Sender<ble::coc_session::CommandRequest>>>,
    >,
    state: &mut SwitchState,
    state_machine: &Arc<tokio::sync::Mutex<HandoffStateMachine>>,
    local_playback: &Arc<std::sync::atomic::AtomicBool>,
    advertise_state_tx: &Option<mpsc::Sender<ble::AdvUpdate>>,
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
            media::MprisController::pause_all().await.ok();

            // Release the audio links first: the phone starts its own connection
            // when it processes the response, so an active Linux link would race.
            disconnect_buds_profiles(adapter, buds_address).await;

            let was_playing = local_playback.swap(false, std::sync::atomic::Ordering::Relaxed);
            if let Some(tx) = advertise_state_tx {
                let _ = tx.try_send(ble::AdvUpdate::Audio(AudioState::Idle));
            }
            let now = Instant::now();
            state.last_yield = Some(now);
            if was_playing {
                state.was_playing_on_yield = Some(now);
            }
            if reason == ble::coc_session::REASON_CALL {
                state.mark_call_started(now, was_playing);
                info!("Phone call session owns the Buds; local playback triggers paused");
            }
            state_machine.lock().await.on_handoff_complete(false);

            let response = ble::coc_session::CommandRequest::SwitchResponse {
                result: 1,
                adv_id,
                address,
            };
            if let Some(sender) = channels.lock().await.get(peer)
                && sender.send(response).await.is_err() {
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
            state.call_active_until = None;
            if result != 1 {
                warn!(result, "Phone rejected the Buds handoff request");
                return;
            }
            let buds_string = format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                buds_address[0],
                buds_address[1],
                buds_address[2],
                buds_address[3],
                buds_address[4],
                buds_address[5]
            );
            let Ok(device) = adapter.device(buds_string.parse().unwrap()) else {
                return;
            };
            let Ok(uuid) = uuid::Uuid::parse_str(A2DP_SINK_UUID) else {
                return;
            };
            info!(address = %buds_string, "Pulling the Buds A2DP link to Linux");
            match device.connect_profile(&uuid).await {
                Ok(()) => {
                    state.last_connect_failure = None;
                    state_machine.lock().await.on_handoff_complete(true);
                }
                Err(error) => {
                    warn!(address = %buds_string, "Could not connect the A2DP profile: {error}");
                    state.last_connect_failure = Some(Instant::now());
                    state_machine.lock().await.set_buds_connected(false);
                }
            }
        }
    }
}

/// Connect to a peer that advertised a CoC PSM.
///
/// Skips the attempt when a channel is already open or the last attempt failed
/// less than [`COC_RETRY_INTERVAL`] ago. The connect runs in its own task so a
/// slow or unreachable peer cannot stall the event loop. After a successful
/// handshake the stream moves into a command-channel task that sends the ready
/// event at once and then serves Auto Switch traffic. Credentials are reloaded
/// when each attempt is prepared, so a re-enrollment applies without a restart.
#[allow(clippy::too_many_arguments)]
async fn maybe_connect_coc(
    adapter: Arc<Adapter>,
    event: &ble::BleAdvEvent,
    psm: u16,
    channels: &Arc<
        tokio::sync::Mutex<HashMap<String, mpsc::Sender<ble::coc_session::CommandRequest>>>,
    >,
    attempts: &mut HashMap<String, Instant>,
    incoming: mpsc::Sender<(String, ble::coc_session::IncomingCommand)>,
    buds_address: Option<[u8; 6]>,
    local_playback: Arc<std::sync::atomic::AtomicBool>,
    switch_state: Arc<tokio::sync::Mutex<SwitchState>>,
) {
    let address = event.address.clone();
    if channels.lock().await.contains_key(&address) {
        return;
    }

    let now = Instant::now();
    if !attempt_allowed(attempts.get(&address).copied(), now) {
        return;
    }
    attempts.insert(address.clone(), now);

    let address_type = event.address_type;
    let channels = channels.clone();
    tokio::spawn(async move {
        // Reload the credential store when preparing each attempt, so a key
        // replaced by re-enrollment is used on the next attempt without a
        // daemon restart.
        let credentials = handshake_credentials();

        // Try to pair/bond with the device first only when not already paired.
        if let Ok(device) = adapter.device(address.parse().unwrap())
            && !device.is_paired().await.unwrap_or(false)
        {
            info!(address = %address, "Attempting BLE pairing");
            match device.pair().await {
                Ok(_) => info!(address = %address, "BLE pairing successful"),
                Err(e) => warn!(address = %address, "BLE pairing failed: {}", e),
            }
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
                        info!(address = %address, "Continuity account handshake complete");
                        session_key
                    }
                    Err(error) => {
                        warn!(address = %address, "Continuity account handshake failed: {error}");
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
        let (out_tx, out_rx) = mpsc::channel(8);
        let peer = address.clone();
        let task_channels = channels.clone();
        let incoming = incoming.clone();
        tokio::spawn(async move {
            if let Err(error) = ble::coc_session::run_command_channel(
                channel.stream,
                session_key,
                peer.clone(),
                out_rx,
                incoming,
            )
            .await
            {
                warn!(address = %peer, "Command channel ended: {error:#}");
            }
            task_channels.lock().await.remove(&peer);
        });
        channels.lock().await.insert(address, out_tx);

        // Catch up when playback already started before the channel opened: the
        // media event is edge-based, so without this the first handoff after a
        // daemon start would be skipped.
        if let Some(buds_address) = buds_address
            && local_playback.load(std::sync::atomic::Ordering::Relaxed) {
                let state = switch_state.lock().await;
                request_buds_switch(&adapter, buds_address, &channels, &state).await;
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
    state_machine: Arc<tokio::sync::Mutex<HandoffStateMachine>>,
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
            let was_connected = last == Some(true);
            last = Some(connected);
            state_machine.lock().await.set_buds_connected(connected);
            let buds = connected.then_some(ble::BudsAdRecord {
                adv_id,
                flags: ble::BUDS_AD_FLAGS_CONNECTED,
            });
            info!(%buds_address, connected, "Buds ownership changed; updating the advertisement");
            if connected {
                switch_state.lock().await.last_connect_failure = None;
            } else if was_connected {
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
                state_machine.lock().await.set_buds_connected(connected);
                let buds = connected.then_some(ble::BudsAdRecord {
                    adv_id,
                    flags: ble::BUDS_AD_FLAGS_CONNECTED,
                });
                info!(%buds_address, connected, "Buds ownership changed; updating the advertisement");
                if connected {
                    switch_state.lock().await.last_connect_failure = None;
                } else {
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
/// produces a clean `AudioStarted` edge and starts the anti-ping-pong cooldown.
async fn release_local_playback(
    local_playback: &Arc<std::sync::atomic::AtomicBool>,
    switch_state: &Arc<tokio::sync::Mutex<SwitchState>>,
) {
    let was_playing = local_playback.swap(false, std::sync::atomic::Ordering::Relaxed);
    if was_playing {
        info!("Buds left Linux; pausing local media to reset the playback edge");
        if let Err(error) = media::MprisController::pause_all().await {
            warn!("Could not pause MPRIS players after the Buds left: {error}");
        }
    }
    let now = Instant::now();
    let mut state = switch_state.lock().await;
    state.last_yield = Some(now);
    if was_playing {
        state.was_playing_on_yield = Some(now);
        if state.phone_in_call {
            state.resume_after_call = true;
        }
    }
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

#[allow(clippy::too_many_arguments)]
async fn handle_action(
    action: HandoffAction,
    dry_run: &bool,
    adapter: &Arc<Adapter>,
    buds_address: Option<[u8; 6]>,
    switch_state: &Arc<tokio::sync::Mutex<SwitchState>>,
    local_playback: &Arc<std::sync::atomic::AtomicBool>,
    advertise_state_tx: &Option<mpsc::Sender<ble::AdvUpdate>>,
    sm: &mut HandoffStateMachine,
) {
    if *dry_run {
        info!("[DRY RUN] Would execute action: {:?}", action);
        return;
    }

    match action {
        HandoffAction::YieldToPhone => {
            info!("=== HANDOFF: Yielding to Phone ===");
            // Pause local media
            if let Err(e) = media::MprisController::pause_all().await {
                error!("Failed to pause MPRIS players: {}", e);
            }
            if let Some(buds_address) = buds_address {
                disconnect_buds_profiles(adapter, buds_address).await;
            }
            let was_playing = local_playback.swap(false, std::sync::atomic::Ordering::Relaxed);
            if let Some(tx) = advertise_state_tx {
                let _ = tx.try_send(ble::AdvUpdate::Audio(AudioState::Idle));
            }
            let now = Instant::now();
            let mut state = switch_state.lock().await;
            state.last_yield = Some(now);
            if was_playing {
                state.was_playing_on_yield = Some(now);
                if state.phone_in_call {
                    state.resume_after_call = true;
                }
            }
            drop(state);
            sm.on_handoff_complete(false);
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
            // TODO: Send SET_SEAMLESS_CONNECTION via Buds SPP
        }
        HandoffAction::SendHandoffCommand(data) => {
            info!("Sending handoff command to phone ({} bytes)", data.len());
            // TODO: Send over RFCOMM
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_attempt_is_allowed() {
        assert!(attempt_allowed(None, Instant::now()));
    }

    #[test]
    fn attempt_within_retry_interval_is_rejected() {
        let now = Instant::now();
        assert!(!attempt_allowed(Some(now), now));
        assert!(!attempt_allowed(
            Some(now - COC_RETRY_INTERVAL / 2),
            now
        ));
    }

    #[test]
    fn attempt_after_retry_interval_is_allowed() {
        let now = Instant::now();
        assert!(attempt_allowed(Some(now - COC_RETRY_INTERVAL), now));
        assert!(attempt_allowed(
            Some(now - COC_RETRY_INTERVAL - Duration::from_secs(1)),
            now
        ));
    }

    #[test]
    fn connect_failure_cooldown_blocks_until_elapsed_or_cleared() {
        let now = Instant::now();
        let mut state = SwitchState {
            last_connect_failure: Some(now),
            ..Default::default()
        };
        assert!(!state.may_request(now + Duration::from_secs(10)));
        assert!(state.may_request(now + CONNECT_FAILURE_COOLDOWN + Duration::from_secs(1)));

        state.last_connect_failure = None;
        assert!(state.may_request(now));
    }

    #[test]
    fn call_interruption_resumes_when_phone_returns_to_idle() {
        let now = Instant::now();
        let mut state = SwitchState {
            was_playing_on_yield: Some(now),
            ..Default::default()
        };
        state.mark_call_started(now + Duration::from_secs(2), false);
        assert!(state.phone_in_call);
        assert!(state.resume_after_call);
        assert!(!state.may_request(now + Duration::from_secs(3)));

        assert!(state.on_phone_call_ended());
        assert!(!state.phone_in_call);
        assert!(!state.resume_after_call);
        assert!(state.may_request(now + Duration::from_secs(4)));
    }
}
