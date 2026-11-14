//! Browser sign-in with a passive WebDriver BiDi listener.
//!
//! Samsung ends the sign-in with a navigation to `ms-app://…/signInComplete`.
//! Linux has no handler for that scheme, so the browser aborts the navigation
//! and the callback never reaches the address bar. Gecko still reports the
//! attempt through BiDi: `browsingContext.navigationStarted` carries the full
//! destination URL. This module opens the desktop's default browser on the
//! sign-in page and listens for that event without driving the page.
//!
//! The profile is persistent (`$XDG_CACHE_HOME/seuil/browser-profile`) and
//! seeded from the user's real Zen profile so the browser never shows a
//! welcome or onboarding screen before the sign-in page.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use super::crypto;
use super::{AuthError, Result};

const BIDI_EVENTS: &[&str] = &[
    "browsingContext.navigationStarted",
    "browsingContext.navigationFailed",
    "browsingContext.navigationAborted",
    "browsingContext.contextCreated",
    "browsingContext.fragmentNavigated",
    "network.beforeRequestSent",
    "network.responseCompleted",
    "network.fetchError",
];
const CALLBACK_SCHEME: &str = "ms-app://";
const WEB_SOCKET_TIMEOUT: Duration = Duration::from_secs(3);
/// Cold-start Zen can take a while before the remote agent listens.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_HEADER_BYTES: usize = 16 * 1024;
const SEED_MARKER: &str = ".seuil-seeded";

/// Prefs forced on the throwaway-but-persistent profile. Mirrored welcome and
/// onboarding prefs from the user's own profile are written first.
const PROFILE_PREFS: &[(&str, &str)] = &[
    ("zen.welcome-screen.seen", "true"),
    ("zen.welcome.start-seen", "true"),
    ("browser.aboutwelcome.enabled", "false"),
    ("trailhead.firstrun.didSeeAboutWelcome", "true"),
    ("browser.shell.checkDefaultBrowser", "false"),
    ("browser.startup.homepage_override.mstone", "\"ignore\""),
    ("browser.startup.page", "0"),
    ("browser.startup.homepage", "\"about:blank\""),
    ("datareporting.policy.dataSubmissionEnabled", "false"),
    (
        "datareporting.policy.dataSubmissionPolicyBypassNotification",
        "true",
    ),
    ("toolkit.telemetry.reportingpolicy.firstRun", "false"),
    ("browser.uitour.enabled", "false"),
    // Keep navigator.webdriver false so Samsung's sign-in and reCAPTCHA do not
    // treat the remote-agent session as automation.
    ("dom.webdriver.enabled", "false"),
    // Do not block window.open("ms-app://…") issued while the page loads.
    ("dom.disable_open_during_load", "false"),
    // Treat ms-app:// as external and skip the "Open ms-app?" dialog, so the
    // attempted navigation reaches BiDi instead of being silently dropped.
    ("security.external_protocol_requires_permission", "false"),
    ("network.protocol-handler.external.ms-app", "true"),
    ("network.protocol-handler.warn-external.ms-app", "false"),
];

/// Zen UI state worth carrying over so the browser opens ready to use.
const ZEN_STATE_FILES: &[&str] = &[
    "zen-themes.json",
    "zen-keyboard-shortcuts.json",
    "containers.json",
];

/// Resolves the browser binary the desktop is configured to use.
pub fn default_browser() -> Option<PathBuf> {
    if let Some(id) = default_desktop_id()
        && let Some(exec) = desktop_exec(&id)
        && let Some(program) = exec_program(&exec)
    {
        return Some(program);
    }
    for name in ["zen-bin", "zen-browser", "firefox"] {
        if let Some(program) = find_in_path(name) {
            return Some(program);
        }
    }
    None
}

fn default_desktop_id() -> Option<String> {
    let output = Command::new("xdg-settings")
        .args(["get", "default-web-browser"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!id.is_empty()).then_some(id)
}

fn desktop_dirs() -> Vec<PathBuf> {
    let mut directories = Vec::new();
    if let Some(home) = std::env::var_os("XDG_DATA_HOME") {
        directories.push(PathBuf::from(home).join("applications"));
    } else if let Some(home) = std::env::var_os("HOME") {
        directories.push(PathBuf::from(home).join(".local/share/applications"));
    }
    if let Some(dirs) = std::env::var_os("XDG_DATA_DIRS") {
        for directory in std::env::split_paths(&dirs) {
            directories.push(directory.join("applications"));
        }
    } else {
        directories.push(PathBuf::from("/usr/share/applications"));
        directories.push(PathBuf::from("/usr/local/share/applications"));
    }
    directories
}

fn desktop_exec(id: &str) -> Option<String> {
    for directory in desktop_dirs() {
        if let Ok(text) = std::fs::read_to_string(directory.join(id))
            && let Some(exec) = desktop_exec_line(&text)
        {
            return Some(exec);
        }
    }
    None
}

/// Reads `Exec=` from the `[Desktop Entry]` group only.
fn desktop_exec_line(text: &str) -> Option<String> {
    let mut in_main_entry = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_main_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_main_entry {
            continue;
        }
        if let Some(value) = line.strip_prefix("Exec=") {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Resolves the first token of an `Exec=` line to an executable path.
fn exec_program(exec: &str) -> Option<PathBuf> {
    let name = first_exec_token(exec)?;
    let program = if name.contains('/') {
        PathBuf::from(&name)
    } else {
        find_in_path(&name)?
    };
    is_executable(&program).then_some(program)
}

fn first_exec_token(exec: &str) -> Option<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    for character in exec.chars() {
        match (quote, character) {
            (Some(open), character) if character == open => quote = None,
            (Some(_), character) => current.push(character),
            (None, '"' | '\'') => quote = Some(character),
            (None, character) if character.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            (None, character) => current.push(character),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }

    let mut tokens = tokens.into_iter();
    let first = tokens.next()?;
    if first == "env" {
        return tokens.find(|token| !token.contains('='));
    }
    Some(first)
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| is_executable(candidate))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// Persistent profile directory, so onboarding state survives between runs.
pub fn profile_dir() -> PathBuf {
    match std::env::var_os("XDG_CACHE_HOME") {
        Some(cache) => PathBuf::from(cache).join("seuil/browser-profile"),
        None => {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir);
            home.join(".cache/seuil/browser-profile")
        }
    }
}

/// Prepares the profile: seeds it once from the user's real Zen profile and
/// writes the prefs that suppress the welcome screen on every run.
fn prepare_profile(profile: &Path) -> Result<()> {
    std::fs::create_dir_all(profile).map_err(|error| {
        AuthError::Protocol(format!(
            "could not create browser profile {}: {error}",
            profile.display()
        ))
    })?;

    let marker = profile.join(SEED_MARKER);
    if !marker.exists() {
        if let Some(source) = real_profile_dir() {
            seed_from_profile(&source, profile)?;
        }
        std::fs::write(&marker, b"seeded\n")?;
    }
    write_user_js(profile)
}

fn seed_from_profile(source: &Path, profile: &Path) -> Result<()> {
    let prefs = source.join("prefs.js");
    if !prefs.is_file() {
        return Ok(());
    }
    copy_file(&prefs, &profile.join("prefs.js"))?;
    for name in ZEN_STATE_FILES {
        let from = source.join(name);
        if from.is_file() {
            copy_file(&from, &profile.join(name))?;
        }
    }
    debug!(source = %source.display(), "Seeded the sign-in profile from the user's Zen profile");
    Ok(())
}

fn copy_file(from: &Path, to: &Path) -> Result<()> {
    std::fs::copy(from, to).map_err(|error| {
        AuthError::Protocol(format!(
            "could not copy {} to {}: {error}",
            from.display(),
            to.display()
        ))
    })?;
    Ok(())
}

fn write_user_js(profile: &Path) -> Result<()> {
    let mut prefs = String::new();
    if let Some(source) = real_profile_dir()
        && let Ok(text) = std::fs::read_to_string(source.join("prefs.js"))
    {
        for line in welcome_prefs(&text) {
            prefs.push_str(&line);
            prefs.push('\n');
        }
    }
    for (name, value) in PROFILE_PREFS {
        prefs.push_str(&format!("user_pref(\"{name}\", {value});\n"));
    }
    std::fs::write(profile.join("user.js"), prefs).map_err(|error| {
        AuthError::Protocol(format!(
            "could not write {}: {error}",
            profile.join("user.js").display()
        ))
    })
}

/// Pulls `zen.*welcome*` and `zen.*onboarding*` settings out of the user's
/// prefs so the sign-in profile starts in the same welcome state. The trailing
/// semicolon is kept: without it Firefox rejects the whole `user.js`.
fn welcome_prefs(prefs: &str) -> Vec<String> {
    prefs
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("user_pref("))
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("\"zen.") && (lower.contains("welcome") || lower.contains("onboarding"))
        })
        .map(|line| {
            if line.ends_with(';') {
                line.to_string()
            } else {
                format!("{line};")
            }
        })
        .collect()
}

/// Finds the user's default Zen profile through `profiles.ini`.
fn real_profile_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    for base in [home.join(".zen"), home.join(".config/zen")] {
        let ini = base.join("profiles.ini");
        let Ok(text) = std::fs::read_to_string(&ini) else {
            continue;
        };
        if let Some(path) = default_profile_from_ini(&text, &base) {
            return Some(path);
        }
    }
    None
}

fn default_profile_from_ini(text: &str, base: &Path) -> Option<PathBuf> {
    let mut sections: Vec<(String, Vec<(String, String)>)> = Vec::new();
    let mut current = String::new();
    let mut entries: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            if !current.is_empty() {
                sections.push((std::mem::take(&mut current), std::mem::take(&mut entries)));
            }
            current = line.trim_matches(['[', ']']).to_string();
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            entries.push((key.trim().to_string(), value.trim().to_string()));
        }
    }
    if !current.is_empty() {
        sections.push((current, entries));
    }

    let value = |section: &(String, Vec<(String, String)>), key: &str| {
        section
            .1
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.clone())
    };

    // Firefox prefers the profile selected by the Install section.
    let installed = sections
        .iter()
        .filter(|(name, _)| name.starts_with("Install"))
        .find_map(|section| value(section, "Default"));
    let default_profile = sections
        .iter()
        .filter(|(name, _)| name.starts_with("Profile"))
        .filter(|section| value(section, "Default").as_deref() == Some("1"))
        .find_map(|section| value(section, "Path"));

    installed
        .or(default_profile)
        .map(|relative| base.join(relative))
        .filter(|path| path.is_dir())
}

/// Launches the default browser and waits for the `ms-app://` navigation.
///
/// The process is killed and reaped as soon as the URL arrives, or when this
/// future is dropped.
pub async fn capture_bidi_callback(sign_in_uri: &str) -> Result<String> {
    let program = default_browser().ok_or_else(|| {
        AuthError::Protocol("no Gecko browser found for the Samsung sign-in".into())
    })?;
    let profile = profile_dir();
    prepare_profile(&profile)?;

    let port = ephemeral_port()?;
    info!(browser = %program.display(), port, "Launching the browser for Samsung sign-in");
    let mut browser = BrowserProcess::launch(&program, &profile, port, sign_in_uri)?;

    let mut bidi = connect_with_backoff(port, &mut browser).await?;
    info!(port, "Connected to WebDriver BiDi");

    if let Err(error) = bidi
        .call("session.new", json!({ "capabilities": {} }))
        .await
    {
        warn!(%error, "WebDriver BiDi session.new failed");
        return Err(error);
    }
    info!("WebDriver BiDi session created");

    // Subscribe one event at a time: Firefox rejects the whole request when one
    // name is unknown (for example `navigationAborted` on Firefox 150), and the
    // remaining events must still be captured.
    let mut subscribed: Vec<&str> = Vec::new();
    for event in BIDI_EVENTS {
        match bidi
            .call("session.subscribe", json!({ "events": [event] }))
            .await
        {
            Ok(_) => subscribed.push(event),
            Err(error) => {
                warn!(%error, event, "WebDriver BiDi rejected an event subscription");
            }
        }
    }
    if subscribed.is_empty() {
        warn!("WebDriver BiDi accepted no event subscriptions");
        return Err(AuthError::Protocol(
            "the browser rejected every BiDi event subscription".into(),
        ));
    }
    info!(events = ?subscribed, "Subscribed to WebDriver BiDi events");

    let mut reached_complete = false;
    loop {
        let (message, raw) = match bidi.next_message().await {
            Ok(message) => message,
            Err(error) => {
                let error = match browser.exited() {
                    Some(status) => AuthError::Protocol(format!(
                        "the browser closed before the Samsung sign-in callback \
                         ({status})"
                    )),
                    None => error,
                };
                warn!(%error, "WebDriver BiDi stream ended");
                return Err(error);
            }
        };

        if let Some(method) = message.get("method").and_then(Value::as_str) {
            let level_url = event_url(&message).map(redacted);
            if method.starts_with("network.") {
                // Network events are summarised by log_network_event.
                debug!(method, url = ?level_url, "BiDi event");
            } else {
                match level_url {
                    Some(url) => info!(method, url = %url, "BiDi event"),
                    None => info!(method, "BiDi event"),
                }
            }
            log_network_event(method, &message);
            if !reached_complete
                && method == "browsingContext.navigationStarted"
                && event_url(&message).is_some_and(|url| url.contains("/signInComplete"))
            {
                reached_complete = true;
                info!("Reached Samsung signInComplete; waiting for the ms-app:// redirect");
            }
        }

        if let Some(callback) = callback_from_message(&raw, &message) {
            info!(url = %redacted(&callback), "Captured the ms-app:// callback");
            browser.shutdown();
            return Ok(callback);
        }
    }
}

/// URL carried by a BiDi event, for logging.
fn event_url(message: &Value) -> Option<&str> {
    message
        .pointer("/params/url")
        .and_then(Value::as_str)
        .or_else(|| {
            message
                .pointer("/params/request/url")
                .and_then(Value::as_str)
        })
}

/// Logs Samsung network traffic so a request that never completes is visible.
fn log_network_event(method: &str, message: &Value) {
    let Some(url) = message
        .pointer("/params/request/url")
        .and_then(Value::as_str)
    else {
        return;
    };
    let relevant = ["samsung", "samsungosp", "account.samsung.com"]
        .iter()
        .any(|marker| url.contains(marker));
    if url.starts_with("data:") {
        return;
    }
    match method {
        "network.beforeRequestSent" => {
            let request_method = message
                .pointer("/params/request/method")
                .and_then(Value::as_str)
                .unwrap_or("GET");
            if relevant {
                info!(request_method, url = %redacted(url), "BiDi request");
            } else {
                debug!(request_method, url = %redacted(url), "BiDi request");
            }
        }
        "network.responseCompleted" => {
            let status = message
                .pointer("/params/response/status")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            if relevant {
                info!(status, url = %redacted(url), "BiDi response");
            } else {
                debug!(status, url = %redacted(url), "BiDi response");
            }
        }
        "network.fetchError" => {
            let error = message
                .pointer("/params/errorText")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            warn!(%error, url = %redacted(url), "BiDi request failed");
        }
        _ => {}
    }
}

/// Drops the query string so tokens never reach the logs.
fn redacted(url: &str) -> String {
    match url.split_once('?') {
        Some((base, _)) => format!("{base}?<redacted>"),
        None => url.to_string(),
    }
}

/// Finds the `ms-app://` URL in a frame, whether it sits in a known parameter
/// or only in the raw JSON. Covers subframes, popups, and aborted external
/// protocol navigations.
fn callback_from_message(raw: &str, message: &Value) -> Option<String> {
    for pointer in ["/params/url", "/params/request/url", "/params/context/url"] {
        if let Some(url) = message.pointer(pointer).and_then(Value::as_str)
            && let Some(callback) = ms_app_url(url)
        {
            return Some(callback);
        }
    }
    ms_app_url(raw)
}

/// Extracts the `ms-app://` URL from text, undoing JSON escaping.
fn ms_app_url(input: &str) -> Option<String> {
    let normalized = input
        .replace("&amp;", "&")
        .replace("\\/", "/")
        .replace("\\u0026", "&")
        .replace("\\u003d", "=")
        .replace("\\u003D", "=");
    let start = normalized.find(CALLBACK_SCHEME)?;
    let rest = &normalized[start..];
    let end = rest
        .char_indices()
        .find(|(_, character)| {
            character.is_whitespace() || matches!(character, '"' | '\'' | '`' | '<' | '>' | '\\')
        })
        .map(|(index, _)| index)
        .unwrap_or(rest.len());
    let url = rest[..end].trim_end_matches([',', ';', ')', ']', '}']);
    (!url.is_empty()).then(|| url.to_string())
}

fn ephemeral_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// Owns the browser process so it is always killed and reaped.
struct BrowserProcess {
    child: Child,
}

impl BrowserProcess {
    fn launch(program: &Path, profile: &Path, port: u16, sign_in_uri: &str) -> Result<Self> {
        let child = Command::new(program)
            .arg("--no-remote")
            .arg("--profile")
            .arg(profile)
            .arg("--remote-debugging-port")
            .arg(port.to_string())
            .arg(sign_in_uri)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| {
                AuthError::Protocol(format!("could not launch {}: {error}", program.display()))
            })?;
        Ok(Self { child })
    }

    fn exited(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().ok().flatten()
    }

    fn shutdown(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for BrowserProcess {
    fn drop(&mut self) {
        self.shutdown();
    }
}

async fn connect_with_backoff(port: u16, browser: &mut BrowserProcess) -> Result<Bidi> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let mut delay = Duration::from_millis(100);
    let mut attempts = 0u32;
    loop {
        if let Some(status) = browser.exited() {
            warn!(%status, "The browser exited before the debug protocol started");
            return Err(AuthError::Protocol(format!(
                "the browser exited before the sign-in started ({status})"
            )));
        }
        attempts += 1;
        match Bidi::connect(port).await {
            Ok(bidi) => return Ok(bidi),
            Err(error) => {
                debug!(%error, attempts, "Browser debug protocol is not ready yet");
            }
        }
        if Instant::now() >= deadline {
            warn!(
                port,
                attempts,
                timeout_seconds = STARTUP_TIMEOUT.as_secs(),
                "Timed out connecting to the browser debug protocol"
            );
            return Err(AuthError::Protocol(format!(
                "the browser debug protocol did not start within {} s",
                STARTUP_TIMEOUT.as_secs()
            )));
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(1));
    }
}

/// Minimal WebDriver BiDi client over the remote agent's WebSocket.
struct Bidi {
    stream: TcpStream,
    next_id: u64,
    queue: VecDeque<(Value, String)>,
}

impl Bidi {
    async fn connect(port: u16) -> Result<Self> {
        let mut stream =
            tokio::time::timeout(WEB_SOCKET_TIMEOUT, TcpStream::connect(("127.0.0.1", port)))
                .await
                .map_err(|_| {
                    AuthError::Protocol("browser debug protocol connect timed out".into())
                })??;

        let key = STANDARD.encode(crypto::random_bytes(16));
        let handshake = format!(
            "GET /session HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        );
        stream.write_all(handshake.as_bytes()).await?;
        let header = tokio::time::timeout(WEB_SOCKET_TIMEOUT, read_http_header(&mut stream))
            .await
            .map_err(|_| AuthError::Protocol("browser WebSocket handshake timed out".into()))??;
        if !header.starts_with("HTTP/1.1 101") {
            return Err(AuthError::Protocol(
                "browser rejected the WebSocket upgrade".into(),
            ));
        }
        Ok(Self {
            stream,
            next_id: 1,
            queue: VecDeque::new(),
        })
    }

    async fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let request = json!({ "id": id, "method": method, "params": params });
        write_websocket_frame(&mut self.stream, 0x1, &serde_json::to_vec(&request)?).await?;
        loop {
            // Read straight from the socket: draining the event queue here would
            // spin on an already-received event and starve the response frame.
            let (message, raw) = self.read_message().await?;
            if message.get("id").and_then(Value::as_i64) != Some(id as i64) {
                self.queue.push_back((message, raw));
                continue;
            }
            if message.get("type").and_then(Value::as_str) == Some("error") {
                let detail = message
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown error");
                return Err(AuthError::Protocol(format!(
                    "browser rejected {method}: {detail}"
                )));
            }
            return Ok(message);
        }
    }

    /// Next message with its raw JSON text. Errors when the browser goes away.
    async fn next_message(&mut self) -> Result<(Value, String)> {
        if let Some(message) = self.queue.pop_front() {
            return Ok(message);
        }
        self.read_message().await
    }

    async fn read_message(&mut self) -> Result<(Value, String)> {
        loop {
            let bytes = read_websocket_message(&mut self.stream).await?;
            let raw = String::from_utf8_lossy(&bytes).into_owned();
            if let Ok(message) = serde_json::from_str::<Value>(&raw) {
                return Ok((message, raw));
            }
        }
    }
}

async fn read_http_header(stream: &mut TcpStream) -> Result<String> {
    let mut buffer = Vec::new();
    let mut byte = [0u8; 1];
    while buffer.len() < MAX_HEADER_BYTES {
        if stream.read(&mut byte).await? == 0 {
            break;
        }
        buffer.push(byte[0]);
        if buffer.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !buffer.ends_with(b"\r\n\r\n") {
        return Err(AuthError::Protocol(
            "browser sent an incomplete WebSocket handshake".into(),
        ));
    }
    Ok(String::from_utf8_lossy(&buffer).into_owned())
}

async fn read_websocket_message(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut message = Vec::new();
    loop {
        let (fin, opcode, payload) = read_websocket_frame(stream).await?;
        match opcode {
            0x8 => {
                return Err(AuthError::Protocol(
                    "browser closed the debug WebSocket".into(),
                ));
            }
            0x9 => write_websocket_frame(stream, 0xA, &payload).await?,
            0xA => {}
            0x1 | 0x0 => {
                message.extend_from_slice(&payload);
                if fin {
                    return Ok(message);
                }
            }
            _ => {
                if fin {
                    return Ok(message);
                }
            }
        }
    }
}

async fn read_websocket_frame(stream: &mut TcpStream) -> Result<(bool, u8, Vec<u8>)> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    let fin = head[0] & 0x80 != 0;
    let opcode = head[0] & 0x0f;
    let masked = head[1] & 0x80 != 0;
    let mut length = u64::from(head[1] & 0x7f);
    if length == 126 {
        let mut extended = [0u8; 2];
        stream.read_exact(&mut extended).await?;
        length = u64::from(u16::from_be_bytes(extended));
    } else if length == 127 {
        let mut extended = [0u8; 8];
        stream.read_exact(&mut extended).await?;
        length = u64::from_be_bytes(extended);
    }
    if length > 1024 * 1024 {
        return Err(AuthError::Protocol(
            "browser debugger message is too large".into(),
        ));
    }

    let mut mask = [0u8; 4];
    if masked {
        stream.read_exact(&mut mask).await?;
    }
    let mut payload = vec![0u8; length as usize];
    stream.read_exact(&mut payload).await?;
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
    Ok((fin, opcode, payload))
}

async fn write_websocket_frame(stream: &mut TcpStream, opcode: u8, payload: &[u8]) -> Result<()> {
    let mask = crypto::random_bytes(4);
    let mut frame = Vec::with_capacity(payload.len() + 14);
    frame.push(0x80 | opcode);
    if payload.len() < 126 {
        frame.push(0x80 | payload.len() as u8);
    } else if payload.len() <= usize::from(u16::MAX) {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    frame.extend_from_slice(&mask);
    frame.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ mask[index % 4]),
    );
    stream.write_all(&frame).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_exec_line_from_the_desktop_entry_group() {
        assert_eq!(
            desktop_exec_line("[Desktop Entry]\nName=Zen\nExec=/opt/zen-bin %u\n"),
            Some("/opt/zen-bin %u".to_string())
        );
        assert_eq!(
            desktop_exec_line("[Desktop Action new]\nExec=/usr/bin/zen %u\n"),
            None
        );
        assert_eq!(
            first_exec_token("env FOO=bar /usr/bin/zen %u"),
            Some("/usr/bin/zen".into())
        );
        assert_eq!(
            first_exec_token(r#""/opt/my browser/zen-bin" --new-window %u"#),
            Some("/opt/my browser/zen-bin".into())
        );
    }

    #[test]
    fn finds_the_default_profile_in_profiles_ini() {
        let ini = "[Profile1]\nName=Default\nIsRelative=1\nPath=abc.default\n\
                   [Install1234]\nDefault=xyz.default\n";
        let base = std::env::temp_dir();
        assert_eq!(default_profile_from_ini(ini, &base), None);

        let dir = base.join(format!("seuil-ini-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("xyz.default")).expect("create profile dir");
        assert_eq!(
            default_profile_from_ini(ini, &dir),
            Some(dir.join("xyz.default"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mirrors_welcome_and_onboarding_prefs() {
        let prefs = "user_pref(\"zen.welcome-screen.seen\", true);\n\
                     user_pref(\"zen.onboarding.finished\", false);\n\
                     user_pref(\"browser.startup.page\", 3);\n\
                     user_pref(\"zen.theme.color-pref\", \"dark\");\n";
        let mirrored = welcome_prefs(prefs);
        assert_eq!(mirrored.len(), 2);
        assert!(mirrored[0].contains("zen.welcome-screen.seen"));
        assert!(mirrored[1].contains("zen.onboarding.finished"));
        assert!(mirrored.iter().all(|line| line.ends_with(';')));
    }

    #[test]
    fn writes_prefs_that_suppress_onboarding() {
        let profile = std::env::temp_dir().join(format!(
            "seuil-prefs-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&profile).expect("create the test profile");
        prepare_profile(&profile).expect("prepare the profile");
        let user_js = std::fs::read_to_string(profile.join("user.js")).expect("read user.js");
        for line in user_js.lines().filter(|line| !line.trim().is_empty()) {
            assert!(
                line.trim_end().ends_with(';'),
                "unterminated preference: {line}"
            );
        }
        assert!(user_js.contains(r#"user_pref("zen.welcome-screen.seen", true)"#));
        assert!(user_js.contains(r#"user_pref("zen.welcome.start-seen", true)"#));
        assert!(user_js.contains(r#"user_pref("browser.aboutwelcome.enabled", false)"#));
        assert!(user_js.contains(r#"user_pref("trailhead.firstrun.didSeeAboutWelcome", true)"#));
        assert!(user_js.contains(r#"user_pref("dom.webdriver.enabled", false)"#));
        assert!(user_js.contains(r#"user_pref("dom.disable_open_during_load", false)"#));
        assert!(
            user_js
                .contains(r#"user_pref("security.external_protocol_requires_permission", false)"#)
        );
        assert!(user_js.contains(r#"user_pref("network.protocol-handler.external.ms-app", true)"#));
        assert!(profile.join(SEED_MARKER).is_file());
        let _ = std::fs::remove_dir_all(&profile);
    }

    #[test]
    fn recognises_the_ms_app_navigation_event() {
        let event = json!({
            "type": "event",
            "method": "browsingContext.navigationStarted",
            "params": {
                "context": "ctx",
                "url": "ms-app://s-1-15-2-4027708247/ANDROIDSDK/signInComplete?code=test_code&state=test_state"
            }
        });
        let raw = serde_json::to_string(&event).expect("serialize the event");
        assert_eq!(
            callback_from_message(&raw, &event).as_deref(),
            Some(
                "ms-app://s-1-15-2-4027708247/ANDROIDSDK/signInComplete?code=test_code&state=test_state"
            )
        );

        let http = json!({
            "type": "event",
            "method": "browsingContext.navigationStarted",
            "params": { "url": "https://account.samsung.com/accounts/ANDROIDSDK/signInComplete" }
        });
        let raw = serde_json::to_string(&http).expect("serialize the event");
        assert!(callback_from_message(&raw, &http).is_none());

        let other = json!({ "type": "event", "method": "browsingContext.load" });
        assert!(callback_from_message("{}", &other).is_none());
    }

    #[test]
    fn finds_the_callback_in_an_unknown_event_shape() {
        // An event type we do not know, carrying the URL only in its raw JSON
        // with escaped ampersands.
        let raw = r#"{"type":"event","method":"browsingContext.navigationAborted","params":{"url":"ms-app:\/\/s-1-15-2-4027708247\/ANDROIDSDK\/signInComplete?code=raw_code\u0026state=raw_state"}}"#;
        let message: Value = serde_json::from_str(raw).expect("parse");
        assert_eq!(
            callback_from_message(raw, &message).as_deref(),
            Some(
                "ms-app://s-1-15-2-4027708247/ANDROIDSDK/signInComplete?code=raw_code&state=raw_state"
            )
        );
    }

    #[test]
    fn redacts_query_values_for_logs() {
        assert_eq!(
            redacted("ms-app://cb/ANDROIDSDK/signInComplete?code=secret&state=more"),
            "ms-app://cb/ANDROIDSDK/signInComplete?<redacted>"
        );
        assert_eq!(
            redacted("https://account.samsung.com/accounts/ANDROIDSDK/signInComplete"),
            "https://account.samsung.com/accounts/ANDROIDSDK/signInComplete"
        );
    }

    #[tokio::test]
    async fn an_event_before_a_response_does_not_stall_the_call() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind the fake BiDi server");
        let port = listener.local_addr().expect("test address").port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept the client");
            let header = read_http_header(&mut stream).await.expect("read handshake");
            assert!(header.starts_with("GET /session HTTP/1.1"));
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                      Connection: Upgrade\r\n\r\n",
                )
                .await
                .expect("accept the WebSocket");

            let frame = read_websocket_frame(&mut stream)
                .await
                .expect("session.new");
            let request: Value = serde_json::from_slice(&frame.2).expect("parse");
            let id = request["id"].as_i64().expect("id");
            let response = json!({ "type": "success", "id": id, "result": {} });
            write_websocket_frame(&mut stream, 0x1, response.to_string().as_bytes())
                .await
                .expect("write the session response");

            let frame = read_websocket_frame(&mut stream).await.expect("subscribe");
            let request: Value = serde_json::from_slice(&frame.2).expect("parse");
            let id = request["id"].as_i64().expect("id");
            // An event arrives before the response for the same request.
            let event = json!({
                "type": "event",
                "method": "browsingContext.contextCreated",
                "params": { "context": "ctx", "url": "about:blank" }
            });
            write_websocket_frame(&mut stream, 0x1, event.to_string().as_bytes())
                .await
                .expect("write the event");
            let response = json!({
                "type": "success",
                "id": id,
                "result": { "subscription": "sub" }
            });
            write_websocket_frame(&mut stream, 0x1, response.to_string().as_bytes())
                .await
                .expect("write the subscribe response");
            let _ = tokio::time::timeout(Duration::from_secs(2), read_websocket_frame(&mut stream))
                .await;
        });

        let mut bidi = tokio::time::timeout(Duration::from_secs(5), Bidi::connect(port))
            .await
            .expect("connect timed out")
            .expect("connect");
        bidi.call("session.new", json!({ "capabilities": {} }))
            .await
            .expect("session.new");
        bidi.call(
            "session.subscribe",
            json!({ "events": ["browsingContext.contextCreated"] }),
        )
        .await
        .expect("session.subscribe");
        let (event, _raw) = bidi.next_message().await.expect("queued event");
        assert_eq!(event["method"], "browsingContext.contextCreated");
        drop(bidi);
        let _ = tokio::time::timeout(Duration::from_secs(3), server).await;
    }

    const EXPECTED_CALLBACK: &str = "ms-app://s-1-15-2-4027708247/ANDROIDSDK/signInComplete\
        ?code=test_code&state=test_state&auth_server_url=https://example.com&retValue=test_ret";

    /// Minimal HTTP server for the end-to-end run. The page builds the callback
    /// URL in JavaScript so only the browser's BiDi event can carry it.
    struct TestPage {
        port: u16,
        _server: std::thread::JoinHandle<()>,
    }

    impl TestPage {
        fn start(delay_ms: u64) -> Self {
            use std::io::{Read, Write};
            let listener =
                std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind the test page");
            let port = listener.local_addr().expect("test address").port();
            let body = format!(
                "<!doctype html><meta charset=\"utf-8\"><title>Sign-in complete</title>\n\
                 <script>\n\
                 setTimeout(function () {{\n\
                   var base = \"ms-app://s-1-15-2-4027708247/ANDROIDSDK/signInComplete\";\n\
                   var query = \"?code=\" + \"test_code\" + \"&state=\" + \"test_state\" +\n\
                     \"&auth_server_url=\" + \"https://example.com\" + \"&retValue=\" + \"test_ret\";\n\
                   window.location.href = base + query;\n\
                 }}, {delay_ms});\n\
                 </script>\n\
                 <p>Sign-in complete.</p>\n"
            );
            let server = std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { break };
                    let mut request = [0u8; 2048];
                    let _ = stream.read(&mut request);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                }
            });
            Self {
                port,
                _server: server,
            }
        }

        fn url(&self) -> String {
            format!("http://127.0.0.1:{}/ANDROIDSDK/signInComplete", self.port)
        }
    }

    /// Titles of the visible Zen windows, when Hyprland is reachable.
    fn zen_window_titles() -> Option<Vec<String>> {
        let output = std::process::Command::new("hyprctl")
            .args(["clients", "-j"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let clients: Value = serde_json::from_slice(&output.stdout).ok()?;
        Some(
            clients
                .as_array()?
                .iter()
                .filter(|client| client.get("class").and_then(Value::as_str) == Some("zen"))
                .filter_map(|client| client.get("title").and_then(Value::as_str))
                .map(str::to_string)
                .collect(),
        )
    }

    fn browser_processes_for(profile: &Path) -> usize {
        let Ok(output) = std::process::Command::new("pgrep")
            .args(["-f", &profile.display().to_string()])
            .output()
        else {
            return 0;
        };
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count()
    }

    #[tokio::test]
    #[ignore = "launches the real default browser and needs a graphical session"]
    async fn captures_the_ms_app_navigation_without_onboarding() {
        let page = TestPage::start(12000);
        let sign_in_uri = page.url();
        let capture = tokio::spawn(async move { capture_bidi_callback(&sign_in_uri).await });

        // While the window is open, check what the user would see. The page
        // title appears once the sign-in page has loaded.
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut titles = Vec::new();
        while Instant::now() < deadline {
            if let Some(current) = zen_window_titles() {
                titles = current;
                if titles
                    .iter()
                    .any(|title| title.contains("Sign-in complete"))
                {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        if !titles.is_empty() {
            assert!(
                titles
                    .iter()
                    .any(|title| title.contains("Sign-in complete")),
                "expected the sign-in page, got {titles:?}"
            );
            assert!(
                !titles
                    .iter()
                    .any(|title| title.to_ascii_lowercase().contains("welcome")),
                "unexpected onboarding window: {titles:?}"
            );
        }

        let callback = tokio::time::timeout(Duration::from_secs(40), capture)
            .await
            .expect("sign-in did not time out")
            .expect("capture task")
            .expect("receive the callback");
        assert_eq!(callback, EXPECTED_CALLBACK);

        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            browser_processes_for(&profile_dir()),
            0,
            "the browser process was not reaped"
        );
    }
}
