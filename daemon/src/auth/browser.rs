//! Linux desktop integration for the Samsung `ms-app://` OAuth redirect.
//!
//! Samsung's PC SDK hands the authorization code back through a custom
//! `ms-app://` URI. Linux browsers have no handler for it, so the page can sit
//! on a loading spinner after sign-in. `seuil setup` temporarily registers this
//! binary as that handler, receives the redirect over a local Unix socket, and
//! removes the registration when the login ends.

use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::debug;

use super::normalize_callback_input;

const DESKTOP_FILE: &str = "seuil-auth.desktop";
const SCHEME: &str = "x-scheme-handler/ms-app";
const MAX_CALLBACK_BYTES: usize = 256 * 1024;

/// Socket the browser callback helper writes to.
///
/// Prefers the user runtime directory, falls back to the Seuil config directory
/// when `XDG_RUNTIME_DIR` is unset. `MCFDS_AUTH_SOCKET` overrides both.
pub fn socket_path() -> PathBuf {
    if let Some(path) = std::env::var_os("MCFDS_AUTH_SOCKET") {
        return PathBuf::from(path);
    }
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(dir).join("seuil-auth.sock");
    }
    crate::config::config_dir().join("auth.sock")
}

fn applications_dir() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from(".local/share"));
    base.join("applications")
}

/// Hidden `seuil auth-callback <URL>` entry point: forwards the browser redirect
/// to the waiting `seuil setup` process and exits.
pub async fn send_callback(raw: &str) -> Result<()> {
    let url = normalize_callback_input(raw);
    if !url.starts_with("ms-app://") {
        anyhow::bail!("expected an ms-app:// URL, got: {url}");
    }
    let socket = socket_path();
    let mut stream = UnixStream::connect(&socket).await.with_context(|| {
        format!(
            "connect to {} (is `seuil setup` waiting for the browser?)",
            socket.display()
        )
    })?;
    stream.write_all(url.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

/// Temporary registration of Seuil as the `ms-app://` handler.
///
/// Dropping it removes the socket, deletes the desktop entry, and restores the
/// handler that was registered before setup started.
pub struct CallbackRegistration {
    listener: UnixListener,
    socket: PathBuf,
    desktop: Option<PathBuf>,
    previous_handler: Option<String>,
}

impl CallbackRegistration {
    /// Binds the callback socket and installs the desktop entry.
    pub fn install() -> Result<Self> {
        let socket = socket_path();
        if let Some(parent) = socket.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        remove_stale_socket(&socket)?;
        let listener =
            UnixListener::bind(&socket).with_context(|| format!("bind {}", socket.display()))?;
        let _ = fs::set_permissions(&socket, fs::Permissions::from_mode(0o600));

        let previous_handler = query_default_handler();
        let desktop = match write_desktop_entry() {
            Ok(desktop) => Some(desktop),
            Err(error) => {
                eprintln!("warning: could not install the ms-app:// callback entry: {error}");
                None
            }
        };
        if desktop.is_some() && !register_handler() {
            eprintln!(
                "warning: the browser cannot open Seuil automatically; paste the ms-app:// \
                 URL from the browser console when setup asks for it"
            );
        }

        Ok(Self {
            listener,
            socket,
            desktop,
            previous_handler,
        })
    }

    /// Waits for one connection and returns the URL it carried.
    pub async fn receive(&self) -> Result<String> {
        let (mut stream, _) = self
            .listener
            .accept()
            .await
            .context("accept the browser callback")?;
        let mut raw = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            let count = stream.read(&mut buffer).await?;
            if count == 0 {
                break;
            }
            raw.extend_from_slice(&buffer[..count]);
            if raw.len() >= MAX_CALLBACK_BYTES {
                break;
            }
        }
        Ok(normalize_callback_input(&String::from_utf8_lossy(&raw)))
    }
}

impl Drop for CallbackRegistration {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket);
        if let Some(desktop) = &self.desktop {
            let _ = fs::remove_file(desktop);
            refresh_desktop_database(desktop.parent());
            restore_handler(self.previous_handler.as_deref());
        }
    }
}

fn remove_stale_socket(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(path).with_context(|| format!("remove stale {}", path.display()))?;
        }
        Ok(_) => anyhow::bail!(
            "{} exists and is not a socket; remove it and retry",
            path.display()
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {}", path.display()));
        }
    }
    Ok(())
}

fn write_desktop_entry() -> Result<PathBuf> {
    let dir = applications_dir();
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let exe = std::env::current_exe().context("locate the running seuil executable")?;
    let path = dir.join(DESKTOP_FILE);
    let entry = format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=Seuil Auth Callback\n\
         Comment=Receive the Samsung ms-app:// sign-in redirect\n\
         Exec={} auth-callback %u\n\
         MimeType={SCHEME};\n\
         NoDisplay=true\n\
         Terminal=false\n",
        exec_quote(&exe)
    );
    fs::write(&path, entry).with_context(|| format!("write {}", path.display()))?;
    refresh_desktop_database(Some(&dir));
    Ok(path)
}

fn exec_quote(path: &Path) -> String {
    let text = path.to_string_lossy();
    if text
        .chars()
        .any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '\\' | '$' | '`'))
    {
        format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        text.into_owned()
    }
}

fn register_handler() -> bool {
    match Command::new("xdg-mime")
        .args(["default", DESKTOP_FILE, SCHEME])
        .status()
    {
        Ok(status) if status.success() => match query_default_handler() {
            Some(handler) if handler == DESKTOP_FILE => true,
            Some(handler) => {
                eprintln!(
                    "warning: xdg-mime registered {handler}, not {DESKTOP_FILE}, for {SCHEME}"
                );
                false
            }
            None => {
                eprintln!("warning: xdg-mime could not confirm the {SCHEME} handler");
                false
            }
        },
        Ok(status) => {
            eprintln!("warning: xdg-mime failed to register the {SCHEME} handler: {status}");
            false
        }
        Err(error) => {
            eprintln!(
                "warning: xdg-mime is unavailable ({error}); install xdg-utils or paste the URL"
            );
            false
        }
    }
}

fn query_default_handler() -> Option<String> {
    let output = Command::new("xdg-mime")
        .args(["query", "default", SCHEME])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn restore_handler(previous: Option<&str>) {
    let Some(previous) = previous.filter(|name| *name != DESKTOP_FILE) else {
        return;
    };
    match Command::new("xdg-mime")
        .args(["default", previous, SCHEME])
        .status()
    {
        Ok(status) if status.success() => {}
        Ok(status) => {
            debug!(%status, handler = previous, "Could not restore the previous ms-app:// handler")
        }
        Err(error) => debug!(error = %error, "Could not restore the previous ms-app:// handler"),
    }
}

fn refresh_desktop_database(dir: Option<&Path>) {
    let Some(dir) = dir else {
        return;
    };
    match Command::new("update-desktop-database")
        .arg(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            debug!("update-desktop-database is not installed");
        }
        Err(error) => debug!(error = %error, "update-desktop-database failed"),
    }
}
