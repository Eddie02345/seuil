//! `seuil update`: replace a user-space installation from GitHub Releases.
//!
//! SteamOS keeps `/usr` immutable and does not manage Seuil with `pacman`, so
//! the binary lives under the user's home. This command downloads the latest
//! `x86_64` tarball, verifies the archive, swaps the binary atomically, and
//! restarts the user service when it is running.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

const RELEASES_URL: &str = "https://api.github.com/repos/Eddie02345/seuil/releases/latest";
const ASSET_SUFFIX: &str = "x86_64-unknown-linux-gnu.tar.gz";
const SERVICE: &str = "seuil.service";

#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(Debug, Clone, Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    size: u64,
}

/// Downloads and installs the latest release over the running binary.
pub async fn run(force: bool) -> Result<()> {
    let current =
        fs::canonicalize(std::env::current_exe().context("locate the running seuil binary")?)
            .context("resolve the running seuil binary")?;
    if is_system_managed(&current) {
        bail!(
            "{} is managed by the system package manager; update it with pacman or apt",
            current.display()
        );
    }

    let client = reqwest::Client::builder()
        .user_agent(concat!("seuil/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(120))
        .build()
        .context("create the HTTP client")?;

    println!("Checking GitHub for the latest Seuil release");
    let release: Release = client
        .get(RELEASES_URL)
        .send()
        .await
        .context("contact GitHub Releases")?
        .error_for_status()
        .context("GitHub Releases returned an error")?
        .json()
        .await
        .context("read the GitHub release")?;

    let latest = release.tag_name.trim_start_matches(['v', 'V']);
    let installed = env!("CARGO_PKG_VERSION");
    println!("Installed: v{installed}  Latest: v{latest}");

    if !force && !is_newer(latest, installed) {
        println!("Seuil is already up to date. Run `seuil update --force` to reinstall.");
        return Ok(());
    }

    let asset = select_asset(&release.assets)
        .with_context(|| format!("release v{latest} has no {ASSET_SUFFIX} asset"))?;
    println!("Downloading {}", asset.name);
    let response = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .with_context(|| format!("download {}", asset.name))?
        .error_for_status()
        .with_context(|| format!("download {}", asset.name))?;
    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("read {}", asset.name))?;
    if asset.size > 0 && bytes.len() as u64 != asset.size {
        bail!(
            "downloaded {} bytes of {}, expected {}",
            bytes.len(),
            asset.name,
            asset.size
        );
    }

    let bin_dir = current
        .parent()
        .context("the running binary has no parent directory")?;
    let staging = TempDir::create(bin_dir)?;
    let archive = staging.path().join("seuil.tar.gz");
    fs::write(&archive, &bytes).with_context(|| format!("write {}", archive.display()))?;
    extract_archive(&archive, staging.path())?;

    let extracted = staging.path().join("seuil");
    if !extracted.is_file() {
        bail!("{} does not contain a seuil binary", asset.name);
    }
    replace_binary(&extracted, &current)?;
    println!("Updated {}", current.display());

    restart_service();
    Ok(())
}

/// Atomically installs `new_binary` at `target`.
fn replace_binary(new_binary: &Path, target: &Path) -> Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let parent = target
        .parent()
        .context("the installed binary has no parent directory")?;
    let staged = parent.join(format!(".seuil-update-{}.new", std::process::id()));

    fs::copy(new_binary, &staged).with_context(|| {
        format!(
            "stage the update in {} (is the directory writable?)",
            parent.display()
        )
    })?;
    #[cfg(unix)]
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o755))
        .context("make the staged binary executable")?;

    if let Err(error) = fs::rename(&staged, target) {
        let _ = fs::remove_file(&staged);
        return Err(error).with_context(|| format!("replace {}", target.display()));
    }
    Ok(())
}

fn extract_archive(archive: &Path, destination: &Path) -> Result<()> {
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(destination)
        .status()
        .context("run tar")?;
    if !status.success() {
        bail!("tar could not extract {}", archive.display());
    }
    Ok(())
}

/// Picks the generic Linux x86_64 tarball from a release.
fn select_asset(assets: &[Asset]) -> Option<&Asset> {
    assets
        .iter()
        .find(|asset| asset.name.ends_with(ASSET_SUFFIX))
}

/// True for binaries installed under a root-owned system prefix.
fn is_system_managed(path: &Path) -> bool {
    let path = path.to_string_lossy();
    ["/usr/bin/", "/usr/local/bin/", "/bin/", "/sbin/"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// Compares dotted release versions, ignoring a leading `v`.
fn is_newer(candidate: &str, current: &str) -> bool {
    let candidate = parse_version(candidate);
    let current = parse_version(current);
    let length = candidate.len().max(current.len());
    for index in 0..length {
        let left = candidate.get(index).copied().unwrap_or(0);
        let right = current.get(index).copied().unwrap_or(0);
        if left != right {
            return left > right;
        }
    }
    false
}

fn parse_version(value: &str) -> Vec<u64> {
    value
        .trim()
        .trim_start_matches(['v', 'V'])
        .split('.')
        .map(|part| {
            part.chars()
                .take_while(|character| character.is_ascii_digit())
                .collect::<String>()
                .parse()
                .unwrap_or(0)
        })
        .collect()
}

fn restart_service() {
    let active = Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", SERVICE])
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if !active {
        return;
    }

    match Command::new("systemctl")
        .args(["--user", "restart", SERVICE])
        .status()
    {
        Ok(status) if status.success() => println!("Restarted {SERVICE}"),
        Ok(status) => eprintln!("warning: systemctl --user restart {SERVICE} exited with {status}"),
        Err(error) => eprintln!("warning: could not restart {SERVICE}: {error}"),
    }
}

/// Removes the staging directory when the update finishes or fails.
struct TempDir(PathBuf);

impl TempDir {
    fn create(parent: &Path) -> Result<Self> {
        let path = parent.join(format!(".seuil-update-{}", std::process::id()));
        if path.exists() {
            fs::remove_dir_all(&path)
                .with_context(|| format!("remove stale {}", path.display()))?;
        }
        fs::create_dir(&path).with_context(|| {
            format!(
                "create {} (is {} writable?)",
                path.display(),
                parent.display()
            )
        })?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(name: &str) -> Asset {
        Asset {
            name: name.into(),
            browser_download_url: format!("https://example.invalid/{name}"),
            size: 1,
        }
    }

    #[test]
    fn selects_the_generic_x86_64_tarball() {
        let assets = vec![
            asset("seuil-1.0.2-1-x86_64.pkg.tar.zst"),
            asset("seuil-v1.0.2-x86_64-unknown-linux-gnu.tar.gz"),
        ];
        assert_eq!(
            select_asset(&assets).map(|asset| asset.name.as_str()),
            Some("seuil-v1.0.2-x86_64-unknown-linux-gnu.tar.gz")
        );
    }

    #[test]
    fn missing_tarball_is_rejected() {
        assert!(select_asset(&[asset("seuil-1.0.2-1-x86_64.pkg.tar.zst")]).is_none());
    }

    #[test]
    fn compares_release_versions() {
        assert!(is_newer("1.0.2", "1.0.1"));
        assert!(is_newer("v1.1.0", "1.0.9"));
        assert!(is_newer("1.0.1.1", "1.0.1"));
        assert!(!is_newer("1.0.1", "1.0.1"));
        assert!(!is_newer("v1.0.0", "1.0.1"));
    }

    #[test]
    fn parses_versions_with_suffixes() {
        assert_eq!(parse_version("v1.2.3-beta.1"), vec![1, 2, 3, 1]);
        assert_eq!(parse_version("2.0"), vec![2, 0]);
    }

    #[test]
    fn refuses_system_managed_locations() {
        assert!(is_system_managed(Path::new("/usr/bin/seuil")));
        assert!(is_system_managed(Path::new("/usr/local/bin/seuil")));
        assert!(!is_system_managed(Path::new("/home/deck/.local/bin/seuil")));
    }
}
