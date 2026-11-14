//! Samsung account sign-in, Continuity service authorization, and certificate
//! enrollment.
//!
//! The flow mirrors Samsung's Android SDK sign-in used by the Continuity
//! service: an encrypted entry-point envelope, browser PKCE sign-in, a service
//! token exchange, cloud device registration, and a PKCS#10 certificate
//! enrollment that yields the account key used by the BLE/LAN handshake.

pub mod ble_keys;
mod credentials;
pub mod crypto;
pub mod handshake;

pub use credentials::{Credentials, data_path as credentials_path};

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::header::{ACCEPT, HeaderMap, HeaderValue};
use reqwest::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};
use url::Url;

const MASTER_CLIENT_ID: &str = "yfrtglt53o";
const CONTINUITY_CLIENT_ID: &str = "boz0m1awhe";
const APP_VERSION: &str = "4.6.1217.0";
const DEFAULT_AUTH_SERVER: &str = "eu-auth2.samsungosp.com";
/// Windows app callback registered for Samsung's PC SDK client. Linux has no
/// handler for it, so the callback URL is pasted back unless
/// `MCFDS_OAUTH_REDIRECT` names a loopback listener.
const DEFAULT_REDIRECT: &str =
    "ms-app://s-1-15-2-4027708247-2189610-1983755848-2937435718-1578786913-2158692839-1974417358";
const DEVICE_NAME: &str = "seuil";
/// Continuity is a Windows PC service; these identity fields match the working
/// reference client so the cloud accepts this installation as a PC.
const DEVICE_MODEL: &str = "PC";
const DEVICE_OS_VERSION: &str = "11";
const COUNTRY_CODE: &str = "fr";
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(900);

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Samsung request {path} failed: HTTP {status}{detail}")]
    Http {
        status: u16,
        path: String,
        code: Option<i64>,
        detail: String,
    },
    #[error("Samsung network request failed: {0}")]
    Network(String),
    #[error("Samsung response could not be parsed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("credential storage failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Samsung sign-in cryptography failed: {0}")]
    Crypto(String),
    #[error("Samsung sign-in protocol error: {0}")]
    Protocol(String),
    #[error("Continuity handshake failed: {0}")]
    Handshake(String),
}

pub type Result<T> = std::result::Result<T, AuthError>;

#[derive(Debug, Clone)]
pub struct EntryPoint {
    pub sign_in_uri: String,
    pub pki_public_key: String,
    pub chk_do_num: u32,
}

#[derive(Debug, Clone)]
pub struct AuthCallback {
    pub code: String,
    pub auth_server_url: String,
    pub login_id: String,
    pub state: String,
}

#[derive(Debug, Clone)]
pub struct DeviceRegistration {
    pub registration_id: String,
    pub cloud_token: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub bt_address: String,
    pub device_name: String,
    pub device_type: String,
    pub device_model: String,
}

#[derive(Debug, Clone)]
pub struct AccountKeyBundle {
    pub account_key: [u8; 32],
    pub user_fingerprint: String,
    pub revision: u32,
    pub this_device: DeviceInfo,
    pub devices: Vec<DeviceInfo>,
}

pub struct SamsungOAuth {
    client_id: String,
    auth_server: String,
    userauth_token: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    master_client_id: String,
    device_id: String,
    user_id: Option<String>,
    login_id: Option<String>,
    access_expires: i64,
    registration_id: Option<String>,
    cloud_token: Option<String>,
    cloud_expires: i64,
    bt_address: String,
    csr: Mutex<Option<String>>,
    private_key: Mutex<Option<String>>,
    state: String,
    code_verifier: String,
    redirect_uri: String,
    http: Client,
}

impl SamsungOAuth {
    pub fn new(auth_server: &str) -> Result<Self> {
        let mut default_headers = HeaderMap::new();
        default_headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .default_headers(default_headers)
            .user_agent(concat!("seuil/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| AuthError::Network(e.without_url().to_string()))?;
        let normalized = normalize_auth_server(auth_server);
        Ok(Self {
            client_id: CONTINUITY_CLIENT_ID.to_string(),
            auth_server: if normalized.is_empty() {
                DEFAULT_AUTH_SERVER.to_string()
            } else {
                normalized
            },
            userauth_token: None,
            access_token: None,
            refresh_token: None,
            master_client_id: MASTER_CLIENT_ID.to_string(),
            device_id: hex::encode(crypto::random_bytes(16)),
            user_id: None,
            login_id: None,
            access_expires: 0,
            registration_id: None,
            cloud_token: None,
            cloud_expires: 0,
            bt_address: String::new(),
            csr: Mutex::new(None),
            private_key: Mutex::new(None),
            state: crypto::base64_url_no_pad(&crypto::random_bytes(15))
                .chars()
                .take(20)
                .collect(),
            code_verifier: crypto::base64_url_no_pad(&crypto::random_bytes(32)),
            redirect_uri: std::env::var("MCFDS_OAUTH_REDIRECT")
                .unwrap_or_else(|_| DEFAULT_REDIRECT.to_string()),
            http,
        })
    }

    pub fn from_credentials(stored: &Credentials) -> Result<Self> {
        let mut oauth = Self::new(&stored.auth_server)?;
        if !stored.device_id.is_empty() {
            oauth.device_id = stored.device_id.clone();
        }
        oauth.userauth_token = nonempty(&stored.userauth_token);
        oauth.access_token = nonempty(&stored.access_token);
        oauth.refresh_token = nonempty(&stored.refresh_token);
        oauth.user_id = nonempty(&stored.user_id);
        oauth.login_id = nonempty(&stored.login_id);
        oauth.access_expires = stored.access_expires;
        oauth.registration_id = nonempty(&stored.registration_id);
        oauth.cloud_token = nonempty(&stored.cloud_token);
        oauth.cloud_expires = stored.cloud_expires;
        oauth.bt_address = stored.bt_address.clone();
        *lock(&oauth.csr) = nonempty(&stored.csr);
        *lock(&oauth.private_key) = nonempty(&stored.private_key);
        Ok(oauth)
    }

    pub fn set_bt_address(&mut self, address: &str) -> Result<()> {
        self.bt_address = normalize_bt_address(address)?;
        Ok(())
    }

    pub fn user_id(&self) -> Option<&str> {
        self.user_id.as_deref()
    }

    pub fn set_registration(&mut self, registration: &DeviceRegistration) {
        self.registration_id = Some(registration.registration_id.clone());
        self.cloud_token = Some(registration.cloud_token.clone());
        self.cloud_expires = registration.expires_at;
    }

    /// Fetches the SDK entry point: login URI, RSA public key, and the PBKDF2
    /// iteration count that the envelope must use.
    pub async fn get_entry_point(&self) -> Result<EntryPoint> {
        let value = self
            .get_json("https://account.samsung.com/accounts/ANDROIDSDK/getEntryPoint")
            .await?;
        let sign_in_uri = required_string(&value, "signInURI")?;
        let uri = Url::parse(&sign_in_uri)
            .map_err(|e| AuthError::Protocol(format!("invalid Samsung sign-in URI: {e}")))?;
        if uri.scheme() != "https"
            || uri.host_str() != Some("account.samsung.com")
            || !uri.path().starts_with("/accounts/")
            || uri.query().is_some()
            || uri.fragment().is_some()
        {
            return Err(AuthError::Protocol(
                "Samsung returned an untrusted sign-in URI".into(),
            ));
        }
        let pki_public_key = required_string(&value, "pkiPublicKey")?;
        let chk_do_num = value
            .get("chkDoNum")
            .and_then(value_as_i64)
            .filter(|value| (1..=1_000_000).contains(value))
            .ok_or_else(|| {
                AuthError::Protocol("Samsung returned an invalid iteration count".into())
            })?;
        Ok(EntryPoint {
            sign_in_uri,
            pki_public_key,
            chk_do_num: chk_do_num as u32,
        })
    }

    pub fn build_svc_param(&self, entry_point: &EntryPoint) -> Result<String> {
        let payload = json!({
            "clientId": self.master_client_id,
            "code_challenge": crypto::base64_url_no_pad(&crypto::sha256(self.code_verifier.as_bytes())),
            "code_challenge_method": "S256",
            "competitorDeviceYNFlag": "Y",
            "countryCode": COUNTRY_CODE,
            "deviceInfo": "Google|com.android.chrome",
            "deviceModelID": DEVICE_MODEL,
            "deviceName": DEVICE_NAME,
            "deviceOSVersion": DEVICE_OS_VERSION,
            "devicePhysicalAddressText": format!("MAC:{}", self.device_id),
            "deviceType": "APP",
            "deviceUniqueID": self.device_id,
            "redirect_uri": self.redirect_uri,
            "replaceableClientConnectYN": "N",
            "replaceableClientId": "",
            "replaceableDevicePhysicalAddressText": "",
            "responseEncryptionType": "1",
            "responseEncryptionYNFlag": "Y",
            "scope": "",
            "state": self.state,
            "svcIptLgnID": "",
            "iosYNFlag": "Y",
        });
        crypto::build_envelope(
            &payload,
            entry_point.chk_do_num,
            &entry_point.pki_public_key,
        )
    }

    /// Builds the login URL the browser must open.
    pub fn authorize_url(&self, entry_point: &EntryPoint, svc_param: &str) -> Result<String> {
        let mut url = Url::parse(&entry_point.sign_in_uri)
            .map_err(|e| AuthError::Protocol(format!("invalid Samsung sign-in URI: {e}")))?;
        url.query_pairs_mut()
            .append_pair("locale", "en-US")
            .append_pair("svcParam", svc_param)
            .append_pair("mode", "C");
        Ok(url.into())
    }

    pub async fn interactive_login(&self, sign_in_uri: &str) -> Result<AuthCallback> {
        eprintln!("Samsung sign-in URL (open manually if no browser appears):\n{sign_in_uri}");
        let redirect = Url::parse(&self.redirect_uri).map_err(|e| {
            AuthError::Protocol(format!("invalid Samsung redirect URI setting: {e}"))
        })?;
        let raw = if is_loopback(&redirect) {
            self.await_loopback(redirect, sign_in_uri).await?
        } else {
            self.await_pasted_callback(sign_in_uri).await?
        };
        self.parse_callback(&raw)
    }

    pub async fn authenticate(&mut self, callback: &AuthCallback) -> Result<()> {
        if callback.state != self.state {
            return Err(AuthError::Protocol(
                "Samsung sign-in callback does not match this attempt".into(),
            ));
        }
        let form = [
            ("grant_type", "authorization_code".to_string()),
            ("serviceType", "M".to_string()),
            ("client_id", self.master_client_id.clone()),
            ("code", callback.code.clone()),
            ("code_verifier", self.code_verifier.clone()),
            ("username", callback.login_id.clone()),
            ("physical_address_text", self.device_id.clone()),
        ];
        let value = self
            .post_form(
                &format!("{}/auth/oauth2/authenticate", callback.auth_server_url),
                &form,
            )
            .await?;
        let token = required_string(&value, "userauth_token")
            .or_else(|_| required_string(&value, "userAuthToken"))?;
        let user =
            required_string(&value, "userId").or_else(|_| required_string(&value, "user_id"))?;
        if self.user_id.as_deref() != Some(user.as_str()) {
            self.access_token = None;
            self.refresh_token = None;
            self.access_expires = 0;
            self.registration_id = None;
            self.cloud_token = None;
            self.cloud_expires = 0;
            *lock(&self.csr) = None;
            *lock(&self.private_key) = None;
        }
        self.auth_server = normalize_auth_server(&callback.auth_server_url);
        self.userauth_token = Some(token);
        self.user_id = Some(user);
        self.login_id = Some(callback.login_id.clone());
        info!(user = %masked(&callback.login_id), "Samsung account sign-in completed");
        Ok(())
    }

    /// Returns a Continuity service token, refreshing it when it is close to
    /// expiry and re-authorizing when the refresh token is rejected.
    pub async fn get_service_token(&mut self) -> Result<()> {
        if self.access_token.is_some() && !needs_refresh(self.access_expires) {
            return Ok(());
        }
        if let Some(refresh_token) = self.refresh_token.clone() {
            let form = [
                ("grant_type", "refresh_token".to_string()),
                ("refresh_token", refresh_token),
                ("client_id", self.client_id.clone()),
                ("client_secret", String::new()),
                ("physical_address_text", self.device_id.clone()),
            ];
            match self
                .post_form(&format!("{}/auth/oauth2/token", self.base_url()), &form)
                .await
            {
                Ok(token) => return self.apply_token(&token),
                Err(AuthError::Http {
                    status: 400 | 401 | 403,
                    ..
                }) => {
                    warn!("Samsung rejected the service refresh token; re-authorizing");
                }
                Err(e) => return Err(e),
            }
        }
        self.authorize_service().await
    }

    pub async fn register_device(&self) -> Result<DeviceRegistration> {
        let headers = self.identity_headers()?;
        let body = json!({
            "app": {
                "version": APP_VERSION,
                "sdkVersion": "26100.0"
            },
            "device": {
                "osType": "win",
                "osVersion": "11",
                "platformVersion": "10.0.26100.0",
                "type": "pc",
                "countryCode": "FRA",
                "modelName": DEVICE_MODEL,
                "modelCode": DEVICE_MODEL,
                "alias": DEVICE_NAME,
                "osUserId": "0"
            }
        });
        let value = self
            .post_json(
                "https://play.samsungcloud.com/identity/v2/user/register",
                &body,
                &headers,
            )
            .await?;
        let registration_id = required_string(&value, "dvcId")?;
        let tokens = value
            .get("tokens")
            .and_then(Value::as_array)
            .ok_or_else(|| AuthError::Protocol("Samsung returned no cloud tokens".into()))?;
        let token = tokens
            .iter()
            .find(|token| token.get("type").and_then(Value::as_str) == Some("user"))
            .ok_or_else(|| AuthError::Protocol("Samsung returned no cloud user token".into()))?;
        let cloud_token = required_string(token, "accessToken")?;
        Ok(DeviceRegistration {
            registration_id,
            cloud_token,
            expires_at: expiry_epoch(token),
        })
    }

    pub async fn renew_cloud_token(
        &self,
        registration: &DeviceRegistration,
    ) -> Result<DeviceRegistration> {
        let mut headers: Vec<(String, String)> = self
            .identity_headers()?
            .into_iter()
            .filter(|(name, _)| name != "x-sc-cdid" && name != "x-sc-pdid")
            .collect();
        headers.push(("x-sc-dvc-id".into(), registration.registration_id.clone()));
        let value = self
            .post_json(
                "https://play.samsungcloud.com/identity/v2/user/token/renew",
                &json!({ "previousToken": registration.cloud_token }),
                &headers,
            )
            .await?;
        Ok(DeviceRegistration {
            registration_id: registration.registration_id.clone(),
            cloud_token: required_string(&value, "accessToken")?,
            expires_at: expiry_epoch(&value),
        })
    }

    /// Fetches or creates this device's Continuity certificate. The returned
    /// bundle carries the account key, account fingerprint, and peer devices.
    pub async fn enroll_certificate(
        &self,
        registration: &DeviceRegistration,
    ) -> Result<AccountKeyBundle> {
        if self.bt_address.is_empty() {
            return Err(AuthError::Protocol(
                "no local Bluetooth address is set for certificate enrollment".into(),
            ));
        }
        let local = normalize_bt_address(&self.bt_address)?;
        let headers = vec![(
            "Authorization".to_string(),
            format!("Bearer {}", registration.cloud_token),
        )];
        let url = "https://play.samsungcloud.com/certificate/v2/certificates?kcid=KC01";

        match self.get_json_with_headers(url, &headers).await {
            Ok(value) => {
                if let Some(bundle) = parse_bundle(&value, &local)? {
                    return Ok(bundle);
                }
                debug!("Existing Samsung certificate does not identify this device; enrolling");
            }
            Err(AuthError::Http {
                code: Some(40002001),
                ..
            }) => debug!("Samsung requires a certificate enrollment for this device"),
            Err(e) => return Err(e),
        }

        let csr = self.ensure_csr(&registration.registration_id)?;
        let body = json!({
            "csr": csr,
            "device": {
                "deviceName": DEVICE_NAME,
                "deviceModel": DEVICE_MODEL,
                "modelCode": DEVICE_MODEL,
                "deviceType": "pc",
                "btAddress": local,
                "wifiAddress": "",
                "irk": STANDARD.encode([0u8; 16])
            }
        });
        let value = self.post_json(url, &body, &headers).await?;
        parse_bundle(&value, &local)?.ok_or_else(|| {
            AuthError::Protocol("Samsung certificate does not identify this device".into())
        })
    }

    /// Captures the current session for encrypted persistence.
    pub fn credentials(&self, bundle: &AccountKeyBundle) -> Credentials {
        Credentials {
            auth_server: self.auth_server.clone(),
            userauth_token: self.userauth_token.clone().unwrap_or_default(),
            user_id: self.user_id.clone().unwrap_or_default(),
            login_id: self.login_id.clone().unwrap_or_default(),
            device_id: self.device_id.clone(),
            access_token: self.access_token.clone().unwrap_or_default(),
            refresh_token: self.refresh_token.clone().unwrap_or_default(),
            access_expires: self.access_expires,
            registration_id: self.registration_id.clone().unwrap_or_default(),
            cloud_token: self.cloud_token.clone().unwrap_or_default(),
            cloud_expires: self.cloud_expires,
            csr: lock(&self.csr).clone().unwrap_or_default(),
            private_key: lock(&self.private_key).clone().unwrap_or_default(),
            bt_address: self.bt_address.clone(),
            account_key: hex::encode(bundle.account_key),
            user_fingerprint: bundle.user_fingerprint.clone(),
            revision: bundle.revision,
            devices: bundle.devices.clone(),
        }
    }

    async fn authorize_service(&mut self) -> Result<()> {
        let master_token = self.userauth_token.clone().ok_or_else(|| {
            AuthError::Protocol("no Samsung account session; run interactive sign-in first".into())
        })?;
        let login_id = self.login_id.clone().unwrap_or_default();
        let verifier = crypto::base64_url_no_pad(&crypto::random_bytes(32));
        let challenge = crypto::base64_url_no_pad(&crypto::sha256(verifier.as_bytes()));

        let mut url = Url::parse(&format!("{}/auth/oauth2/v2/authorize", self.base_url()))
            .map_err(|e| AuthError::Protocol(format!("invalid Samsung auth server: {e}")))?;
        let mut params = vec![
            ("response_type", "code"),
            ("serviceType", "M"),
            ("client_id", self.client_id.as_str()),
            ("scope", "offline.access"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("childAccountSupported", "Y"),
            ("userauth_token", master_token.as_str()),
            ("physical_address_text", self.device_id.as_str()),
            ("login_id", login_id.as_str()),
        ];
        params.sort_by(|a, b| a.0.cmp(b.0));
        {
            let mut query = url.query_pairs_mut();
            for (name, value) in params {
                query.append_pair(name, value);
            }
        }

        let authorization = self.get_json(url.as_str()).await?;
        let code = required_string(&authorization, "code")?;
        let form = [
            ("grant_type", "authorization_code".to_string()),
            ("code", code),
            ("client_id", self.client_id.clone()),
            ("client_secret", String::new()),
            ("physical_address_text", self.device_id.clone()),
            ("code_verifier", verifier),
        ];
        let token = self
            .post_form(&format!("{}/auth/oauth2/token", self.base_url()), &form)
            .await?;
        self.apply_token(&token)
    }

    fn apply_token(&mut self, token: &Value) -> Result<()> {
        let access = required_string(token, "access_token")?;
        self.access_token = Some(access);
        if let Some(refresh) = token
            .get("refresh_token")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        {
            self.refresh_token = Some(refresh.to_string());
        }
        let expires_in = token
            .get("expires_in")
            .and_then(value_as_i64)
            .unwrap_or(3600);
        self.access_expires = now_seconds() + expires_in;
        Ok(())
    }

    fn identity_headers(&self) -> Result<Vec<(String, String)>> {
        let user_id = self.user_id.as_deref().unwrap_or_default();
        let access_token = self.access_token.as_deref().unwrap_or_default();
        if user_id.is_empty() || access_token.is_empty() {
            return Err(AuthError::Protocol(
                "Samsung service authorization is incomplete".into(),
            ));
        }
        // The cloud API keys the account on the user id; the installation id
        // appears in x-sc-cdid and x-sc-pdid.
        let cdid = hex::encode(crypto::pbkdf2_sha1_16(
            format!("{}{}", self.device_id, self.client_id).as_bytes(),
            b"smcfcore",
        ));
        let pdid = hex::encode(crypto::pbkdf2_sha1_16(
            self.device_id.as_bytes(),
            b"smcfcore",
        ));
        Ok(vec![
            ("x-sc-app-id".into(), self.client_id.clone()),
            ("x-sc-app-version".into(), APP_VERSION.into()),
            ("x-sc-uid".into(), user_id.to_string()),
            ("x-sc-access-token".into(), access_token.to_string()),
            ("x-sc-cdid".into(), cdid),
            ("x-sc-pdid".into(), pdid),
        ])
    }

    fn ensure_csr(&self, device_id: &str) -> Result<String> {
        if let Some(csr) = lock(&self.csr).as_ref().filter(|value| !value.is_empty()) {
            return Ok(csr.clone());
        }
        let (csr, private_key) = crypto::make_csr(device_id)?;
        *lock(&self.csr) = Some(csr.clone());
        *lock(&self.private_key) = Some(private_key);
        Ok(csr)
    }

    fn base_url(&self) -> String {
        format!("https://{}", self.auth_server)
    }

    async fn await_loopback(&self, redirect: Url, sign_in_uri: &str) -> Result<String> {
        let host = redirect.host_str().unwrap_or("127.0.0.1").to_string();
        let port = redirect
            .port_or_known_default()
            .ok_or_else(|| AuthError::Protocol("loopback redirect URI has no port".into()))?;
        let listener = TcpListener::bind((host.as_str(), port)).await?;
        info!(port, "Waiting for the Samsung sign-in callback");
        open_browser(sign_in_uri).await;

        let accept = tokio::time::timeout(CALLBACK_TIMEOUT, listener.accept())
            .await
            .map_err(|_| AuthError::Protocol("Samsung sign-in callback timed out".into()))??;
        let (mut socket, _) = accept;

        let mut buffer = vec![0u8; 16 * 1024];
        let mut read = 0;
        while read < buffer.len() {
            let count = socket.read(&mut buffer[read..]).await?;
            if count == 0 {
                break;
            }
            read += count;
            if buffer[..read]
                .windows(4)
                .any(|window| window == b"\r\n\r\n")
            {
                break;
            }
        }
        let request = String::from_utf8_lossy(&buffer[..read]);
        let target = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .ok_or_else(|| AuthError::Protocol("invalid callback request".into()))?;
        let base = Url::parse("http://127.0.0.1")
            .map_err(|e| AuthError::Protocol(format!("invalid callback base: {e}")))?;
        let callback = base
            .join(target)
            .map_err(|e| AuthError::Protocol(format!("invalid callback URL: {e}")))?;

        let page = "<!doctype html><meta charset=\"utf-8\"><title>Samsung sign-in</title><p>Sign-in complete. You can close this window.";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            page.len(),
            page
        );
        socket.write_all(response.as_bytes()).await?;
        socket.shutdown().await?;
        Ok(callback.into())
    }

    async fn await_pasted_callback(&self, sign_in_uri: &str) -> Result<String> {
        eprintln!(
            "After signing in, the browser may fail to open the ms-app:// callback.\n\
             Copy the complete URL from the address bar, paste it here, and press Enter."
        );
        open_browser(sign_in_uri).await;
        let read = tokio::task::spawn_blocking(read_stdin_line);
        tokio::time::timeout(CALLBACK_TIMEOUT, read)
            .await
            .map_err(|_| AuthError::Protocol("Samsung sign-in callback timed out".into()))?
            .map_err(|e| AuthError::Protocol(format!("could not read callback URL: {e}")))?
    }

    fn parse_callback(&self, raw: &str) -> Result<AuthCallback> {
        let url = Url::parse(raw)
            .map_err(|e| AuthError::Protocol(format!("invalid Samsung callback URL: {e}")))?;
        let mut items: Vec<(String, String)> = url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        if let Some(fragment) = url.fragment() {
            items.extend(
                url::form_urlencoded::parse(fragment.as_bytes())
                    .map(|(key, value)| (key.into_owned(), value.into_owned())),
            );
        }
        let field = |name: &str| -> Result<String> {
            let mut values = items
                .iter()
                .filter(|(key, _)| key == name)
                .map(|(_, value)| value.as_str());
            let first = values
                .next()
                .ok_or_else(|| AuthError::Protocol(format!("Samsung sign-in omitted {name}")))?;
            if values.next().is_some() || first.is_empty() {
                return Err(AuthError::Protocol(format!(
                    "Samsung sign-in returned a duplicate or empty {name}"
                )));
            }
            Ok(first.to_string())
        };

        let response_key = crypto::callback_decrypt(&field("state")?, &self.state)?;
        if response_key.is_empty() {
            return Err(AuthError::Protocol(
                "Samsung sign-in returned an empty callback key".into(),
            ));
        }
        let server = normalize_secure_server(
            crypto::callback_decrypt(&field("auth_server_url")?, &response_key)?.trim(),
        )?;
        let code = crypto::callback_decrypt(&field("code")?, &response_key)?;
        let login_id = crypto::callback_decrypt(&field("retValue")?, &response_key)?;
        Ok(AuthCallback {
            code,
            auth_server_url: server,
            login_id,
            state: self.state.clone(),
        })
    }

    async fn get_json(&self, url: &str) -> Result<Value> {
        self.execute(self.http.get(url)).await
    }

    async fn get_json_with_headers(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<Value> {
        let mut request = self.http.get(url);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        self.execute(request).await
    }

    async fn post_form(&self, url: &str, form: &[(&str, String)]) -> Result<Value> {
        self.execute(self.http.post(url).form(form)).await
    }

    async fn post_json(
        &self,
        url: &str,
        body: &Value,
        headers: &[(String, String)],
    ) -> Result<Value> {
        let mut request = self.http.post(url).json(body);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        self.execute(request).await
    }

    async fn execute(&self, request: RequestBuilder) -> Result<Value> {
        let response = request.send().await.map_err(network_error)?;
        let status = response.status().as_u16();
        let path = response.url().path().to_string();
        let body = response.bytes().await.map_err(network_error)?;

        if !(200..300).contains(&status) {
            let failure: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let code = failure.get("rcode").and_then(value_as_i64);
            let raw = failure
                .get("error")
                .and_then(Value::as_str)
                .or_else(|| failure.get("error_code").and_then(Value::as_str))
                .unwrap_or_default();
            let detail = match (code, raw) {
                (Some(code), _) => format!(", code {code}"),
                (None, "") => String::new(),
                (None, raw) => format!(", {}", sanitize_code(raw)),
            };
            return Err(AuthError::Http {
                status,
                path,
                code,
                detail,
            });
        }
        if body.is_empty() {
            return Ok(Value::Object(Map::new()));
        }
        let value: Value = serde_json::from_slice(&body)?;
        if !value.is_object() {
            return Err(AuthError::Protocol(
                "Samsung returned a non-object JSON response".into(),
            ));
        }
        Ok(value)
    }
}

fn network_error(error: reqwest::Error) -> AuthError {
    // Request URLs for the authorize endpoint carry the master token, so the
    // URL is stripped before the error is logged or returned.
    let sanitized = error.without_url();
    warn!(error = %sanitized, "Samsung request failed");
    AuthError::Network(sanitized.to_string())
}

fn normalize_auth_server(value: &str) -> String {
    let trimmed = value.trim();
    let host = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    host.split('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn normalize_secure_server(value: &str) -> Result<String> {
    let normalized = if value.contains("://") {
        value.to_string()
    } else {
        format!("https://{value}")
    };
    let url = Url::parse(&normalized)
        .map_err(|e| AuthError::Protocol(format!("invalid Samsung auth server: {e}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| {
            AuthError::Protocol("Samsung returned an auth server without a host".into())
        })?
        .to_ascii_lowercase();
    if url.scheme() != "https"
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || url.username() != ""
        || url.password().is_some()
        || url.port().is_some_and(|port| port != 443)
        || !(host == "account.samsung.com"
            || host == "samsungosp.com"
            || host.ends_with(".samsungosp.com"))
    {
        return Err(AuthError::Protocol(format!(
            "Samsung returned an untrusted auth server: {host}"
        )));
    }
    Ok(format!("https://{host}"))
}

pub fn normalize_bt_address(address: &str) -> Result<String> {
    let digits: String = address.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if digits.len() != 12 {
        return Err(AuthError::Protocol(format!(
            "Bluetooth address {address:?} must contain six bytes"
        )));
    }
    let parts: Vec<String> = (0..6)
        .map(|index| digits[index * 2..index * 2 + 2].to_ascii_uppercase())
        .collect();
    Ok(parts.join(":"))
}

fn parse_bundle(value: &Value, local: &str) -> Result<Option<AccountKeyBundle>> {
    let Some(this_value) = value.get("thisDevice").filter(|device| !device.is_null()) else {
        return Ok(None);
    };
    let this_device = parse_device(this_value);
    if normalize_bt_address(&this_device.bt_address)
        .ok()
        .as_deref()
        != Some(local)
    {
        return Ok(None);
    }

    let user_fingerprint = required_string(value, "userFingerprint")?;
    if user_fingerprint.len() != 64
        || !user_fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(AuthError::Protocol(
            "Samsung returned an invalid account fingerprint".into(),
        ));
    }

    let keys = value
        .get("userAesKeys")
        .and_then(Value::as_array)
        .ok_or_else(|| AuthError::Protocol("Samsung returned no account keys".into()))?;
    let now = now_millis();
    let mut selected: Option<([u8; 32], i64)> = None;
    for key in keys {
        let Some(expiry) = key.get("expireTime").and_then(value_as_i64) else {
            continue;
        };
        if expiry <= now {
            continue;
        }
        let Some(encoded) = key.get("aes256Key").and_then(Value::as_str) else {
            continue;
        };
        let Ok(bytes) = STANDARD.decode(encoded) else {
            continue;
        };
        let Ok(array) = <[u8; 32]>::try_from(bytes) else {
            continue;
        };
        if selected.is_none_or(|(_, chosen)| expiry < chosen) {
            selected = Some((array, expiry));
        }
    }
    let (account_key, _) = selected
        .ok_or_else(|| AuthError::Protocol("Samsung returned no current account key".into()))?;

    let revision = value
        .get("revision")
        .and_then(value_as_i64)
        .filter(|revision| (0..=u32::MAX as i64).contains(revision))
        .ok_or_else(|| AuthError::Protocol("Samsung returned an invalid revision".into()))?
        as u32;

    let mut peers = BTreeMap::new();
    if let Some(devices) = value.get("devices").and_then(Value::as_array) {
        for entry in devices {
            let device = parse_device(entry);
            // Peers without a usable Bluetooth address cannot take part in the
            // Continuity handshake.
            let Ok(address) = normalize_bt_address(&device.bt_address) else {
                continue;
            };
            if address == local {
                continue;
            }
            peers.entry(address).or_insert(device);
        }
    }

    Ok(Some(AccountKeyBundle {
        account_key,
        user_fingerprint,
        revision,
        this_device,
        devices: peers.into_values().collect(),
    }))
}

fn parse_device(value: &Value) -> DeviceInfo {
    fn text(value: &Value, key: &str) -> String {
        value
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }
    DeviceInfo {
        bt_address: text(value, "btAddress"),
        device_name: text(value, "deviceName"),
        device_type: text(value, "deviceType"),
        device_model: text(value, "deviceModel"),
    }
}

fn required_string(value: &Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .ok_or_else(|| AuthError::Protocol(format!("Samsung response is missing {key}")))
}

fn value_as_i64(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number
            .as_i64()
            .or_else(|| number.as_f64().map(|number| number as i64)),
        Value::String(text) => text.parse().ok(),
        _ => None,
    }
}

fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

fn expiry_epoch(value: &Value) -> i64 {
    if let Some(epoch) = value
        .get("expiresAt")
        .and_then(value_as_i64)
        .filter(|epoch| *epoch > 0)
    {
        return if epoch > 100_000_000_000 {
            epoch / 1000
        } else {
            epoch
        };
    }
    now_seconds()
        + value
            .get("expiresIn")
            .and_then(value_as_i64)
            .unwrap_or(3600)
}

fn needs_refresh(expires_at: i64) -> bool {
    expires_at < now_seconds() + 120
}

fn now_seconds() -> i64 {
    now_millis() / 1000
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or_default()
}

fn is_loopback(url: &Url) -> bool {
    url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "localhost"))
}

fn masked(value: &str) -> String {
    let count = value.chars().count();
    if count <= 4 {
        return "***".to_string();
    }
    format!("***{}", value.chars().skip(count - 4).collect::<String>())
}

fn sanitize_code(value: &str) -> String {
    value
        .chars()
        .take(80)
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
        .collect()
}

async fn open_browser(url: &str) {
    let target = url.to_string();
    match tokio::task::spawn_blocking(move || open::that(target)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            warn!(error = %e, "Could not launch a browser; open the printed URL manually")
        }
        Err(e) => warn!(error = %e, "Browser launch task failed"),
    }
}

fn read_stdin_line() -> Result<String> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let line = line.trim().to_string();
    if line.is_empty() {
        return Err(AuthError::Protocol(
            "no Samsung callback URL was provided".into(),
        ));
    }
    Ok(line)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bluetooth_addresses_normalize() {
        assert_eq!(
            normalize_bt_address("aa-bb-cc-dd-ee-ff").unwrap(),
            "AA:BB:CC:DD:EE:FF"
        );
        assert!(normalize_bt_address("aa:bb:cc").is_err());
    }

    #[test]
    fn auth_server_requires_samsung_host() {
        assert_eq!(
            normalize_secure_server("eu-auth2.samsungosp.com").unwrap(),
            "https://eu-auth2.samsungosp.com"
        );
        assert!(normalize_secure_server("https://evil.example.com").is_err());
    }

    #[test]
    fn expiry_reads_seconds_and_milliseconds() {
        let seconds = json!({ "expiresAt": 1_700_000_000i64 });
        assert_eq!(expiry_epoch(&seconds), 1_700_000_000);
        let millis = json!({ "expiresAt": 1_700_000_000_000i64 });
        assert_eq!(expiry_epoch(&millis), 1_700_000_000);
    }

    #[test]
    fn masked_keeps_last_four_characters() {
        assert_eq!(masked("user@example.com"), "***.com");
        assert_eq!(masked("abc"), "***");
    }
}
