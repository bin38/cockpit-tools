//! Explicitly enrolled Codex credentials only. Cockpit owns refresh tokens;
//! CPA receives short-lived access tokens, never passwords/notes/refresh tokens.
//! One process/file lock fences sync against connection changes and deletion.
use super::{account, atomic_write, codex_account, codex_oauth, secure_account_storage};
use crate::models::codex::CodexAccount;
use reqwest::{Client, Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use url::Url;

const STORE: &str = "cpa-management.enc";
const MAX_BODY: usize = 4 * 1024 * 1024;
static STARTED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Binding {
    pub account_id: String,
    pub file_name: String,
    pub active: bool,
    pub last_synced_at: Option<i64>,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    fingerprint: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Connection {
    id: String,
    base_url: String,
    api_version: String,
    key: String,
    auto_sync: bool,
    #[serde(default)]
    default_upload: bool,
    #[serde(default)]
    known_account_ids: HashSet<String>,
    blocked: bool,
    last_error: Option<String>,
    bindings: Vec<Binding>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionView {
    id: String,
    base_url: String,
    api_version: String,
    auto_sync: bool,
    default_upload: bool,
    blocked: bool,
    last_error: Option<String>,
    bindings: Vec<Binding>,
}

impl Connection {
    fn view(&self) -> ConnectionView {
        let mut bindings = self.bindings.clone();
        for binding in &mut bindings {
            binding.fingerprint.clear();
        }
        ConnectionView {
            id: self.id.clone(),
            base_url: self.base_url.clone(),
            api_version: self.api_version.clone(),
            auto_sync: self.auto_sync,
            default_upload: self.default_upload,
            blocked: self.blocked,
            last_error: self.last_error.clone(),
            bindings,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RemoteFile {
    pub name: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default, rename = "type", skip_serializing)]
    provider_type: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub unavailable: bool,
    #[serde(default)]
    pub runtime_only: bool,
    #[serde(default)]
    pub source: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadResult {
    pub account_id: String,
    pub file_name: String,
    pub error: Option<String>,
}

fn storage_path() -> Result<PathBuf, String> {
    Ok(account::get_data_dir()?.join(STORE))
}

// try-lock avoids blocking Tauri's async workers. The OS lock also protects
// against a second application process using the same data profile.
fn lock() -> Result<fs::File, String> {
    let path = storage_path()?.with_extension("lock");
    if path.is_symlink() {
        return Err("CPA_STORAGE".into());
    }
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| "CPA_STORAGE")?;
    fs2::FileExt::try_lock_exclusive(&file).map_err(|_| "CPA_BUSY")?;
    Ok(file)
}

fn load() -> Result<Option<Connection>, String> {
    let path = storage_path()?;
    if path.is_symlink() {
        return Err("CPA_STORAGE".into());
    }
    match fs::read_to_string(&path) {
        Ok(raw) => secure_account_storage::deserialize_encrypted_snapshot(&raw)
            .map_err(|_| "CPA_STORAGE".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("CPA_STORAGE".into()),
    }
}

fn save(connection: &Option<Connection>) -> Result<(), String> {
    let encrypted = secure_account_storage::serialize_account_file("cpa-management", connection)
        .map_err(|_| "CPA_STORAGE")?;
    atomic_write::write_secret_string_atomic(&storage_path()?, &encrypted)
        .map_err(|_| "CPA_STORAGE".into())
}

fn persist(connection: &Connection) -> Result<(), String> {
    save(&Some(connection.clone()))
}

fn current(id: &str) -> Result<Connection, String> {
    let connection = load()?.ok_or("CPA_NOT_CONFIGURED")?;
    if connection.id != id {
        return Err("CPA_CONNECTION_CHANGED".into());
    }
    Ok(connection)
}

fn normalize_base(raw: &str) -> Result<String, String> {
    let mut url = Url::parse(raw.trim()).map_err(|_| "CPA_URL")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("CPA_URL".into());
    }
    let loopback = match url.host() {
        Some(url::Host::Domain(host)) => host == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if url.scheme() == "http" && !loopback {
        return Err("CPA_HTTPS_REQUIRED".into());
    }
    let path = url.path().trim_end_matches('/');
    let path = path
        .strip_suffix("/v8/management")
        .or_else(|| path.strip_suffix("/v0/management"))
        .unwrap_or(path)
        .to_string();
    if path.ends_with("/v1") || path.ends_with(".html") {
        return Err("CPA_URL".into());
    }
    url.set_path(&path);
    Ok(url.as_str().trim_end_matches('/').to_string())
}

fn valid_filename(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 240
        && name.ends_with(".json")
        && name != ".json"
        && !name.contains(['/', '\\', ':'])
        && !name.chars().any(char::is_control)
}

fn managed_filename(id: &str) -> String {
    format!("cockpit-codex-{:x}.json", Sha256::digest(id.as_bytes()))
}

fn valid_account_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 200
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

fn payload(account: &CodexAccount) -> Result<Value, String> {
    if account.is_api_key_auth()
        || account.is_agent_identity_auth()
        || account.is_web_session_auth()
        || account.upstream_grok_account_id.is_some()
        || account.tokens.access_token.trim().is_empty()
        || account.tokens.access_token.starts_with("at-")
        || (account.tokens.id_token.trim().is_empty()
            && account
                .tokens
                .refresh_token
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty())
    {
        return Err("CPA_UNSUPPORTED_ACCOUNT".into());
    }
    let expiry = codex_oauth::jwt_token_expiration_timestamp(&account.tokens.access_token)
        .ok_or("CPA_TOKEN_EXPIRY")?;
    if expiry <= chrono::Utc::now().timestamp() + 60 {
        return Err("CPA_TOKEN_EXPIRED".into());
    }
    let expired = chrono::DateTime::from_timestamp(expiry, 0)
        .ok_or("CPA_TOKEN_EXPIRY")?
        .to_rfc3339();
    Ok(
        json!({ "type": "codex", "id_token": account.tokens.id_token,
        "access_token": account.tokens.access_token, "refresh_token": "",
        "account_id": account.account_id, "email": account.email,
        "last_refresh": account.token_updated_at.unwrap_or(account.created_at).to_string(),
        "expired": expired }),
    )
}

fn client() -> Result<Client, String> {
    let builder = Client::builder();
    // HTTP fixtures must stay on loopback regardless of the test host's proxy.
    #[cfg(test)]
    let builder = builder.no_proxy();
    builder
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .connect_timeout(Duration::from_secs(8))
        .build()
        .map_err(|_| "CPA_NETWORK".into())
}

fn resource(version: &str) -> &str {
    if version == "v0" {
        "v0/management/auth-files"
    } else {
        "v8/management/credentials"
    }
}

fn endpoint(connection: &Connection, suffix: &str, name: Option<&str>) -> Result<Url, String> {
    let mut url = Url::parse(&format!(
        "{}/{}{}",
        connection.base_url,
        resource(&connection.api_version),
        suffix
    ))
    .map_err(|_| "CPA_URL")?;
    if let Some(name) = name {
        if !valid_filename(name) {
            return Err("CPA_FILENAME".into());
        }
        url.query_pairs_mut().append_pair("name", name);
    }
    Ok(url)
}

async fn request(
    client: &Client,
    connection: &Connection,
    method: Method,
    suffix: &str,
    name: Option<&str>,
    body: Option<Value>,
) -> Result<Value, String> {
    let mut req = client
        .request(method, endpoint(connection, suffix, name)?)
        .bearer_auth(&connection.key);
    if let Some(body) = body {
        req = req.json(&body);
    }
    let mut response = req.send().await.map_err(|_| "CPA_NETWORK")?;
    match response.status() {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => return Err("CPA_AUTH".into()),
        StatusCode::NOT_FOUND => return Err("CPA_NOT_FOUND".into()),
        status if !status.is_success() || status == StatusCode::MULTI_STATUS => {
            return Err(format!("CPA_HTTP_{}", status.as_u16()))
        }
        _ => {}
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| "CPA_NETWORK")? {
        if bytes.len() + chunk.len() > MAX_BODY {
            return Err("CPA_RESPONSE".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| "CPA_RESPONSE".into())
}

fn expect_ok(value: Value) -> Result<(), String> {
    if value.get("status").and_then(Value::as_str) == Some("ok") {
        Ok(())
    } else {
        Err("CPA_RESPONSE".into())
    }
}

async fn list(client: &Client, connection: &Connection) -> Result<Vec<RemoteFile>, String> {
    let result = request(client, connection, Method::GET, "", None, None).await?;
    let mut files: Vec<RemoteFile> =
        serde_json::from_value(result.get("files").cloned().ok_or("CPA_RESPONSE")?)
            .map_err(|_| "CPA_RESPONSE")?;
    let mut names = HashSet::new();
    for file in &mut files {
        if file.provider.is_empty() {
            file.provider = file.provider_type.clone();
        }
        if !names.insert(file.name.to_lowercase()) {
            return Err("CPA_AMBIGUOUS_FILES".into());
        }
    }
    Ok(files)
}

fn record_error(connection: &mut Connection, error: &str) -> Result<(), String> {
    connection.last_error = Some(error.to_string());
    // Never repeat authentication failures automatically (CPA has IP bans).
    if error == "CPA_AUTH" {
        connection.blocked = true;
    }
    persist(connection)
}

pub fn get() -> Result<Option<ConnectionView>, String> {
    let _guard = lock()?;
    Ok(load()?.map(|c| c.view()))
}

pub async fn configure(
    id: Option<String>,
    base_url: String,
    key: Option<String>,
    version: String,
    auto_sync: bool,
    default_upload: bool,
) -> Result<ConnectionView, String> {
    let _guard = lock()?;
    let old = load()?;
    if old.as_ref().map(|c| &c.id) != id.as_ref() {
        return Err("CPA_CONNECTION_CHANGED".into());
    }
    let base_url = normalize_base(&base_url)?;
    if let Some(old) = &old {
        if old.base_url != base_url && !old.bindings.is_empty() {
            return Err("CPA_DISCONNECT_FIRST".into());
        }
    }
    if !matches!(version.as_str(), "auto" | "v8" | "v0") {
        return Err("CPA_VERSION".into());
    }
    let key = key
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            old.as_ref()
                .filter(|c| c.base_url == base_url)
                .map(|c| c.key.clone())
        })
        .ok_or("CPA_KEY")?;
    if key.chars().any(char::is_control) || key.len() > 4096 {
        return Err("CPA_KEY".into());
    }
    let mut connection = Connection {
        id: uuid::Uuid::new_v4().to_string(),
        base_url,
        api_version: if version == "auto" {
            "v8".into()
        } else {
            version.clone()
        },
        key: key.trim().into(),
        auto_sync,
        default_upload,
        blocked: false,
        last_error: None,
        known_account_ids: if default_upload && old.as_ref().is_some_and(|c| c.default_upload) {
            old.as_ref().unwrap().known_account_ids.clone()
        } else {
            codex_account::list_accounts_checked()
                .map_err(|_| "CPA_LOCAL_MISSING")?
                .into_iter()
                .map(|a| a.id)
                .collect()
        },
        bindings: old.as_ref().map(|c| c.bindings.clone()).unwrap_or_default(),
    };
    let client = client()?;
    let mut result = list(&client, &connection).await;
    // Read-only capability detection only. Never downgrade a failed write or auth failure.
    if version == "auto" && result.as_ref().err().map(String::as_str) == Some("CPA_NOT_FOUND") {
        connection.api_version = "v0".into();
        result = list(&client, &connection).await;
    }
    if let Err(error) = result {
        if let Some(mut old) = old {
            // Pause the previous connection too if the same server rejects a key.
            if old.base_url == connection.base_url && error == "CPA_AUTH" {
                record_error(&mut old, &error)?;
            }
        }
        return Err(error);
    }
    persist(&connection)?;
    Ok(connection.view())
}

pub fn disconnect(id: &str) -> Result<(), String> {
    let _guard = lock()?;
    current(id)?;
    // No remote mutation; replacing with encrypted null also removes the key.
    save(&None)
}

pub async fn list_remote(id: &str) -> Result<Vec<RemoteFile>, String> {
    let _guard = lock()?;
    let mut connection = current(id)?;
    if connection.blocked {
        return Err("CPA_AUTH_BLOCKED".into());
    }
    match list(&client()?, &connection).await {
        Ok(files) => Ok(files
            .into_iter()
            .filter(|f| f.provider == "codex")
            .collect()),
        Err(e) => {
            record_error(&mut connection, &e)?;
            Err(e)
        }
    }
}

fn writable(file: &RemoteFile) -> bool {
    !file.runtime_only
        && file.source != "memory"
        && valid_filename(&file.name)
        && file.provider == "codex"
}

async fn transfer(
    client: &Client,
    connection: &Connection,
    file_name: &str,
    data: Value,
    existing: bool,
) -> Result<(), String> {
    if existing {
        // Merge only token fields: preserve CPA's disabled state, proxy, priority,
        // excluded models and other remote metadata. PATCH never creates a file.
        let mut fields = data;
        fields["name"] = json!(file_name);
        expect_ok(
            request(
                client,
                connection,
                Method::PATCH,
                "/fields",
                None,
                Some(fields),
            )
            .await?,
        )
    } else {
        expect_ok(
            request(
                client,
                connection,
                Method::POST,
                "",
                Some(file_name),
                Some(data),
            )
            .await?,
        )
    }
}

pub async fn upload(id: &str, account_ids: Vec<String>) -> Result<Vec<UploadResult>, String> {
    let _guard = lock()?;
    let mut connection = current(id)?;
    if connection.blocked {
        return Err("CPA_AUTH_BLOCKED".into());
    }
    if account_ids.is_empty()
        || account_ids.len() > 100
        || account_ids.iter().any(|id| !valid_account_id(id))
    {
        return Err("CPA_SELECTION".into());
    }
    let client = client()?;
    let files = match list(&client, &connection).await {
        Ok(files) => files,
        Err(e) => {
            record_error(&mut connection, &e)?;
            return Err(e);
        }
    };
    let mut results = Vec::new();
    let mut seen = HashSet::new();
    let mut network_failed = false;
    for account_id in account_ids {
        if !seen.insert(account_id.clone()) {
            continue;
        }
        let file_name = connection
            .bindings
            .iter()
            .find(|b| b.account_id == account_id)
            .map(|b| b.file_name.clone())
            .unwrap_or_else(|| managed_filename(&account_id));
        connection.known_account_ids.insert(account_id.clone());
        let account_payload = codex_account::load_account(&account_id)
            .ok_or("CPA_LOCAL_MISSING".into())
            .and_then(|a| payload(&a));
        let existing = files.iter().find(|f| f.name == file_name);
        let known = connection
            .bindings
            .iter()
            .any(|b| b.account_id == account_id && b.file_name == file_name);
        let error = if connection.blocked {
            Some("CPA_AUTH_BLOCKED".into())
        } else if network_failed {
            Some("CPA_NETWORK".into())
        } else if existing.is_some() && !known {
            Some("CPA_NAME_CONFLICT".into())
        } else if existing.is_some_and(|f| !writable(f)) {
            Some("CPA_READ_ONLY".into())
        } else {
            match account_payload {
                Err(e) => Some(e),
                Ok(data) => {
                    let fingerprint = format!("{:x}", Sha256::digest(data.to_string()));
                    // Publish ownership before sending; an uncertain result is never auto-retried.
                    connection.bindings.retain(|b| b.account_id != account_id);
                    connection.bindings.push(Binding {
                        account_id: account_id.clone(),
                        file_name: file_name.clone(),
                        active: false,
                        last_synced_at: None,
                        error: Some("CPA_VERIFY_REQUIRED".into()),
                        fingerprint: String::new(),
                    });
                    persist(&connection)?;
                    match transfer(&client, &connection, &file_name, data, existing.is_some()).await
                    {
                        Ok(()) => {
                            let binding = connection.bindings.last_mut().unwrap();
                            binding.active = true;
                            binding.last_synced_at = Some(chrono::Utc::now().timestamp());
                            binding.error = None;
                            binding.fingerprint = fingerprint;
                            persist(&connection)?;
                            None
                        }
                        Err(e) => {
                            connection.bindings.last_mut().unwrap().error = Some(e.clone());
                            record_error(&mut connection, &e)?;
                            Some(e)
                        }
                    }
                }
            }
        };
        if error.as_deref() == Some("CPA_NETWORK") {
            network_failed = true;
        }
        results.push(UploadResult {
            account_id,
            file_name,
            error,
        });
    }
    Ok(results)
}

pub async fn set_disabled(id: &str, name: &str, disabled: bool) -> Result<(), String> {
    let _guard = lock()?;
    let mut connection = current(id)?;
    if connection.blocked {
        return Err("CPA_AUTH_BLOCKED".into());
    }
    let client = client()?;
    let result: Result<(), String> = async {
        let files = list(&client, &connection).await?;
        let file = files
            .iter()
            .find(|f| f.name == name)
            .ok_or("CPA_NOT_FOUND")?;
        if !writable(file) {
            return Err("CPA_READ_ONLY".into());
        }
        expect_ok(
            request(
                &client,
                &connection,
                Method::PATCH,
                "/status",
                None,
                Some(json!({"name": name, "disabled": disabled})),
            )
            .await?,
        )
    }
    .await;
    if let Err(e) = &result {
        record_error(&mut connection, e)?;
    }
    result
}

pub async fn delete_remote(id: &str, name: &str, delete_local: bool) -> Result<(), String> {
    let _guard = lock()?;
    let mut connection = current(id)?;
    if !valid_filename(name) {
        return Err("CPA_FILENAME".into());
    }
    let local_id = connection
        .bindings
        .iter()
        .find(|b| b.file_name == name)
        .map(|b| b.account_id.clone());
    if delete_local && local_id.is_none() {
        return Err("CPA_NOT_LINKED".into());
    }
    // Durable stop BEFORE network I/O: no background upload may resurrect a
    // deleted credential, even if deletion succeeds but its response is lost.
    for binding in &mut connection.bindings {
        if binding.file_name == name {
            binding.active = false;
            binding.error = Some("CPA_SYNC_STOPPED".into());
        }
    }
    persist(&connection)?;
    if connection.blocked {
        return Err("CPA_AUTH_BLOCKED".into());
    }
    let client = client()?;
    let result: Result<(), String> = async {
        let files = list(&client, &connection).await?;
        let Some(file) = files.iter().find(|f| f.name == name) else {
            return Ok(());
        };
        if !writable(file) {
            return Err("CPA_READ_ONLY".into());
        }
        match request(&client, &connection, Method::DELETE, "", Some(name), None).await {
            Ok(value) => expect_ok(value),
            Err(e) if e == "CPA_NOT_FOUND" => Ok(()),
            Err(e) => Err(e),
        }
    }
    .await;
    if let Err(e) = &result {
        record_error(&mut connection, e)?;
    }
    result?;
    if delete_local {
        let local_id = local_id.unwrap();
        // Use the existing deletion workflow, including recycle bin and cleanup.
        crate::commands::codex::delete_codex_account(local_id)
            .await
            .map_err(|_| "CPA_REMOTE_DELETED_LOCAL_FAILED")?;
    }
    Ok(())
}

pub async fn link_existing(id: &str, name: &str, account_id: &str) -> Result<(), String> {
    let _guard = lock()?;
    let mut connection = current(id)?;
    if connection.blocked {
        return Err("CPA_AUTH_BLOCKED".into());
    }
    if !valid_filename(name) || !valid_account_id(account_id) {
        return Err("CPA_SELECTION".into());
    }
    if connection
        .bindings
        .iter()
        .any(|b| b.file_name == name || b.account_id == account_id)
    {
        return Err("CPA_ALREADY_LINKED".into());
    }
    let account = codex_account::load_account(account_id).ok_or("CPA_LOCAL_MISSING")?;
    payload(&account)?;
    let client = client()?;
    let result: Result<(), String> = async {
        let files = list(&client, &connection).await?;
        if !files.iter().any(|f| f.name == name && writable(f)) {
            return Err("CPA_READ_ONLY".into());
        }
        // A filename/email guess never authorizes linking or coupled deletion.
        // Read only this explicitly chosen credential and compare both identities.
        let remote = request(
            &client,
            &connection,
            Method::GET,
            "/download",
            Some(name),
            None,
        )
        .await?;
        let local_account = account
            .account_id
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .ok_or("CPA_IDENTITY_MISMATCH")?;
        if remote.get("type").and_then(Value::as_str) != Some("codex")
            || remote.get("account_id").and_then(Value::as_str) != Some(local_account)
            || !remote
                .get("email")
                .and_then(Value::as_str)
                .is_some_and(|s| s.eq_ignore_ascii_case(&account.email))
        {
            return Err("CPA_IDENTITY_MISMATCH".into());
        }
        Ok(())
    }
    .await;
    if let Err(e) = result {
        record_error(&mut connection, &e)?;
        return Err(e);
    }
    connection.known_account_ids.insert(account_id.into());
    connection.bindings.push(Binding {
        account_id: account_id.into(),
        file_name: name.into(),
        active: false,
        last_synced_at: None,
        error: Some("CPA_LINKED_NOT_UPLOADED".into()),
        fingerprint: String::new(),
    });
    persist(&connection)
}

pub fn stop_sync(id: &str, account_id: &str) -> Result<(), String> {
    let _guard = lock()?;
    let mut connection = current(id)?;
    let binding = connection
        .bindings
        .iter_mut()
        .find(|b| b.account_id == account_id)
        .ok_or("CPA_LOCAL_MISSING")?;
    binding.active = false;
    binding.error = Some("CPA_SYNC_STOPPED".into());
    persist(&connection)
}

async fn sync_once() -> Result<(), String> {
    let _guard = lock()?;
    let Some(mut connection) = load()? else {
        return Ok(());
    };
    if connection.blocked {
        return Ok(());
    }
    // Discover only accounts added after explicit opt-in. Historical accounts,
    // stopped/deleted links and failed attempts are never silently re-enrolled.
    if connection.default_upload {
        let ids: Vec<String> = codex_account::list_accounts_checked()
            .map_err(|_| "CPA_LOCAL_MISSING")?
            .into_iter()
            .map(|a| a.id)
            .filter(|id| !connection.known_account_ids.contains(id))
            .filter(|id| codex_account::load_account(id).is_some_and(|a| payload(&a).is_ok()))
            .take(100)
            .collect();
        if !ids.is_empty() {
            connection.known_account_ids.extend(ids.iter().cloned());
            persist(&connection)?;
            let id = connection.id.clone();
            drop(_guard);
            upload(&id, ids).await?;
            return Ok(());
        }
    }
    if !connection.auto_sync || !connection.bindings.iter().any(|b| b.active) {
        return Ok(());
    }
    let client = client()?;
    let files = match list(&client, &connection).await {
        Ok(files) => files,
        Err(e) => {
            record_error(&mut connection, &e)?;
            return Err(e);
        }
    };
    connection.last_error = None;
    for index in 0..connection.bindings.len() {
        if !connection.bindings[index].active {
            continue;
        }
        let binding = connection.bindings[index].clone();
        let file = files.iter().find(|f| f.name == binding.file_name);
        let data = codex_account::load_account(&binding.account_id)
            .ok_or("CPA_LOCAL_MISSING".into())
            .and_then(|a| payload(&a));
        let error = if !file.is_some_and(writable) {
            Some("CPA_REMOTE_MISSING".into())
        } else {
            match data {
                Err(e) => Some(e),
                Ok(data) => {
                    let fingerprint = format!("{:x}", Sha256::digest(data.to_string()));
                    if binding.fingerprint == fingerprint {
                        continue;
                    }
                    match transfer(&client, &connection, &binding.file_name, data, true).await {
                        Ok(()) => {
                            connection.bindings[index].fingerprint = fingerprint;
                            connection.bindings[index].last_synced_at =
                                Some(chrono::Utc::now().timestamp());
                            None
                        }
                        Err(e) => Some(e),
                    }
                }
            }
        };
        if let Some(e) = &error {
            // Explicit recovery only: fail closed rather than repeat writes or
            // recreate records removed by another CPA administrator.
            connection.bindings[index].active = false;
            if e == "CPA_AUTH" {
                connection.blocked = true;
                connection.last_error = Some(e.clone());
            }
        }
        connection.bindings[index].error = error;
        persist(&connection)?;
        if connection.blocked {
            break;
        }
    }
    persist(&connection)
}

pub fn ensure_started() {
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    tauri::async_runtime::spawn(async {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            // All errors are persisted without remote bodies or credentials.
            let _ = sync_once().await;
        }
    });
}

#[cfg(test)]
#[path = "cpa_management_tests.rs"]
mod tests;
