use super::*;
use crate::models::codex::{CodexAuthMode, CodexTokens};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

fn fixture() -> CodexAccount {
    let claims = json!({"exp": chrono::Utc::now().timestamp() + 3600});
    let token = format!("e30.{}.sig", URL_SAFE_NO_PAD.encode(claims.to_string()));
    let mut account = CodexAccount::new(
        "codex_test".into(),
        "test@example.com".into(),
        CodexTokens {
            id_token: "id-secret".into(),
            access_token: token,
            refresh_token: Some("never-upload-refresh".into()),
        },
    );
    account.account_id = Some("account-123".into());
    account.account_password = Some("never-upload-password".into());
    account.two_factor_secret = Some("never-upload-2fa".into());
    account
}

fn connection(base_url: String) -> Connection {
    Connection {
        id: "connection-test".into(),
        base_url,
        api_version: "v8".into(),
        key: "management-secret".into(),
        auto_sync: true,
        default_upload: false,
        known_account_ids: HashSet::new(),
        blocked: false,
        last_error: None,
        bindings: vec![],
    }
}

// Local HTTP fixtures only. No provider or user CPA receives test credentials.
fn server(
    responses: Vec<(u16, Value)>,
) -> (String, Arc<Mutex<Vec<String>>>, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let calls = Arc::new(Mutex::new(vec![]));
    let captured = calls.clone();
    let handle = std::thread::spawn(move || {
        for (status, body) in responses {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut bytes = vec![];
            loop {
                let mut buffer = [0; 4096];
                let count = stream.read(&mut buffer).unwrap();
                if count == 0 {
                    break;
                }
                bytes.extend_from_slice(&buffer[..count]);
                if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
                    let length: usize = headers
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length: "))
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    if bytes.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            captured
                .lock()
                .unwrap()
                .push(String::from_utf8(bytes).unwrap());
            let body = body.to_string();
            write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        }
    });
    (address, calls, handle)
}

#[test]
fn urls_filenames_and_ids_fail_closed() {
    assert_eq!(
        normalize_base("https://example.com/prefix/v8/management/").unwrap(),
        "https://example.com/prefix"
    );
    assert_eq!(
        normalize_base("http://127.0.0.1:8317").unwrap(),
        "http://127.0.0.1:8317"
    );
    assert!(normalize_base("http://[::1]:8317").is_ok());
    for url in [
        "http://example.com",
        "ftp://example.com",
        "https://user:secret@example.com",
        "https://example.com?key=secret",
        "https://example.com/#x",
        "https://example.com/v1",
    ] {
        assert!(normalize_base(url).is_err(), "{url}");
    }
    for name in [
        "../file.json",
        "a/b.json",
        "a\\b.json",
        "a.json\n",
        "file",
        ".json",
    ] {
        assert!(!valid_filename(name));
    }
    assert!(valid_filename("a b&c.json"));
    assert!(!valid_account_id("../secret"));
    assert_eq!(managed_filename("account"), managed_filename("account"));
    assert_ne!(managed_filename("account"), managed_filename("other"));
}

#[test]
fn payload_excludes_secrets_and_rejects_unsupported_accounts() {
    let mut account = fixture();
    let value = payload(&account).unwrap();
    assert_eq!(value["refresh_token"], "");
    for secret in [
        "never-upload-refresh",
        "never-upload-password",
        "never-upload-2fa",
    ] {
        assert!(!value.to_string().contains(secret));
    }
    account.auth_mode = CodexAuthMode::Apikey;
    assert!(payload(&account).is_err());
    account.auth_mode = CodexAuthMode::OAuth;
    account.tokens.access_token = "at-personal".into();
    assert!(payload(&account).is_err());
    account.tokens.access_token = format!("e30.{}.sig", URL_SAFE_NO_PAD.encode(r#"{"exp":1}"#));
    assert!(payload(&account).is_err());
}

#[test]
fn public_view_never_contains_management_key_or_token_fingerprint() {
    let mut conn = connection("https://example.com".into());
    conn.bindings.push(Binding {
        account_id: "x".into(),
        file_name: "x.json".into(),
        active: true,
        last_synced_at: None,
        error: None,
        fingerprint: "secret-fingerprint".into(),
    });
    let view = serde_json::to_string(&conn.view()).unwrap();
    assert!(!view.contains("management-secret"));
    assert!(!view.contains("secret-fingerprint"));
}

#[tokio::test]
async fn token_update_uses_patch_and_preserves_unrelated_remote_fields() {
    let (url, calls, thread) = server(vec![
        (
            200,
            json!({"type":"codex","account_id":"account-123","email":"test@example.com"}),
        ),
        (200, json!({"status":"ok"})),
    ]);
    transfer(
        &client().unwrap(),
        &connection(url),
        "a b&c.json",
        payload(&fixture()).unwrap(),
        true,
    )
    .await
    .unwrap();
    thread.join().unwrap();
    let call = calls.lock().unwrap()[1].clone();
    assert!(call.starts_with("PATCH /v8/management/credentials/fields "));
    assert!(call
        .to_lowercase()
        .contains("authorization: bearer management-secret"));
    assert!(call.contains("\"name\":\"a b&c.json\""));
    assert!(!call.contains("never-upload-refresh"));
    assert!(!call.contains("disabled"));
}

#[tokio::test]
async fn upload_and_delete_encode_exact_filename_and_support_v0() {
    let (url, calls, thread) = server(vec![
        (200, json!({"status":"ok"})),
        (200, json!({"status":"ok"})),
    ]);
    let mut conn = connection(url);
    conn.api_version = "v0".into();
    let client = client().unwrap();
    transfer(
        &client,
        &conn,
        "a&b.json",
        payload(&fixture()).unwrap(),
        false,
    )
    .await
    .unwrap();
    request(&client, &conn, Method::DELETE, "", Some("a&b.json"), None)
        .await
        .unwrap();
    thread.join().unwrap();
    let calls = calls.lock().unwrap();
    assert!(calls[0].starts_with("POST /v0/management/auth-files?name=a%26b.json "));
    assert!(calls[1].starts_with("DELETE /v0/management/auth-files?name=a%26b.json "));
    assert!(!calls[1].contains("all=true"));
}

#[tokio::test]
async fn auth_failures_are_not_retried_or_exposed() {
    let (url, calls, thread) = server(vec![(401, json!({"error":"private-server-token"}))]);
    assert_eq!(
        list(&client().unwrap(), &connection(url))
            .await
            .err()
            .unwrap(),
        "CPA_AUTH"
    );
    thread.join().unwrap();
    assert_eq!(calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn malformed_success_and_duplicate_names_are_not_treated_as_empty() {
    let (url, _, thread) = server(vec![
        (200, json!({"wrong":[]})),
        (200, json!({"files":[{"name":"a.json"},{"name":"a.json"}]})),
    ]);
    let conn = connection(url);
    let client = client().unwrap();
    assert_eq!(list(&client, &conn).await.err().unwrap(), "CPA_RESPONSE");
    assert_eq!(
        list(&client, &conn).await.err().unwrap(),
        "CPA_AMBIGUOUS_FILES"
    );
    thread.join().unwrap();
    assert!(expect_ok(json!({"status":"partial"})).is_err());
}

#[tokio::test]
async fn real_cpa_list_supports_both_provider_and_type_fields() {
    let (url, _, thread) = server(vec![(
        200,
        json!({"files":[
            {"name":"a.json","provider":"codex","type":"codex","source":"file"},
            {"name":"b.json","type":"codex"}
        ]}),
    )]);
    let files = list(&client().unwrap(), &connection(url)).await.unwrap();
    thread.join().unwrap();
    assert_eq!(files.len(), 2);
    assert!(files.iter().all(|f| f.provider == "codex"));
}

struct TestStore {
    dir: PathBuf,
    previous: Option<std::ffi::OsString>,
}
impl TestStore {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("cpa-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let previous = std::env::var_os("COCKPIT_TOOLS_TEST_DATA_DIR");
        std::env::set_var("COCKPIT_TOOLS_TEST_DATA_DIR", &dir);
        Self { dir, previous }
    }
}
impl Drop for TestStore {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => std::env::set_var("COCKPIT_TOOLS_TEST_DATA_DIR", value),
            None => std::env::remove_var("COCKPIT_TOOLS_TEST_DATA_DIR"),
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}
fn remote(name: &str) -> Value {
    json!({"name":name,"provider":"codex","source":"file","email":"test@example.com"})
}

#[tokio::test]
async fn configure_detects_v0_without_mutating_remote_and_encrypts_key() {
    let _env_lock = super::super::test_support::env_lock().lock().unwrap();
    let _store = TestStore::new();
    let (url, calls, thread) = server(vec![(404, json!({})), (200, json!({"files":[]}))]);
    let view = configure(
        None,
        url,
        Some("management-secret".into()),
        "auto".into(),
        true,
        false,
    )
    .await
    .unwrap();
    assert_eq!(view.api_version, "v0");
    thread.join().unwrap();
    assert!(calls.lock().unwrap().iter().all(|r| r.starts_with("GET ")));
    let disk = fs::read_to_string(storage_path().unwrap()).unwrap();
    assert!(disk.contains("AES-256-GCM"));
    assert!(!disk.contains("management-secret"));
    disconnect(&view.id).unwrap();
    assert!(load().unwrap().is_none());
}

#[tokio::test]
async fn partial_batch_preserves_success_and_never_enrolls_failed_write() {
    let _env_lock = super::super::test_support::env_lock().lock().unwrap();
    let _store = TestStore::new();
    let first = fixture();
    let mut second = fixture();
    second.id = "codex_second".into();
    codex_account::save_account(&first).unwrap();
    codex_account::save_account(&second).unwrap();
    let (url, _, thread) = server(vec![
        (200, json!({"files":[]})),
        (200, json!({"status":"ok"})),
        (500, json!({"secret":"do-not-expose"})),
    ]);
    let conn = connection(url);
    persist(&conn).unwrap();
    let result = upload(&conn.id, vec![first.id.clone(), second.id.clone()])
        .await
        .unwrap();
    thread.join().unwrap();
    assert!(result[0].error.is_none());
    assert_eq!(result[1].error.as_deref(), Some("CPA_HTTP_500"));
    let stored = load().unwrap().unwrap();
    assert!(stored.bindings[0].active);
    assert!(!stored.bindings[1].active);
    assert!(!serde_json::to_string(&stored.view())
        .unwrap()
        .contains("do-not-expose"));
}

#[tokio::test]
async fn deleting_remote_fences_sync_and_failure_keeps_local_account() {
    let _env_lock = super::super::test_support::env_lock().lock().unwrap();
    let _store = TestStore::new();
    let account = fixture();
    codex_account::save_account(&account).unwrap();
    let name = managed_filename(&account.id);
    let (url, _, thread) = server(vec![
        (200, json!({"files":[remote(&name)]})),
        (
            200,
            json!({"type":"codex","account_id":account.account_id,"email":account.email}),
        ),
        (500, json!({})),
    ]);
    let mut conn = connection(url);
    conn.bindings.push(Binding {
        account_id: account.id.clone(),
        file_name: name.clone(),
        active: true,
        last_synced_at: None,
        error: None,
        fingerprint: String::new(),
    });
    persist(&conn).unwrap();
    assert!(delete_remote(&conn.id, &name, true).await.is_err());
    thread.join().unwrap();
    assert!(codex_account::load_account(&account.id).is_some());
    assert!(!load().unwrap().unwrap().bindings[0].active);
    // No network request, despite having a changed token and automatic sync on.
    sync_once().await.unwrap();
}

#[tokio::test]
async fn missing_remote_is_never_recreated_by_background_sync() {
    let _env_lock = super::super::test_support::env_lock().lock().unwrap();
    let _store = TestStore::new();
    let account = fixture();
    codex_account::save_account(&account).unwrap();
    let (url, calls, thread) = server(vec![(200, json!({"files":[]}))]);
    let mut conn = connection(url);
    conn.bindings.push(Binding {
        account_id: account.id.clone(),
        file_name: managed_filename(&account.id),
        active: true,
        last_synced_at: None,
        error: None,
        fingerprint: String::new(),
    });
    persist(&conn).unwrap();
    sync_once().await.unwrap();
    thread.join().unwrap();
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert!(!load().unwrap().unwrap().bindings[0].active);
}

#[tokio::test]
async fn default_upload_enrolls_only_new_accounts_and_does_not_repeat() {
    let _env_lock = super::super::test_support::env_lock().lock().unwrap();
    let _store = TestStore::new();
    let old = fixture();
    codex_account::save_account(&old).unwrap();
    let mut new = fixture();
    new.id = "codex_new".into();
    let (url, calls, thread) = server(vec![
        (200, json!({"files":[]})),
        (200, json!({"status":"ok"})),
    ]);
    let mut conn = connection(url);
    conn.auto_sync = false;
    conn.default_upload = true;
    conn.known_account_ids.insert(old.id.clone());
    persist(&conn).unwrap();
    codex_account::save_account(&new).unwrap();
    sync_once().await.unwrap();
    thread.join().unwrap();
    sync_once().await.unwrap();
    let saved = load().unwrap().unwrap();
    assert_eq!(saved.bindings.len(), 1);
    assert_eq!(saved.bindings[0].account_id, new.id);
    assert_eq!(calls.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn linking_checks_account_identity_without_writing_remote_tokens() {
    let _env_lock = super::super::test_support::env_lock().lock().unwrap();
    let _store = TestStore::new();
    let account = fixture();
    codex_account::save_account(&account).unwrap();
    let (url, calls, thread) = server(vec![
        (200, json!({"files":[remote("existing.json")]})),
        (
            200,
            json!({"type":"codex","account_id":"other-account","email":account.email}),
        ),
        (200, json!({"files":[remote("existing.json")]})),
        (
            200,
            json!({"type":"codex","account_id":account.account_id,"email":account.email}),
        ),
    ]);
    let conn = connection(url);
    persist(&conn).unwrap();
    assert_eq!(
        link_existing(&conn.id, "existing.json", &account.id)
            .await
            .err()
            .unwrap(),
        "CPA_IDENTITY_MISMATCH"
    );
    assert!(load().unwrap().unwrap().bindings.is_empty());
    link_existing(&conn.id, "existing.json", &account.id)
        .await
        .unwrap();
    thread.join().unwrap();
    assert!(calls.lock().unwrap().iter().all(|r| r.starts_with("GET ")));
    let saved = load().unwrap().unwrap();
    assert!(!saved.bindings[0].active);
    assert_eq!(saved.bindings[0].file_name, "existing.json");
}

#[tokio::test]
async fn blocked_connection_and_stale_id_never_send_requests() {
    let _env_lock = super::super::test_support::env_lock().lock().unwrap();
    let _store = TestStore::new();
    let mut conn = connection("https://never-contact.invalid".into());
    conn.blocked = true;
    persist(&conn).unwrap();
    assert_eq!(
        list_remote(&conn.id).await.err().unwrap(),
        "CPA_AUTH_BLOCKED"
    );
    assert_eq!(
        upload("stale", vec!["a".into()]).await.err().unwrap(),
        "CPA_CONNECTION_CHANGED"
    );
    sync_once().await.unwrap();
}

#[tokio::test]
async fn replaced_remote_identity_blocks_token_update() {
    let (url, calls, thread) = server(vec![(
        200,
        json!({"type":"codex","account_id":"another-account","email":"test@example.com"}),
    )]);
    let result = transfer(
        &client().unwrap(),
        &connection(url),
        "old.json",
        payload(&fixture()).unwrap(),
        true,
    )
    .await;
    thread.join().unwrap();
    assert_eq!(result.err().unwrap(), "CPA_IDENTITY_MISMATCH");
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert!(calls.lock().unwrap()[0].starts_with("GET "));
}
