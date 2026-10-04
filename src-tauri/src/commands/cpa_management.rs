use crate::modules::cpa_management::{self as cpa, ConnectionView, RemoteFile, UploadResult};

#[tauri::command]
pub fn cpa_get_connection() -> Result<Option<ConnectionView>, String> {
    cpa::get()
}

#[tauri::command]
pub async fn cpa_save_connection(
    id: Option<String>,
    base_url: String,
    key: Option<String>,
    version: String,
    auto_sync: bool,
    default_upload: bool,
    allow_insecure_http: Option<bool>,
    auto_delete_invalid: Option<bool>,
) -> Result<ConnectionView, String> {
    cpa::configure(
        id,
        base_url,
        key,
        version,
        auto_sync,
        default_upload,
        allow_insecure_http.unwrap_or(false),
        auto_delete_invalid.unwrap_or(false),
    )
    .await
}

#[tauri::command]
pub fn cpa_disconnect(id: String) -> Result<(), String> {
    cpa::disconnect(&id)
}

#[tauri::command]
pub async fn cpa_list_credentials(id: String) -> Result<Vec<RemoteFile>, String> {
    cpa::list_remote(&id).await
}

#[tauri::command]
pub async fn cpa_upload_accounts(
    id: String,
    account_ids: Vec<String>,
) -> Result<Vec<UploadResult>, String> {
    cpa::upload(&id, account_ids).await
}

#[tauri::command]
pub async fn cpa_set_disabled(id: String, name: String, disabled: bool) -> Result<(), String> {
    cpa::set_disabled(&id, &name, disabled).await
}

#[tauri::command]
pub async fn cpa_delete_credential(
    id: String,
    name: String,
    delete_local: bool,
) -> Result<(), String> {
    cpa::delete_remote(&id, &name, delete_local).await
}

#[tauri::command]
pub async fn cpa_link_credential(
    id: String,
    name: String,
    account_id: String,
) -> Result<(), String> {
    cpa::link_existing(&id, &name, &account_id).await
}

#[tauri::command]
pub fn cpa_stop_sync(id: String, account_id: String) -> Result<(), String> {
    cpa::stop_sync(&id, &account_id)
}
