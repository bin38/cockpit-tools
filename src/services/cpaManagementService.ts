import { invoke } from '@tauri-apps/api/core';

export interface CpaBinding {
  accountId: string;
  fileName: string;
  active: boolean;
  lastSyncedAt: number | null;
  error: string | null;
}
export interface CpaConnection {
  id: string;
  baseUrl: string;
  apiVersion: 'v8' | 'v0';
  allowInsecureHttp: boolean;
  autoSync: boolean;
  defaultUpload: boolean;
  blocked: boolean;
  lastError: string | null;
  bindings: CpaBinding[];
}
export interface CpaRemoteFile {
  name: string;
  provider: string;
  email: string;
  status: string;
  disabled: boolean;
  unavailable: boolean;
  runtime_only: boolean;
  source: string;
}
export interface CpaUploadResult { accountId: string; fileName: string; error: string | null }
export const getConnection = () => invoke<CpaConnection | null>('cpa_get_connection');
export const saveConnection = (input: {
  id: string | null; baseUrl: string; key: string | null; version: string;
  autoSync: boolean; defaultUpload: boolean; allowInsecureHttp: boolean;
}) => invoke<CpaConnection>('cpa_save_connection', input);
export const disconnect = (id: string) => invoke<void>('cpa_disconnect', { id });
export const listCredentials = (id: string) => invoke<CpaRemoteFile[]>('cpa_list_credentials', { id });
export const uploadAccounts = (id: string, accountIds: string[]) =>
  invoke<CpaUploadResult[]>('cpa_upload_accounts', { id, accountIds });
export const setDisabled = (id: string, name: string, disabled: boolean) =>
  invoke<void>('cpa_set_disabled', { id, name, disabled });
export const deleteCredential = (id: string, name: string, deleteLocal: boolean) =>
  invoke<void>('cpa_delete_credential', { id, name, deleteLocal });
export const linkCredential = (id: string, name: string, accountId: string) =>
  invoke<void>('cpa_link_credential', { id, name, accountId });
export const stopSync = (id: string, accountId: string) => invoke<void>('cpa_stop_sync', { id, accountId });

export function canManageCpaFile(file: CpaRemoteFile): boolean {
  return file.provider === 'codex' && !file.runtime_only && file.source !== 'memory'
    && file.name.endsWith('.json') && !/[\\/\x00-\x1f]/.test(file.name);
}

// Never echo arbitrary host/server errors (which could contain credentials).
export function cpaErrorKey(error: unknown): string {
  const code = String(error);
  return /^CPA_[A-Z_]+$/.test(code) ? code : /^CPA_HTTP_\d{3}$/.test(code) ? 'CPA_HTTP' : 'CPA_UNKNOWN';
}
