// Development-only visual fixture: no real credentials or external requests.
import React from 'react';
import { createRoot } from 'react-dom/client';
import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import zh from '../src/locales/zh-CN.json';
import en from '../src/locales/en.json';
import { cpaEn, cpaZhCn } from '../src/i18n/cpa';
import { CpaManagementModal } from '../src/components/CpaManagementModal';
import type { CodexAccount } from '../src/types/codex';
import '../src/App.css';

await i18n.use(initReactI18next).init({ lng: 'zh', resources: { zh: { translation: { ...zh, cpa: cpaZhCn } }, en: { translation: { ...en, cpa: cpaEn } } }, interpolation: { escapeValue: false } });
const accounts = ['alice', 'bob', 'charlie'].map((name, index) => ({ id: `codex_${name}`, email: `${name}@example.invalid`, account_id: `account-${index}`, tokens: { id_token: 'fixture', access_token: 'fixture', refresh_token: 'fixture' }, created_at: 1, last_used: 1 })) as CodexAccount[];
let connection = { id: 'preview', baseUrl: 'https://my-cpa.example.invalid', apiVersion: 'v8', autoSync: true, defaultUpload: false, blocked: false, lastError: null, bindings: [{ accountId: 'codex_alice', fileName: 'codex-alice.json', active: true, lastSyncedAt: 1790689200, error: null }] };
let files = ['alice', 'bob', 'runtime'].map(name => ({ name: `codex-${name}.json`, email: `${name}@example.invalid`, provider: 'codex', status: 'ready', disabled: name === 'bob', unavailable: false, runtime_only: name === 'runtime', source: name === 'runtime' ? 'memory' : 'file' }));
Object.assign(window, { __TAURI_INTERNALS__: { invoke: async (command: string, args: any) => {
  switch (command) {
    case 'cpa_get_connection': return structuredClone(connection);
    case 'cpa_list_credentials': return structuredClone(files);
    case 'cpa_save_connection': connection = { ...connection, baseUrl: args.baseUrl, autoSync: args.autoSync, defaultUpload: args.defaultUpload }; return structuredClone(connection);
    case 'cpa_upload_accounts': return args.accountIds.map((accountId: string) => ({ accountId, fileName: `${accountId}.json`, error: null }));
    case 'cpa_set_disabled': files = files.map(f => f.name === args.name ? { ...f, disabled: args.disabled } : f); return;
    case 'cpa_delete_credential': files = files.filter(f => f.name !== args.name); return;
    case 'cpa_stop_sync': connection.bindings = connection.bindings.map(b => b.accountId === args.accountId ? { ...b, active: false } : b); return;
    case 'cpa_link_credential': return;
    default: throw 'CPA_UNKNOWN';
  }
} } });
createRoot(document.getElementById('root')!).render(<CpaManagementModal accounts={accounts} initialSelected={new Set(['codex_alice'])} maskAccountText={v => v} onClose={() => location.reload()} onAccountsChanged={async () => {}} />);
