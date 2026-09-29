import assert from 'node:assert/strict';
import test from 'node:test';
import { deferred, loadHookModule, settlePromises } from '../../tests/helpers/reactHookHarness';
import { canManageCpaFile, cpaErrorKey } from '../services/cpaManagementService';

type Element = { type: unknown; props: Record<string, any> };
function nodes(tree: any): Element[] {
  if (Array.isArray(tree)) return tree.flatMap(nodes);
  if (!tree || typeof tree !== 'object' || !('props' in tree)) return [];
  return [tree, ...nodes(tree.props.children)];
}
function text(tree: any): string {
  if (typeof tree === 'string' || typeof tree === 'number') return String(tree);
  if (Array.isArray(tree)) return tree.map(text).join('');
  return tree?.props ? text(tree.props.children) : '';
}
const t = (key: string) => key;
function harness() {
  const conn = { id: 'server-1', baseUrl: 'https://cpa.example.com', apiVersion: 'v8', autoSync: true, defaultUpload: false, blocked: false, lastError: null,
    bindings: [{ accountId: 'a', fileName: 'a.json', active: true, lastSyncedAt: 100, error: null }] };
  const file = { name: 'a.json', email: 'a@example.com', provider: 'codex', runtime_only: false, source: 'file' };
  const pending = deferred<any>();
  const calls: any[] = [];
  let failRead = false;
  let closed = 0;
  const error = { message: null as string | null, scrollKey: 0, clear() { error.message = null; }, report(value: string) { error.message = value; } };
  const h = loadHookModule(new URL('./CpaManagementModal.tsx', import.meta.url), {
    'react-dom': { createPortal: (value: unknown) => value },
    'react-i18next': { useTranslation: () => ({ t }) },
    '../types/codex': { isStandardCodexOAuthAccount: (a: any) => a.id !== 'unsupported' },
    '../hooks/useModalScrollLock': { useModalScrollLock() {} },
    '../hooks/useEscClose': { useEscCloseTopmost() {} },
    './ModalErrorMessage': { ModalErrorMessage: 'error', useModalErrorState: () => error },
    '../services/cpaManagementService': {
      canManageCpaFile, cpaErrorKey,
      async getConnection() { return conn; },
      async listCredentials() { if (failRead) throw 'CPA_NETWORK'; return [file]; },
      async saveConnection(input: any) { calls.push(['save', input]); return conn; },
      uploadAccounts(id: string, ids: string[]) { calls.push(['upload', id, ids]); return pending.promise; },
      deleteCredential(id: string, name: string, deleteLocal: boolean) { calls.push(['delete', id, name, deleteLocal]); return pending.promise; },
      async stopSync() {},
    },
  }, { document: { body: {} } });
  h.render(() => h.exports.CpaManagementModal({
    accounts: [{ id: 'a', email: 'a@example.com' }, { id: 'b', email: 'b@example.com' }, { id: 'unsupported', email: 'u@example.com' }],
    initialSelected: new Set(['a', 'unsupported']), maskAccountText: () => 'MASKED', onClose() { closed++; }, async onAccountsChanged() { calls.push(['local-changed']); },
  }));
  const button = (key: string) => {
    const button = nodes(h.flush()).find(n => n.type === 'button' && text(n.props.children).includes(key));
    assert.ok(button, `missing ${key}`); return button;
  };
  return { h, button, calls, error, pending, failRead() { failRead = true; }, closed: () => closed };
}
test('upload requires confirmation, uses eligible selection snapshot and deduplicates clicks', async () => {
  const h = harness(); await settlePromises();
  h.button('cpa.upload').props.onClick(); assert.equal(h.calls.length, 0);
  const confirm = h.button('common.confirm'); confirm.props.onClick(); confirm.props.onClick();
  assert.equal(h.calls.length, 1); assert.equal(h.calls[0][0], 'upload');
  assert.deepEqual(Array.from(h.calls[0][2]), ['a']);
  h.pending.resolve([{ accountId: 'a', fileName: 'a.json', error: null }]); await settlePromises();
  assert.match(text(h.h.flush()), /cpa.uploaded/); h.h.unmount();
});
test('remote deletion defaults to keeping local; linked deletion is explicit', async () => {
  const h = harness(); await settlePromises();
  h.button('cpa.loadRemote').props.onClick(); await settlePromises();
  h.button('common.delete').props.onClick(); assert.equal(h.calls.length, 0);
  const checkbox = nodes(h.h.flush()).find(n => n.type === 'input' && n.props.type === 'checkbox');
  assert.equal(checkbox?.props.checked, false);
  checkbox?.props.onChange({ target: { checked: true } });
  h.button('common.confirm').props.onClick();
  assert.deepEqual(h.calls[0], ['delete', 'server-1', 'a.json', true]);
  h.pending.resolve(undefined); await settlePromises();
  assert.ok(h.calls.some(c => c[0] === 'local-changed')); h.h.unmount();
});
test('delete failure retains confirmation and never reports local deletion', async () => {
  const h = harness(); await settlePromises(); h.button('cpa.loadRemote').props.onClick(); await settlePromises();
  h.button('common.delete').props.onClick(); h.button('common.confirm').props.onClick();
  h.pending.reject('CPA_HTTP_500'); await settlePromises();
  assert.equal(h.error.message, 'cpa.errors.CPA_HTTP');
  assert.match(text(h.h.flush()), /cpa.confirm.delete/);
  assert.equal(h.calls.some(c => c[0] === 'local-changed'), false); h.h.unmount();
});
test('failed remote reload removes stale actionable rows', async () => {
  const h = harness(); await settlePromises(); h.button('cpa.loadRemote').props.onClick(); await settlePromises();
  assert.ok(h.button('common.delete')); h.failRead(); h.button('cpa.loadRemote').props.onClick(); await settlePromises();
  assert.equal(nodes(h.h.flush()).filter(n => n.type === 'button' && text(n.props.children).includes('common.delete')).length, 0);
  assert.match(text(h.h.flush()), /cpa.remoteNotLoaded/); h.h.unmount();
});
test('settings do not expose saved key, default upload is opt-in and accounts stay masked', async () => {
  const h = harness(); await settlePromises();
  assert.doesNotMatch(text(h.h.flush()), /a@example.com|b@example.com/);
  h.button('cpa.settings').props.onClick();
  const inputs = nodes(h.h.flush()).filter(n => n.type === 'input');
  assert.equal(inputs.find(n => n.props.type === 'password')?.props.value, '');
  assert.equal(inputs.filter(n => n.props.type === 'checkbox')[1].props.checked, false);
  h.button('cpa.testSave').props.onClick(); await settlePromises();
  assert.equal(h.calls[0][1].key, null); assert.equal(h.calls[0][1].defaultUpload, false);
  h.h.unmount();
});
