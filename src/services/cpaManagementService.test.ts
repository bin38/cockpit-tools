import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { cpaEn, cpaZhCn } from '../i18n/cpa';
import { canManageCpaFile, cpaErrorKey, type CpaRemoteFile } from './cpaManagementService';
test('only named Codex files can be managed; memory entries and paths are read-only', () => {
  const file: CpaRemoteFile = { name: 'test.json', provider: 'codex', email: '', status: '', disabled: false, unavailable: false, runtime_only: false, source: 'file' };
  assert.equal(canManageCpaFile(file), true);
  for (const patch of [{ runtime_only: true }, { source: 'memory' }, { name: '../test.json' }, { name: 'a\\b.json' }, { provider: 'claude' }]) {
    assert.equal(canManageCpaFile({ ...file, ...patch }), false);
  }
});
test('raw server errors and credentials are not interpolated into the UI', () => {
  assert.equal(cpaErrorKey('CPA_AUTH'), 'CPA_AUTH');
  assert.equal(cpaErrorKey('CPA_HTTP_500'), 'CPA_HTTP');
  assert.equal(cpaErrorKey('https://user:secret@example.com access_token=secret'), 'CPA_UNKNOWN');
});
test('CPA scoped translations cover all backend errors in Chinese and English', () => {
  const source = readFileSync(new URL('../../src-tauri/src/modules/cpa_management.rs', import.meta.url), 'utf8');
  for (const [, code] of source.matchAll(/"(CPA_[A-Z_]+)"/g)) {
    assert.ok(code in cpaEn.errors, `Missing English ${code}`);
    assert.ok(code in cpaZhCn.errors, `Missing Chinese ${code}`);
  }
  assert.deepEqual(Object.keys(cpaEn).sort(), Object.keys(cpaZhCn).sort());
  assert.deepEqual(Object.keys(cpaEn.errors).sort(), Object.keys(cpaZhCn.errors).sort());
});
