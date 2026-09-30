import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import test from 'node:test';
import { cpaEn, cpaZhCn } from '../src/i18n/cpa';

const require = createRequire(import.meta.url);
const { withCpaTranslationResources } = require('../scripts/cpa_locale_resources.cjs');
const { findMissingTranslationReferences } = require('../scripts/locale_references.cjs');

test('locale checker uses the runtime CPA resources and English fallback only for CPA', () => {
  const input = new Map([
    ['en.json', { common: { confirm: 'Confirm' } }],
    ['zh-CN.json', { common: { confirm: '确认' } }],
    ['ja.json', {}],
  ]);
  const resources = withCpaTranslationResources(input);
  assert.deepEqual(resources.get('en.json').cpa, cpaEn);
  assert.deepEqual(resources.get('zh-CN.json').cpa, cpaZhCn);
  assert.deepEqual(resources.get('ja.json').cpa, cpaEn);
  assert.equal('cpa' in input.get('en.json')!, false, 'do not mutate source locales');
  assert.deepEqual(findMissingTranslationReferences([{ key: 'cpa.title' }], resources), []);
  const missing = findMissingTranslationReferences([
    { key: 'cpa.missingKey' }, { key: 'common.confirm' },
  ], resources);
  assert.deepEqual(missing.map((item: any) => [item.key, item.languages]), [
    ['cpa.missingKey', ['en.json', 'zh-CN.json', 'ja.json']],
    ['common.confirm', ['ja.json']],
  ]);
});

test('CPA English and Chinese bundles have the same nonempty string keys and placeholders', () => {
  function flatten(value: Record<string, any>, prefix = ''): Record<string, string> {
    return Object.fromEntries(Object.entries(value).flatMap(([key, item]) => {
      const path = prefix ? `${prefix}.${key}` : key;
      return typeof item === 'object' ? Object.entries(flatten(item, path)) : [[path, item]];
    }));
  }
  const en = flatten(cpaEn);
  const zh = flatten(cpaZhCn);
  assert.deepEqual(Object.keys(en).sort(), Object.keys(zh).sort());
  for (const key of Object.keys(en)) {
    assert.equal(typeof en[key], 'string');
    assert.equal(typeof zh[key], 'string');
    assert.ok(en[key].trim() && zh[key].trim(), key);
    const placeholders = (text: string) => (text.match(/\{\{[^}]+\}\}/g) ?? []).sort();
    assert.deepEqual(placeholders(en[key]), placeholders(zh[key]), key);
  }
});
