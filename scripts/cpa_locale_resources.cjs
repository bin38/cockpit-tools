// CPA is registered outside src/locales; mirror only its runtime English fallback.
// Keep all upstream namespaces strict so missing translations still fail checks.
const { en, zhCn } = require('../src/i18n/cpa-translations.json');

function withCpaTranslationResources(locales) {
  return new Map(Array.from(locales, ([language, data]) => [language, {
    ...data,
    cpa: language.toLowerCase().replace(/\.json$/, '') === 'zh-cn' ? zhCn : en,
  }]));
}

module.exports = { withCpaTranslationResources };
