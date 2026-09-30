// Shared data lets runtime i18n and the upstream locale checker validate the same CPA copy.
// Other UI languages keep using the existing English fallback.
import translations from './cpa-translations.json';

export const cpaEn = translations.en;
export const cpaZhCn = translations.zhCn;
