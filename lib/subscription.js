/**
 * Выбор формата подписки по User-Agent и заголовки ответа.
 *
 * Наш профиль держится на freedom-аутбаунде с `noises` — такой концепции нет
 * ни в sing-box, ни в clash. Отдавать им конфиг без обфускации нельзя: он
 * выглядит рабочим, но на мобильной сети умирает, и пользователь об этом не
 * узнает. Поэтому таким клиентам уходит честный текст с объяснением.
 */

export const XRAY_CLIENTS = ['Happ/', 'v2raytun/', 'v2rayNG/', 'v2rayN/', 'Throne/', 'Streisand/'];
export const SINGBOX_CLIENTS = ['SFA/', 'SFI/', 'SFM/', 'SFT/', 'HiddifyNext/', 'Karing/'];
export const CLASH_CLIENTS = ['ClashMeta', 'clash-verge', 'mihomo', 'Stash'];
export const BROWSERS = ['Mozilla', 'Chrome', 'Safari', 'Firefox', 'Opera', 'Edge'];

const has = (ua, list) => list.some((needle) => ua.toLowerCase().includes(needle.toLowerCase()));

/**
 * @returns {'xray'|'browser'|'singbox'|'clash'|'unknown'}
 * Порядок проверок важен: конкретные клиенты раньше браузеров, потому что
 * некоторые клиенты таскают в UA слово Mozilla.
 */
export function detectClient(userAgent) {
  const ua = String(userAgent || '');
  if (has(ua, XRAY_CLIENTS)) return 'xray';
  if (has(ua, SINGBOX_CLIENTS)) return 'singbox';
  if (has(ua, CLASH_CLIENTS)) return 'clash';
  if (has(ua, BROWSERS)) return 'browser';
  return 'unknown';
}

/**
 * @returns {'json'|'browser'|'unsupported'}
 * Неизвестный UA получает наш JSON — это fallback, а не ошибка.
 */
export function pickFormat(userAgent) {
  const kind = detectClient(userAgent);
  if (kind === 'singbox' || kind === 'clash') return 'unsupported';
  if (kind === 'browser') return 'browser';
  return 'json';
}

export function unsupportedText(kind) {
  const name = kind === 'singbox' ? 'sing-box' : 'clash / mihomo';
  return [
    `Этот клиент (${name}) не поддерживается.`,
    '',
    'Конфиг держится на обфускации Xray: outbound freedom с полем "noises",',
    'который перед хендшейком WireGuard отправляет поддельный QUIC Initial и',
    'серию случайных пакетов. Ни в sing-box, ни в clash такой концепции нет —',
    'воспроизвести профиль нечем.',
    '',
    'Отдать урезанный конфиг молча было бы хуже: он подключается, но на',
    'мобильной сети поток режется сразу, и причина не видна.',
    '',
    'Подойдут: v2rayNG, v2rayTun, Happ, Throne, Streisand, v2rayN.',
  ].join('\n');
}

/** Заголовки подписки. profile-update-interval намеренно большой: ссылка живёт
 *  5 минут и живой подпиской не является, это одноразовый канал доставки. */
export function subscriptionHeaders(profileName = 'WARP') {
  return {
    'content-type': 'application/json',
    'content-disposition': 'attachment; filename="warp"',
    'profile-title': `base64:${Buffer.from(String(profileName), 'utf8').toString('base64')}`,
    'profile-update-interval': '168',
    'subscription-userinfo': 'upload=0; download=0; total=0; expire=0',
  };
}

export default pickFormat;
