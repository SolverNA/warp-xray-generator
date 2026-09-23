/**
 * Регистрация аккаунта Cloudflare WARP.
 *
 * Два запроса: POST /reg с публичным ключом, затем PATCH /reg/<id> с
 * {"warp_enabled": true}. Из ответов нужны id, token, публичный ключ пира и
 * адреса интерфейса v4/v6.
 *
 * Отличия от референсной реализации (они же — исправленные дефекты):
 *
 *  1. Согласованный identity. В референсе был User-Agent okhttp/3.12.1
 *     (андроидная HTTP-библиотека) при "type": "ios" в теле и без заголовка
 *     CF-Client-Version. Здесь всё три признака — андроидные. Оба варианта
 *     проверены живым запросом 23.09.2026: оба дают 200, поэтому взят
 *     согласованный.
 *  2. POST /reg НЕ ретраится вслепую. Таймаут или обрыв на этом запросе не
 *     говорят, что аккаунт не создан, — повтор плодит «аккаунты-сироты»,
 *     которые уже некому удалить (id и token остались на той стороне).
 *     Повторяется только 429 (сервер явно сказал, что запрос не обработан).
 *     PATCH идемпотентен, его повторять безопасно.
 *  3. Разбор ответа отделён от сети. res.json() внутри общего try превращал
 *     WAF-страницу или челлендж в «сетевую ошибку»; здесь это отдельный класс
 *     CfBadResponse со статусом, content-type и началом тела.
 *  4. Общий дедлайн, по умолчанию 8.5 с — влезает в лимит Vercel (10 с).
 */

import { generateKeyPairSync } from 'node:crypto';

export const CF_API = 'https://api.cloudflareclient.com/v0i1909051800';

/** Согласованный андроидный identity: UA, CF-Client-Version и type из одной семьи. */
export const CF_IDENTITY = {
  userAgent: 'okhttp/3.12.1',
  clientVersion: 'a-6.30-3596',
  type: 'Android',
  locale: 'en_US',
};

export const DEFAULT_BUDGET_MS = 8500;
const MIN_REQUEST_MS = 1200;
const MAX_REQUEST_MS = 4500;
const RETRY_PAUSE_MS = 400;

/** Сеть не ответила: обрыв, DNS, таймаут. Что успел сделать сервер — неизвестно. */
export class CfNetworkError extends Error {
  constructor(message, { phase, cause } = {}) {
    super(message);
    this.name = 'CfNetworkError';
    this.code = 'cloudflare_unreachable';
    this.phase = phase;
    this.cause = cause;
  }
}

/** Ответ пришёл, но это не JSON (WAF, челлендж, HTML-заглушка) либо JSON не той формы. */
export class CfBadResponse extends Error {
  constructor(message, { phase, status, contentType, body } = {}) {
    super(message);
    this.name = 'CfBadResponse';
    this.code = 'cloudflare_bad_response';
    this.phase = phase;
    this.status = status;
    this.contentType = contentType;
    this.bodySnippet = typeof body === 'string' ? body.slice(0, 300) : undefined;
  }
}

/** Валидный JSON, но статус не 2xx. */
export class CfHttpError extends Error {
  constructor(message, { phase, status, data } = {}) {
    super(message);
    this.name = 'CfHttpError';
    this.code = 'cloudflare_http_error';
    this.phase = phase;
    this.status = status;
    this.data = data;
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Пара ключей x25519 в сыром виде (32 байта, base64).
 * Только JWK-экспорт: срез DER по длине ломается на любом другом кодировании.
 */
export function generateKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('x25519');
  const priv = Buffer.from(privateKey.export({ format: 'jwk' }).d, 'base64url');
  const pub = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
  if (priv.length !== 32 || pub.length !== 32) {
    throw new Error(`x25519: ожидали 32+32 байта, получили ${priv.length}+${pub.length}`);
  }
  return { privateKey: priv.toString('base64'), publicKey: pub.toString('base64') };
}

function headers(token) {
  const h = {
    'User-Agent': CF_IDENTITY.userAgent,
    'CF-Client-Version': CF_IDENTITY.clientVersion,
    'Content-Type': 'application/json',
    Accept: 'application/json',
  };
  if (token) h.Authorization = `Bearer ${token}`;
  return h;
}

/**
 * Один сетевой запрос. Три исхода разведены:
 *   сеть не ответила            -> CfNetworkError
 *   ответ пришёл, но не JSON    -> CfBadResponse
 *   JSON есть                   -> { status, ok, data, headers }
 */
async function once({ method, path, token, body, phase, timeoutMs }) {
  let res;
  try {
    res = await fetch(`${CF_API}/${path}`, {
      method,
      headers: headers(token),
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    throw new CfNetworkError(`${phase}: Cloudflare не ответил (${err.name}: ${err.message})`, { phase, cause: err });
  }

  const contentType = res.headers.get('content-type') || '';
  const text = await res.text().catch(() => '');
  if (!contentType.includes('json')) {
    throw new CfBadResponse(
      `${phase}: ответ ${res.status} не JSON (content-type: ${contentType || 'нет'})`,
      { phase, status: res.status, contentType, body: text });
  }
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new CfBadResponse(`${phase}: тело помечено как JSON, но не разбирается`, {
      phase, status: res.status, contentType, body: text,
    });
  }
  return { status: res.status, ok: res.ok, data, retryAfter: res.headers.get('retry-after') };
}

function budgetSlice(deadline, want) {
  const left = deadline - Date.now();
  if (left <= MIN_REQUEST_MS) return 0;
  return Math.min(want, left, MAX_REQUEST_MS);
}

/**
 * Регистрирует аккаунт и включает WARP.
 * @returns {{accountId, token, privateKey, publicKey, peerPublicKey, addresses:{v4,v6}, clientId, endpoint}}
 */
export async function registerAccount({ budgetMs = DEFAULT_BUDGET_MS, keys = null } = {}) {
  const deadline = Date.now() + budgetMs;
  const pair = keys || generateKeyPair();
  const tos = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

  // --- POST /reg: один раз. Повтор только на явном 429. --------------------
  let reg;
  for (let attempt = 1; ; attempt += 1) {
    const timeoutMs = budgetSlice(deadline, 4000);
    if (!timeoutMs) throw new CfNetworkError('reg: не осталось времени в бюджете запроса', { phase: 'reg' });
    reg = await once({
      method: 'POST',
      path: 'reg',
      phase: 'reg',
      timeoutMs,
      body: {
        install_id: '',
        tos,
        key: pair.publicKey,
        fcm_token: '',
        type: CF_IDENTITY.type,
        locale: CF_IDENTITY.locale,
      },
    });
    // 429 — единственный статус, при котором точно известно, что аккаунт не создан.
    if (reg.status === 429 && attempt === 1) {
      const after = Number.parseInt(reg.retryAfter || '0', 10) * 1000;
      const pause = Math.max(RETRY_PAUSE_MS, Number.isFinite(after) ? after : 0);
      if (Date.now() + pause + MIN_REQUEST_MS < deadline) {
        await sleep(pause);
        continue;
      }
    }
    break;
  }
  if (!reg.ok) {
    throw new CfHttpError(`reg: Cloudflare вернул ${reg.status}`, { phase: 'reg', status: reg.status, data: reg.data });
  }

  const accountId = reg.data?.result?.id;
  const token = reg.data?.result?.token;
  if (!accountId || !token) {
    throw new CfBadResponse('reg: в ответе нет result.id / result.token', {
      phase: 'reg', status: reg.status, contentType: 'application/json', body: JSON.stringify(reg.data),
    });
  }

  // --- PATCH /reg/<id>: идемпотентен, повторять безопасно. -----------------
  let patch;
  let lastErr = null;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const timeoutMs = budgetSlice(deadline, 3000);
    if (!timeoutMs) break;
    try {
      patch = await once({
        method: 'PATCH',
        path: `reg/${accountId}`,
        token,
        phase: 'warp_enable',
        timeoutMs,
        body: { warp_enabled: true },
      });
    } catch (err) {
      lastErr = err;
      if (err instanceof CfNetworkError && Date.now() + RETRY_PAUSE_MS + MIN_REQUEST_MS < deadline) {
        await sleep(RETRY_PAUSE_MS);
        continue;
      }
      err.accountId = accountId;
      err.token = token;
      throw err;
    }
    if ((patch.status === 429 || patch.status >= 500) && Date.now() + RETRY_PAUSE_MS + MIN_REQUEST_MS < deadline) {
      await sleep(RETRY_PAUSE_MS);
      continue;
    }
    break;
  }
  if (!patch) {
    const err = lastErr || new CfNetworkError('warp_enable: не осталось времени в бюджете запроса', { phase: 'warp_enable' });
    err.accountId = accountId;
    err.token = token;
    throw err;
  }
  if (!patch.ok) {
    throw new CfHttpError(`warp_enable: Cloudflare вернул ${patch.status}`, {
      phase: 'warp_enable', status: patch.status, data: patch.data,
    });
  }

  const cfg = patch.data?.result?.config;
  const peerPublicKey = cfg?.peers?.[0]?.public_key;
  const v4 = cfg?.interface?.addresses?.v4;
  const v6 = cfg?.interface?.addresses?.v6;
  if (!peerPublicKey || !v4) {
    throw new CfBadResponse('warp_enable: в ответе нет публичного ключа пира или адреса v4', {
      phase: 'warp_enable', status: patch.status, contentType: 'application/json', body: JSON.stringify(patch.data),
    });
  }

  return {
    accountId,
    token,
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    peerPublicKey,
    addresses: { v4, v6: v6 || null },
    clientId: cfg?.client_id || null,
  };
}

export default registerAccount;
