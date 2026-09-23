/**
 * Хранилище одноразовых конфигов.
 *
 * Upstash Redis через REST API обычным fetch — никаких пакетов. Команда
 * передаётся телом как JSON-массив (["SET", key, value, "EX", 300]).
 *
 * Если переменных окружения нет — прозрачный откат на память процесса, чтобы
 * локальная разработка работала без Upstash. ВНИМАНИЕ: на Vercel такой откат
 * бесполезен, POST /api/generate и GET /sub/<id> обслуживаются разными
 * инстансами функции, и запись просто не найдётся. Без KV_REST_API_* на
 * проде подписка будет отдавать 404.
 */

import { randomInt } from 'node:crypto';

export const TTL_SECONDS = 300;
const KEY_PREFIX = 'warp:cfg:';
const ID_ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const ID_LENGTH = 22;
const ID_RE = /^[A-Za-z0-9]{16,64}$/;

/**
 * Идентификатор подписки: только буквы и цифры, длина 22.
 * Ссылка строится как /sub/<id> — без query-параметров, иначе ломаются
 * deep-link'и клиентов вида happ://add/?url=...
 */
export function newId(length = ID_LENGTH) {
  let out = '';
  for (let i = 0; i < length; i += 1) out += ID_ALPHABET[randomInt(ID_ALPHABET.length)];
  return out;
}

export function isValidId(id) {
  return typeof id === 'string' && ID_RE.test(id);
}

function restConfig() {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return null;
  return { url: url.replace(/\/+$/, ''), token };
}

/** Есть ли настоящее хранилище (иначе — память процесса). */
export function isPersistent() {
  return restConfig() !== null;
}

// --- откат в память -------------------------------------------------------
const memory = new Map();

function memorySweep() {
  const now = Date.now();
  for (const [k, v] of memory) if (v.expiresAt <= now) memory.delete(k);
}

async function redis(command, { timeoutMs = 3000 } = {}) {
  const cfg = restConfig();
  const res = await fetch(cfg.url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${cfg.token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(command),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`Upstash вернул не JSON (${res.status}): ${text.slice(0, 200)}`);
  }
  if (!res.ok || data.error) {
    throw new Error(`Upstash: ${data.error || `статус ${res.status}`}`);
  }
  return data.result;
}

/**
 * Кладёт запись ровно на TTL_SECONDS секунд.
 * @returns {{expiresAt:number}} момент истечения, unix ms
 */
export async function put(id, value, ttl = TTL_SECONDS) {
  if (!isValidId(id)) throw new Error(`некорректный идентификатор: ${JSON.stringify(id)}`);
  const expiresAt = Date.now() + ttl * 1000;
  const payload = JSON.stringify({ ...value, expiresAt });
  if (isPersistent()) {
    await redis(['SET', KEY_PREFIX + id, payload, 'EX', String(ttl)]);
  } else {
    memorySweep();
    memory.set(id, { payload, expiresAt });
  }
  return { expiresAt };
}

/** Возвращает запись или null, если её нет или она протухла. */
export async function get(id) {
  if (!isValidId(id)) return null;
  let payload = null;
  if (isPersistent()) {
    payload = await redis(['GET', KEY_PREFIX + id]);
  } else {
    memorySweep();
    const row = memory.get(id);
    payload = row && row.expiresAt > Date.now() ? row.payload : null;
  }
  if (!payload) return null;
  try {
    return JSON.parse(payload);
  } catch {
    return null;
  }
}

export async function del(id) {
  if (!isValidId(id)) return false;
  if (isPersistent()) return Boolean(await redis(['DEL', KEY_PREFIX + id]));
  return memory.delete(id);
}

export default { newId, isValidId, put, get, del, TTL_SECONDS, isPersistent };
