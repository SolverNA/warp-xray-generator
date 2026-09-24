/**
 * POST /api/generate — регистрирует аккаунт WARP, собирает конфиг с уникальным
 * QUIC-шумом, кладёт его в хранилище на 5 минут и возвращает ссылку подписки.
 *
 * Контракт рассчитан на форму, где можно менять всё и перегенерировать
 * отдельные поля. Дорогая часть — только регистрация в Cloudflare; если в теле
 * пришёл блок `account` из прошлого ответа, похода в Cloudflare не будет вовсе,
 * и «перегенерировать SNI» стоит несколько миллисекунд.
 *
 * Тело (всё необязательно):
 *   account   {privateKey, address[], peerPublicKey}  переиспользовать аккаунт
 *   id        существующий идентификатор — ссылка остаётся прежней (TTL заново)
 *   endpoint, mtu, keepAlive, dns[], ipVersion, loglevel, reserved
 *   sni, alpn[], quicSize, quicDelay, randCount, randSize, randDelay
 *   quicPacket  готовый hex QUIC Initial (ручная правка; иначе генерируется)
 *   remarks, inbounds, listen, socksPort, httpPort
 */

import { buildConfig, buildNoises, DEF_ALPN, DEF_ENDPOINT, DEF_IP_VERSION, DEF_KEEPALIVE, DEF_LOGLEVEL,
  DEF_MTU, DEF_QUIC_DELAY, DEF_QUIC_SIZE, DEF_RAND_COUNT, DEF_RAND_DELAY, DEF_RAND_SIZE,
  DEF_DNS } from '../lib/build-config.js';
import { isValidId, newId, put, TTL_SECONDS, isPersistent } from '../lib/store.js';
import { registerAccount } from '../lib/warp.js';

function readBody(req) {
  const b = req.body;
  if (!b) return {};
  if (typeof b === 'string') {
    if (!b.trim()) return {};
    return JSON.parse(b);
  }
  if (Buffer.isBuffer(b)) return b.length ? JSON.parse(b.toString('utf8')) : {};
  return b;
}

function baseUrl(req) {
  const host = req.headers['x-forwarded-host'] || req.headers.host || 'localhost';
  const proto = req.headers['x-forwarded-proto'] || (host.startsWith('localhost') ? 'http' : 'https');
  return `${proto}://${host}`;
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  // Регистрация — только по POST: GET, создающий аккаунт, срабатывает на
  // любой префетч ссылки и плодит аккаунты.
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST, OPTIONS');
    return res.status(405).json({ ok: false, error: 'method_not_allowed', message: 'нужен POST' });
  }

  let body;
  try {
    body = readBody(req);
  } catch (err) {
    return res.status(400).json({ ok: false, error: 'bad_json', message: err.message });
  }

  // --- 1. Аккаунт: переиспользуем присланный или регистрируем новый --------
  let account;
  let registered = false;
  const given = body.account;
  if (given && given.privateKey && given.address) {
    account = {
      privateKey: given.privateKey,
      address: Array.isArray(given.address) ? given.address : [given.address],
      peerPublicKey: given.peerPublicKey || body.publicKey,
      accountId: given.accountId || null,
    };
  } else {
    try {
      const reg = await registerAccount();
      registered = true;
      account = {
        privateKey: reg.privateKey,
        address: [reg.addresses.v4, reg.addresses.v6].filter(Boolean),
        peerPublicKey: reg.peerPublicKey,
        accountId: reg.accountId,
        token: reg.token,
        clientId: reg.clientId,
      };
    } catch (err) {
      const status = err.code === 'cloudflare_http_error' ? 502 : 503;
      return res.status(status).json({
        ok: false,
        error: err.code || 'registration_failed',
        phase: err.phase,
        message: err.message,
        cf_status: err.status,
        details: err.data || err.bodySnippet,
      });
    }
  }

  // --- 2. Шум и конфиг ----------------------------------------------------
  const params = {
    sni: body.sni ?? null,
    alpn: body.alpn ?? DEF_ALPN,
    quicSize: body.quicSize ?? DEF_QUIC_SIZE,
    quicDelay: body.quicDelay ?? DEF_QUIC_DELAY,
    randCount: body.randCount ?? DEF_RAND_COUNT,
    randSize: body.randSize ?? DEF_RAND_SIZE,
    randDelay: body.randDelay ?? DEF_RAND_DELAY,
    endpoint: body.endpoint ?? DEF_ENDPOINT,
    mtu: body.mtu ?? DEF_MTU,
    keepAlive: body.keepAlive ?? DEF_KEEPALIVE,
    dns: body.dns ?? DEF_DNS,
    ipVersion: body.ipVersion ?? DEF_IP_VERSION,
    loglevel: body.loglevel ?? DEF_LOGLEVEL,
    remarks: body.remarks ?? 'WARP',
    inbounds: body.inbounds ?? true,
  };

  let config;
  let noiseInfo;
  try {
    noiseInfo = buildNoises({
      sni: params.sni,
      alpn: params.alpn,
      quicSize: params.quicSize,
      quicDelay: params.quicDelay,
      randCount: params.randCount,
      randSize: params.randSize,
      randDelay: params.randDelay,
      quicPacketHex: body.quicPacket ?? null,
    });
    config = buildConfig({
      secretKey: body.privateKey ?? account.privateKey,
      address: body.address ?? account.address,
      publicKey: body.peerPublicKey ?? account.peerPublicKey,
      endpoint: params.endpoint,
      mtu: params.mtu,
      keepAlive: params.keepAlive,
      dns: params.dns,
      ipVersion: params.ipVersion,
      loglevel: params.loglevel,
      noises: noiseInfo.noises,
      reserved: body.reserved ?? null,
      inbounds: params.inbounds,
      listen: body.listen,
      socksPort: body.socksPort,
      httpPort: body.httpPort,
      remarks: params.remarks,
    });
  } catch (err) {
    return res.status(400).json({
      ok: false,
      error: 'bad_params',
      message: err.message,
      // аккаунт уже создан — вернём его, чтобы повтор не регистрировал новый
      account: registered ? account : undefined,
    });
  }

  // --- 3. Хранилище -------------------------------------------------------
  const id = isValidId(body.id) ? body.id : newId();
  let expiresAt;
  try {
    ({ expiresAt } = await put(id, {
      config,
      remarks: params.remarks,
      createdAt: Date.now(),
    }));
  } catch (err) {
    return res.status(503).json({ ok: false, error: 'store_unavailable', message: err.message, account });
  }

  const url = `${baseUrl(req)}/sub/${id}`;
  return res.status(200).json({
    ok: true,
    id,
    url,
    path: `/sub/${id}`,
    ttl: TTL_SECONDS,
    expiresAt,
    config,
    account,
    params: { ...params, quicPacket: noiseInfo.packetHex },
    warnings: isPersistent() ? [] : ['хранилище в памяти процесса: на Vercel ссылка подписки не найдётся'],
  });
}
