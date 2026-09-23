/**
 * Сборка конфига Xray для Cloudflare WARP с обфускацией.
 *
 * Порт функций build_noises / build_config / norm_address / parse_endpoint
 * из gen-warp-config.py проекта «awg to xray». Все константы — из проверенной
 * в бою базы (results/profiles-report-mobile.txt), менять их без нового
 * полевого прогона нельзя.
 *
 * SIP-профиль намеренно НЕ перенесён: на мобильных сетях режется сам признак
 * SIP, все три варианта (статичный, рандомизированный, перехваченный) дают FAIL.
 */

import { isIPv4, isIPv6 } from 'node:net';

import { buildInitial } from './quic-initial.js';

// --- проверенная рабочая база ---------------------------------------------
export const DEF_ENDPOINT = '162.159.192.1:500';
export const DEF_MTU = 1280;
export const DEF_KEEPALIVE = 5;
export const DEF_RAND_COUNT = 8;
export const DEF_RAND_SIZE = '23-911';
export const DEF_RAND_DELAY = '1-3';
export const DEF_QUIC_SIZE = 1252;
export const DEF_ALPN = ['h3'];
export const DEF_QUIC_DELAY = '1-2';
export const DEF_DNS = ['1.1.1.1', '1.0.0.1', '2606:4700:4700::1111', '2606:4700:4700::1001'];
export const DEF_PEER_PUBKEY = 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=';
export const DEF_LOGLEVEL = 'warning';
export const DEF_ALLOWED_IPS = ['0.0.0.0/0', '::/0'];
export const DEF_LISTEN = '127.0.0.1';
export const DEF_SOCKS_PORT = 10808;
export const DEF_HTTP_PORT = 10809;

/** Xray валидирует поле type в noises — допустимы только эти четыре значения. */
export const NOISE_TYPES = ['rand', 'str', 'hex', 'base64'];

/** Диапазон «A-B» или одно число, как их понимает сам Xray. */
const RANGE_RE = /^\d+(-\d+)?$/;

// --------------------------------------------------------------------------
// Адреса и эндпоинт
// --------------------------------------------------------------------------

/** Добавляет префикс, если в исходнике он опущен (WireGuard-конфиги часто без него). */
export function normAddress(addr) {
  const a = String(addr ?? '').trim();
  if (!a) return null;
  if (a.includes('/')) return a;
  return a + (a.includes(':') ? '/128' : '/32');
}

/**
 * Проверяет доменное имя по RFC 1123: метки 1..63 символа из [A-Za-z0-9-],
 * дефис не с краю, вся строка не длиннее 253 символов.
 */
export function validHostname(host) {
  let h = String(host ?? '');
  if (h.endsWith('.')) h = h.slice(0, -1);
  if (!h || h.length > 253) return false;
  for (const label of h.split('.')) {
    if (label.length < 1 || label.length > 63) return false;
    if (label.startsWith('-') || label.endsWith('-')) return false;
    if (!/^[A-Za-z0-9-]+$/.test(label)) return false;
  }
  return true;
}

/**
 * Разбирает ХОСТ:ПОРТ на { host, port, kind }.
 *
 * Принимает три формы:
 *   162.159.192.1:500                  IPv4
 *   engage.cloudflareclient.com:500    доменное имя
 *   [2606:4700:d0::a29f:c001]:500      IPv6 строго в скобках
 *
 * Голый IPv6 без скобок неоднозначен (последнее двоеточие — часть адреса или
 * разделитель порта?), поэтому отвергается с подсказкой.
 */
export function parseEndpoint(value) {
  const v = String(value ?? '').trim();
  if (!v) throw new Error('пустое значение, ожидалось ХОСТ:ПОРТ');

  let host;
  let port;
  let kind;

  if (v.startsWith('[')) {
    const close = v.indexOf(']');
    if (close === -1 || v[close + 1] !== ':') {
      throw new Error(`скобочная форма задаётся как [АДРЕС]:ПОРТ, получено ${JSON.stringify(v)}`);
    }
    host = v.slice(1, close);
    port = v.slice(close + 2);
    if (!isIPv6(host)) {
      throw new Error(`в скобках ожидался IPv6-адрес, получено ${JSON.stringify(host)}`);
    }
    kind = 'ipv6';
  } else {
    const sep = v.lastIndexOf(':');
    if (sep === -1) {
      throw new Error(`не указан порт, ожидалось ХОСТ:ПОРТ, получено ${JSON.stringify(v)}`);
    }
    host = v.slice(0, sep);
    port = v.slice(sep + 1);
    if (host.includes(':')) {
      if (isIPv6(v)) throw new Error(`это IPv6-адрес без порта, нужна форма [${v}]:ПОРТ`);
      throw new Error(`IPv6-адрес пишется в скобках: [АДРЕС]:ПОРТ, получено ${JSON.stringify(v)}`);
    }
    if (!host) {
      throw new Error(`не указан хост, ожидалось ХОСТ:ПОРТ, получено ${JSON.stringify(v)}`);
    }
    if (isIPv4(host)) {
      kind = 'ipv4';
    } else if (validHostname(host)) {
      kind = 'name';
    } else {
      throw new Error(`${JSON.stringify(host)} не похож ни на IPv4-адрес, ни на доменное имя`);
    }
  }

  if (!/^\d+$/.test(port)) {
    throw new Error(`порт должен быть числом, получено ${JSON.stringify(port)}`);
  }
  const number = Number(port);
  if (number < 1 || number > 65535) {
    throw new Error(`порт ${number} вне диапазона 1..65535`);
  }
  return { host, port: number, kind };
}

/** Канонический вид эндпоинта: IPv6 всегда в скобках. */
export function formatEndpoint({ host, port, kind }) {
  return kind === 'ipv6' ? `[${host}]:${port}` : `${host}:${port}`;
}

// --------------------------------------------------------------------------
// Сборка noises
// --------------------------------------------------------------------------

/**
 * Собирает массив noises: один hex-пакет QUIC Initial и N штук rand-диапазонов.
 *
 * ВАЖНО: rand-шумы — это СТРОКИ-ДИАПАЗОНЫ («23-911»), их раскрывает сам Xray
 * на каждой отправке. Генерировать байты здесь нельзя: получится один и тот же
 * пакет на все попытки, то есть стабильный признак.
 */
export function buildNoises({
  sni = null,
  alpn = DEF_ALPN,
  quicSize = DEF_QUIC_SIZE,
  quicDelay = DEF_QUIC_DELAY,
  randCount = DEF_RAND_COUNT,
  randSize = DEF_RAND_SIZE,
  randDelay = DEF_RAND_DELAY,
  quicPacketHex = null,
} = {}) {
  const alpnList = (Array.isArray(alpn) ? alpn : String(alpn).split(','))
    .map((p) => String(p).trim())
    .filter(Boolean);
  if (alpnList.length === 0) {
    throw new Error('alpn пуст, нужен хотя бы один протокол (например h3)');
  }
  for (const [name, value] of [['quicDelay', quicDelay], ['randSize', randSize], ['randDelay', randDelay]]) {
    if (!RANGE_RE.test(String(value))) {
      throw new Error(`${name}: ожидался диапазон вида «A-B» или число, получено ${JSON.stringify(value)}`);
    }
  }
  if (!Number.isInteger(randCount) || randCount < 0 || randCount > 64) {
    throw new Error(`randCount: ожидалось целое 0..64, получено ${JSON.stringify(randCount)}`);
  }

  let packetHex = quicPacketHex;
  let chosenSni = sni;
  if (packetHex) {
    if (!/^[0-9a-fA-F]+$/.test(packetHex) || packetHex.length % 2 !== 0) {
      throw new Error('quicPacketHex: ожидалась чётная строка из шестнадцатеричных цифр');
    }
    packetHex = packetHex.toLowerCase();
  } else {
    const pkt = buildInitial({ sni, size: quicSize, alpn: alpnList });
    packetHex = pkt.toString('hex');
  }

  const noises = [{ type: 'hex', packet: packetHex, delay: String(quicDelay) }];
  for (let i = 0; i < randCount; i += 1) {
    noises.push({ type: 'rand', packet: String(randSize), delay: String(randDelay) });
  }

  for (const n of noises) {
    if (!NOISE_TYPES.includes(n.type)) {
      throw new Error(`недопустимый type в noises: ${JSON.stringify(n.type)} (Xray принимает только ${NOISE_TYPES.join(', ')})`);
    }
  }
  return { noises, sni: chosenSni, alpn: alpnList, quicSize, packetHex };
}

// --------------------------------------------------------------------------
// Сборка конфига
// --------------------------------------------------------------------------

/**
 * Готовый объект конфига Xray.
 *
 * Поле `reserved` у wireguard-аутбаунда НЕ добавляется: в питоне оно попадает
 * в конфиг только если было в исходных кредах (`if creds.get("reserved")`),
 * а проверенный в бою warp-xray-client.json его не содержит. Регистрация в
 * Cloudflare возвращает client_id, но проверенный профиль работает без него —
 * поэтому поля нет. Передать его явно всё же можно параметром `reserved`.
 */
export function buildConfig({
  secretKey,
  address,
  publicKey = DEF_PEER_PUBKEY,
  endpoint = DEF_ENDPOINT,
  mtu = DEF_MTU,
  keepAlive = DEF_KEEPALIVE,
  dns = DEF_DNS,
  loglevel = DEF_LOGLEVEL,
  noises,
  reserved = null,
  inbounds = true,
  listen = DEF_LISTEN,
  socksPort = DEF_SOCKS_PORT,
  httpPort = DEF_HTTP_PORT,
  remarks = null,
} = {}) {
  if (!secretKey) throw new Error('не задан secretKey (приватный ключ клиента)');
  if (!publicKey) throw new Error('не задан publicKey (публичный ключ пира)');
  const addresses = (Array.isArray(address) ? address : [address])
    .map(normAddress)
    .filter(Boolean);
  if (addresses.length === 0) throw new Error('не задан ни один адрес интерфейса');
  if (!Array.isArray(noises) || noises.length === 0) {
    throw new Error('не задан ни один noise — обфускация обязательна');
  }
  const ep = formatEndpoint(parseEndpoint(endpoint));

  const warp = {
    tag: 'warp',
    protocol: 'wireguard',
    settings: {
      secretKey,
      address: addresses,
      mtu,
      peers: [{
        publicKey,
        endpoint: ep,
        keepAlive: keepAlive,
        allowedIPs: [...DEF_ALLOWED_IPS],
      }],
    },
    streamSettings: { sockopt: { dialerProxy: 'noise-out' } },
  };
  if (reserved) warp.settings.reserved = reserved;

  const noiseOut = {
    tag: 'noise-out',
    protocol: 'freedom',
    settings: { domainStrategy: 'AsIs', noises },
  };

  const cfg = {};
  if (remarks) cfg.remarks = remarks;
  cfg.log = { loglevel };
  cfg.dns = { servers: Array.isArray(dns) ? dns : String(dns).split(',').map((s) => s.trim()).filter(Boolean) };
  if (inbounds) {
    cfg.inbounds = [
      {
        tag: 'socks-in',
        listen,
        port: socksPort,
        protocol: 'socks',
        settings: { auth: 'noauth', udp: true },
        sniffing: { enabled: true, destOverride: ['http', 'tls'] },
      },
      {
        tag: 'http-in',
        listen,
        port: httpPort,
        protocol: 'http',
        settings: {},
        sniffing: { enabled: true, destOverride: ['http', 'tls'] },
      },
    ];
  }
  cfg.outbounds = [warp, noiseOut];
  cfg.routing = {
    domainStrategy: 'AsIs',
    rules: [{ type: 'field', network: 'tcp,udp', outboundTag: 'warp' }],
  };
  return cfg;
}

export default buildConfig;
