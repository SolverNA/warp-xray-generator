/**
 * Генератор НАСТОЯЩЕГО QUIC Initial-пакета (RFC 9000 / RFC 9001, QUIC v1).
 *
 * Порт tests/gen-quic-initial.py из проекта «awg to xray», строка в строку.
 *
 * Зачем: у freedom-аутбаунда Xray в `noises` можно отправить произвольный пакет
 * типом `hex`. Рабочие профили AmneziaWG содержат НАСТОЯЩИЙ QUIC Initial: его
 * payload расшифровывается Initial-ключами, выведенными из DCID, и внутри лежит
 * валидный TLS ClientHello с SNI и ALPN=h3. Пакет из случайных байт под видом
 * QUIC не работает — ТСПУ (или что-то по пути) явно проверяет расшифровку.
 *
 * Криптография — ТОЛЬКО встроенный node:crypto, синхронно, без зависимостей.
 */

import {
  createCipheriv,
  createHmac,
  generateKeyPairSync,
  randomBytes,
  randomInt,
} from 'node:crypto';

// RFC 9001 §5.2
const INITIAL_SALT_V1 = Buffer.from('38762cf7f55934b34d179ae6a4c80cadccbb7f0a', 'hex');

export const DEFAULT_SNIS = [
  'www.google.com', 'mail.ru', 'www.youtube.com', 'yandex.ru',
  'vk.com', 'cloudflare.com', 'www.cloudflare.com', 'ok.ru',
];

/** Случайные байты. Только CSPRNG, никакого Math.random(). */
function randBytes(n) {
  return randomBytes(n);
}

/** Случайный элемент массива (аналог random.choice). */
function choice(arr) {
  return arr[randomInt(arr.length)];
}

/** Честный Fisher-Yates на CSPRNG (аналог random.shuffle), на месте. */
function shuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    const t = arr[i];
    arr[i] = arr[j];
    arr[j] = t;
  }
  return arr;
}

// --------------------------------------------------------------------------
// HKDF / TLS 1.3 key schedule (RFC 5869, RFC 8446 §7.1)
// --------------------------------------------------------------------------
// ВАЖНО: Expand написан руками на HMAC. Встроенный crypto.hkdf делает
// Extract+Expand за один вызов, а здесь нужен Expand от УЖЕ готового секрета.
// Подмена даёт внешне рабочий пакет с неверными ключами — то есть молча
// сломанную обфускацию.

function hkdfExtract(salt, ikm) {
  return createHmac('sha256', salt).update(ikm).digest();
}

function hkdfExpand(prk, info, length) {
  const out = [];
  let t = Buffer.alloc(0);
  let total = 0;
  let i = 1;
  while (total < length) {
    t = createHmac('sha256', prk)
      .update(Buffer.concat([t, info, Buffer.from([i])]))
      .digest();
    out.push(t);
    total += t.length;
    i += 1;
  }
  return Buffer.concat(out).subarray(0, length);
}

function expandLabel(secret, label, length) {
  const full = Buffer.from(`tls13 ${label}`, 'ascii');
  const info = Buffer.concat([
    u16(length),
    Buffer.from([full.length]),
    full,
    Buffer.from([0x00]),
  ]);
  return hkdfExpand(secret, info, length);
}

/** Клиентские Initial-ключи, выведенные из DCID (RFC 9001 §5.2). */
export function initialKeys(dcid) {
  const initialSecret = hkdfExtract(INITIAL_SALT_V1, dcid);
  const clientSecret = expandLabel(initialSecret, 'client in', 32);
  return {
    key: expandLabel(clientSecret, 'quic key', 16),
    iv: expandLabel(clientSecret, 'quic iv', 12),
    hp: expandLabel(clientSecret, 'quic hp', 16),
  };
}

// --------------------------------------------------------------------------
// varint (RFC 9000 §16)
// --------------------------------------------------------------------------
export function varint(v) {
  if (v < 0x40) return Buffer.from([v]);
  if (v < 0x4000) {
    const b = Buffer.alloc(2);
    b.writeUInt16BE(0x4000 | v, 0);
    return b;
  }
  if (v < 0x40000000) {
    const b = Buffer.alloc(4);
    b.writeUInt32BE((0x80000000 | v) >>> 0, 0);
    return b;
  }
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(0xc000000000000000n | BigInt(v), 0);
  return b;
}

/** Принудительно 2-байтовый varint — как в рабочих образцах поле length. */
export function varint2(v) {
  if (v >= 0x4000) throw new Error(`varint2: значение ${v} не влезает в 2 байта`);
  const b = Buffer.alloc(2);
  b.writeUInt16BE(0x4000 | v, 0);
  return b;
}

// --------------------------------------------------------------------------
// TLS ClientHello
// --------------------------------------------------------------------------
function u16(v) {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(v, 0);
  return b;
}

function u24(v) {
  const b = Buffer.alloc(3);
  b.writeUIntBE(v, 0, 3);
  return b;
}

function ext(etype, body) {
  return Buffer.concat([u16(etype), u16(body.length), body]);
}

/** Сырой (32 байта) публичный ключ x25519 из свежей настоящей пары. */
function x25519PublicRaw() {
  const { publicKey } = generateKeyPairSync('x25519');
  const jwk = publicKey.export({ format: 'jwk' });
  const raw = Buffer.from(jwk.x, 'base64url');
  if (raw.length !== 32) throw new Error(`x25519: ожидали 32 байта, получили ${raw.length}`);
  return raw;
}

/** RFC 9000 §18. Правдоподобный набор, как у браузера. */
function quicTransportParameters(scid) {
  const tp = (pid, value = Buffer.alloc(0)) =>
    Buffer.concat([varint(pid), varint(value.length), value]);

  return Buffer.concat([
    tp(0x0f, scid),                                   // initial_source_connection_id
    tp(0x01, varint(choice([30000, 60000]))),         // max_idle_timeout
    tp(0x03, varint(choice([1350, 1452, 1472]))),     // max_udp_payload_size
    tp(0x04, varint(15728640)),                       // initial_max_data
    tp(0x05, varint(6291456)),                        // initial_max_stream_data_bidi_local
    tp(0x06, varint(6291456)),                        // initial_max_stream_data_bidi_remote
    tp(0x07, varint(6291456)),                        // initial_max_stream_data_uni
    tp(0x08, varint(100)),                            // initial_max_streams_bidi
    tp(0x09, varint(103)),                            // initial_max_streams_uni
    tp(0x0b, varint(choice([20, 25, 26]))),           // max_ack_delay
    tp(0x0e, varint(choice([4, 8, 16]))),             // active_connection_id_limit
    tp(0x0c),                                         // disable_active_migration
  ]);
}

/** Валидный TLS 1.3 ClientHello для QUIC (RFC 8446 + RFC 9001 §8). */
export function clientHello(sni, scid, alpn = ['h3']) {
  const pub = x25519PublicRaw();

  const parts = [];
  parts.push(Buffer.from([0x03, 0x03]));              // legacy_version = TLS 1.2
  parts.push(randBytes(32));                          // random
  parts.push(Buffer.from([0x00]));                    // legacy_session_id: пусто (RFC 9001 §8.4)
  // Порядок как у Chromium: он cipher suites НЕ перемешивает (оба браузерных
  // образца дают строго 1301,1302,1303). Рандомизация здесь ломала бы мимикрию:
  // такой порядок не встречается ни в одном реальном стеке.
  const suites = [0x1301, 0x1302, 0x1303];
  parts.push(u16(suites.length * 2), ...suites.map(u16));
  parts.push(Buffer.from([0x01, 0x00]));              // legacy_compression_methods = null

  // server_name
  const sniB = Buffer.from(sni, 'utf8');
  const eSni = ext(0x0000, Buffer.concat([
    u16(sniB.length + 3), Buffer.from([0x00]), u16(sniB.length), sniB,
  ]));
  // supported_groups: x25519, secp256r1, secp384r1
  const eGrp = ext(0x000a, Buffer.concat([u16(6), u16(0x001d), u16(0x0017), u16(0x0018)]));
  // signature_algorithms — порядок дословный: в JA4 они хешируются как есть
  const sigs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201];
  const eSig = ext(0x000d, Buffer.concat([u16(sigs.length * 2), ...sigs.map(u16)]));
  // ALPN
  const a = Buffer.concat(alpn.map((p) => {
    const pb = Buffer.from(p, 'ascii');
    return Buffer.concat([Buffer.from([pb.length]), pb]);
  }));
  const eAlpn = ext(0x0010, Buffer.concat([u16(a.length), a]));
  // supported_versions = TLS 1.3
  const eVer = ext(0x002b, Buffer.concat([Buffer.from([0x02]), u16(0x0304)]));
  // psk_key_exchange_modes = psk_dhe_ke
  const ePsk = ext(0x002d, Buffer.from([0x01, 0x01]));
  // key_share: x25519
  const ks = Buffer.concat([u16(0x001d), u16(32), pub]);
  const eKs = ext(0x0033, Buffer.concat([u16(ks.length), ks]));
  // quic_transport_parameters
  const eQtp = ext(0x0039, quicTransportParameters(scid));
  // compress_certificate = brotli (Chromium шлёт всегда)
  const eCc = ext(0x001b, Buffer.concat([Buffer.from([0x02]), u16(0x0002)]));
  // application_settings (ALPS), тот же список протоколов, что и в ALPN
  const eAlps = ext(0x4469, Buffer.concat([u16(a.length), a]));

  // session_ticket (0x0023) здесь НЕТ намеренно: для QUIC его не шлёт ни один
  // из перехваченных браузерных ClientHello.
  const exts = [eSni, eGrp, eSig, eAlpn, eVer, ePsk, eKs, eQtp, eCc, eAlps];
  shuffle(exts);
  const extBlob = Buffer.concat(exts);
  parts.push(u16(extBlob.length), extBlob);

  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([0x01]), u24(body.length), body]);
}

// --------------------------------------------------------------------------
// Сборка QUIC Initial
// --------------------------------------------------------------------------
export function buildInitial({
  sni = null,
  size = 1252,
  dcidLen = null,
  pn = null,
  pnLen = null,
  scidLen = 0,
  alpn = ['h3'],
} = {}) {
  if (sni === null) sni = choice(DEFAULT_SNIS);
  if (dcidLen === null) dcidLen = choice([8, 8, 20]);
  if (pn === null) pn = choice([0, 0, 1]);
  if (pnLen === null) pnLen = choice([1, 2]);
  if (!alpn || alpn.length === 0) {
    throw new Error('alpn пуст, нужен хотя бы один протокол (например h3)');
  }

  const dcid = randBytes(dcidLen);
  const scid = scidLen ? randBytes(scidLen) : Buffer.alloc(0);
  const keys = initialKeys(dcid);

  const ch = clientHello(sni, scid, alpn);
  const crypto = Buffer.concat([Buffer.from([0x06]), varint(0), varint(ch.length), ch]);

  // token_len = 1 байт, length = 2 байта varint
  const hdrLen = 1 + 4 + 1 + dcidLen + 1 + scidLen + 1 + 2;
  const plainLen = size - hdrLen - pnLen - 16;          // 16 = AEAD tag
  const pad = plainLen - crypto.length;
  if (pad < 0) {
    throw new Error(
      `size ${size} слишком мал: только ClientHello занимает ${crypto.length} байт, ` +
      `нужно минимум ${size - pad}`);
  }

  // PADDING до или после CRYPTO — в реальных образцах встречается и так, и так
  const padding = Buffer.alloc(pad, 0x00);
  const plaintext = randomInt(2) === 0
    ? Buffer.concat([padding, crypto])
    : Buffer.concat([crypto, padding]);

  const first = 0xc0 | (pnLen - 1);                     // long|fixed|Initial|resv=00|pnlen
  const pnBytes = Buffer.alloc(pnLen);
  pnBytes.writeUIntBE(pn, 0, pnLen);
  const version = Buffer.alloc(4);
  version.writeUInt32BE(1, 0);
  const header = Buffer.concat([
    Buffer.from([first]), version,
    Buffer.from([dcidLen]), dcid, Buffer.from([scidLen]), scid,
    varint(0),                                          // token length = 0
    varint2(pnLen + plaintext.length + 16),             // length
  ]);
  const aad = Buffer.concat([header, pnBytes]);

  const pn12 = Buffer.alloc(12);
  pn12.writeBigUInt64BE(BigInt(pn), 4);
  const nonce = Buffer.alloc(12);
  for (let i = 0; i < 12; i++) nonce[i] = keys.iv[i] ^ pn12[i];

  const cipher = createCipheriv('aes-128-gcm', keys.key, nonce);
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);

  // header protection (RFC 9001 §5.4)
  const pnOff = header.length;
  const protected_ = Buffer.concat([header, pnBytes, ct]);
  const sample = protected_.subarray(pnOff + 4, pnOff + 20);
  const ecb = createCipheriv('aes-128-ecb', keys.hp, Buffer.alloc(0));
  ecb.setAutoPadding(false);
  const mask = Buffer.concat([ecb.update(sample), ecb.final()]);
  protected_[0] ^= mask[0] & 0x0f;
  for (let i = 0; i < pnLen; i++) protected_[pnOff + i] ^= mask[1 + i];

  if (protected_.length !== size) {
    throw new Error(`собранный пакет ${protected_.length} байт, ожидалось ${size}`);
  }
  return protected_;
}

export default buildInitial;
