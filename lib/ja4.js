/**
 * Калькулятор JA4 (спецификация FoxIO) для QUIC Initial-пакета.
 *
 * Порт калькулятора из tests/test-fingerprint.sh проекта «awg to xray»
 * (встроенный там python-скрипт ja4-fingerprint.py). Нужен тестам: по готовому
 * пакету снимает header protection, расшифровывает AEAD, достаёт ClientHello и
 * считает отпечаток. Крипта — только встроенный node:crypto.
 */

import { createDecipheriv, createCipheriv, createHash } from 'node:crypto';

import { initialKeys } from './quic-initial.js';

const GREASE = new Set([
  0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
  0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
]);

const VERMAP = new Map([
  [0x0304, '13'], [0x0303, '12'], [0x0302, '11'], [0x0301, '10'], [0x0300, 's3'],
]);

/** varint, RFC 9000 §16 */
function rv(buf, off) {
  const b0 = buf[off];
  const n = 1 << (b0 >> 6);
  let v = b0 & 0x3f;
  for (let i = 1; i < n; i++) v = v * 256 + buf[off + i];
  return [v, off + n];
}

const hex4 = (v) => v.toString(16).padStart(4, '0');

/** Снимаем header protection и AEAD клиентскими Initial-ключами из DCID. */
export function decryptInitial(pkt) {
  let o = 1 + 4;
  const dl = pkt[o]; o += 1;
  const dcid = pkt.subarray(o, o + dl); o += dl;
  const sl = pkt[o]; o += 1 + sl;
  let tl;
  [tl, o] = rv(pkt, o); o += tl;
  let ln;
  [ln, o] = rv(pkt, o);
  const pnOff = o;

  const k = initialKeys(dcid);
  const ecb = createCipheriv('aes-128-ecb', k.hp, Buffer.alloc(0));
  ecb.setAutoPadding(false);
  const mask = Buffer.concat([
    ecb.update(pkt.subarray(pnOff + 4, pnOff + 20)),
    ecb.final(),
  ]);

  const fb = pkt[0] ^ (mask[0] & 0x0f);
  const pl = (fb & 3) + 1;
  const pnb = Buffer.alloc(pl);
  for (let i = 0; i < pl; i++) pnb[i] = pkt[pnOff + i] ^ mask[1 + i];
  const pn = pnb.readUIntBE(0, pl);

  const hdr = Buffer.from(pkt.subarray(0, pnOff + pl));
  hdr[0] = fb;
  pnb.copy(hdr, pnOff);

  const pn12 = Buffer.alloc(12);
  pn12.writeBigUInt64BE(BigInt(pn), 4);
  const nonce = Buffer.alloc(12);
  for (let i = 0; i < 12; i++) nonce[i] = k.iv[i] ^ pn12[i];

  const body = pkt.subarray(pnOff + pl, pnOff + ln);
  const ct = body.subarray(0, body.length - 16);
  const tag = body.subarray(body.length - 16);
  const d = createDecipheriv('aes-128-gcm', k.key, nonce);
  d.setAAD(hdr);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

/** Склеиваем CRYPTO-фреймы по offset, PADDING/PING пропускаем. */
export function cryptoPayload(plain) {
  const chunks = new Map();
  let i = 0;
  while (i < plain.length) {
    const t = plain[i];
    if (t === 0x00 || t === 0x01) { i += 1; continue; }
    if (t === 0x06) {
      i += 1;
      let off;
      [off, i] = rv(plain, i);
      let ln;
      [ln, i] = rv(plain, i);
      chunks.set(off, plain.subarray(i, i + ln));
      i += ln;
      continue;
    }
    break;
  }
  const keys = [...chunks.keys()].sort((a, b) => a - b);
  return Buffer.concat(keys.map((o) => chunks.get(o)));
}

export function parseClientHello(ch) {
  if (!ch || ch.length === 0 || ch[0] !== 0x01) {
    throw new Error('CRYPTO не содержит ClientHello');
  }
  let j = 4 + 2 + 32;
  j += 1 + ch[j];                                   // legacy_session_id
  const cs = ch.readUInt16BE(j); j += 2;
  const ciphers = [];
  for (let n = 0; n < cs / 2; n++) ciphers.push(ch.readUInt16BE(j + 2 * n));
  j += cs;
  j += 1 + ch[j];                                   // legacy_compression_methods
  const el = ch.readUInt16BE(j); j += 2;
  const end = j + el;

  const exts = [];
  const alpn = [];
  let sni = null;
  let sigs = [];
  let vers = [];
  while (j + 4 <= end) {
    const et = ch.readUInt16BE(j);
    const ln = ch.readUInt16BE(j + 2);
    const d = ch.subarray(j + 4, j + 4 + ln);
    j += 4 + ln;
    exts.push(et);
    if (et === 0x0000 && d.length >= 5) {
      const n = d.readUInt16BE(3);
      sni = d.subarray(5, 5 + n).toString('ascii');
    } else if (et === 0x0010) {
      let p = 2;
      while (p < d.length) {
        alpn.push(d.subarray(p + 1, p + 1 + d[p]).toString('ascii'));
        p += 1 + d[p];
      }
    } else if (et === 0x000d) {
      const n = d.readUInt16BE(0);
      sigs = [];
      for (let i = 0; i < n / 2; i++) sigs.push(d.readUInt16BE(2 + 2 * i));
    } else if (et === 0x002b) {
      const n = d[0];
      vers = [];
      for (let i = 0; i < n / 2; i++) vers.push(d.readUInt16BE(1 + 2 * i));
    }
  }
  return { ciphers, exts, sni, alpn, sigs, vers };
}

function h12(s) {
  return createHash('sha256').update(s, 'utf8').digest('hex').slice(0, 12);
}

/** JA4 по спецификации FoxIO: ja4_a_ja4_b_ja4_c. */
export function ja4(pkt, proto = 'q') {
  const { ciphers, exts, sni, alpn, sigs, vers } =
    parseClientHello(cryptoPayload(decryptInitial(pkt)));

  const cip = ciphers.filter((c) => !GREASE.has(c));
  const ex = exts.filter((e) => !GREASE.has(e));
  const real = vers.filter((v) => !GREASE.has(v));
  const ver = real.length ? (VERMAP.get(Math.max(...real)) ?? '00') : '12';
  const a = alpn.length ? alpn[0] : '';

  // a: протокол, версия TLS, есть ли SNI, число шифров, число расширений
  // (SNI и ALPN здесь СЧИТАЮТСЯ), первый и последний символ первого ALPN
  const ja4a = proto + ver + (sni ? 'd' : 'i')
    + String(Math.min(cip.length, 99)).padStart(2, '0')
    + String(Math.min(ex.length, 99)).padStart(2, '0')
    + (a ? a[0] + a[a.length - 1] : '00');

  // b: шифры ОТСОРТИРОВАНЫ — поэтому перемешивание порядка на него не влияет
  const ja4b = h12([...cip].sort((x, y) => x - y).map(hex4).join(','));

  // c: расширения отсортированы и БЕЗ SNI(0000) и ALPN(0010), затем
  //    signature_algorithms в ИСХОДНОМ порядке
  let s = ex.filter((e) => e !== 0x0000 && e !== 0x0010)
    .sort((x, y) => x - y).map(hex4).join(',');
  if (sigs.length) {
    s += '_' + sigs.filter((x) => !GREASE.has(x)).map(hex4).join(',');
  }
  const ja4c = h12(s);

  return {
    ja4: `${ja4a}_${ja4b}_${ja4c}`,
    sni,
    alpn: alpn.join(','),
    ciphers: cip.length,
    exts: ex.length,
    size: pkt.length,
    extOrder: exts.map(hex4).join(','),
    extList: [...ex].sort((x, y) => x - y).map(hex4).join(','),
  };
}

export default ja4;
