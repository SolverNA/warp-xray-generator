/**
 * Проверка порта генератора QUIC Initial: отпечаток ClientHello (JA4) обязан
 * совпадать с перехваченным браузерным эталоном, а сами пакеты при этом обязаны
 * быть каждый раз разными.
 *
 * Эталонное значение взято из самопроверки tests/test-fingerprint.sh проекта
 * «awg to xray»: такой JA4 дают перехваченные браузерные пакеты
 * awg-samples/megafon-ok-1180.conf и megafon-ok-903.conf. Если тест красный —
 * ищем расхождение с оригиналом, а НЕ правим это значение под результат.
 */

import assert from 'node:assert/strict';
import test from 'node:test';

import { buildInitial } from '../lib/quic-initial.js';
import { cryptoPayload, decryptInitial, ja4, parseClientHello } from '../lib/ja4.js';

const EXPECTED_JA4 = 'q13d0310h3_55b375c5d22e_cd85d2d88918';
const PACKET_SIZE = 1252;
const N = 50;

/** Один общий прогон: 50 пакетов, дальше все проверки смотрят на него. */
const packets = Array.from({ length: N }, () => buildInitial());
const infos = packets.map((p) => ja4(p));

test(`JA4 всех ${N} пакетов равен эталону ${EXPECTED_JA4}`, () => {
  infos.forEach((info, i) => {
    assert.equal(
      info.ja4, EXPECTED_JA4,
      `пакет #${i} (SNI=${info.sni}, расширения=${info.extList}) дал ${info.ja4}`);
  });
});

test(`размер каждого пакета ровно ${PACKET_SIZE} байт`, () => {
  packets.forEach((p, i) => {
    assert.equal(p.length, PACKET_SIZE, `пакет #${i}`);
  });
});

test('пакеты различаются между собой — обфускация уникальна', () => {
  const seen = new Set(packets.map((p) => p.toString('hex')));
  assert.equal(seen.size, N, `найдены дубликаты: уникальных ${seen.size} из ${N}`);
});

test('порядок расширений варьируется — shuffle жив', () => {
  const orders = new Set(infos.map((info) => info.extOrder));
  assert.ok(
    orders.size >= N / 2,
    `порядок расширений почти не меняется: различных ${orders.size} из ${N} ` +
    `(пример: ${infos[0].extOrder})`);
});

test('состав ClientHello не поехал: 10 расширений, ALPN h3, SNI есть', () => {
  const WANT_EXTS = '0000,000a,000d,0010,001b,002b,002d,0033,0039,4469';
  infos.forEach((info, i) => {
    assert.equal(info.exts, 10, `пакет #${i}: расширений ${info.exts}`);
    assert.equal(info.extList, WANT_EXTS, `пакет #${i}: набор расширений`);
    assert.equal(info.alpn, 'h3', `пакет #${i}: ALPN`);
    assert.ok(info.sni, `пакет #${i}: SNI пуст`);
  });
});

test('cipher suites строго 1301,1302,1303 и НЕ перемешаны', () => {
  packets.forEach((p, i) => {
    const { ciphers } = parseClientHello(cryptoPayload(decryptInitial(p)));
    assert.deepEqual(ciphers, [0x1301, 0x1302, 0x1303], `пакет #${i}`);
  });
});

test('signature_algorithms в исходном порядке, без сортировки', () => {
  const WANT = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201];
  packets.forEach((p, i) => {
    const { sigs } = parseClientHello(cryptoPayload(decryptInitial(p)));
    assert.deepEqual(sigs, WANT, `пакет #${i}`);
  });
});
