/**
 * Сборка конфига и разбор эндпоинта. Все проверенные в бою константы
 * зафиксированы здесь: если тест покраснел — это расхождение с рабочим
 * профилем, а не повод править ожидания.
 */

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildConfig, buildNoises, formatEndpoint, normAddress, parseEndpoint, validHostname,
  DEF_ENDPOINT, DEF_MTU, DEF_KEEPALIVE, DEF_PEER_PUBKEY,
} from '../lib/build-config.js';

const CREDS = {
  secretKey: 'p1FqpOMu1cDKDc8+7INZPyrunI/Z4FsvKeMYw7ktrIk=',
  address: ['172.16.0.2', '2606:4700:110:8798:f77d:7e3b:a4ad:2943'],
  publicKey: DEF_PEER_PUBKEY,
};

function make(extra = {}) {
  const { noises } = buildNoises(extra.noise || {});
  return buildConfig({ ...CREDS, noises, remarks: 'WARP', ...extra.config });
}

test('в конфиге есть все обязательные для клиентов ключи', () => {
  const cfg = make();
  for (const key of ['remarks', 'inbounds', 'outbounds', 'routing']) {
    assert.ok(key in cfg, `нет ключа ${key} — v2rayNG не опознает подписку`);
  }
  assert.deepEqual(cfg.routing.rules, [{ type: 'field', network: 'tcp,udp', outboundTag: 'warp' }]);
  assert.equal(cfg.routing.domainStrategy, 'AsIs');
});

test('wireguard-аутбаунд повторяет проверенный в бою профиль', () => {
  const [warp, noiseOut] = make().outbounds;
  assert.equal(warp.tag, 'warp');
  assert.equal(warp.protocol, 'wireguard');
  assert.equal(warp.settings.mtu, DEF_MTU);
  assert.deepEqual(warp.settings.address, ['172.16.0.2/32', '2606:4700:110:8798:f77d:7e3b:a4ad:2943/128']);
  assert.equal(warp.settings.peers[0].endpoint, DEF_ENDPOINT);
  assert.equal(warp.settings.peers[0].keepAlive, DEF_KEEPALIVE);
  assert.deepEqual(warp.settings.peers[0].allowedIPs, ['0.0.0.0/0', '::/0']);
  assert.deepEqual(warp.streamSettings, { sockopt: { dialerProxy: 'noise-out' } });
  assert.equal(noiseOut.tag, 'noise-out');
  assert.equal(noiseOut.protocol, 'freedom');
  assert.equal(noiseOut.settings.domainStrategy, 'AsIs');
});

test('поля reserved нет, пока его не передали явно', () => {
  assert.equal('reserved' in make().outbounds[0].settings, false);
  const withReserved = make({ config: { reserved: [1, 2, 3] } });
  assert.deepEqual(withReserved.outbounds[0].settings.reserved, [1, 2, 3]);
});

test('noises: один QUIC hex 1252 байта и 8 rand-диапазонов', () => {
  const { noises } = buildNoises();
  assert.equal(noises.length, 9);
  assert.equal(noises[0].type, 'hex');
  assert.equal(noises[0].delay, '1-2');
  assert.equal(noises[0].packet.length, 1252 * 2, 'QUIC Initial обязан быть ровно 1252 байта');
  assert.match(noises[0].packet, /^[0-9a-f]+$/);
  for (const n of noises.slice(1)) {
    assert.deepEqual(n, { type: 'rand', packet: '23-911', delay: '1-3' });
    assert.equal(typeof n.packet, 'string', 'rand-шум — диапазон-строка, байты раскрывает сам Xray');
  }
});

test('QUIC-шум уникален от вызова к вызову', () => {
  const a = buildNoises().noises[0].packet;
  const b = buildNoises().noises[0].packet;
  assert.notEqual(a, b);
});

test('параметры шума переопределяются', () => {
  const { noises } = buildNoises({ randCount: 2, randSize: '10-20', randDelay: '5', quicDelay: '3-4' });
  assert.equal(noises.length, 3);
  assert.equal(noises[0].delay, '3-4');
  assert.deepEqual(noises[1], { type: 'rand', packet: '10-20', delay: '5' });
});

test('готовый hex-пакет принимается как есть (ручная правка)', () => {
  const { noises } = buildNoises({ quicPacketHex: 'AABB' });
  assert.equal(noises[0].packet, 'aabb');
});

test('мусорные параметры шума отвергаются', () => {
  assert.throws(() => buildNoises({ randDelay: 'много' }), /randDelay/);
  assert.throws(() => buildNoises({ randCount: -1 }), /randCount/);
  assert.throws(() => buildNoises({ alpn: [] }), /alpn/);
  assert.throws(() => buildNoises({ quicPacketHex: 'zz' }), /hex|шестнадцат/i);
});

test('конфиг без ключа или адреса не собирается', () => {
  const { noises } = buildNoises();
  assert.throws(() => buildConfig({ ...CREDS, secretKey: null, noises }), /secretKey/);
  assert.throws(() => buildConfig({ ...CREDS, address: [], noises }), /адрес/);
  assert.throws(() => buildConfig({ ...CREDS, noises: [] }), /noise/);
});

test('inbounds можно выключить — получается клиентский конфиг', () => {
  const cfg = make({ config: { inbounds: false } });
  assert.equal('inbounds' in cfg, false);
  assert.equal(cfg.outbounds.length, 2);
});

test('normAddress добавляет префикс по семейству адреса', () => {
  assert.equal(normAddress('172.16.0.2'), '172.16.0.2/32');
  assert.equal(normAddress('2606:4700::1'), '2606:4700::1/128');
  assert.equal(normAddress('10.0.0.1/24'), '10.0.0.1/24');
  assert.equal(normAddress('  '), null);
});

test('parseEndpoint разбирает три допустимые формы', () => {
  assert.deepEqual(parseEndpoint('162.159.192.1:500'), { host: '162.159.192.1', port: 500, kind: 'ipv4' });
  assert.deepEqual(parseEndpoint('engage.cloudflareclient.com:2408'),
    { host: 'engage.cloudflareclient.com', port: 2408, kind: 'name' });
  assert.deepEqual(parseEndpoint('[2606:4700:d0::a29f:c001]:500'),
    { host: '2606:4700:d0::a29f:c001', port: 500, kind: 'ipv6' });
});

test('parseEndpoint объясняет каждую ошибку', () => {
  assert.throws(() => parseEndpoint(''), /пустое/);
  assert.throws(() => parseEndpoint('162.159.192.1'), /не указан порт/);
  assert.throws(() => parseEndpoint('2606:4700:d0::a29f:c001'), /без порта/);
  assert.throws(() => parseEndpoint('[2606:4700:d0::a29f:c001]500'), /скобочная форма/);
  assert.throws(() => parseEndpoint('[не-адрес]:500'), /в скобках ожидался IPv6/);
  assert.throws(() => parseEndpoint('host:0'), /вне диапазона/);
  assert.throws(() => parseEndpoint('host:70000'), /вне диапазона/);
  assert.throws(() => parseEndpoint('host:abc'), /числом/);
  assert.throws(() => parseEndpoint(':500'), /не указан хост/);
  assert.throws(() => parseEndpoint('-bad-.example:500'), /не похож/);
});

test('IPv6-эндпоинт возвращается в скобках', () => {
  const cfg = make({ config: { endpoint: '[2606:4700:d0::a29f:c001]:500' } });
  assert.equal(cfg.outbounds[0].settings.peers[0].endpoint, '[2606:4700:d0::a29f:c001]:500');
  assert.equal(formatEndpoint(parseEndpoint('1.2.3.4:500')), '1.2.3.4:500');
});

test('validHostname следует RFC 1123', () => {
  assert.equal(validHostname('example.com'), true);
  assert.equal(validHostname('example.com.'), true);
  assert.equal(validHostname('a-b.c-d.ru'), true);
  assert.equal(validHostname('-bad.com'), false);
  assert.equal(validHostname('bad-.com'), false);
  assert.equal(validHostname('a'.repeat(64) + '.com'), false);
  assert.equal(validHostname('под_чёрк.com'), false);
  assert.equal(validHostname(''), false);
});
