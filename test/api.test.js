/**
 * Хендлеры целиком, без сети: аккаунт передаётся в теле, поэтому в Cloudflare
 * никто не ходит, а хранилище работает в памяти процесса.
 */

import assert from 'node:assert/strict';
import test from 'node:test';

import generate from '../api/generate.js';
import sub from '../api/sub/[id].js';

function mockRes() {
  const res = {
    statusCode: 200,
    headers: {},
    body: undefined,
    ended: false,
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; return this; },
    status(c) { this.statusCode = c; return this; },
    json(v) { this.body = v; this.ended = true; return this; },
    send(v) { this.body = v; this.ended = true; return this; },
    end() { this.ended = true; return this; },
  };
  return res;
}

const ACCOUNT = {
  privateKey: 'p1FqpOMu1cDKDc8+7INZPyrunI/Z4FsvKeMYw7ktrIk=',
  address: ['172.16.0.2', '2606:4700:110:8798:f77d:7e3b:a4ad:2943'],
  peerPublicKey: 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=',
};

async function gen(body = {}, headers = {}) {
  const req = { method: 'POST', headers: { host: 'example.com', ...headers }, body: { account: ACCOUNT, ...body } };
  const res = mockRes();
  await generate(req, res);
  return res;
}

async function fetchSub(id, ua) {
  const req = { method: 'GET', headers: { 'user-agent': ua }, query: { id } };
  const res = mockRes();
  await sub(req, res);
  return res;
}

test('generate отвечает только на POST', async () => {
  const res = mockRes();
  await generate({ method: 'GET', headers: {}, query: {} }, res);
  assert.equal(res.statusCode, 405);
  assert.equal(res.body.error, 'method_not_allowed');
});

test('generate отдаёт id, ссылку без query, конфиг и момент истечения', async () => {
  const res = await gen();
  assert.equal(res.statusCode, 200);
  const b = res.body;
  assert.ok(b.ok);
  assert.match(b.id, /^[A-Za-z0-9]{16,}$/);
  assert.equal(b.url, `https://example.com/sub/${b.id}`);
  assert.equal(b.url.includes('?'), false, 'query-параметр ломает deep-link вида ?url=');
  assert.equal(b.ttl, 300);
  const left = b.expiresAt - Date.now();
  assert.ok(left > 295_000 && left <= 300_000);
  for (const key of ['remarks', 'inbounds', 'outbounds', 'routing']) assert.ok(key in b.config);
  assert.equal(b.config.outbounds[0].settings.secretKey, ACCOUNT.privateKey);
});

test('переданный аккаунт переиспользуется, в Cloudflare не ходим', async () => {
  const a = (await gen()).body;
  const b = (await gen({ account: a.account })).body;
  assert.equal(a.config.outbounds[0].settings.secretKey, b.config.outbounds[0].settings.secretKey);
  assert.notEqual(
    a.config.outbounds[1].settings.noises[0].packet,
    b.config.outbounds[1].settings.noises[0].packet,
    'QUIC-шум обязан быть новым на каждую генерацию');
});

test('ручные правки полей доезжают до конфига', async () => {
  const b = (await gen({
    endpoint: '[2606:4700:d0::a29f:c001]:4500', mtu: 1420, keepAlive: 25,
    dns: ['9.9.9.9'], loglevel: 'debug', remarks: 'Мой WARP',
    randCount: 2, randSize: '50-60', quicDelay: '7', inbounds: false,
  })).body;
  const [warp, noiseOut] = b.config.outbounds;
  assert.equal(warp.settings.peers[0].endpoint, '[2606:4700:d0::a29f:c001]:4500');
  assert.equal(warp.settings.mtu, 1420);
  assert.equal(warp.settings.peers[0].keepAlive, 25);
  assert.deepEqual(b.config.dns.servers, ['9.9.9.9']);
  assert.equal(b.config.log.loglevel, 'debug');
  assert.equal(b.config.remarks, 'Мой WARP');
  assert.equal(noiseOut.settings.noises.length, 3);
  assert.equal(noiseOut.settings.noises[0].delay, '7');
  assert.equal('inbounds' in b.config, false);
});

test('перегенерация в ту же ссылку: id сохраняется, шум новый', async () => {
  const a = (await gen()).body;
  const b = (await gen({ account: a.account, id: a.id, sni: 'mail.ru' })).body;
  assert.equal(b.id, a.id);
  assert.equal(b.url, a.url);
  assert.notEqual(b.params.quicPacket, a.params.quicPacket);
});

test('кривой параметр — 400 с объяснением, аккаунт не теряется', async () => {
  const res = await gen({ endpoint: 'без-порта' });
  assert.equal(res.statusCode, 400);
  assert.equal(res.body.error, 'bad_params');
  assert.match(res.body.message, /порт/);
});

test('подписка: клиенту Xray уходит массив конфигов и все заголовки', async () => {
  const { id } = (await gen({ remarks: 'WARP' })).body;
  const res = await fetchSub(id, 'v2rayNG/1.8.23');
  assert.equal(res.statusCode, 200);
  assert.equal(res.headers['content-type'], 'application/json');
  assert.equal(res.headers['content-disposition'], 'attachment; filename="warp"');
  assert.equal(res.headers['profile-update-interval'], '168');
  assert.equal(res.headers['subscription-userinfo'], 'upload=0; download=0; total=0; expire=0');
  assert.equal(res.headers['profile-title'], `base64:${Buffer.from('WARP').toString('base64')}`);
  const arr = JSON.parse(res.body);
  assert.ok(Array.isArray(arr));
  assert.equal(arr.length, 1);
  for (const key of ['remarks', 'inbounds', 'outbounds', 'routing']) assert.ok(key in arr[0], `нет ${key}`);
});

test('подписка: sing-box и clash получают отказ текстом, а не конфиг', async () => {
  const { id } = (await gen()).body;
  for (const ua of ['SFI/1.10.1', 'mihomo/1.18.8']) {
    const res = await fetchSub(id, ua);
    assert.equal(res.statusCode, 200);
    assert.match(res.headers['content-type'], /text\/plain/);
    assert.match(res.body, /не поддерживается/);
    assert.equal(res.body.includes('"outbounds"'), false);
  }
});

test('подписка: браузер получает человекочитаемый текст', async () => {
  const { id } = (await gen()).body;
  const res = await fetchSub(id, 'Mozilla/5.0 Firefox/131.0');
  assert.equal(res.statusCode, 200);
  assert.match(res.headers['content-type'], /text\/plain/);
  assert.match(res.body, /вставьте её в v2rayNG/i);
});

test('подписка: неизвестный UA получает тот же JSON-массив', async () => {
  const { id } = (await gen()).body;
  const res = await fetchSub(id, 'curl/8.9.1');
  assert.equal(res.headers['content-type'], 'application/json');
  assert.equal(JSON.parse(res.body).length, 1);
});

test('подписка: нет записи или кривой id — 404 с понятным текстом', async () => {
  for (const id of ['zzzzzzzzzzzzzzzzzzzzzz', '../../etc/passwd', 'short']) {
    const res = await fetchSub(id, 'v2rayNG/1.8.23');
    assert.equal(res.statusCode, 404);
    assert.match(res.body, /истекла|не найдена/);
  }
});
