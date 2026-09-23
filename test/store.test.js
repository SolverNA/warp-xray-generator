/**
 * Идентификатор подписки и откат хранилища в память.
 * Upstash тестом не трогаем: без переменных окружения store работает в памяти.
 */

import assert from 'node:assert/strict';
import test from 'node:test';

import { get, isPersistent, isValidId, newId, put, TTL_SECONDS } from '../lib/store.js';

test('TTL ровно 300 секунд', () => {
  assert.equal(TTL_SECONDS, 300);
});

test('без переменных окружения хранилище — в памяти', () => {
  assert.equal(isPersistent(), false);
});

test('идентификатор: не меньше 16 символов, только буквы и цифры', () => {
  for (let i = 0; i < 200; i += 1) {
    const id = newId();
    assert.ok(id.length >= 16, `слишком короткий: ${id}`);
    assert.match(id, /^[A-Za-z0-9]+$/, `посторонние символы: ${id}`);
    assert.ok(isValidId(id));
  }
});

test('идентификаторы не повторяются', () => {
  const seen = new Set(Array.from({ length: 500 }, () => newId()));
  assert.equal(seen.size, 500);
});

test('isValidId отвергает всё, что ломает ссылку', () => {
  for (const bad of ['', 'short', 'a'.repeat(15), 'a'.repeat(65), '../etc/passwd',
    'id?url=x', 'id/with/slash', 'ид-кириллица', 'плюс+', null, undefined, 42, {}]) {
    assert.equal(isValidId(bad), false, `принят плохой id: ${JSON.stringify(bad)}`);
  }
  assert.equal(isValidId('a'.repeat(16)), true);
});

test('запись кладётся и читается, момент истечения — примерно через TTL', async () => {
  const id = newId();
  const { expiresAt } = await put(id, { config: { hello: 'world' }, remarks: 'WARP' });
  const delta = expiresAt - Date.now();
  assert.ok(delta > 295_000 && delta <= 300_000, `TTL уехал: ${delta} мс`);
  const row = await get(id);
  assert.deepEqual(row.config, { hello: 'world' });
  assert.equal(row.remarks, 'WARP');
  assert.equal(row.expiresAt, expiresAt);
});

test('протухшая и несуществующая запись одинаково дают null', async () => {
  assert.equal(await get(newId()), null);
  const id = newId();
  await put(id, { config: {} }, -1);
  assert.equal(await get(id), null);
});

test('put не принимает кривой идентификатор', async () => {
  await assert.rejects(() => put('short', { config: {} }), /идентификатор/);
});
