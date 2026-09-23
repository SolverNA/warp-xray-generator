/** Выбор формата подписки по User-Agent. */

import assert from 'node:assert/strict';
import test from 'node:test';

import { detectClient, pickFormat, subscriptionHeaders, unsupportedText } from '../lib/subscription.js';

const CASES = [
  ['Happ/1.16.0', 'xray', 'json'],
  ['v2raytun/1.9.1 (iPhone)', 'xray', 'json'],
  ['v2rayNG/1.8.23', 'xray', 'json'],
  ['v2rayN/7.0.1', 'xray', 'json'],
  ['Throne/1.0.0', 'xray', 'json'],
  ['Streisand/1.6.44', 'xray', 'json'],
  ['SFA/1.10.1 (io.nekohasekai.sfa)', 'singbox', 'unsupported'],
  ['SFI/1.10.1', 'singbox', 'unsupported'],
  ['SFM/1.10.1', 'singbox', 'unsupported'],
  ['SFT/1.10.1', 'singbox', 'unsupported'],
  ['HiddifyNext/2.5.7', 'singbox', 'unsupported'],
  ['Karing/1.0.20', 'singbox', 'unsupported'],
  ['ClashMetaForAndroid/2.11.6', 'clash', 'unsupported'],
  ['clash-verge/1.7.7', 'clash', 'unsupported'],
  ['mihomo/1.18.8', 'clash', 'unsupported'],
  ['Stash/2.7.0', 'clash', 'unsupported'],
  ['Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/131.0', 'browser', 'browser'],
  ['Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/129 Safari/537.36', 'browser', 'browser'],
  ['Opera/9.80', 'browser', 'browser'],
  ['curl/8.9.1', 'unknown', 'json'],
  ['', 'unknown', 'json'],
  [undefined, 'unknown', 'json'],
];

for (const [ua, kind, format] of CASES) {
  test(`UA ${JSON.stringify(ua)} -> ${kind} / ${format}`, () => {
    assert.equal(detectClient(ua), kind);
    assert.equal(pickFormat(ua), format);
  });
}

test('клиент опознаётся раньше браузерных подстрок в том же UA', () => {
  assert.equal(pickFormat('Mozilla/5.0 v2rayNG/1.8.23'), 'json');
  assert.equal(pickFormat('Mozilla/5.0 HiddifyNext/2.5.7'), 'unsupported');
});

test('заголовки подписки полные и с base64-именем', () => {
  const h = subscriptionHeaders('WARP тест');
  assert.equal(h['content-type'], 'application/json');
  assert.equal(h['content-disposition'], 'attachment; filename="warp"');
  assert.equal(h['profile-update-interval'], '168');
  assert.equal(h['subscription-userinfo'], 'upload=0; download=0; total=0; expire=0');
  assert.match(h['profile-title'], /^base64:/);
  assert.equal(Buffer.from(h['profile-title'].slice(7), 'base64').toString('utf8'), 'WARP тест');
});

test('отказ объясняет причину, а не просто отказывает', () => {
  assert.match(unsupportedText('singbox'), /sing-box/);
  assert.match(unsupportedText('clash'), /clash/);
  for (const kind of ['singbox', 'clash']) assert.match(unsupportedText(kind), /noises/);
});
