/*
 * Интерфейс генератора. Ничего внешнего: ни CDN, ни шрифтов, ни фреймворков —
 * страницу открывают из России без работающего VPN, и любой внешний запрос
 * может просто не дойти.
 *
 * Контракт сервера: POST /api/generate принимает все поля формы и (необязательно)
 * блок account из прошлого ответа. Если account прислан — похода в Cloudflare
 * не будет, и пересборка конфига стоит миллисекунды. Ответ:
 * { ok, id, url, ttl, expiresAt, config, account, params, warnings }.
 */
'use strict';

// Значения по умолчанию продублированы с lib/build-config.js: это подписи полей,
// а не источник истины — конфиг всё равно собирает сервер.
var DEFAULTS = {
  endpoint: '162.159.192.1:500',
  mtu: 1280,
  keepAlive: 5,
  dns: '1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001',
  loglevel: 'warning',
  remarks: 'WARP',
  alpn: 'h3',
  quicSize: 1252,
  quicDelay: '1-2',
  randCount: 8,
  randSize: '23-911',
  randDelay: '1-3',
  listen: '127.0.0.1',
  socksPort: 10808,
  httpPort: 10809,
  inbounds: true
};

// Тот же список, что в lib/quic-initial.js. SNI выбирается здесь, а не на
// сервере, только чтобы показать пользователю, что именно уехало в пакет:
// ответ API случайно выбранный SNI не возвращает.
var SNI_POOL = [
  'www.google.com', 'mail.ru', 'www.youtube.com', 'yandex.ru',
  'vk.com', 'cloudflare.com', 'www.cloudflare.com', 'ok.ru'
];

var $ = function (id) { return document.getElementById(id); };

var state = {
  busy: false,
  id: null,
  url: null,
  config: null,
  expiresAt: 0,
  timer: null,
  staleShown: false
};

// --------------------------------------------------------------------------
// Мелочи
// --------------------------------------------------------------------------

function randomOf(list) {
  var buf;
  if (window.crypto && window.crypto.getRandomValues) {
    buf = new Uint32Array(1);
    window.crypto.getRandomValues(buf);
    return list[buf[0] % list.length];
  }
  return list[Math.floor(Math.random() * list.length)];
}

function val(id) { return ($(id).value || '').trim(); }

function strOr(id) { var v = val(id); return v ? v : undefined; }

function numOr(id) {
  var v = val(id);
  if (!v) return undefined;
  var n = Number(v);
  return isFinite(n) ? n : undefined;
}

function listOr(id) {
  var v = val(id);
  if (!v) return undefined;
  var out = v.split(/[,\s]+/).map(function (s) { return s.trim(); }).filter(Boolean);
  return out.length ? out : undefined;
}

function fill(id, value) {
  if (value === undefined || value === null) return;
  $(id).value = Array.isArray(value) ? value.join(', ') : String(value);
}

// --------------------------------------------------------------------------
// Статус и ошибки
// --------------------------------------------------------------------------

function setStatus(kind, title, detail) {
  var box = $('status');
  box.className = 'status' + (kind ? ' ' + kind : '');
  box.innerHTML = '';
  var strong = document.createElement('strong');
  strong.textContent = title;
  box.appendChild(strong);
  if (detail) {
    var p = document.createElement('div');
    p.className = 'detail';
    p.textContent = detail;
    box.appendChild(p);
  }
  box.hidden = false;
}

function clearStatus() {
  $('status').hidden = true;
}

/** Человеческий текст вместо кода ошибки. */
function describeError(status, data) {
  var code = data && data.error;
  var msg = data && data.message;
  var cf = data && data.cf_status;

  if (cf === 429 || status === 429) {
    return ['Cloudflare временно отказывает в регистрации',
      'С этого адреса слишком много новых аккаунтов WARP. Подождите минуту и попробуйте снова — или впишите свои креды в настройках, тогда регистрация не потребуется.'];
  }
  switch (code) {
    case 'cloudflare_unreachable':
      return ['Cloudflare не ответил',
        'Запрос на регистрацию аккаунта WARP не дошёл или оборвался по таймауту. Это бывает и само проходит: попробуйте ещё раз через несколько секунд.'];
    case 'cloudflare_bad_response':
      return ['Cloudflare ответил не тем, чем должен',
        'Вместо JSON пришла заглушка или проверка. Повторите попытку позже.' + (msg ? ' Подробности: ' + msg : '')];
    case 'cloudflare_http_error':
      return ['Cloudflare отклонил регистрацию' + (cf ? ' (HTTP ' + cf + ')' : ''),
        msg || 'Повторите попытку позже.'];
    case 'registration_failed':
      return ['Не удалось зарегистрировать аккаунт WARP', msg || 'Попробуйте ещё раз.'];
    case 'bad_params':
      return ['Сервер не принял настройки', msg || 'Проверьте поля в «Редактировать настройки».'];
    case 'bad_json':
      return ['Сервер не разобрал запрос', msg || ''];
    case 'store_unavailable':
      return ['Хранилище недоступно',
        'Конфиг собран, но положить его под ссылку не вышло, поэтому ссылки нет. ' + (msg || '')];
    case 'method_not_allowed':
      return ['Запрос ушёл не тем методом', 'Перезагрузите страницу.'];
    default:
      return ['Не получилось сгенерировать конфиг',
        msg || ('Сервер ответил статусом ' + status + '.')];
  }
}

// --------------------------------------------------------------------------
// Копирование (clipboard может быть недоступен на http и в старых webview)
// --------------------------------------------------------------------------

function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text).then(function () { return true; },
      function () { return legacyCopy(text); });
  }
  return Promise.resolve(legacyCopy(text));
}

function legacyCopy(text) {
  var ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.style.position = 'fixed';
  ta.style.top = '-1000px';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  ta.setSelectionRange(0, text.length);
  var ok = false;
  try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
  document.body.removeChild(ta);
  return ok;
}

function copyButton(btn, getText, okLabel) {
  var original = btn.textContent;
  btn.disabled = true;
  copyText(getText()).then(function (ok) {
    btn.textContent = ok ? (okLabel || 'Скопировано') : 'Не вышло — выделите вручную';
    if (!ok) {
      setStatus('warn', 'Браузер не дал доступ к буферу обмена',
        'Выделите ссылку пальцем и скопируйте вручную — она целиком видна на странице.');
    }
    setTimeout(function () { btn.textContent = original; btn.disabled = false; }, 1800);
  });
}

// --------------------------------------------------------------------------
// QR-код
// --------------------------------------------------------------------------

function drawQr(text) {
  var canvas = $('qr');
  var wrap = canvas.parentNode.parentNode;
  if (typeof qrcodegen === 'undefined') {
    wrap.hidden = true;
    return;
  }
  try {
    var qr = qrcodegen.QrCode.encodeText(text, qrcodegen.QrCode.Ecc.MEDIUM);
    var border = 4;
    var total = qr.size + border * 2;
    var scale = Math.max(4, Math.ceil(640 / total));
    var px = total * scale;
    canvas.width = px;
    canvas.height = px;
    var ctx = canvas.getContext('2d');
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, px, px);
    ctx.fillStyle = '#000000';
    for (var y = 0; y < qr.size; y++) {
      for (var x = 0; x < qr.size; x++) {
        if (qr.getModule(x, y)) {
          ctx.fillRect((x + border) * scale, (y + border) * scale, scale, scale);
        }
      }
    }
    wrap.hidden = false;
  } catch (e) {
    wrap.hidden = true;
  }
}

// --------------------------------------------------------------------------
// Счётчик живости
// --------------------------------------------------------------------------

function stopTimer() {
  if (state.timer) { clearInterval(state.timer); state.timer = null; }
}

function startCountdown(expiresAt, ttlSeconds) {
  stopTimer();
  var ttlMs = (ttlSeconds || 300) * 1000;
  var left = expiresAt - Date.now();
  // Часы браузера могут врать; если расхождение со сроком жизни больше минуты,
  // верим TTL и считаем от текущего момента.
  if (!isFinite(left) || Math.abs(left - ttlMs) > 60000) {
    expiresAt = Date.now() + ttlMs;
  }
  state.expiresAt = expiresAt;

  $('life-live').hidden = false;
  $('life-dead').hidden = true;

  tick();
  state.timer = setInterval(tick, 1000);

  function tick() {
    var ms = state.expiresAt - Date.now();
    var secs = Math.max(0, Math.round(ms / 1000));
    var bar = $('bar-fill');
    if (secs <= 0) {
      stopTimer();
      $('life-live').hidden = true;
      $('life-dead').hidden = false;
      return;
    }
    $('countdown').textContent = Math.floor(secs / 60) + ':' + ('0' + (secs % 60)).slice(-2);
    var pct = Math.max(0, Math.min(100, (ms / ttlMs) * 100));
    bar.style.width = pct + '%';
    bar.className = 'bar-fill' + (secs <= 30 ? ' out' : (secs <= 90 ? ' low' : ''));
  }
}

// --------------------------------------------------------------------------
// Форма
// --------------------------------------------------------------------------

function newSni() { fill('f-sni', randomOf(SNI_POOL)); }

function applyDefaults() {
  fill('f-endpoint', DEFAULTS.endpoint);
  fill('f-mtu', DEFAULTS.mtu);
  fill('f-keepAlive', DEFAULTS.keepAlive);
  fill('f-dns', DEFAULTS.dns);
  fill('f-remarks', DEFAULTS.remarks);
  $('f-loglevel').value = DEFAULTS.loglevel;
  fill('f-alpn', DEFAULTS.alpn);
  fill('f-quicSize', DEFAULTS.quicSize);
  fill('f-quicDelay', DEFAULTS.quicDelay);
  fill('f-randCount', DEFAULTS.randCount);
  fill('f-randSize', DEFAULTS.randSize);
  fill('f-randDelay', DEFAULTS.randDelay);
  fill('f-listen', DEFAULTS.listen);
  fill('f-socksPort', DEFAULTS.socksPort);
  fill('f-httpPort', DEFAULTS.httpPort);
  $('f-inbounds').checked = DEFAULTS.inbounds;
  $('f-quicPacket').value = '';
  newSni();
}

/** Собирает тело запроса из формы. */
function collectBody(opts) {
  var body = {
    endpoint: strOr('f-endpoint'),
    mtu: numOr('f-mtu'),
    keepAlive: numOr('f-keepAlive'),
    dns: listOr('f-dns'),
    loglevel: strOr('f-loglevel'),
    remarks: strOr('f-remarks'),
    sni: strOr('f-sni'),
    alpn: listOr('f-alpn'),
    quicSize: numOr('f-quicSize'),
    quicDelay: strOr('f-quicDelay'),
    randCount: numOr('f-randCount'),
    randSize: strOr('f-randSize'),
    randDelay: strOr('f-randDelay'),
    inbounds: $('f-inbounds').checked,
    listen: strOr('f-listen'),
    socksPort: numOr('f-socksPort'),
    httpPort: numOr('f-httpPort')
  };

  var packet = val('f-quicPacket').replace(/\s+/g, '');
  if (packet) body.quicPacket = packet;

  if (!opts.newAccount) {
    var pk = val('f-privateKey');
    var addr = listOr('f-address');
    if (pk && addr) {
      body.account = { privateKey: pk, address: addr, peerPublicKey: strOr('f-peerPublicKey') };
    }
  }
  if (opts.keepId && state.id) body.id = state.id;

  Object.keys(body).forEach(function (k) { if (body[k] === undefined) delete body[k]; });
  return body;
}

function fillFromResponse(data) {
  if (data.account) {
    fill('f-privateKey', data.account.privateKey);
    fill('f-address', data.account.address);
    fill('f-peerPublicKey', data.account.peerPublicKey);
  }
  var p = data.params || {};
  fill('f-endpoint', p.endpoint);
  fill('f-mtu', p.mtu);
  fill('f-keepAlive', p.keepAlive);
  fill('f-dns', p.dns);
  fill('f-remarks', p.remarks);
  if (p.loglevel) $('f-loglevel').value = p.loglevel;
  fill('f-sni', p.sni);
  fill('f-alpn', p.alpn);
  fill('f-quicSize', p.quicSize);
  fill('f-quicDelay', p.quicDelay);
  fill('f-randCount', p.randCount);
  fill('f-randSize', p.randSize);
  fill('f-randDelay', p.randDelay);
  fill('f-quicPacket', p.quicPacket);
  if (typeof p.inbounds === 'boolean') $('f-inbounds').checked = p.inbounds;
}

// --------------------------------------------------------------------------
// Показ результата
// --------------------------------------------------------------------------

function showResult(data) {
  state.id = data.id;
  state.url = data.url;
  state.config = data.config;

  $('out-url').textContent = data.url;
  $('out-json').textContent = JSON.stringify(data.config, null, 2);

  var enc = encodeURIComponent(data.url);
  $('app-happ').href = 'happ://add/' + data.url;
  $('app-v2raytun').href = 'v2raytun://import/' + data.url;
  $('app-v2rayng').href = 'v2rayng://install-config?name=WARP&url=' + enc;

  drawQr(data.url);
  startCountdown(data.expiresAt, data.ttl);

  $('result').hidden = false;
  $('btn-generate').textContent = 'Сгенерировать ещё одну ссылку';
  $('cta-note').textContent = 'Ссылка ниже уже готова — новая генерация её заменит.';
  state.staleShown = false;
}

// --------------------------------------------------------------------------
// Запрос
// --------------------------------------------------------------------------

function setBusy(on, what) {
  state.busy = on;
  var buttons = document.querySelectorAll('button');
  for (var i = 0; i < buttons.length; i++) buttons[i].disabled = on;
  if (on) {
    setStatus('busy', what || 'Генерирую…', null);
  }
}

function run(opts) {
  if (state.busy) return;
  opts = opts || {};
  var body = collectBody(opts);
  var willRegister = !body.account;

  setBusy(true, willRegister ? 'Регистрирую аккаунт WARP…' : 'Пересобираю конфиг…');

  var ctrl = null;
  var killer = null;
  if (typeof AbortController !== 'undefined') {
    ctrl = new AbortController();
    killer = setTimeout(function () { ctrl.abort(); }, 25000);
  }

  fetch('/api/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: ctrl ? ctrl.signal : undefined
  }).then(function (res) {
    return res.text().then(function (text) {
      var data = null;
      try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
      return { res: res, data: data, text: text };
    });
  }).then(function (r) {
    if (killer) clearTimeout(killer);
    setBusy(false);

    if (!r.res.ok || !r.data || !r.data.ok) {
      // Аккаунт мог быть создан до ошибки — сервер вернёт его, сохраним,
      // чтобы повтор не регистрировал ещё один.
      if (r.data && r.data.account) fillFromResponse({ account: r.data.account });
      if (!r.data) {
        setStatus('error', 'Сервер ответил чем-то нечитаемым (HTTP ' + r.res.status + ')',
          'Похоже на сбой хостинга или на страницу-заглушку по пути. Попробуйте ещё раз.');
        return;
      }
      var e = describeError(r.res.status, r.data);
      setStatus('error', e[0], e[1]);
      return;
    }

    fillFromResponse(r.data);
    showResult(r.data);

    if (r.data.warnings && r.data.warnings.length) {
      setStatus('warn', 'Ссылка создана, но есть замечание', r.data.warnings.join(' '));
    } else {
      clearStatus();
    }
    if (!opts.silentScroll) {
      $('result').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }).catch(function (err) {
    if (killer) clearTimeout(killer);
    setBusy(false);
    if (err && err.name === 'AbortError') {
      setStatus('error', 'Сервер не ответил за 25 секунд',
        'Регистрация в Cloudflare иногда подвисает. Попробуйте ещё раз.');
    } else {
      setStatus('error', 'Не удалось достучаться до сервера',
        'Проверьте соединение и попробуйте снова. Если страница открыта давно — обновите её.');
    }
  });
}

// --------------------------------------------------------------------------
// Привязка кнопок
// --------------------------------------------------------------------------

function markStale() {
  if (state.busy || !state.url || state.staleShown) return;
  state.staleShown = true;
  setStatus('warn', 'Настройки изменены — ссылка ниже собрана по старым',
    'Нажмите «Применить настройки» в шторке: конфиг пересоберётся на тех же кредах, регистрации не будет.');
}

function init() {
  applyDefaults();

  $('btn-generate').addEventListener('click', function () { run({}); });

  $('btn-apply').addEventListener('click', function () { run({ keepId: true }); });

  $('btn-refresh').addEventListener('click', function () {
    newSni();
    $('f-quicPacket').value = '';
    run({ newAccount: true });
  });

  $('btn-account').addEventListener('click', function () {
    $('f-quicPacket').value = '';
    run({ newAccount: true, keepId: true });
  });

  $('btn-sni').addEventListener('click', function () {
    newSni();
    $('f-quicPacket').value = '';   // пакет собран со старым SNI, он больше не годится
    markStale();
  });

  $('btn-quic').addEventListener('click', function () {
    $('f-quicPacket').value = '';
    if (state.url) run({ keepId: true }); else markStale();
  });

  $('btn-reset').addEventListener('click', function () {
    applyDefaults();
    markStale();
  });

  $('btn-copy-url').addEventListener('click', function () {
    copyButton(this, function () { return state.url || ''; }, 'Ссылка скопирована');
  });

  $('btn-copy-json').addEventListener('click', function () {
    copyButton(this, function () { return JSON.stringify(state.config, null, 2); }, 'JSON скопирован');
  });

  $('app-throne').addEventListener('click', function () {
    copyButton(this, function () { return state.url || ''; }, 'Ссылка скопирована');
  });

  $('btn-extend').addEventListener('click', function () { run({ keepId: true, silentScroll: true }); });
  $('btn-again').addEventListener('click', function () { run({ newAccount: true }); });

  // Готовый hex-пакет в поле старше, чем правка SNI/ALPN/размера, и перебил бы
  // её молча: сервер принимает присланный пакет как есть. Поэтому сбрасываем.
  ['f-sni', 'f-alpn', 'f-quicSize'].forEach(function (id) {
    $(id).addEventListener('input', function () { $('f-quicPacket').value = ''; });
  });

  var panel = document.querySelector('.panel-body');
  panel.addEventListener('input', markStale);
  panel.addEventListener('change', markStale);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
