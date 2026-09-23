/**
 * GET /sub/<id> — одноразовая подписка. Отдаёт МАССИВ полных конфигов Xray.
 *
 * В каждом элементе обязаны быть remarks, inbounds, outbounds и routing:
 * без routing v2rayNG не опознаёт подписку вообще.
 */

import { get, isValidId } from '../../lib/store.js';
import { detectClient, pickFormat, subscriptionHeaders, unsupportedText } from '../../lib/subscription.js';

const NOT_FOUND = [
  'Ссылка не найдена или уже истекла.',
  '',
  'Конфиг живёт 5 минут с момента генерации — это одноразовый канал доставки,',
  'а не постоянная подписка. Сгенерируйте новый на главной странице.',
].join('\n');

export default async function handler(req, res) {
  const id = req.query?.id;
  const ua = req.headers['user-agent'] || '';
  const kind = detectClient(ua);
  const format = pickFormat(ua);

  if (!isValidId(id)) {
    res.setHeader('content-type', 'text/plain; charset=utf-8');
    return res.status(404).send(NOT_FOUND);
  }

  let record;
  try {
    record = await get(id);
  } catch (err) {
    res.setHeader('content-type', 'text/plain; charset=utf-8');
    return res.status(503).send(`Хранилище недоступно: ${err.message}`);
  }
  if (!record || !record.config) {
    res.setHeader('content-type', 'text/plain; charset=utf-8');
    return res.status(404).send(NOT_FOUND);
  }

  // sing-box и clash: честный отказ вместо молча деградированного конфига.
  if (format === 'unsupported') {
    res.setHeader('content-type', 'text/plain; charset=utf-8');
    return res.status(200).send(unsupportedText(kind));
  }

  const name = record.remarks || 'WARP';
  const left = Math.max(0, Math.round(((record.expiresAt || 0) - Date.now()) / 1000));

  if (format === 'browser') {
    res.setHeader('content-type', 'text/plain; charset=utf-8');
    return res.status(200).send([
      `Подписка ${id}. Осталось ${left} с.`,
      '',
      'Это ссылка для клиента, а не для браузера: вставьте её в v2rayNG, Happ,',
      'v2rayTun, Throne, Streisand или v2rayN как подписку.',
      '',
      'Ниже — тот же конфиг целиком, если хотите импортировать его вручную:',
      '',
      JSON.stringify(record.config, null, 2),
    ].join('\n'));
  }

  for (const [k, v] of Object.entries(subscriptionHeaders(name))) res.setHeader(k, v);
  return res.status(200).send(JSON.stringify([record.config]));
}
