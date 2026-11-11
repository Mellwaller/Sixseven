'use strict';
/*
 * Mell Wallet — сервер на Node.js.
 *
 * Запуск:   npm install && npm start      (по умолчанию http://localhost:3000)
 *
 * Настройки через переменные окружения:
 *   PORT, HOST           порт и хост (3000, 0.0.0.0)
 *   DATA_DIR             где хранить базу (./data)
 *   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, MAIL_FROM
 *                        почта для отправки кодов. Без SMTP_HOST код
 *                        печатается в консоль сервера (режим разработки).
 *   ADMIN_EMAIL          почта аккаунта админа. У админа больше всего Mytacoin и
 *                        чуть меньше всех остальных монет, он выдаёт крипту на любой
 *                        кошелёк. Без SMTP по умолчанию admin@mell.local (для разработки),
 *                        с SMTP админа нужно задать явно.
 *   COOKIE_SECURE=1      ставить Secure на cookie (нужно при HTTPS)
 *   TRUST_PROXY=1        брать IP из X-Forwarded-For (если сервер за прокси)
 *   SECRET               ключ для подписи кодов; если не задан, создаётся
 *                        и хранится в DATA_DIR/secret.key
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const HTML_FILE = path.join(__dirname, 'index.html');
const COOKIE_SECURE = process.env.COOKIE_SECURE === '1';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';

const CODE_TTL_MS = 10 * 60 * 1000;
const RESEND_COOLDOWN_MS = 60 * 1000;
const MAX_CODE_ATTEMPTS = 5;
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const ADDRESS_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
const PREFIXES = ['MQ', 'UQ', 'EQ'];

/* Монеты и цены в звёздах (должны совпадать с таблицей в index.html). */
const COINS = {
  fogcoin: { ticker: 'FGC', price: 35 },
  mytacoin: { ticker: 'MTC', price: 29 },
  oblacoin: { ticker: 'OBC', price: 24 },
  molcoin: { ticker: 'MLC', price: 19 },
  kotcoin: { ticker: 'KTC', price: 15 },
  dpgcoin: { ticker: 'DGC', price: 12 },
  eljcoin: { ticker: 'EJC', price: 9 },
  shlyacoin: { ticker: 'SHC', price: 7 },
  chekcoin: { ticker: 'CHC', price: 5 },
  kachestvocoin: { ticker: 'KSC', price: 3 },
  burmalcoin: { ticker: 'BLC', price: 2 },
};
const ADMIN_MTC = 1000000;   // у админа больше всего Mytacoin
const ADMIN_OTHER = 900000;  // и чуть меньше каждой из остальных монет
const ADMIN_EMAIL = normalizeEmail(process.env.ADMIN_EMAIL || '') || (process.env.SMTP_HOST ? null : 'admin@mell.local');
const ADDR_RE = /^(MQ|UQ|EQ)[A-Za-z0-9_-]{46}$/;
const MAX_AMOUNT = 1e12;

/* ---------- хранилище ---------- */

fs.mkdirSync(DATA_DIR, { recursive: true });

function loadSecret() {
  if (process.env.SECRET) return process.env.SECRET;
  const f = path.join(DATA_DIR, 'secret.key');
  try {
    return fs.readFileSync(f, 'utf8').trim();
  } catch (_) {
    const s = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(f, s, { mode: 0o600 });
    return s;
  }
}
const SECRET = loadSecret();

let db = { users: {}, sessions: {} };
try {
  db = Object.assign(db, JSON.parse(fs.readFileSync(DB_FILE, 'utf8')));
} catch (_) { /* первый запуск */ }

const addrIndex = {}; // адрес -> почта
for (const u of Object.values(db.users)) {
  u.balances = u.balances || {};
  u.history = u.history || [];
  addrIndex[u.address] = u.email;
}

function isAdmin(u) { return !!ADMIN_EMAIL && u.email === ADMIN_EMAIL; }
function seedAdmin(u) {
  if (!isAdmin(u) || u.seeded) return;
  for (const id of Object.keys(COINS)) {
    u.balances[id] = (u.balances[id] || 0) + (id === 'mytacoin' ? ADMIN_MTC : ADMIN_OTHER);
  }
  u.seeded = true;
}
function userByAddress(a) { return db.users[addrIndex[a]] || null; }
function shortAddr(a) { return a.slice(0, 6) + '…' + a.slice(-4); }
function pushHistory(u, entry) {
  u.history.unshift(Object.assign({ t: new Date().toISOString() }, entry));
  if (u.history.length > 50) u.history.length = 50;
}
function publicUser(u) {
  return { email: u.email, address: u.address, isAdmin: isAdmin(u), balances: u.balances, history: u.history.slice(0, 20) };
}
function parseAmount(v) {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 1 && v <= MAX_AMOUNT ? v : null;
}

function saveDb() {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db), { mode: 0o600 });
  fs.renameSync(tmp, DB_FILE);
}

/* ---------- почта ---------- */

let transporter = null;
if (process.env.SMTP_HOST) {
  try {
    const nodemailer = require('nodemailer');
    const port = Number(process.env.SMTP_PORT) || 587;
    transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port,
      secure: port === 465,
      auth: process.env.SMTP_USER
        ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
        : undefined,
    });
  } catch (e) {
    console.warn('[mail] SMTP_HOST задан, но nodemailer не установлен (npm install). Коды будут печататься в консоль.');
  }
}

async function sendCode(email, code) {
  if (!transporter) {
    console.log('[DEV] Код для ' + email + ': ' + code);
    return;
  }
  await transporter.sendMail({
    from: process.env.MAIL_FROM || process.env.SMTP_USER,
    to: email,
    subject: 'Mell Wallet: код подтверждения ' + code,
    text: 'Ваш код для входа в Mell Wallet: ' + code + '\nОн действует 10 минут. Если вы его не запрашивали, просто проигнорируйте письмо.',
    html:
      '<div style="font-family:Georgia,serif;max-width:420px;margin:auto;padding:24px;background:#3b2418;color:#f3e3c3;border-radius:16px">' +
      '<h2 style="margin:0 0 12px">Mell Wallet</h2>' +
      '<p style="margin:0 0 16px">Ваш код подтверждения:</p>' +
      '<p style="font:700 34px/1 monospace;letter-spacing:8px;background:#e8cf84;color:#3b2418;padding:16px;border-radius:10px;text-align:center;margin:0 0 16px">' + code + '</p>' +
      '<p style="margin:0;font-size:13px;opacity:.8">Код действует 10 минут. Если вы его не запрашивали, просто проигнорируйте письмо.</p>' +
      '</div>',
  });
}

/* ---------- коды, лимиты, сессии ---------- */

const pending = new Map(); // email -> { hash, exp, attempts, sentAt }
const hits = new Map();    // ip -> [timestamps]

function hmac(value) {
  return crypto.createHmac('sha256', SECRET).update(value).digest('hex');
}
function safeEqual(a, b) {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function rateLimited(ip, limit, windowMs) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter((t) => now - t < windowMs);
  arr.push(now);
  hits.set(ip, arr);
  return arr.length > limit;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of pending) if (v.exp < now) pending.delete(k);
  for (const [k, v] of hits) if (!v.some((t) => now - t < 600000)) hits.delete(k);
  let changed = false;
  for (const [k, s] of Object.entries(db.sessions)) {
    if (s.exp < now) { delete db.sessions[k]; changed = true; }
  }
  if (changed) saveDb();
}, 60 * 1000).unref();

function normalizeEmail(v) {
  if (typeof v !== 'string') return null;
  const e = v.trim().toLowerCase();
  if (e.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e)) return null;
  return e;
}

/* Адрес создаётся один раз при регистрации и дальше не меняется. */
function generateAddress(prefix) {
  const used = new Set(Object.values(db.users).map((u) => u.address));
  for (;;) {
    const bytes = crypto.randomBytes(46);
    let body = '';
    for (const b of bytes) body += ADDRESS_ALPHABET[b & 63];
    const addr = prefix + body;
    if (!used.has(addr)) return addr;
  }
}

function createSession(email) {
  const token = crypto.randomBytes(32).toString('base64url');
  db.sessions[hmac(token)] = { email, exp: Date.now() + SESSION_TTL_MS };
  return token;
}

function getCookie(req, name) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

function currentUser(req) {
  const token = getCookie(req, 'mw_sid');
  if (!token) return null;
  const s = db.sessions[hmac(token)];
  if (!s || s.exp < Date.now()) return null;
  return db.users[s.email] || null;
}

function cookieHeader(value, maxAge) {
  return 'mw_sid=' + value + '; HttpOnly; SameSite=Lax; Path=/; Max-Age=' + maxAge + (COOKIE_SECURE ? '; Secure' : '');
}

/* ---------- HTTP ---------- */

function clientIp(req) {
  if (TRUST_PROXY) {
    const xf = req.headers['x-forwarded-for'];
    if (xf) return String(xf).split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

function send(res, status, body, headers) {
  const isObj = typeof body === 'object';
  res.writeHead(status, Object.assign({
    'Content-Type': isObj ? 'application/json; charset=utf-8' : 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
  }, headers));
  res.end(isObj ? JSON.stringify(body) : body);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const ct = String(req.headers['content-type'] || '');
    if (!ct.startsWith('application/json')) return reject({ status: 415, error: 'Нужен JSON' });
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > 4096) { reject({ status: 413, error: 'Слишком большой запрос' }); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); }
      catch (_) { reject({ status: 400, error: 'Некорректный JSON' }); }
    });
    req.on('error', () => reject({ status: 400, error: 'Ошибка запроса' }));
  });
}

async function handleApi(req, res, url) {
  const ip = clientIp(req);

  if (req.method === 'GET' && url === '/api/me') {
    const u = currentUser(req);
    if (!u) return send(res, 401, { error: 'Не выполнен вход' });
    return send(res, 200, publicUser(u));
  }

  if (req.method === 'POST' && url === '/api/logout') {
    const token = getCookie(req, 'mw_sid');
    if (token && db.sessions[hmac(token)]) { delete db.sessions[hmac(token)]; saveDb(); }
    return send(res, 200, { ok: true }, { 'Set-Cookie': cookieHeader('', 0) });
  }

  if (req.method === 'POST' && url === '/api/register/request') {
    if (rateLimited('req:' + ip, 10, 10 * 60 * 1000)) return send(res, 429, { error: 'Слишком много попыток, попробуйте позже' });
    const body = await readJson(req);
    const email = normalizeEmail(body.email);
    if (!email) return send(res, 400, { error: 'Введите корректную почту' });

    const prev = pending.get(email);
    if (prev && Date.now() - prev.sentAt < RESEND_COOLDOWN_MS) {
      const wait = Math.ceil((RESEND_COOLDOWN_MS - (Date.now() - prev.sentAt)) / 1000);
      return send(res, 429, { error: 'Повторно отправить код можно через ' + wait + ' с', retryIn: wait });
    }
    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    pending.set(email, { hash: hmac(email + ':' + code), exp: Date.now() + CODE_TTL_MS, attempts: 0, sentAt: Date.now() });
    try {
      await sendCode(email, code);
    } catch (e) {
      pending.delete(email);
      console.error('[mail] ошибка отправки:', e && e.message);
      return send(res, 502, { error: 'Не удалось отправить письмо, попробуйте позже' });
    }
    return send(res, 200, { ok: true, cooldown: RESEND_COOLDOWN_MS / 1000 });
  }

  if (req.method === 'POST' && url === '/api/register/verify') {
    if (rateLimited('ver:' + ip, 30, 10 * 60 * 1000)) return send(res, 429, { error: 'Слишком много попыток, попробуйте позже' });
    const body = await readJson(req);
    const email = normalizeEmail(body.email);
    const code = typeof body.code === 'string' ? body.code.trim() : '';
    if (!email || !/^\d{6}$/.test(code)) return send(res, 400, { error: 'Введите шестизначный код' });

    const p = pending.get(email);
    if (!p || p.exp < Date.now()) { pending.delete(email); return send(res, 400, { error: 'Код истёк или не запрашивался. Запросите новый' }); }
    p.attempts++;
    if (!safeEqual(p.hash, hmac(email + ':' + code))) {
      if (p.attempts >= MAX_CODE_ATTEMPTS) { pending.delete(email); return send(res, 400, { error: 'Слишком много неверных попыток. Запросите новый код' }); }
      return send(res, 400, { error: 'Неверный код. Осталось попыток: ' + (MAX_CODE_ATTEMPTS - p.attempts) });
    }
    pending.delete(email);

    let isNew = false;
    let user = db.users[email];
    if (!user) {
      // Случайный кошелёк создаётся сразу при регистрации и дальше не меняется.
      const prefix = PREFIXES[crypto.randomInt(0, PREFIXES.length)];
      user = db.users[email] = { email, address: generateAddress(prefix), createdAt: new Date().toISOString(), balances: {}, history: [] };
      addrIndex[user.address] = email;
      isNew = true;
    }
    seedAdmin(user);
    const token = createSession(email);
    saveDb();
    return send(res, 200, Object.assign(publicUser(user), { isNew }),
      { 'Set-Cookie': cookieHeader(token, SESSION_TTL_MS / 1000) });
  }

  /* ---------- переводы ---------- */

  if (req.method === 'POST' && url === '/api/transfer') {
    const me = currentUser(req);
    if (!me) return send(res, 401, { error: 'Не выполнен вход' });
    if (rateLimited('tx:' + ip, 60, 60 * 1000)) return send(res, 429, { error: 'Слишком много операций, подождите минуту' });
    const b = await readJson(req);
    const amount = parseAmount(b.amount);
    const to = typeof b.to === 'string' ? b.to.trim() : '';
    if (!COINS[b.coin]) return send(res, 400, { error: 'Неизвестная монета' });
    if (!amount) return send(res, 400, { error: 'Введите целое количество монет' });
    if (!ADDR_RE.test(to)) return send(res, 400, { error: 'Некорректный адрес кошелька' });
    const rcpt = userByAddress(to);
    if (!rcpt) return send(res, 404, { error: 'Кошелёк с таким адресом не найден' });
    if (rcpt === me) return send(res, 400, { error: 'Нельзя отправить самому себе' });
    if ((me.balances[b.coin] || 0) < amount) return send(res, 400, { error: 'Недостаточно монет' });
    me.balances[b.coin] -= amount;
    rcpt.balances[b.coin] = (rcpt.balances[b.coin] || 0) + amount;
    pushHistory(me, { type: 'out', coin: b.coin, amount, peer: shortAddr(to) });
    pushHistory(rcpt, { type: 'in', coin: b.coin, amount, peer: shortAddr(me.address) });
    saveDb();
    return send(res, 200, publicUser(me));
  }

  if (req.method === 'POST' && url === '/api/exchange') {
    const me = currentUser(req);
    if (!me) return send(res, 401, { error: 'Не выполнен вход' });
    if (rateLimited('tx:' + ip, 60, 60 * 1000)) return send(res, 429, { error: 'Слишком много операций, подождите минуту' });
    const b = await readJson(req);
    const amount = parseAmount(b.amount);
    if (!COINS[b.from] || !COINS[b.to] || b.from === b.to) return send(res, 400, { error: 'Выберите две разные монеты' });
    if (!amount) return send(res, 400, { error: 'Введите целое количество монет' });
    const pf = COINS[b.from].price, pt = COINS[b.to].price;
    const got = Math.floor(amount * pf / pt);
    if (got < 1) return send(res, 400, { error: 'Слишком маленькая сумма для обмена' });
    const spent = Math.ceil(got * pt / pf); // списываем только то, что реально нужно
    if ((me.balances[b.from] || 0) < spent) return send(res, 400, { error: 'Недостаточно монет' });
    me.balances[b.from] -= spent;
    me.balances[b.to] = (me.balances[b.to] || 0) + got;
    pushHistory(me, { type: 'swap', coin: b.from, amount: spent, coin2: b.to, amount2: got });
    saveDb();
    return send(res, 200, publicUser(me));
  }

  /* Админ выдаёт крипту на любой кошелёк. */
  if (req.method === 'POST' && url === '/api/admin/issue') {
    const me = currentUser(req);
    if (!me) return send(res, 401, { error: 'Не выполнен вход' });
    if (!isAdmin(me)) return send(res, 403, { error: 'Только для админа' });
    const b = await readJson(req);
    const amount = parseAmount(b.amount);
    const to = typeof b.to === 'string' ? b.to.trim() : '';
    if (!COINS[b.coin]) return send(res, 400, { error: 'Неизвестная монета' });
    if (!amount) return send(res, 400, { error: 'Введите целое количество монет' });
    if (!ADDR_RE.test(to)) return send(res, 400, { error: 'Некорректный адрес кошелька' });
    const rcpt = userByAddress(to);
    if (!rcpt) return send(res, 404, { error: 'Кошелёк с таким адресом не найден' });
    rcpt.balances[b.coin] = (rcpt.balances[b.coin] || 0) + amount;
    pushHistory(rcpt, { type: 'issue', coin: b.coin, amount, peer: 'Админ' });
    if (rcpt !== me) pushHistory(me, { type: 'issued', coin: b.coin, amount, peer: shortAddr(to) });
    saveDb();
    return send(res, 200, publicUser(me));
  }

  return send(res, 404, { error: 'Не найдено' });
}

const server = http.createServer(async (req, res) => {
  const url = (req.url || '/').split('?')[0];
  try {
    if (url.startsWith('/api/')) return await handleApi(req, res, url);

    if (req.method === 'GET' && (url === '/' || url === '/index.html')) {
      const nonce = crypto.randomBytes(16).toString('base64');
      const html = fs.readFileSync(HTML_FILE, 'utf8').replace(/\{\{NONCE\}\}/g, nonce);
      return send(res, 200, html, {
        'Content-Security-Policy':
          "default-src 'none'; script-src 'nonce-" + nonce + "'; style-src 'nonce-" + nonce + "'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
      });
    }
    if (url === '/health') return send(res, 200, { ok: true });
    return send(res, 404, { error: 'Не найдено' });
  } catch (e) {
    if (e && e.status) return send(res, e.status, { error: e.error });
    console.error(e);
    return send(res, 500, { error: 'Внутренняя ошибка сервера' });
  }
});

server.listen(PORT, HOST, () => {
  console.log('Mell Wallet: http://localhost:' + PORT + (transporter ? '' : '  (почта не настроена: коды печатаются здесь)'));
});
