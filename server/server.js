// KeepSafe IoT server: REST API + SQLite + rule-based analysis + Telegram alerts
// Run: npm install && ADMIN_PASS=secret node server.js   (Node 18+)
const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.DEVICE_KEY || 'change-me-device-key';   // same as firmware
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin';
const TG_TOKEN = process.env.TELEGRAM_TOKEN || '';
const TG_CHAT = process.env.TELEGRAM_CHAT_ID || '';

const db = new Database(path.join(__dirname, 'keepsafe.db'));
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, card TEXT, pin TEXT, anytime INTEGER DEFAULT 0, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, locker TEXT, ts INTEGER, type TEXT, user TEXT, result TEXT, detail TEXT, level TEXT DEFAULT 'NORMAL');
CREATE TABLE IF NOT EXISTS lockers(id TEXT PRIMARY KEY, last_seen INTEGER, state TEXT, door TEXT, level TEXT);
CREATE TABLE IF NOT EXISTS commands(locker TEXT PRIMARY KEY, unlock INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v INTEGER);
INSERT OR IGNORE INTO meta VALUES('creds_version', 1);
`);
const bump = () => db.prepare("UPDATE meta SET v=v+1 WHERE k='creds_version'").run();
const now = () => Math.floor(Date.now() / 1000);

const app = express();
app.use(express.json({ limit: '1mb' }));

// ---------- Telegram ----------
const lastTg = {};
async function telegram(key, text) {
  console.log('[ALERT]', text);
  if (!TG_TOKEN || !TG_CHAT) return;
  if (lastTg[key] && Date.now() - lastTg[key] < 60000) return;   // throttle
  lastTg[key] = Date.now();
  try {
    await fetch(`https://api.telegram.org/bot${TG_TOKEN}/sendMessage`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: TG_CHAT, text })
    });
  } catch (e) { console.error('Telegram failed:', e.message); }
}

// ---------- rule-based analysis ----------
function analyze(locker, e) {
  let level = 'NORMAL', msg = null;
  const since = (s) => e.ts - s;
  if (e.type === 'tamper' && e.result === 'critical') { level = 'CRITICAL'; msg = 'Break-in: door opened while locked'; }
  else if (e.type === 'tamper') { level = 'ALERT'; msg = 'Vibration / impact detected'; }
  else if (e.type === 'door_left_open') { level = 'ALERT'; msg = 'Door left open too long'; }
  else if (e.type === 'lockout') { level = 'ALERT'; msg = 'Too many failed attempts: device locked out'; }
  else if (e.type === 'access' && e.result === 'denied') {
    const fails = db.prepare("SELECT COUNT(*) c FROM events WHERE locker=? AND type='access' AND result='denied' AND ts>=?")
      .get(locker, since(300)).c;
    level = fails >= 5 ? 'ALERT' : 'WARNING';
    msg = fails >= 3 ? `${fails} failed attempts in 5 minutes` : null;
    if (/outside allowed hours/.test(e.detail || '')) { msg = `${e.user} tried to open outside allowed hours`; }
    // auto-revoke a known user with repeated denials
    if (e.user && e.user !== 'unknown') {
      const n = db.prepare("SELECT COUNT(*) c FROM events WHERE locker=? AND user=? AND result='denied' AND ts>=?")
        .get(locker, e.user, since(600)).c;
      if (n >= 3) {
        db.prepare('UPDATE users SET active=0 WHERE name=?').run(e.user); bump();
        level = 'ALERT'; msg = `${e.user} disabled after ${n} denied attempts`;
      }
    }
  }
  if (msg && level !== 'NORMAL') telegram(`${locker}:${e.type}`, `KeepSafe ${level} [${locker}]\n${msg}`);
  return level;
}

// ---------- device endpoints (API key) ----------
const device = express.Router();
device.use((req, res, next) => req.get('x-api-key') === API_KEY ? next() : res.status(401).json({ error: 'bad key' }));

device.post('/events', (req, res) => {
  const { locker, events } = req.body || {};
  if (!locker || !Array.isArray(events)) return res.status(400).json({ error: 'bad body' });
  const ins = db.prepare('INSERT INTO events(locker,ts,type,user,result,detail,level) VALUES(?,?,?,?,?,?,?)');
  db.transaction(() => {
    for (const e of events) {
      e.ts = e.ts || now();
      const lvl = analyze(locker, e);
      ins.run(locker, e.ts, e.type, e.user || '', e.result || '', e.detail || '', lvl);
    }
  })();
  res.json({ ok: true, stored: events.length });
});

device.post('/heartbeat', (req, res) => {
  const { locker, state, door, level } = req.body || {};
  if (!locker) return res.status(400).json({ error: 'locker required' });
  db.prepare(`INSERT INTO lockers(id,last_seen,state,door,level) VALUES(?,?,?,?,?)
    ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,state=excluded.state,door=excluded.door,level=excluded.level`)
    .run(locker, now(), state, door, level);
  const cmd = db.prepare('SELECT unlock FROM commands WHERE locker=?').get(locker);
  if (cmd && cmd.unlock) db.prepare('UPDATE commands SET unlock=0 WHERE locker=?').run(locker);
  res.json({ unlock: !!(cmd && cmd.unlock), credsVersion: db.prepare("SELECT v FROM meta WHERE k='creds_version'").get().v });
});

device.get('/credentials', (req, res) => {
  const list = [];
  for (const u of db.prepare('SELECT * FROM users WHERE active=1').all()) {
    if (u.card) list.push({ t: 'card', v: u.card.toUpperCase(), u: u.name, any: u.anytime });
    if (u.pin) list.push({ t: 'pin', v: u.pin, u: u.name, any: u.anytime });
  }
  res.json({ version: db.prepare("SELECT v FROM meta WHERE k='creds_version'").get().v, creds: list });
});
app.use('/api/device', device);

// ---------- admin auth (HTTP Basic) ----------
app.use((req, res, next) => {
  const h = req.get('authorization') || '';
  const [u, p] = Buffer.from(h.split(' ')[1] || '', 'base64').toString().split(':');
  if (u === ADMIN_USER && p === ADMIN_PASS) return next();
  res.set('WWW-Authenticate', 'Basic realm="KeepSafe"').status(401).send('Login required');
});

app.get('/api/status', (req, res) => {
  const t = now();
  res.json(db.prepare('SELECT * FROM lockers').all().map(l => ({ ...l, online: t - l.last_seen < 15 })));
});

function queryEvents(q, limit) {
  const like = `%${q || ''}%`;
  return db.prepare(`SELECT * FROM events WHERE (user LIKE ? OR type LIKE ? OR result LIKE ? OR detail LIKE ? OR locker LIKE ?)
    ORDER BY ts DESC, id DESC LIMIT ?`).all(like, like, like, like, like, limit);
}
app.get('/api/events', (req, res) => res.json(queryEvents(req.query.q, Math.min(+req.query.limit || 100, 1000))));

app.get('/api/export.csv', (req, res) => {
  const rows = queryEvents(req.query.q, 100000);
  const esc = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const csv = ['time,locker,type,user,result,detail,level',
    ...rows.map(r => [new Date(r.ts * 1000).toISOString(), r.locker, r.type, r.user, r.result, r.detail, r.level].map(esc).join(','))].join('\n');
  res.set({ 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=keepsafe-access-log.csv' }).send(csv);
});

app.get('/api/users', (req, res) => res.json(db.prepare('SELECT id,name,card,anytime,active, (LENGTH(pin) > 0) AS has_pin FROM users').all()));
app.post('/api/users', (req, res) => {
  const { name, card, pin, anytime } = req.body || {};
  if (!name || (!card && !pin)) return res.status(400).json({ error: 'name and a card or PIN required' });
  db.prepare('INSERT INTO users(name,card,pin,anytime) VALUES(?,?,?,?)').run(name, (card || '').toUpperCase(), pin || '', anytime ? 1 : 0);
  bump(); res.json({ ok: true });
});
app.patch('/api/users/:id', (req, res) => { db.prepare('UPDATE users SET active=? WHERE id=?').run(req.body.active ? 1 : 0, req.params.id); bump(); res.json({ ok: true }); });
app.delete('/api/users/:id', (req, res) => { db.prepare('DELETE FROM users WHERE id=?').run(req.params.id); bump(); res.json({ ok: true }); });

app.post('/api/unlock/:locker', (req, res) => {
  db.prepare('INSERT INTO commands(locker,unlock) VALUES(?,1) ON CONFLICT(locker) DO UPDATE SET unlock=1').run(req.params.locker);
  res.json({ ok: true });
});

app.get('/api/stats', (req, res) => {
  const since = now() - 7 * 86400;
  const hours = Array(24).fill(0), days = {};
  for (const r of db.prepare("SELECT ts,result FROM events WHERE type='access' AND ts>=?").all(since)) {
    const d = new Date(r.ts * 1000);
    if (r.result === 'granted') hours[d.getHours()]++;
    else { const k = d.toISOString().slice(0, 10); days[k] = (days[k] || 0) + 1; }
  }
  res.json({ hours, failedByDay: days });
});

app.use(express.static(path.join(__dirname, 'public')));
app.listen(PORT, '0.0.0.0', () => console.log(`KeepSafe server on http://localhost:${PORT}`));