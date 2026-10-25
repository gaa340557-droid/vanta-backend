// vanta.js — Node 18+ Professional Build
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const dns = require('dns').promises;
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const winston = require('winston');
const jwt = require('jsonwebtoken');
const { WebSocketServer } = require('ws');
const http = require('http');

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 8443;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

const DATA = path.join(__dirname, 'data');
if (!fs.existsSync(DATA)) fs.mkdirSync(DATA);
const ENC_KEY = crypto.createHash('sha256').update(process.env.DATA_KEY || 'vanta-default-key-change-me').digest();

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-cbc', ENC_KEY, iv);
  return Buffer.concat([iv, c.update(text), c.final()]).toString('base64');
}
function decrypt(b64) {
  const b = Buffer.from(b64, 'base64');
  const iv = b.slice(0, 16);
  const d = crypto.createDecipheriv('aes-256-cbc', ENC_KEY, iv);
  return Buffer.concat([d.update(b.slice(16)), d.final()]).toString();
}
const load = (f, d) => {
  try {
    const raw = fs.readFileSync(path.join(DATA, f), 'utf8');
    if (f.startsWith('enc_')) return JSON.parse(decrypt(raw));
    return JSON.parse(raw);
  } catch { return d; }
};
const saveEnc = (f, o) => fs.writeFileSync(path.join(DATA, 'enc_' + f), encrypt(JSON.stringify(o)));
const save = (f, o) => fs.writeFileSync(path.join(DATA, f), JSON.stringify(o, null, 2));

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console({ format: winston.format.simple() })]
});

function audit(user, action, meta = {}) {
  const entry = { ts: new Date().toISOString(), user, action, meta };
  logger.info('AUDIT', entry);
}

function getUsers() { return load('enc_users.json', {}); }
function saveUsers(u) { saveEnc('users.json', u); }
function hashPassword(p) { return crypto.createHash('sha256').update(p + (process.env.SALT || 'vanta')).digest('hex'); }

const PLANS = { free: { scansPerMin: 10, modules: ['*'], price: 0 }, pro: { scansPerMin: 100, modules: ['*'], price: 49 } };

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email + password required' });
    const users = getUsers();
    if (users[email]) return res.status(409).json({ error: 'exists' });
    users[email] = { email, passwordHash: hashPassword(password), plan: 'free', apiKey: crypto.randomBytes(24).toString('hex'), licenseKey: 'VNT-' + crypto.randomBytes(4).toString('hex') };
    saveUsers(users);
    res.json({ ok: true, apiKey: users[email].apiKey, licenseKey: users[email].licenseKey });
  } catch (e) { res.status(500).json({ error: 'server' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const u = getUsers()[email];
    if (!u || u.passwordHash !== hashPassword(password)) return res.status(401).json({ error: 'invalid' });
    const token = jwt.sign({ email, plan: u.plan }, process.env.JWT_SECRET || 'vanta-jwt', { expiresIn: '30d' });
    res.json({ ok: true, token, apiKey: u.apiKey, plan: u.plan });
  } catch (e) { res.status(500).json({ error: 'server' }); }
});

function auth(req, res, next) {
  const key = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '');
  if (!key) return res.status(401).json({ error: 'no key' });
  const u = Object.values(getUsers()).find(x => x.apiKey === key);
  if (!u) return res.status(401).json({ error: 'bad key' });
  req.user = u;
  next();
}

const userRate = {};
const scanLimiter = (req, res, next) => {
  if (!req.user) return next();
  const now = Date.now();
  const key = req.user.email;
  if (!userRate[key]) userRate[key] = [];
  userRate[key] = userRate[key].filter(t => t > now - 60000);
  if (userRate[key].length >= 10) return res.status(429).json({ error: 'rate limit' });
  userRate[key].push(now);
  next();
};

app.use('/api/', rateLimit({ windowMs: 60000, max: 200 }));

const UA = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15'];
const rUA = () => UA[Math.floor(Math.random() * UA.length)];

async function safeFetch(url, opts = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), opts.timeout || 20000);
  const headers = { 'User-Agent': rUA(), 'Accept': '*/*', ...(opts.headers || {}) };
  try { return await fetch(url, { ...opts, headers, signal: ctrl.signal, redirect: opts.redirect || 'follow' }); }
  finally { clearTimeout(timer); }
}

async function pool(items, limit, fn) {
  const q = [...items];
  await Promise.all(Array.from({ length: limit }, async () => {
    while (q.length) { const i = q.shift(); if (i !== undefined) { try { await fn(i); } catch {} } }
  }));
}

async function dataLeaks(url) {
  const out = [];
  try {
    const r = await safeFetch(url);
    const body = await r.text();
    const pat = { aws: /AKIA[0-9A-Z]{16}/g, password: /(password|passwd|pwd)["'\s:=]+([^\s"'<>]{6,})/gi, api_key: /(api[_-]?key|apikey|secret)["'\s:=]+([A-Za-z0-9]{16,})/gi };
    for (const [n, re] of Object.entries(pat)) {
      const m = [...body.matchAll(re)];
      if (m.length) out.push({ type: `Secret: ${n}`, severity: 'high', description: `${m.length} hits`, url, evidence: m[0][0].slice(0, 80), cvss: 8.0 });
    }
    if (!out.length) out.push({ type: 'Info', severity: 'info', description: 'No secrets', url, evidence: null, cvss: 0 });
  } catch (e) { out.push({ type: 'Error', severity: 'high', description: e.message, url, evidence: null, cvss: 0 }); }
  return out;
}

async function corsCheck(url) { const out = []; try { const r = await safeFetch(url, { headers: { Origin: 'https://evil.com' } }); const a = r.headers.get('access-control-allow-origin'); if (a === '*' || a === 'https://evil.com') out.push({ type: 'CORS', severity: 'medium', description: `ACAO: ${a}`, url, evidence: a, cvss: 5.0 }); if (!out.length) out.push({ type: 'Info', severity: 'info', description: 'CORS secure', url, evidence: null, cvss: 0 }); } catch {} return out; }

async function portScan(url) { const out = []; const ports = [21, 22, 80, 443, 3306, 3389, 8080, 8443]; const u = new URL(url); await Promise.all(ports.map(async p => { try { const r = await safeFetch(`${u.protocol}//${u.hostname}:${p}`, { timeout: 3000 }); if (r.status < 500) out.push({ type: 'Open Port', severity: 'medium', description: `Port ${p}`, url: `${u.protocol}//${u.hostname}:${p}`, evidence: `HTTP ${r.status}`, cvss: 5.0 }); } catch {} })); if (!out.length) out.push({ type: 'Info', severity: 'info', description: 'No open ports', url, evidence: null, cvss: 0 }); return out; }

async function scanSensitive(url) { 
  const out = []; 
  const base = new URL(url).origin; 
  const S = ['.env', '.git/config', 'config.php', 'wp-config.php', 'backup.sql', 'id_rsa', '.aws/credentials', 'swagger.json']; 
  await pool(S, 10, async f => { 
    try { 
      const r = await safeFetch(`${base}/${f}`, { redirect: 'manual' }); 
      if (r.status === 200) { 
        const t = await r.text(); 
        if (t.length > 10) { 
          out.push({ type: 'Sensitive File', severity: 'critical', description: f, url: `${base}/${f}`, evidence: '200 OK', cvss: 9.8 }); 
        } 
      } 
    } catch {} 
  }); 
  if (!out.length) out.push({ type: 'Info', severity: 'info', description: 'No sensitive files', url, evidence: null, cvss: 0 }); 
  return out; 
}

async function adminPanels(url) { const out = []; const base = new URL(url).origin; const P = ['admin', 'login', 'wp-admin']; await pool(P, 5, async p => { try { const r = await safeFetch(`${base}/${p}`, { redirect: 'manual' }); if (r.status === 200) { const t = (await r.text()).toLowerCase(); if (t.includes('login') || t.includes('password')) out.push({ type: 'Admin Panel', severity: 'medium', description: `/${p}`, url: `${base}/${p}`, evidence: 'Login form', cvss: 5.3 }); } } catch {} }); if (!out.length) out.push({ type: 'Info', severity: 'info', description: 'No admin panels', url, evidence: null, cvss: 0 }); return out; }

app.post('/api/scan', auth, scanLimiter, async (req, res) => {
  try {
    const { target, checks } = req.body || {};
    if (!target) return res.status(400).json({ error: 'target required' });
    let url = target.startsWith('http') ? target : 'https://' + target;
    const type = (checks && checks[0]) || 'scanAll';
    let findings = [];
    if (type === 'vulnerabilities' || type === 'scanAll') findings = findings.concat(await dataLeaks(url), await corsCheck(url));
    if (type === 'sensitiveFiles' || type === 'scanAll') findings = findings.concat(await scanSensitive(url));
    if (type === 'adminPanels' || type === 'scanAll') findings = findings.concat(await adminPanels(url));
    if (type === 'cors' || type === 'scanAll') findings = findings.concat(await corsCheck(url));
    if (type === 'ports' || type === 'scanAll') findings = findings.concat(await portScan(url));
    const seen = new Set();
    findings = findings.filter(f => { const k = `${f.type}|${f.url}|${f.description}`; if (seen.has(k)) return false; seen.add(k); return true; });
    res.json({ target: url, timestamp: new Date().toISOString(), findings });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/loot', auth, (req, res) => res.json(load('enc_loot.json', {})));
app.post('/api/loot', (req, res) => { const { botId, category, data } = req.body || {}; const l = load('enc_loot.json', {}); if (!l[botId]) l[botId] = { categories: {} }; if (!l[botId].categories[category]) l[botId].categories[category] = []; l[botId].categories[category].push({ ts: Date.now(), ...data }); saveEnc('loot.json', l); res.json({ ok: true }); });

app.get('/health', (req, res) => res.json({ ok: true, ts: Date.now(), version: 'v2.3.1' }));

if (require.main === module) {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`[vanta] listening on :${PORT}`);
  });
}
module.exports = { app, server };
