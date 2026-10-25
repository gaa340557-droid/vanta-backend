const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const { phone } = require('phone');

const app = express();
const PORT = process.env.PORT || 8443;

app.use(cors());
app.use(express.json({ limit: '100mb' }));

const DATA = path.join(__dirname, 'data');
if (!fs.existsSync(DATA)) fs.mkdirSync(DATA);
const load = (f, d) => { try { return JSON.parse(fs.readFileSync(path.join(DATA, f), 'utf8')); } catch { return d; } };
const save = (f, o) => fs.writeFileSync(path.join(DATA, f), JSON.stringify(o, null, 2));

// ============================================================
// 1. AUTH SYSTEM
// ============================================================
function getUsers() { return load('users.json', {}); }
function hashPassword(p) { return crypto.createHash('sha256').update(p + 'vanta').digest('hex'); }

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email/password required' });
    const users = getUsers();
    if (users[email]) return res.status(409).json({ error: 'exists' });
    users[email] = { email, passwordHash: hashPassword(password), apiKey: crypto.randomBytes(24).toString('hex') };
    save('users.json', users);
    res.json({ ok: true, apiKey: users[email].apiKey });
  } catch (e) { res.status(500).json({ error: 'server' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const u = getUsers()[email];
    if (!u || u.passwordHash !== hashPassword(password)) return res.status(401).json({ error: 'invalid' });
    res.json({ ok: true, apiKey: u.apiKey });
  } catch (e) { res.status(500).json({ error: 'server' }); }
});

function auth(req, res, next) {
  const key = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '');
  if (!key) return res.status(401).json({ error: 'Missing API Key' });
  const u = Object.values(getUsers()).find(x => x.apiKey === key);
  if (!u) return res.status(401).json({ error: 'Invalid API Key. Server may have restarted.' });
  req.user = u;
  next();
}

// ============================================================
// 2. CORE SCANNERS & CVE DB
// ============================================================
const UA = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'];
const rUA = () => UA[Math.floor(Math.random() * UA.length)];

async function safeFetch(url, opts = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), opts.timeout || 15000);
  try { return await fetch(url, { ...opts, headers: { 'User-Agent': rUA(), ...(opts.headers || {}) }, signal: ctrl.signal }); }
  finally { clearTimeout(timer); }
}

async function pool(items, limit, fn) {
  const q = [...items];
  await Promise.all(Array.from({ length: limit }, async () => {
    while (q.length) { const i = q.shift(); if (i !== undefined) { try { await fn(i); } catch {} } }
  }));
}

const CVE_DB = [
  { match: /Apache\/2\.4\.49/i, cve: 'CVE-2021-41773', cvss: 7.5, desc: 'Path traversal RCE' },
  { match: /Log4j/i, cve: 'CVE-2021-44228', cvss: 10.0, desc: 'Log4Shell RCE' },
  { match: /Spring/i, cve: 'CVE-2022-22965', cvss: 9.8, desc: 'Spring4Shell RCE' },
  { match: /nginx\/1\.1[0-6]\.\d+/i, cve: 'CVE-2019-20372', cvss: 6.5, desc: 'nginx request smuggling' },
  { match: /Jenkins/i, cve: 'CVE-2024-23897', cvss: 9.8, desc: 'Jenkins CLI RCE' },
  { match: /WordPress\/[4-5]\./i, cve: 'CVE-2023-2745', cvss: 9.8, desc: 'WP core dir traversal' },
  { match: /Tomcat\/9\./i, cve: 'CVE-2020-1938', cvss: 9.8, desc: 'Ghostcat AJP RCE' },
  { match: /Drupal\/[78]\./i, cve: 'CVE-2018-7600', cvss: 9.8, desc: 'Drupalgeddon2' },
  { match: /Confluence/i, cve: 'CVE-2023-22515', cvss: 10.0, desc: 'Confluence auth bypass' },
  { match: /Exchange/i, cve: 'CVE-2023-23397', cvss: 9.8, desc: 'Exchange NTLM leak' }
];

async function cveMatch(url) {
  const out = [];
  try {
    const r = await safeFetch(url);
    const headers = {}; r.headers.forEach((v, k) => headers[k] = v);
    const html = (await r.text()).slice(0, 5000);
    const fp = `${headers.server || ''} ${headers['x-powered-by'] || ''} ${html}`;
    for (const c of CVE_DB) {
      if (c.match.test(fp)) out.push({ type: 'CVE', severity: c.cvss >= 9 ? 'critical' : 'high', description: `${c.cve}: ${c.desc}`, url, evidence: headers.server || 'body fingerprint', cvss: c.cvss });
    }
  } catch {}
  return out;
}

async function dataLeaks(url) {
  const out = [];
  try {
    const r = await safeFetch(url); const body = await r.text();
    const pat = { password: /(password|passwd|pwd)["'\s:=]+([^\s"'<>]{6,})/gi };
    for (const [n, re] of Object.entries(pat)) {
      const m = [...body.matchAll(re)];
      if (m.length) out.push({ type: `Secret: ${n}`, severity: 'high', description: `${m.length} hits`, url, evidence: m[0][0].slice(0, 40), cvss: 8.0 });
    }
  } catch {}
  return out;
}

async function scanSensitive(url) {
  const out = []; const base = new URL(url).origin;
  const S = ['.env', '.git/config', 'backup.sql', 'id_rsa', '.aws/credentials', 'phpinfo.php'];
  await pool(S, 10, async f => {
    try { const r = await safeFetch(`${base}/${f}`, { redirect: 'manual', timeout: 3000 }); if (r.status === 200) out.push({ type: 'Sensitive File', severity: 'critical', description: f, url: `${base}/${f}`, evidence: '200 OK', cvss: 9.8 }); } catch {}
  });
  return out;
}

app.post('/api/scan', auth, async (req, res) => {
  try {
    const { target, checks } = req.body;
    let url = target.startsWith('http') ? target : 'https://' + target;
    const type = checks?.[0] || 'scanAll';
    let findings = [];
    
    if (type === 'vulnerabilities' || type === 'scanAll') findings = findings.concat(await dataLeaks(url));
    if (type === 'sensitiveFiles' || type === 'scanAll') findings = findings.concat(await scanSensitive(url));
    if (type === 'cve' || type === 'scanAll') findings = findings.concat(await cveMatch(url));

    const seen = new Set();
    findings = findings.filter(f => { const k = `${f.type}|${f.url}|${f.description}`; if (seen.has(k)) return false; seen.add(k); return true; });
    res.json({ target: url, findings });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================
// 3. PHONE OSINT MODULE
// ============================================================
// ============================================================
// 3. PHONE OSINT MODULE (Real lookup)
// ============================================================
const { parsePhoneNumberFromString } = require('libphonenumber-js');

app.post('/api/osint/phone', auth, async (req, res) => {
  try {
    const { number } = req.body;
    if (!number) return res.status(400).json({ error: 'Phone number required' });
    
    // Clean the number (keep + and numbers only)
    let clean = number.replace(/[^\d+]/g, '');
    if (!clean.startsWith('+')) {
        if (clean.startsWith('00')) clean = '+' + clean.slice(2);
        else if (clean.startsWith('0')) clean = '+970' + clean.slice(1); // Default to PS if no code
        else clean = '+' + clean;
    }

    const phoneNumber = parsePhoneNumberFromString(clean);
    
    if (!phoneNumber || !phoneNumber.isValid()) {
        return res.json({
            query: number,
            clean: clean,
            valid: false,
            error: 'Invalid phone number format.'
        });
    }

    let countryName = phoneNumber.country;
    // Convert country code (PS) to full name
    const regionNames = new Intl.DisplayNames(['en'], { type: 'region' });
    if (countryName) countryName = regionNames.of(countryName);

    res.json({
      query: number,
      clean: phoneNumber.number,
      valid: true,
      country: countryName || 'Unknown',
      iso: phoneNumber.country || 'Unknown',
      carrier: phoneNumber.carrier || 'Unknown (Requires paid API)',
      lineType: phoneNumber.getType() || 'Unknown', // mobile, fixed_line, etc.
      formatNational: phoneNumber.formatNational(),
      formatInternational: phoneNumber.formatInternational(),
      socialLinks: {
        whatsapp: `https://wa.me/${phoneNumber.number.replace('+', '')}`,
        telegram: `https://t.me/+${phoneNumber.number.replace('+', '')}`
      }
    });
  } catch (e) { 
    res.status(500).json({ error: 'Server error parsing number: ' + e.message }); 
  }
});

// ============================================================
// 4. STUBS FOR OTHER TOOLS
// ============================================================
app.post('/api/api/reverse', auth, (req, res) => res.json({ status: 'OK' }));
app.post('/api/fuzz', auth, (req, res) => res.json({ anomalies: [], exploits: [] }));
app.post('/api/android/bind', auth, (req, res) => res.json({ downloadUrl: 'https://example.com/apk' }));
app.post('/api/android/payload', auth, (req, res) => res.json({ payload: 'msfvenom...' }));
app.post('/api/c2/cmd', auth, (req, res) => res.json({ ok: true }));
app.post('/api/phish/clone', auth, (req, res) => res.json({ html: '...' }));
app.post('/api/jwt/attack', auth, (req, res) => res.json({ attacks: [] }));
app.post('/api/jwt/crack', auth, (req, res) => res.json({ cracked: null }));
app.post('/api/graphql/scan', auth, (req, res) => res.json({ introspection: false }));
app.post('/api/revshell', auth, (req, res) => res.json({ payloads: {} }));
app.post('/api/ddos/launch', auth, (req, res) => res.json({ ok: true }));

app.get('/health', (req, res) => res.json({ ok: true, version: 'v2.5.0' }));
app.listen(PORT, '0.0.0.0', () => console.log(`[vanta] :${PORT}`));
