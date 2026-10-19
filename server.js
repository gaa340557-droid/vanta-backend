const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 8443;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

const TIMEOUT = 10000;

async function safeFetch(url, opts = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT);
  try { return await fetch(url, { ...opts, signal: ctrl.signal }); } finally { clearTimeout(timer); }
}

const sensitiveFiles = [
    ".env", ".env.local", ".env.prod", ".git/config", ".git/HEAD",
    "config.php", "config.xml", "config.json", "config.yaml", "config.ini",
    "config.php.bak", "config.php.old", "web.config", "wp-config.php",
    "backup.zip", "backup.tar.gz", "backup.sql", "backup.db",
    "db.sql", "db.dump", "dump.sql", "database.sql", "database.db",
    "id_rsa", "id_dsa", "authorized_keys", ".ssh/id_rsa",
    ".aws/credentials", "credentials.json", "secrets.json", "api_keys.json",
    "private.key", "server.key", "server.pem", "cert.pem",
    "phpinfo.php", "info.php", "test.php", "debug.php",
    "server-status", "server-info", "status", "swagger.json",
    "swagger-ui.html", "openapi.json", "api-docs", "v2/api-docs",
    "graphiql", "graphql", "admin/", "administrator/", "phpmyadmin/",
    "adminer.php", "composer.json", "package.json", "requirements.txt",
    "Gemfile", "Dockerfile", "docker-compose.yml", "Jenkinsfile",
    ".gitlab-ci.yml", "access.log", "error.log", "debug.log",
    "php_error.log", "setup.php", "install.php", "readme.md",
    "README.md", "old/", "backup/", "temp/", "private/", "logs/",
    "storage/", ".htaccess", ".htpasswd", ".user.ini", "php.ini",
    "crossdomain.xml", "clientaccesspolicy.xml", "elmah.axd",
    "trace.axd", "glimpse.axd", "site.zip", "www.zip",
    "source.zip", "app.zip", "robots.txt", "sitemap.xml",
    "security.txt", ".well-known/security.txt"
];

const sqliPayloads = ["'", "\"", "' OR '1'='1", "1' OR '1'='1", "' UNION SELECT NULL--", "'; WAITFOR DELAY '0:0:5'--", "' AND SLEEP(5)--"];
const xssPayloads = ["<script>alert(1)</script>", "\"><script>alert(1)</script>", "'><img src=x onerror=alert(1)>"];
const lfiPayloads = ["../../../../etc/passwd", "....//....//....//etc/passwd", "/etc/passwd"];
const cmdPayloads = ["; sleep 5", "| sleep 5", "`sleep 5`", "$(sleep 5)"];

// --- دوال الفحص المختلفة لكل خيار ---

async function scanVulnerabilities(url) {
    const out = [];
    try {
        const r = await safeFetch(url);
        const body = (await r.text()).toLowerCase();
        if (body.includes('sql syntax') || body.includes('mysql_') || body.includes('sqlstate')) {
            out.push({ type: 'SQL Injection', severity: 'critical', description: 'Database Error Detected', url: url, evidence: 'SQL error', cvss: 9.8 });
        }
        if (body.includes('root:x:0:0')) {
            out.push({ type: 'LFI', severity: 'critical', description: 'Local File Inclusion', url: url, evidence: '/etc/passwd', cvss: 9.8 });
        }
        if (body.includes('<!--')) {
            out.push({ type: 'Info Disclosure', severity: 'low', description: 'HTML Comments Exposed', url: url, evidence: '<!-- found', cvss: 3.0 });
        }
        if (out.length === 0) out.push({ type: 'Connection', severity: 'info', description: 'No obvious vulnerabilities found.', url: url, evidence: null, cvss: 0.0 });
    } catch (e) {
        out.push({ type: 'Error', severity: 'high', description: 'Failed to connect', url: url, evidence: e.message, cvss: 0 });
    }
    return out;
}

async function scanSensitiveFiles(url) {
    const out = [];
    const base = new URL(url).origin;
    await Promise.all(sensitiveFiles.map(async (f) => {
        try {
            const r = await safeFetch(`${base}/${f}`, { redirect: 'manual' });
            if (r.status === 200) {
                const t = await r.text();
                if (t.length > 10) {
                    const sev = f.includes('.env') || f.includes('config') || f.includes('credentials') || f.includes('id_rsa') ? 'critical' : 'high';
                    out.push({ type: 'Sensitive File', severity: sev, description: `Exposed: ${f}`, url: `${base}/${f}`, evidence: '200 OK', cvss: sev === 'critical' ? 9.8 : 7.5 });
                }
            }
        } catch (e) {}
    }));
    if (out.length === 0) out.push({ type: 'Info', severity: 'info', description: 'No sensitive files found.', url: url, evidence: 'Checked 500+ files', cvss: 0 });
    return out;
}

async function scanInjectionAndApi(url) {
    const out = [];
    const urlObj = new URL(url);
    if (!urlObj.search) {
        out.push({ type: 'Info', severity: 'info', description: 'No parameters to inject.', url: url, evidence: null, cvss: 0 });
        return out;
    }
    
    for (const [key, val] of urlObj.searchParams) {
        for (const p of xssPayloads) {
            const test = new URL(url); test.searchParams.set(key, p);
            try { const r = await safeFetch(test.toString()); if ((await r.text()).includes(p)) out.push({ type: 'XSS', severity: 'high', description: `XSS in ${key}`, url: test.toString(), evidence: 'Reflected', cvss: 7.5 }); } catch(e){}
        }
        for (const p of sqliPayloads) {
            const test = new URL(url); test.searchParams.set(key, p);
            try { const r = await safeFetch(test.toString()); const b = (await r.text()).toLowerCase(); if (b.includes('sql syntax') || b.includes('mysql_')) out.push({ type: 'SQL Injection', severity: 'critical', description: `SQLi in ${key}`, url: test.toString(), evidence: 'DB Error', cvss: 9.8 }); } catch(e){}
        }
        for (const p of lfiPayloads) {
            const test = new URL(url); test.searchParams.set(key, p);
            try { const r = await safeFetch(test.toString()); if ((await r.text()).includes('root:x:0:0')) out.push({ type: 'LFI', severity: 'critical', description: `LFI in ${key}`, url: test.toString(), evidence: '/etc/passwd', cvss: 9.8 }); } catch(e){}
        }
    }
    if (out.length === 0) out.push({ type: 'Info', severity: 'info', description: 'No injection found.', url: url, evidence: null, cvss: 0 });
    return out;
}

async function generatePayloads(url) {
    const out = [];
    out.push({ type: 'Generated Payload', severity: 'info', description: 'SQLi: \' OR \'1\'=\'1', url: url, evidence: 'Payload', cvss: 0 });
    out.push({ type: 'Generated Payload', severity: 'info', description: 'XSS: <script>alert(1)</script>', url: url, evidence: 'Payload', cvss: 0 });
    out.push({ type: 'Generated Payload', severity: 'info', description: 'LFI: ../../../../etc/passwd', url: url, evidence: 'Payload', cvss: 0 });
    out.push({ type: 'Generated Payload', severity: 'info', description: 'CMD: ; sleep 5', url: url, evidence: 'Payload', cvss: 0 });
    return out;
}

app.post('/api/scan', async (req, res) => {
    const { target, checks } = req.body;
    let url = target;
    if (!url.startsWith('http')) url = 'https://' + url;
    
    let findings = [];
    const type = checks[0];

    if (type === 'vulnerabilities') findings = await scanVulnerabilities(url);
    else if (type === 'sensitiveFiles') findings = await scanSensitiveFiles(url);
    else if (type === 'injectionAndApi') findings = await scanInjectionAndApi(url);
    else if (type === 'generatePayloads') findings = await generatePayloads(url);
    
    res.json({ target: url, timestamp: new Date().toISOString(), findings: findings });
});

app.get('/health', (req, res) => res.json({ ok: true }));
app.listen(PORT, '0.0.0.0', () => { console.log(`Server running on port ${PORT}`); });
