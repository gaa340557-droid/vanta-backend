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

// ============================================================
// 1. قائمة ضخمة بالملفات الحساسة (1000+)
// ============================================================
const sensitiveFiles = [
    ".env", ".env.local", ".env.prod", ".env.backup", ".git/config", ".git/HEAD",
    "config.php", "config.xml", "config.json", "config.yaml", "config.ini",
    "config.php.bak", "config.php.old", "config.php~", "web.config",
    "wp-config.php", "wp-config.php.bak", "wp-login.php", "xmlrpc.php",
    "backup.zip", "backup.tar.gz", "backup.sql", "backup.db",
    "db.sql", "db.dump", "dump.sql", "database.sql", "database.db",
    "id_rsa", "id_dsa", "authorized_keys", ".ssh/id_rsa",
    ".aws/credentials", "credentials.json", "secrets.json", "api_keys.json",
    "private.key", "server.key", "server.pem", "cert.pem",
    "phpinfo.php", "info.php", "test.php", "debug.php",
    "server-status", "server-info", "nginx_status", "status",
    "swagger.json", "swagger-ui.html", "openapi.json", "api-docs",
    "v2/api-docs", "v3/api-docs", "graphiql", "graphql",
    "admin/", "administrator/", "phpmyadmin/", "adminer.php",
    "composer.json", "package.json", "requirements.txt", "Gemfile",
    "Dockerfile", "docker-compose.yml", "Jenkinsfile", ".gitlab-ci.yml",
    "access.log", "error.log", "debug.log", "php_error.log",
    "setup.php", "install.php", "readme.md", "README.md",
    "old/", "backup/", "temp/", "private/", "logs/", "storage/",
    ".htaccess", ".htpasswd", ".user.ini", "php.ini",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "elmah.axd", "trace.axd", "glimpse.axd",
    "site.zip", "www.zip", "source.zip", "app.zip",
    "robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt",
    "info.php", "php.php", "admin.php", "login.php", "upload.php",
    "backup/", "backups/", "db/", "database/", "sql/", "test/",
    "dev/", "development/", "staging/", "stage/", "prod/",
    "old/", "new/", "temp/", "tmp/", "cache/", "logs/", "log/",
    "api/", "v1/", "v2/", "v3/", "rest/", "services/",
    "internal/", "private/", "secret/", "hidden/", "conf/",
    "config/", "settings/", "setup/", "install/", "migration/",
    "dump/", "export/", "backup.sql.gz", "backup.tar.gz",
    "data.json", "data.xml", "data.csv", "data.yml", "data.yaml",
    "users.json", "users.xml", "users.csv", "users.sql",
    "passwords.txt", "passwords.json", "passwords.csv",
    "secrets.txt", "secrets.yaml", "secrets.yml", "secrets.env",
    "keys.txt", "keys.json", "keys.pem", "keys.key",
    "token.txt", "token.json", "tokens.csv",
    "credentials.txt", "credentials.csv", "credentials.yaml",
    "auth.json", "auth.xml", "auth.yml", "auth.yaml",
    "accounts.json", "accounts.xml", "accounts.csv",
    "admin.json", "admin.xml", "admin.yml", "admin.yaml",
    "wp-config.php~", "wp-config.php.old", "wp-config.php.save",
    "configuration.php", "configuration.php.bak",
    "settings.py", "settings.py.bak", "settings.py.old",
    "app.py", "app.py.bak", "app.py.old",
    "manage.py", "manage.py.bak", "manage.py.old",
    "package.json.bak", "package.json.old",
    "composer.json.bak", "composer.json.old",
    "Gemfile.bak", "Gemfile.old",
    "Dockerfile.bak", "Dockerfile.old",
    "docker-compose.yml.bak", "docker-compose.yml.old",
    "Jenkinsfile.bak", "Jenkinsfile.old",
    ".gitlab-ci.yml.bak", ".gitlab-ci.yml.old",
    "php.ini.bak", "php.ini.old", "php.ini~",
    "web.config.bak", "web.config.old", "web.config~",
    ".htaccess.bak", ".htaccess.old", ".htaccess~",
    ".htpasswd.bak", ".htpasswd.old", ".htpasswd~",
    "robots.txt.bak", "robots.txt.old", "robots.txt~",
    "sitemap.xml.bak", "sitemap.xml.old", "sitemap.xml~",
    "security.txt.bak", "security.txt.old", "security.txt~",
    ".svn/entries", ".hg/hgrc", ".bzr/branch-format",
    "backup.tar", "backup.rar", "backup.7z", "site.tar.gz", "www.tar.gz",
    "public_html.zip", "html.zip", "webroot.zip", "mysql.sql", "postgres.sql",
    "mssql.sql", "oracle.dmp", "firebird.fdb", "sqlite.db", "sqlite3.db",
    "data.sqlite", "test.db", "main.db", "access.mdb", "db.accdb",
    "redis.conf", "mongod.conf", "my.cnf", "pg_hba.conf",
    "elasticsearch.yml", "kibana.yml", "logstash.conf",
    "actuator/health", "actuator/env", "actuator/beans", "actuator/dump",
    "actuator/trace", "actuator/heapdump", "actuator/threaddump",
    "prometheus", "metrics", "healthz", "livez", "readyz",
    "debug/vars", "debug/pprof", "debug/pprof/heap",
    "graphiql", "altair", "playground", "redoc",
    "swagger-resources", "api/swagger.json", "api/openapi.json",
    "console", "_console", "manager/html", "host-manager/html",
    "jmx-console", "web-console", "admin-console"
];

// ============================================================
// 2. بايلودز حقيقية (XSS, SQLi, LFI, CMD, SSRF, SSTI)
// ============================================================
const payloads = {
    xss: ["<script>alert(1)</script>", "\"><script>alert(1)</script>", "'><img src=x onerror=alert(1)>", "javascript:alert(1)", "<svg/onload=alert(1)>", "<iframe src=javascript:alert(1)>"],
    sqli: ["'", "\"", "' OR '1'='1", "1' OR '1'='1", "' UNION SELECT NULL--", "'; WAITFOR DELAY '0:0:5'--", "' AND SLEEP(5)--", "') OR ('1'='1"],
    lfi: ["../../../../etc/passwd", "....//....//....//etc/passwd", "/etc/passwd", "..\\..\\..\\..\\windows\\win.ini"],
    cmd: ["; sleep 5", "| sleep 5", "`sleep 5`", "$(sleep 5)"],
    ssrf: ["http://127.0.0.1:80", "http://169.254.169.254/latest/meta-data/", "http://localhost:8080"],
    ssti: ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"]
};

// ============================================================
// 3. دوال الفحص
// ============================================================

// الثغرات العامة
async function scanVulnerabilities(url) {
    const out = [];
    try {
        const r = await safeFetch(url);
        const body = (await r.text()).toLowerCase();
        if (body.includes('sql syntax') || body.includes('mysql_') || body.includes('sqlstate')) out.push({ type: 'SQL Injection', severity: 'critical', description: 'Database Error Detected', url: url, evidence: 'SQL error', cvss: 9.8 });
        if (body.includes('root:x:0:0')) out.push({ type: 'LFI', severity: 'critical', description: 'Local File Inclusion', url: url, evidence: '/etc/passwd', cvss: 9.8 });
        if (body.includes('<!--')) out.push({ type: 'Info Disclosure', severity: 'low', description: 'HTML Comments Exposed', url: url, evidence: '<!--', cvss: 3.0 });
        
        if (out.length === 0) out.push({ type: 'Connection', severity: 'info', description: 'No obvious vulnerabilities found.', url: url, evidence: null, cvss: 0.0 });
    } catch (e) {
        out.push({ type: 'Error', severity: 'high', description: 'Failed to connect', url: url, evidence: e.message, cvss: 0 });
    }
    return out;
}

// الملفات الحساسة (1000+)
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
    if (out.length === 0) out.push({ type: 'Info', severity: 'info', description: 'No sensitive files found.', url: url, evidence: null, cvss: 0 });
    return out;
}

// الحقن والـ API
async function scanInjectionAndApi(url) {
    const out = [];
    const urlObj = new URL(url);
    if (!urlObj.search) {
        out.push({ type: 'Info', severity: 'info', description: 'No parameters to inject.', url: url, evidence: null, cvss: 0 });
        return out;
    }

    for (const [key, val] of urlObj.searchParams) {
        for (const p of payloads.xss) {
            const test = new URL(url); test.searchParams.set(key, p);
            try { const r = await safeFetch(test.toString()); if ((await r.text()).includes(p)) out.push({ type: 'XSS', severity: 'high', description: `XSS in ${key}`, url: test.toString(), evidence: p, cvss: 7.5 }); } catch(e){}
        }
        for (const p of payloads.sqli) {
            const test = new URL(url); test.searchParams.set(key, p);
            try { const r = await safeFetch(test.toString()); const b = (await r.text()).toLowerCase(); if (b.includes('sql syntax') || b.includes('mysql_')) out.push({ type: 'SQL Injection', severity: 'critical', description: `SQLi in ${key}`, url: test.toString(), evidence: p, cvss: 9.8 }); } catch(e){}
        }
        for (const p of payloads.lfi) {
            const test = new URL(url); test.searchParams.set(key, p);
            try { const r = await safeFetch(test.toString()); if ((await r.text()).includes('root:x:0:0')) out.push({ type: 'LFI', severity: 'critical', description: `LFI in ${key}`, url: test.toString(), evidence: p, cvss: 9.8 }); } catch(e){}
        }
        for (const p of payloads.cmd) {
            const test = new URL(url); test.searchParams.set(key, p);
            const start = Date.now();
            try { await safeFetch(test.toString()); if (Date.now() - start > 4500) out.push({ type: 'Command Injection', severity: 'critical', description: `CMDi in ${key}`, url: test.toString(), evidence: p, cvss: 9.8 }); } catch(e){}
        }
        for (const p of payloads.ssrf) {
            const test = new URL(url); test.searchParams.set(key, p);
            try { const r = await safeFetch(test.toString()); const b = await r.text(); if (b.includes('meta-data') || b.includes('localhost')) out.push({ type: 'SSRF', severity: 'high', description: `SSRF in ${key}`, url: test.toString(), evidence: p, cvss: 8.0 }); } catch(e){}
        }
        for (const p of payloads.ssti) {
            const test = new URL(url); test.searchParams.set(key, p);
            try { const r = await safeFetch(test.toString()); const b = await r.text(); if (b.includes('49') && !b.includes('{{7*7}}')) out.push({ type: 'SSTI', severity: 'critical', description: `SSTI in ${key}`, url: test.toString(), evidence: p, cvss: 9.8 }); } catch(e){}
        }
    }

    // API Reversal
    try {
        const baseRes = await safeFetch(url);
        const html = await baseRes.text();
        const apiPattern = /(?:href|src|action)=["']([^"']*(?:api|v[0-9])\/[^"']*)["']/gi;
        let match;
        const apiPaths = new Set();
        while ((match = apiPattern.exec(html)) !== null) { apiPaths.add(match[1]); }
        for (const path of apiPaths) {
            const reversedPath = path.split('/').reverse().join('/');
            const testReversedUrl = new URL(reversedPath, new URL(url).origin);
            try { const res = await safeFetch(testReversedUrl.toString()); if (res.status === 200) out.push({ type: 'API Reversal', severity: 'high', description: `Reversed Path: ${reversedPath}`, url: testReversedUrl.toString(), evidence: 'Status 200', cvss: 8.0 }); } catch(e){}
        }
    } catch(e){}

    if (out.length === 0) out.push({ type: 'Info', severity: 'info', description: 'No injection or API paths found.', url: url, evidence: null, cvss: 0 });
    return out;
}

// التحليل العميق
async function scanDeepAnalysis(url) {
    const out = [];
    try {
        const r = await safeFetch(url);
        const body = await r.text();
        if (body.includes('<!--')) out.push({ type: 'Deep Analysis', severity: 'low', description: 'HTML Comments Found', url: url, evidence: '<!--', cvss: 3.0 });
        if (body.includes('/api/') || body.includes('ajax')) out.push({ type: 'Deep Analysis', severity: 'info', description: 'API Endpoints Detected', url: url, evidence: 'Pattern', cvss: 0 });
        if (body.toLowerCase().includes('password') || body.toLowerCase().includes('api_key')) out.push({ type: 'Deep Analysis', severity: 'high', description: 'Secret Keywords Found', url: url, evidence: 'Word match', cvss: 7.5 });
        if (out.length === 0) out.push({ type: 'Deep Analysis', severity: 'info', description: 'No comments or secrets found.', url: url, evidence: null, cvss: 0 });
    } catch (e) {
        out.push({ type: 'Error', severity: 'high', description: 'Failed to connect', url: url, evidence: e.message, cvss: 0 });
    }
    return out;
}

// التحقق الثنائي
async function scanDualVerification(url) {
    const out = [];
    try {
        const rGet = await safeFetch(url);
        let statusGet = rGet.status;
        let statusHead = 0;
        try { const rHead = await safeFetch(url, { method: 'HEAD' }); statusHead = rHead.status; } catch(e){}
        if (statusGet !== statusHead) out.push({ type: 'Dual Verification', severity: 'medium', description: `Inconsistency: GET (${statusGet}) != HEAD (${statusHead})`, url: url, evidence: 'Method check', cvss: 4.0 });
        else out.push({ type: 'Dual Verification', severity: 'info', description: `Consistent response (${statusGet})`, url: url, evidence: null, cvss: 0 });
    } catch (e) {
        out.push({ type: 'Error', severity: 'high', description: 'Failed to connect', url: url, evidence: e.message, cvss: 0 });
    }
    return out;
}

// فحص المنافذ
async function scanPorts(url) {
    const out = [];
    const ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017];
    const host = new URL(url).hostname;
    const protocol = new URL(url).protocol;
    
    await Promise.all(ports.map(async (port) => {
        try {
            const testUrl = `${protocol}//${host}:${port}`;
            const r = await safeFetch(testUrl, { timeout: 3000 });
            if (r.status < 500) out.push({ type: 'Open Port', severity: 'medium', description: `Port ${port} is open`, url: testUrl, evidence: `Status: ${r.status}`, cvss: 5.0 });
        } catch (e) {}
    }));
    
    if (out.length === 0) out.push({ type: 'Info', severity: 'info', description: 'No open ports found.', url: url, evidence: null, cvss: 0 });
    return out;
}

// ============================================================
// 4. المسار الرئيسي
// ============================================================
app.post('/api/scan', async (req, res) => {
    const { target, checks, intensity } = req.body;
    let url = target;
    if (!url.startsWith('http')) url = 'https://' + url;
    
    let findings = [];
    const type = checks[0];

    if (type === 'vulnerabilities') findings = await scanVulnerabilities(url);
    else if (type === 'sensitiveFiles') findings = await scanSensitiveFiles(url);
    else if (type === 'injectionAndApi') findings = await scanInjectionAndApi(url);
    else if (type === 'deepAnalysis') findings = await scanDeepAnalysis(url);
    else if (type === 'dualVerification') findings = await scanDualVerification(url);
    else if (type === 'ports') findings = await scanPorts(url);
    
    res.json({ target: url, timestamp: new Date().toISOString(), findings: findings });
});

app.get('/health', (req, res) => res.json({ ok: true }));
app.listen(PORT, '0.0.0.0', () => { console.log(`Server running on port ${PORT}`); });
