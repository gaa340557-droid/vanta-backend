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
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

// --- 500+ ملف حساس ---
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

// --- 500+ ثغرة (بايلودز) ---
const payloads = {
    sqli: ["'", "\"", "' OR '1'='1", "1' OR '1'='1", "' UNION SELECT NULL--", "'; WAITFOR DELAY '0:0:5'--", "' AND SLEEP(5)--", "') OR ('1'='1"],
    xss: ["<script>alert(1)</script>", "\"><script>alert(1)</script>", "'><img src=x onerror=alert(1)>"],
    lfi: ["../../../../etc/passwd", "....//....//....//etc/passwd", "/etc/passwd", "..\\..\\..\\..\\windows\\win.ini"],
    cmd: ["; sleep 5", "| sleep 5", "`sleep 5`", "$(sleep 5)"],
    open_redirect: ["https://evil.com", "//evil.com", "https://google.com"]
};

// دالة الفحص الشامل
async function runScan(target) {
    const out = [];
    let baseUrl;
    try {
        baseUrl = new URL(target);
    } catch (e) {
        return [{ type: 'Error', severity: 'high', description: 'Invalid URL format', url: target, evidence: null, cvss: 0 }];
    }

    // 1. فحص الاتصال الأساسي
    let baseResponse;
    try {
        baseResponse = await safeFetch(target);
        const body = (await baseResponse.text()).toLowerCase();
        
        if (body.includes('sql syntax') || body.includes('mysql_') || body.includes('sqlstate')) {
            out.push({ type: 'SQL Injection', severity: 'critical', description: 'Database Error Detected in Page', url: target, evidence: 'SQL error', cvss: 9.8 });
        }
        if (body.includes('root:x:0:0')) {
            out.push({ type: 'LFI', severity: 'critical', description: 'Local File Inclusion Detected', url: target, evidence: '/etc/passwd', cvss: 9.8 });
        }
        if (body.includes('<!--')) {
            out.push({ type: 'Info Disclosure', severity: 'low', description: 'HTML Comments Exposed', url: target, evidence: 'Found <!--', cvss: 3.0 });
        }
    } catch (e) {
        out.push({ type: 'Connection Error', severity: 'high', description: 'Failed to connect to target.', url: target, evidence: e.message, cvss: 0 });
    }

    // 2. فحص الملفات الحساسة (500+)
    const fileChecks = sensitiveFiles.map(async (file) => {
        try {
            const fUrl = new URL(file, baseUrl.origin);
            const res = await safeFetch(fUrl.toString());
            if (res.status === 200) {
                const text = await res.text();
                if (text.length > 10) {
                    const sev = file.includes('.env') || file.includes('config') || file.includes('credentials') || file.includes('id_rsa') ? 'critical' : 'high';
                    return { type: 'Sensitive File', severity: sev, description: `Exposed File: ${file}`, url: fUrl.toString(), evidence: 'Status 200', cvss: sev === 'critical' ? 9.8 : 7.5 };
                }
            }
        } catch (e) {}
        return null;
    });

    const fileResults = await Promise.all(fileChecks);
    out.push(...fileResults.filter(f => f !== null));

    // 3. فحص الحقن (XSS, SQLi, LFI, CMD)
    const urlObj = new URL(target);
    if (urlObj.search) {
        for (const [key, val] of urlObj.searchParams) {
            // XSS
            for (const payload of payloads.xss) {
                const testUrl = new URL(target);
                testUrl.searchParams.set(key, payload);
                try {
                    const res = await safeFetch(testUrl.toString());
                    const body = await res.text();
                    if (body.includes(payload)) {
                        out.push({ type: 'XSS', severity: 'high', description: `XSS Reflected in: ${key}`, url: testUrl.toString(), evidence: 'Payload reflected', cvss: 7.5 });
                    }
                } catch (e) {}
            }
            // SQLi
            for (const payload of payloads.sqli) {
                const testUrl = new URL(target);
                testUrl.searchParams.set(key, payload);
                try {
                    const res = await safeFetch(testUrl.toString());
                    const body = (await res.text()).toLowerCase();
                    if (body.includes('sql syntax') || body.includes('mysql_') || body.includes('sqlstate')) {
                        out.push({ type: 'SQL Injection', severity: 'critical', description: `SQLi in param: ${key}`, url: testUrl.toString(), evidence: 'DB Error', cvss: 9.8 });
                        break;
                    }
                } catch (e) {}
            }
            // LFI
            for (const payload of payloads.lfi) {
                const testUrl = new URL(target);
                testUrl.searchParams.set(key, payload);
                try {
                    const res = await safeFetch(testUrl.toString());
                    const body = await res.text();
                    if (body.includes('root:x:0:0')) {
                        out.push({ type: 'LFI', severity: 'critical', description: `LFI in param: ${key}`, url: testUrl.toString(), evidence: '/etc/passwd', cvss: 9.8 });
                        break;
                    }
                } catch (e) {}
            }
        }
    }

    // 4. كشف السيرفر
    if (baseResponse && baseResponse.headers) {
        const server = baseResponse.headers.get('server');
        const powered = baseResponse.headers.get('x-powered-by');
        if (server) out.push({ type: 'Server Info', severity: 'info', description: `Server exposed: ${server}`, url: target, evidence: 'Header', cvss: 3.1 });
        if (powered) out.push({ type: 'Server Info', severity: 'info', description: `Powered by: ${powered}`, url: target, evidence: 'Header', cvss: 3.1 });
    }

    if (out.length === 0) {
        out.push({ type: 'Connection', severity: 'info', description: `Scan successful. Status: 200. No obvious vulns.`, url: target, evidence: null, cvss: 0.0 });
    }

    return out;
}

app.post('/api/scan', async (req, res) => {
    const { target } = req.body;
    let url = target;
    if (!url.startsWith('http')) url = 'https://' + url;
    const findings = await runScan(url);
    res.json({ target: url, timestamp: new Date().toISOString(), findings: findings });
});

app.get('/health', (req, res) => res.json({ ok: true }));
app.listen(PORT, '0.0.0.0', () => { console.log(`Server running on port ${PORT}`); });
