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

const sensitiveFiles = [
    ".env", ".git/config", "config.php", "config.xml", "web.config", "wp-config.php", "backup.zip", "backup.sql", "db.sql", "database.sql", "id_rsa", "credentials.json", "secrets.json", "phpinfo.php", "info.php", "server-status", "swagger.json", "admin/", "composer.json", "package.json", "Dockerfile", "access.log", "error.log", ".htaccess"
];

const payloads = {
    xss: ["<script>alert(1)</script>", "\"><script>alert(1)</script>", "'><img src=x onerror=alert(1)>", "javascript:alert(1)", "<svg/onload=alert(1)>"],
    sqli: ["'", "\"", "' OR '1'='1", "1' OR '1'='1", "' UNION SELECT NULL--", "'; WAITFOR DELAY '0:0:5'--", "' AND SLEEP(5)--"],
    lfi: ["../../../../etc/passwd", "....//....//....//etc/passwd", "/etc/passwd", "..\\..\\..\\..\\windows\\win.ini"],
    cmd: ["; sleep 5", "| sleep 5", "`sleep 5`", "$(sleep 5)"],
    ssrf: ["http://127.0.0.1:80", "http://169.254.169.254/latest/meta-data/", "http://localhost:8080"],
    ssti: ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"]
};

// 1. الثغرات العامة
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

// 2. الملفات الحساسة
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

// 3. الحقن وعكس API
async function scanInjectionAndApi(url) {
    const out = [];
    const urlObj = new URL(url);
    const baseUrl = urlObj.origin;
    
    // 1. فحص الحقن
    if (!urlObj.search) {
        out.push({ type: 'Info', severity: 'info', description: 'No URL parameters for injection testing.', url: url, evidence: null, cvss: 0 });
    } else {
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
        }
    }

    // 2. استخراج مسارات API من HTML والـ JS
    const apiPaths = new Set();
    try {
        const baseRes = await safeFetch(url);
        const html = await baseRes.text();
        
        // استخراج من HTML
        const htmlPattern = /(?:href|src|action)=["']([^"']*(?:api|v[0-9]|rest|services)\/[^"']*)["']/gi;
        let match;
        while ((match = htmlPattern.exec(html)) !== null) { apiPaths.add(match[1]); }

        // استخراج من ملفات JS
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

    // 3. عكس المسارات وجلبها
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
    } else {
        out.push({ type: 'API Reversal', severity: 'info', description: 'No API paths found to reverse.', url: url, evidence: null, cvss: 0 });
    }

    if (out.length === 0) out.push({ type: 'Info', severity: 'info', description: 'No injection or API paths found.', url: url, evidence: null, cvss: 0 });
    return out;
}

// 4. التحليل العميق
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

// 5. التحقق الثنائي
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

// 6. فحص المنافذ
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
