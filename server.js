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

async function runScan(target) {
  const out = [];
  const payloads = ["'", "\"", "' OR '1'='1", "<script>alert(1)</script>"];
  
  try {
    const baseRes = await safeFetch(target);
    const baseBody = (await baseRes.text()).toLowerCase();
    
    if (baseBody.includes('sql syntax') || baseBody.includes('mysql_') || baseBody.includes('sqlstate')) {
      out.push({ type: 'SQL Injection', severity: 'critical', description: 'Database Error Detected', url: target, evidence: 'SQL error', cvss: 9.8 });
    }
    if (baseBody.includes('root:x:0:0')) {
      out.push({ type: 'LFI', severity: 'critical', description: 'File Inclusion Detected', url: target, evidence: '/etc/passwd', cvss: 9.8 });
    }

    const urlObj = new URL(target);
    if (urlObj.search) {
        for (const payload of payloads) {
            for (const [key, val] of urlObj.searchParams) {
                const testUrl = new URL(target);
                testUrl.searchParams.set(key, payload);
                const res = await safeFetch(testUrl.toString());
                const body = (await res.text()).toLowerCase();
                
                if (body.includes(payload.toLowerCase())) {
                    out.push({ type: 'XSS', severity: 'high', description: `XSS Reflected in: ${key}`, url: testUrl.toString(), evidence: 'Payload reflected', cvss: 7.5 });
                } else if (body.includes('sql syntax') || body.includes('mysql_')) {
                    out.push({ type: 'SQL Injection', severity: 'critical', description: `SQLi in param: ${key}`, url: testUrl.toString(), evidence: 'DB Error', cvss: 9.8 });
                }
            }
        }
    }

    if (out.length === 0) {
      out.push({ type: 'Connection', severity: 'info', description: `Scan successful. Status: ${baseRes.status}. No obvious vulns.`, url: target, evidence: null, cvss: 0.0 });
    }
  } catch (e) {
    out.push({ type: 'Error', severity: 'high', description: 'Failed to connect to target.', url: target, evidence: e.message, cvss: 0 });
  }
  return out;
}

app.post('/api/scan', async (req, res) => {
  const { target, checks } = req.body;
  let url = target;
  if (!url.startsWith('http')) url = 'https://' + url;
  const findings = await runScan(url);
  res.json({ target: url, timestamp: new Date().toISOString(), findings: findings });
});

app.get('/health', (req, res) => res.json({ ok: true }));
app.listen(PORT, '0.0.0.0', () => { console.log(`Server running on port ${PORT}`); });
