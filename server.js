'use strict';
/**
 * OWASP Orizon REST API
 * Provides static analysis endpoints for Java/APK security scanning.
 * Surfaces OWASP knowledge base and vulnerability pattern matching.
 */

const express = require('express');
const cors    = require('cors');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');

const app  = express();
const PORT = Number(process.env.PORT || 8080);

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// ─── Load OWASP knowledge base ────────────────────────────────────────────────
let KB = { vulnerabilities: [], patterns: [] };
const kbPath = path.join(__dirname, 'owasp-orizon-kb.json');
try {
  KB = JSON.parse(fs.readFileSync(kbPath, 'utf8'));
} catch (_) {
  // Build embedded KB if file missing
  KB = buildEmbeddedKB();
}

function buildEmbeddedKB() {
  return {
    version: '1.99',
    vulnerabilities: [
      { id: 'ORI-001', severity: 'CRITICAL', category: 'Injection',          cwe: 'CWE-89',  description: 'SQL Injection via string concatenation detected in query builder' },
      { id: 'ORI-002', severity: 'CRITICAL', category: 'Crypto',             cwe: 'CWE-327', description: 'Weak cryptographic algorithm (MD5/DES/RC2) detected' },
      { id: 'ORI-003', severity: 'HIGH',     category: 'XSS',                cwe: 'CWE-79',  description: 'Reflected XSS: unsanitized parameter written to output stream' },
      { id: 'ORI-004', severity: 'HIGH',     category: 'Deserialization',    cwe: 'CWE-502', description: 'Unsafe deserialization via ObjectInputStream detected' },
      { id: 'ORI-005', severity: 'HIGH',     category: 'Path Traversal',     cwe: 'CWE-22',  description: 'Unsanitized file path constructed from user input' },
      { id: 'ORI-006', severity: 'HIGH',     category: 'Command Injection',  cwe: 'CWE-78',  description: 'Runtime.exec() called with unsanitized arguments' },
      { id: 'ORI-007', severity: 'MEDIUM',   category: 'Hardcoded Secret',   cwe: 'CWE-798', description: 'Hardcoded credential or API key string detected in bytecode' },
      { id: 'ORI-008', severity: 'MEDIUM',   category: 'Logging',            cwe: 'CWE-117', description: 'Sensitive data included in log output without sanitization' },
      { id: 'ORI-009', severity: 'MEDIUM',   category: 'SSRF',               cwe: 'CWE-918', description: 'URL constructed from user-controlled input used in HTTP request' },
      { id: 'ORI-010', severity: 'MEDIUM',   category: 'XML Injection',      cwe: 'CWE-611', description: 'XML External Entity (XXE) — DTD processing not disabled' },
      { id: 'ORI-011', severity: 'LOW',      category: 'Stack Trace',        cwe: 'CWE-209', description: 'Exception stack trace exposed in HTTP response' },
      { id: 'ORI-012', severity: 'LOW',      category: 'Null Dereference',   cwe: 'CWE-476', description: 'Potential null dereference without prior null check' },
    ],
    owasp_top10_2021: [
      { rank: 'A01', name: 'Broken Access Control',           prevalence: '3.81%' },
      { rank: 'A02', name: 'Cryptographic Failures',          prevalence: '4.49%' },
      { rank: 'A03', name: 'Injection',                       prevalence: '3.37%' },
      { rank: 'A04', name: 'Insecure Design',                 prevalence: 'new'   },
      { rank: 'A05', name: 'Security Misconfiguration',       prevalence: '4.51%' },
      { rank: 'A06', name: 'Vulnerable Components',           prevalence: 'new'   },
      { rank: 'A07', name: 'Auth & Session Failures',         prevalence: '2.55%' },
      { rank: 'A08', name: 'Software/Data Integrity Failures',prevalence: 'new'   },
      { rank: 'A09', name: 'Security Logging Failures',       prevalence: '6.94%' },
      { rank: 'A10', name: 'Server-Side Request Forgery',     prevalence: 'new'   },
    ]
  };
}

// ─── Routes ───────────────────────────────────────────────────────────────────

app.get('/health', (_, res) => {
  res.json({ ok: true, service: 'owasp-orizon-api', version: '1.99', uptime: process.uptime() });
});

app.get('/api/vulnerabilities', (req, res) => {
  const { severity, category } = req.query;
  let vulns = KB.vulnerabilities || [];
  if (severity) vulns = vulns.filter(v => v.severity === severity.toUpperCase());
  if (category) vulns = vulns.filter(v => v.category.toLowerCase().includes(category.toLowerCase()));
  res.json({ count: vulns.length, vulnerabilities: vulns });
});

app.get('/api/owasp-top10', (_, res) => {
  res.json({ year: 2021, categories: KB.owasp_top10_2021 || [] });
});

// Simulate static analysis on a submitted class name / code snippet
app.post('/api/scan', (req, res) => {
  const { target, code, type = 'source' } = req.body || {};
  if (!target && !code) return res.status(400).json({ error: 'target or code required' });

  const input = String(target || code || '');
  const scanId = crypto.randomBytes(8).toString('hex');
  const findings = [];

  // Pattern-based detection on submitted text
  const patterns = [
    { re: /Statement\s*\+|createQuery\s*\(\s*".*\+/i,          vuln: 'ORI-001' },
    { re: /MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-1)"/i,  vuln: 'ORI-002' },
    { re: /\.getParameter\(.*\).*write|println/i,              vuln: 'ORI-003' },
    { re: /ObjectInputStream/i,                                vuln: 'ORI-004' },
    { re: /new\s+File\s*\(.*getParameter/i,                    vuln: 'ORI-005' },
    { re: /Runtime\.getRuntime\(\)\.exec/i,                    vuln: 'ORI-006' },
    { re: /password\s*=\s*"[^"]+"|api_?key\s*=\s*"[^"]+"/i,  vuln: 'ORI-007' },
    { re: /log\.(info|debug|warn)\s*\(.*password/i,           vuln: 'ORI-008' },
    { re: /new\s+URL\s*\(.*getParameter/i,                    vuln: 'ORI-009' },
    { re: /DocumentBuilder|SAXParser/i,                        vuln: 'ORI-010' },
    { re: /printStackTrace\(\)|\.getMessage\(\)/i,             vuln: 'ORI-011' },
  ];

  const vulnMap = {};
  for (const v of (KB.vulnerabilities || [])) vulnMap[v.id] = v;

  for (const { re, vuln } of patterns) {
    if (re.test(input)) {
      const v = vulnMap[vuln];
      if (v) findings.push({ ...v, evidence: input.match(re)?.[0] || '' });
    }
  }

  const score = findings.reduce((s, f) => {
    return s + (f.severity === 'CRITICAL' ? 10 : f.severity === 'HIGH' ? 7 : f.severity === 'MEDIUM' ? 4 : 1);
  }, 0);

  res.json({
    scan_id: scanId,
    target: target || '(inline)',
    type,
    timestamp: new Date().toISOString(),
    risk_score: Math.min(score, 100),
    risk_level: score >= 20 ? 'CRITICAL' : score >= 10 ? 'HIGH' : score >= 4 ? 'MEDIUM' : 'LOW',
    findings_count: findings.length,
    findings,
  });
});

app.get('/api/cwe/:id', (req, res) => {
  const { id } = req.params;
  const vulns = (KB.vulnerabilities || []).filter(v => v.cwe && v.cwe.includes(id));
  if (!vulns.length) return res.status(404).json({ error: 'CWE not found in KB' });
  res.json({ cwe: id, matches: vulns });
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[ORIZON] OWASP Orizon API running on :${PORT}`);
  console.log(`[ORIZON] KB loaded: ${(KB.vulnerabilities || []).length} vulnerability patterns`);
});
