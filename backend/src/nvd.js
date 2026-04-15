const https = require('https');

const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

const SEVERITY_MAP = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  NONE: 'INFO',
};

function fetchNvd(cveId) {
  return new Promise((resolve, reject) => {
    const url = `${NVD_BASE}?cveId=${encodeURIComponent(cveId)}`;
    const headers = { 'User-Agent': 'VulnOps/1.0' };
    if (process.env.NVD_API_KEY) headers['apiKey'] = process.env.NVD_API_KEY;

    const req = https.get(url, { headers, timeout: 10000 }, (res) => {
      let raw = '';
      res.on('data', (chunk) => { raw += chunk; });
      res.on('end', () => {
        if (res.statusCode !== 200) {
          return reject(new Error(`NVD returned HTTP ${res.statusCode} for ${cveId}`));
        }
        try {
          resolve(JSON.parse(raw));
        } catch (e) {
          reject(new Error(`NVD response parse failed for ${cveId}: ${e.message}`));
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`NVD request timed out for ${cveId}`));
    });
    req.on('error', reject);
  });
}

function parseNvdResponse(json) {
  const cve = json?.vulnerabilities?.[0]?.cve;
  if (!cve) return null;

  // English description
  const descEntry = cve.descriptions?.find((d) => d.lang === 'en');
  const description = descEntry?.value ?? null;

  // CVSS — prefer V3.1 > V3.0 > V2.0
  const v31 = cve.metrics?.cvssMetricV31?.[0];
  const v30 = cve.metrics?.cvssMetricV30?.[0];
  const v2  = cve.metrics?.cvssMetricV2?.[0];

  let cvss_score = null;
  let severity = null;

  let vector_string = null;

  if (v31) {
    cvss_score    = v31.cvssData?.baseScore ?? null;
    severity      = v31.cvssData?.baseSeverity ?? null;
    vector_string = v31.cvssData?.vectorString ?? null;
  } else if (v30) {
    cvss_score    = v30.cvssData?.baseScore ?? null;
    severity      = v30.cvssData?.baseSeverity ?? null;
    vector_string = v30.cvssData?.vectorString ?? null;
  } else if (v2) {
    cvss_score = v2.cvssData?.baseScore ?? null;
    severity   = v2.baseSeverity ?? null; // V2 puts baseSeverity on the metric, not cvssData
    // No vector_string for V2 — metrics don't map 1:1 to V3.1 calculator
  }

  const mappedSeverity = severity ? (SEVERITY_MAP[severity.toUpperCase()] ?? null) : null;

  return { description, cvss_score, severity: mappedSeverity, vector_string };
}

async function enrichFromNvd(pool, vulnId, cveId) {
  try {
    const json = await fetchNvd(cveId);
    const data = parseNvdResponse(json);

    if (!data) {
      console.log(`[NVD] No data found for ${cveId} — may not be indexed yet`);
      return;
    }

    const setClauses = [];
    const values = [];
    let idx = 1;

    if (data.description) {
      setClauses.push(`description = $${idx++}`);
      values.push(data.description);
    }
    if (data.cvss_score !== null) {
      setClauses.push(`cvss_score = $${idx++}`);
      values.push(data.cvss_score);
    }
    if (data.severity) {
      setClauses.push(`severity = $${idx++}`);
      values.push(data.severity);
    }

    if (setClauses.length === 0) {
      console.log(`[NVD] Nothing to update for ${cveId}`);
      return;
    }

    setClauses.push(`nvd_enriched = true`);
    setClauses.push(`updated_at = NOW()`);
    values.push(vulnId);

    await pool.query(
      `UPDATE vulnerabilities SET ${setClauses.join(', ')} WHERE id = $${idx}`,
      values
    );

    console.log(`[NVD] Enriched ${cveId} (id=${vulnId}) — CVSS: ${data.cvss_score}, severity: ${data.severity}`);
  } catch (err) {
    console.error(`[NVD] Enrichment failed for ${cveId}:`, err.message);
  }
}

// Returns parsed NVD data for a CVE without touching the DB
async function lookupNvd(cveId) {
  const json = await fetchNvd(cveId);
  return parseNvdResponse(json);
}

module.exports = { enrichFromNvd, lookupNvd };
