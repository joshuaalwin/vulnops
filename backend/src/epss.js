const https = require('https');

const EPSS_BASE = 'https://api.first.org/data/v1/epss';

function fetchEpss(cveId) {
  return new Promise((resolve, reject) => {
    const url = `${EPSS_BASE}?cve=${encodeURIComponent(cveId)}`;

    const req = https.get(url, { headers: { 'User-Agent': 'VulnOps/1.0' }, timeout: 8000 }, (res) => {
      let raw = '';
      res.on('data', (chunk) => { raw += chunk; });
      res.on('end', () => {
        if (res.statusCode !== 200) {
          return reject(new Error(`EPSS returned HTTP ${res.statusCode} for ${cveId}`));
        }
        try {
          resolve(JSON.parse(raw));
        } catch (e) {
          reject(new Error(`EPSS response parse failed for ${cveId}: ${e.message}`));
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`EPSS request timed out for ${cveId}`));
    });
    req.on('error', reject);
  });
}

function parseEpssResponse(json) {
  const entry = json?.data?.[0];
  if (!entry) return null;

  const score = parseFloat(entry.epss);
  const percentile = Math.round(parseFloat(entry.percentile) * 100);

  if (isNaN(score) || isNaN(percentile)) return null;

  return { epss_score: score, epss_percentile: percentile };
}

async function enrichFromEpss(pool, vulnId, cveId) {
  try {
    const json = await fetchEpss(cveId);
    const data = parseEpssResponse(json);

    if (!data) {
      console.log(`[EPSS] No data found for ${cveId}`);
      return;
    }

    await pool.query(
      `UPDATE vulnerabilities SET epss_score = $1, epss_percentile = $2, updated_at = NOW() WHERE id = $3`,
      [data.epss_score, data.epss_percentile, vulnId]
    );

    console.log(`[EPSS] Enriched ${cveId} (id=${vulnId}) — score: ${data.epss_score}, percentile: ${data.epss_percentile}`);
  } catch (err) {
    console.error(`[EPSS] Enrichment failed for ${cveId}:`, err.message);
  }
}

async function lookupEpss(cveId) {
  const json = await fetchEpss(cveId);
  return parseEpssResponse(json);
}

module.exports = { enrichFromEpss, lookupEpss };
