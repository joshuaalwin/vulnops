const https = require('https');

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const REFRESH_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours

// Module-level cache: Map from CVE ID → { dateAdded, requiredAction, dueDate }
let kevMap = new Map();

function fetchKevFeed() {
  return new Promise((resolve, reject) => {
    const req = https.get(KEV_URL, { headers: { 'User-Agent': 'VulnOps/1.0' }, timeout: 15000 }, (res) => {
      let raw = '';
      res.on('data', (chunk) => { raw += chunk; });
      res.on('end', () => {
        if (res.statusCode !== 200) {
          return reject(new Error(`KEV feed returned HTTP ${res.statusCode}`));
        }
        try {
          resolve(JSON.parse(raw));
        } catch (e) {
          reject(new Error(`KEV feed parse failed: ${e.message}`));
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('KEV feed request timed out'));
    });
    req.on('error', reject);
  });
}

async function refreshKevCache(pool) {
  try {
    const json = await fetchKevFeed();
    const vulns = json?.vulnerabilities;
    if (!Array.isArray(vulns)) throw new Error('KEV feed missing vulnerabilities array');

    // Build in-memory map
    const newMap = new Map();
    for (const v of vulns) {
      if (v.cveID) {
        newMap.set(v.cveID.toUpperCase(), {
          dateAdded: v.dateAdded || null,
          requiredAction: v.requiredAction || null,
          dueDate: v.dueDate || null,
        });
      }
    }
    kevMap = newMap;

    // Persist to DB (replace single row)
    await pool.query('DELETE FROM kev_cache');
    await pool.query('INSERT INTO kev_cache (data) VALUES ($1)', [JSON.stringify(json)]);

    console.log(`[KEV] Cache refreshed — ${kevMap.size} known exploited CVEs`);
  } catch (err) {
    console.error('[KEV] Cache refresh failed:', err.message);

    // On failure, try to load from DB if in-memory map is empty
    if (kevMap.size === 0 && pool) {
      try {
        const result = await pool.query('SELECT data FROM kev_cache ORDER BY fetched_at DESC LIMIT 1');
        if (result.rows.length > 0) {
          const cached = result.rows[0].data;
          const cachedVulns = cached?.vulnerabilities;
          if (Array.isArray(cachedVulns)) {
            const fallbackMap = new Map();
            for (const v of cachedVulns) {
              if (v.cveID) fallbackMap.set(v.cveID.toUpperCase(), {
                dateAdded: v.dateAdded || null,
                requiredAction: v.requiredAction || null,
                dueDate: v.dueDate || null,
              });
            }
            kevMap = fallbackMap;
            console.log(`[KEV] Loaded ${kevMap.size} entries from DB cache`);
          }
        }
      } catch (dbErr) {
        console.error('[KEV] DB fallback failed:', dbErr.message);
      }
    }
  }
}

// Synchronous O(1) lookup after cache is warm
function isKnownExploited(cveId) {
  const entry = kevMap.get(cveId.toUpperCase());
  if (!entry) return { isKev: false, dateAdded: null, requiredAction: null, dueDate: null };
  return { isKev: true, ...entry };
}

async function enrichKevStatus(pool, vulnId, cveId) {
  try {
    const { isKev, dateAdded } = isKnownExploited(cveId);
    await pool.query(
      `UPDATE vulnerabilities SET is_kev = $1, kev_date_added = $2, updated_at = NOW() WHERE id = $3`,
      [isKev, dateAdded || null, vulnId]
    );
    if (isKev) {
      console.log(`[KEV] ${cveId} (id=${vulnId}) is a known exploited vulnerability — added ${dateAdded}`);
    }
  } catch (err) {
    console.error(`[KEV] Enrichment failed for ${cveId}:`, err.message);
  }
}

// Call on startup, then every 24h
function startKevRefreshLoop(pool) {
  refreshKevCache(pool);
  setInterval(() => refreshKevCache(pool), REFRESH_INTERVAL_MS);
}

module.exports = { startKevRefreshLoop, isKnownExploited, enrichKevStatus };
