const express = require('express');
const { pool } = require('../db');

module.exports = function statsRouter() {
  const router = express.Router();

  router.get('/', async (req, res) => {
    try {
      const [summaryRes, severityRes, statusRes, epssRes, recentRes, productsRes, kevRes] =
        await Promise.all([
          pool.query(`
            SELECT
              COUNT(*)::int AS total,
              SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END)::int AS critical,
              SUM(CASE WHEN status = 'OPEN' THEN 1 ELSE 0 END)::int AS open,
              SUM(CASE WHEN is_kev = true THEN 1 ELSE 0 END)::int AS kev
            FROM vulnerabilities
          `),
          pool.query(`
            SELECT severity, COUNT(*)::int AS count
            FROM vulnerabilities
            GROUP BY severity
          `),
          pool.query(`
            SELECT status, COUNT(*)::int AS count
            FROM vulnerabilities
            GROUP BY status
          `),
          pool.query(`
            SELECT id, cve_id, title, epss_score, severity
            FROM vulnerabilities
            WHERE epss_score IS NOT NULL
            ORDER BY epss_score DESC
            LIMIT 5
          `),
          pool.query(`
            SELECT id, cve_id, title, severity, status, created_at
            FROM vulnerabilities
            ORDER BY created_at DESC
            LIMIT 5
          `),
          pool.query(`
            SELECT affected_product AS product, COUNT(*)::int AS count
            FROM vulnerabilities
            WHERE affected_product IS NOT NULL AND affected_product != ''
            GROUP BY affected_product
            ORDER BY count DESC
            LIMIT 5
          `),
          pool.query(`
            SELECT id, cve_id, title, severity, created_at
            FROM vulnerabilities
            WHERE is_kev = true
            ORDER BY created_at DESC
            LIMIT 5
          `),
        ]);

      const bySeverity = {};
      for (const row of severityRes.rows) bySeverity[row.severity] = row.count;

      const byStatus = {};
      for (const row of statusRes.rows) byStatus[row.status] = row.count;

      res.json({
        summary: summaryRes.rows[0],
        by_severity: bySeverity,
        by_status: byStatus,
        top_epss: epssRes.rows,
        recent: recentRes.rows,
        top_products: productsRes.rows,
        latest_kev: kevRes.rows,
      });
    } catch (err) {
      console.error('[Stats] Query failed:', err.message);
      res.status(500).json({ error: 'Failed to fetch stats' });
    }
  });

  return router;
};
