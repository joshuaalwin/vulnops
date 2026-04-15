const express = require('express');
const { pool } = require('../db');
const { enrichFromNvd } = require('../nvd');

const CVE_ID_RE = /^CVE-\d{4}-\d{4,}$/i;
const VALID_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const VALID_STATUSES = ['OPEN', 'IN_PROGRESS', 'MITIGATED', 'RESOLVED'];

function validateVulnBody(body) {
  const { cve_id, title, description, severity, affected_product, cvss_score, status } = body;
  const errors = [];

  if (!cve_id) errors.push('cve_id is required');
  else if (!CVE_ID_RE.test(cve_id)) errors.push('cve_id must match CVE-YYYY-NNNN format');

  if (!title) errors.push('title is required');
  else if (title.length > 255) errors.push('title must be 255 characters or fewer');

  if (!description) errors.push('description is required');
  else if (description.length > 10000) errors.push('description must be 10,000 characters or fewer');

  if (!severity) errors.push('severity is required');
  else if (!VALID_SEVERITIES.includes(severity)) errors.push(`severity must be one of: ${VALID_SEVERITIES.join(', ')}`);

  if (!affected_product) errors.push('affected_product is required');
  else if (affected_product.length > 255) errors.push('affected_product must be 255 characters or fewer');

  if (cvss_score !== undefined && cvss_score !== null && cvss_score !== '') {
    const score = parseFloat(cvss_score);
    if (isNaN(score) || score < 0 || score > 10) errors.push('cvss_score must be between 0 and 10');
  }

  if (status && !VALID_STATUSES.includes(status)) errors.push(`status must be one of: ${VALID_STATUSES.join(', ')}`);

  return errors;
}

module.exports = function vulnsRouter(writeLimiter) {
  const router = express.Router();

  // GET all vulnerabilities (newest first)
  router.get('/', async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT v.*,
          (SELECT COUNT(*) FROM notes n WHERE n.vuln_id = v.id) as note_count
         FROM vulnerabilities v
         ORDER BY v.created_at DESC`
      );
      res.json(result.rows);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Failed to fetch vulnerabilities' });
    }
  });

  // GET single vulnerability with notes
  router.get('/:id', async (req, res) => {
    try {
      const vulnResult = await pool.query('SELECT * FROM vulnerabilities WHERE id = $1', [req.params.id]);
      if (vulnResult.rows.length === 0) {
        return res.status(404).json({ error: 'Vulnerability not found' });
      }

      const notesResult = await pool.query(
        'SELECT * FROM notes WHERE vuln_id = $1 ORDER BY created_at DESC',
        [req.params.id]
      );

      res.json({
        ...vulnResult.rows[0],
        notes: notesResult.rows,
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Failed to fetch vulnerability' });
    }
  });

  // CREATE vulnerability
  router.post('/', writeLimiter, async (req, res) => {
    const errors = validateVulnBody(req.body);
    if (errors.length) return res.status(400).json({ error: errors.join('; ') });

    const { cve_id, title, description, severity, cvss_score, affected_product, affected_version, status, reporter } = req.body;

    try {
      const result = await pool.query(
        `INSERT INTO vulnerabilities (cve_id, title, description, severity, cvss_score, affected_product, affected_version, status, reporter)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING *`,
        [
          cve_id.toUpperCase(),
          title,
          description,
          severity,
          cvss_score || null,
          affected_product,
          affected_version || null,
          status || 'OPEN',
          reporter ? reporter.slice(0, 100) : 'Anonymous',
        ]
      );
      const created = result.rows[0];
      // Fire-and-forget — does not block the 201 response
      enrichFromNvd(pool, created.id, created.cve_id);
      res.status(201).json(created);
    } catch (err) {
      if (err.code === '23505') {
        return res.status(409).json({ error: `CVE ID '${cve_id}' already exists` });
      }
      console.error(err);
      res.status(500).json({ error: 'Failed to create vulnerability' });
    }
  });

  // UPDATE vulnerability
  router.put('/:id', writeLimiter, async (req, res) => {
    const errors = validateVulnBody(req.body);
    if (errors.length) return res.status(400).json({ error: errors.join('; ') });

    const { cve_id, title, description, severity, cvss_score, affected_product, affected_version, status, reporter } = req.body;

    try {
      const result = await pool.query(
        `UPDATE vulnerabilities
         SET cve_id = $1, title = $2, description = $3, severity = $4, cvss_score = $5,
             affected_product = $6, affected_version = $7, status = $8, reporter = $9, updated_at = NOW()
         WHERE id = $10
         RETURNING *`,
        [
          cve_id.toUpperCase(),
          title,
          description,
          severity,
          cvss_score || null,
          affected_product,
          affected_version || null,
          status || 'OPEN',
          reporter ? reporter.slice(0, 100) : 'Anonymous',
          req.params.id,
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Vulnerability not found' });
      }

      res.json(result.rows[0]);
    } catch (err) {
      if (err.code === '23505') {
        return res.status(409).json({ error: `CVE ID '${cve_id}' already exists` });
      }
      console.error(err);
      res.status(500).json({ error: 'Failed to update vulnerability' });
    }
  });

  // DELETE vulnerability
  router.delete('/:id', writeLimiter, async (req, res) => {
    try {
      const result = await pool.query('DELETE FROM vulnerabilities WHERE id = $1 RETURNING *', [req.params.id]);
      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Vulnerability not found' });
      }
      res.json({ message: 'Vulnerability deleted successfully' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Failed to delete vulnerability' });
    }
  });

  return router;
};
