const express = require('express');
const router = express.Router();
const { pool } = require('../db');

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
router.post('/', async (req, res) => {
  const { cve_id, title, description, severity, cvss_score, affected_product, affected_version, status, reporter } = req.body;

  if (!cve_id || !title || !description || !severity || !affected_product) {
    return res.status(400).json({ error: 'cve_id, title, description, severity, and affected_product are required' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO vulnerabilities (cve_id, title, description, severity, cvss_score, affected_product, affected_version, status, reporter)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [
        cve_id,
        title,
        description,
        severity,
        cvss_score || null,
        affected_product,
        affected_version || null,
        status || 'OPEN',
        reporter || 'Anonymous',
      ]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: `CVE ID '${cve_id}' already exists` });
    }
    console.error(err);
    res.status(500).json({ error: 'Failed to create vulnerability' });
  }
});

// UPDATE vulnerability
router.put('/:id', async (req, res) => {
  const { cve_id, title, description, severity, cvss_score, affected_product, affected_version, status, reporter } = req.body;

  if (!cve_id || !title || !description || !severity || !affected_product) {
    return res.status(400).json({ error: 'cve_id, title, description, severity, and affected_product are required' });
  }

  try {
    const result = await pool.query(
      `UPDATE vulnerabilities
       SET cve_id = $1, title = $2, description = $3, severity = $4, cvss_score = $5,
           affected_product = $6, affected_version = $7, status = $8, reporter = $9, updated_at = NOW()
       WHERE id = $10
       RETURNING *`,
      [
        cve_id,
        title,
        description,
        severity,
        cvss_score || null,
        affected_product,
        affected_version || null,
        status || 'OPEN',
        reporter || 'Anonymous',
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
router.delete('/:id', async (req, res) => {
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

module.exports = router;
