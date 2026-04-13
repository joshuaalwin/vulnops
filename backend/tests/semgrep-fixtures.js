/**
 * SECURITY TEST FIXTURE — intentionally insecure code
 *
 * This file exists ONLY to validate that Semgrep SAST rules fire correctly in CI.
 * It is never imported, executed, or deployed. It lives in tests/ and is excluded
 * from the main SAST source scan.
 *
 * Used by the sast-validate CI job, which runs Semgrep against this file and
 * expects findings. If Semgrep returns clean, the job fails — the tool is broken.
 *
 * Patterns under test:
 *   1. Dangerous eval with user input   → javascript.lang.security.audit.dangerous-eval
 *   2. SQL injection via concatenation  → javascript.express.security.audit.express-sql-injection
 */

'use strict';

const express = require('express');
const router = express.Router();

// Pattern 1: eval() with user-controlled input — arbitrary code execution
// Rule: javascript.lang.security.audit.dangerous-eval
router.get('/debug', (req, res) => {
  const result = eval(req.query.expr);
  res.send(String(result));
});

// Pattern 2: SQL query built by string concatenation — SQL injection
// Rule: javascript.express.security.audit.express-sql-injection (or equivalent)
router.get('/search', (req, res) => {
  const query = "SELECT * FROM vulnerabilities WHERE title = '" + req.query.q + "'";
  pool.query(query).then(r => res.json(r.rows));
});

module.exports = router;
