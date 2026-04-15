const express = require('express');
const { lookupNvd } = require('../nvd');

const CVE_ID_RE = /^CVE-\d{4}-\d{4,}$/i;

module.exports = function nvdLookupRouter() {
  const router = express.Router();

  // GET /api/nvd/:cveId — fetch NVD data for a CVE ID (no DB write)
  router.get('/:cveId', async (req, res) => {
    const { cveId } = req.params;

    if (!CVE_ID_RE.test(cveId)) {
      return res.status(400).json({ error: 'Invalid CVE ID format' });
    }

    try {
      const data = await lookupNvd(cveId.toUpperCase());
      if (!data) {
        return res.status(404).json({ error: 'CVE not found in NVD — it may not be indexed yet' });
      }
      res.json(data);
    } catch (err) {
      console.error(`[NVD lookup] ${cveId}:`, err.message);
      res.status(502).json({ error: 'NVD lookup failed — try again shortly' });
    }
  });

  return router;
};
