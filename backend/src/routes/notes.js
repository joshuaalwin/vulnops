const express = require('express');
const { pool } = require('../db');

module.exports = function notesRouter(writeLimiter) {
  const router = express.Router();

  // CREATE note on a vulnerability
  router.post('/', writeLimiter, async (req, res) => {
    const { vuln_id, author, content } = req.body;

    if (!vuln_id || !content) {
      return res.status(400).json({ error: 'vuln_id and content are required' });
    }

    if (typeof content !== 'string' || content.length > 5000) {
      return res.status(400).json({ error: 'content must be 5,000 characters or fewer' });
    }

    try {
      const result = await pool.query(
        `INSERT INTO notes (vuln_id, author, content)
         VALUES ($1, $2, $3)
         RETURNING *`,
        [vuln_id, author ? String(author).slice(0, 100) : 'Anonymous', content]
      );
      res.status(201).json(result.rows[0]);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Failed to create note' });
    }
  });

  // DELETE note
  router.delete('/:id', writeLimiter, async (req, res) => {
    try {
      const result = await pool.query('DELETE FROM notes WHERE id = $1 RETURNING *', [req.params.id]);
      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Note not found' });
      }
      res.json({ message: 'Note deleted successfully' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Failed to delete note' });
    }
  });

  return router;
};
