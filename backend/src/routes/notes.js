const express = require('express');
const router = express.Router();
const { pool } = require('../db');

// CREATE note on a vulnerability
router.post('/', async (req, res) => {
  const { vuln_id, author, content } = req.body;

  if (!vuln_id || !content) {
    return res.status(400).json({ error: 'vuln_id and content are required' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO notes (vuln_id, author, content)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [vuln_id, author || 'Anonymous', content]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create note' });
  }
});

// DELETE note
router.delete('/:id', async (req, res) => {
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

module.exports = router;
