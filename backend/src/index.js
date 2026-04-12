// VulnOps backend — Phase 5 CI/CD golden test
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { initDB } = require('./db');

const vulnsRouter = require('./routes/vulns');
const notesRouter = require('./routes/notes');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

app.use('/api/vulns', vulnsRouter);
app.use('/api/notes', notesRouter);

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'vulnops-backend' });
});

async function start() {
  await initDB();
  app.listen(PORT, () => {
    console.log(`VulnOps backend running on port ${PORT}`);
  });
}

start().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
