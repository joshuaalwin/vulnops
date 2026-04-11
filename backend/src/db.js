const { Pool } = require('pg');

const pool = new Pool({
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT, 10),
  database: process.env.DB_NAME,
});

async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS vulnerabilities (
        id SERIAL PRIMARY KEY,
        cve_id VARCHAR(20) UNIQUE NOT NULL,
        title VARCHAR(255) NOT NULL,
        description TEXT NOT NULL,
        severity VARCHAR(10) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
        cvss_score NUMERIC(3,1) CHECK (cvss_score >= 0 AND cvss_score <= 10),
        affected_product VARCHAR(255) NOT NULL,
        affected_version VARCHAR(100),
        status VARCHAR(20) NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'IN_PROGRESS', 'MITIGATED', 'RESOLVED')),
        reporter VARCHAR(100) NOT NULL DEFAULT 'Anonymous',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS notes (
        id SERIAL PRIMARY KEY,
        vuln_id INTEGER REFERENCES vulnerabilities(id) ON DELETE CASCADE,
        author VARCHAR(100) NOT NULL DEFAULT 'Anonymous',
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    console.log('Database tables initialized');
  } finally {
    client.release();
  }
}

module.exports = { pool, initDB };
