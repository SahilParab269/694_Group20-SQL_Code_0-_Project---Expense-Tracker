const { Pool } = require('pg');

const pool = new Pool({
    host: 'localhost',          // or Docker container host
    user: 'postgres',           // your Postgres user
    password: 'sqlcode0',   // your Postgres password
    database: 'dbms_project',
    port: 5403                  // default PostgreSQL port
});

module.exports = pool;