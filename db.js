// db.js — SQLite via Node's built-in `node:sqlite` (DatabaseSync).
// Why SQLite: zero external services to run, and it lets us demonstrate
// PARAMETERIZED QUERIES (the real defense against SQL injection).
//
// NOTE: originally this used better-sqlite3, but that requires a native C++
// build toolchain (Visual Studio Build Tools) which isn't present here. Node
// 22+/24 ships a built-in SQLite module with the same prepare()/get()/run()/
// exec() surface, so we use it and need no compilation. The `?` placeholder
// still binds input as *data*, so the SQL-injection defense is identical.

const { DatabaseSync } = require('node:sqlite');
const path = require('path');

const db = new DatabaseSync(path.join(__dirname, 'app.db'));

// WAL mode: better concurrency, safer writes.
db.exec('PRAGMA journal_mode = WAL');

// Create the users table if it doesn't exist yet.
// - password_hash: we NEVER store the raw password, only a bcrypt hash.
// - failed_attempts / locked_until: powers the brute-force lockout.
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT UNIQUE NOT NULL,
    password_hash  TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until   INTEGER,
    created_at     INTEGER NOT NULL DEFAULT (strftime('%s','now'))
  );
`);

module.exports = db;
