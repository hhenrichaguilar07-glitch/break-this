// db.js — SQLite via Node's built-in `node:sqlite` (DatabaseSync).
// Why SQLite: zero external services to run, and it lets us demonstrate
// PARAMETERIZED QUERIES (the real defense against SQL injection).
//
// NOTE: this uses the built-in node:sqlite module (Node 22+/24) instead of
// better-sqlite3 so no native C++ build toolchain is required. The prepare()/
// get()/all()/run()/exec() surface is the same, and the `?` placeholder still
// binds input as *data* — so the SQL-injection defense is identical.

const { DatabaseSync } = require('node:sqlite');
const path = require('path');

const db = new DatabaseSync(path.join(__dirname, 'app.db'));

// WAL mode: better concurrency, safer writes.
db.exec('PRAGMA journal_mode = WAL');

// Base users table (fresh installs get every column up front).
// - password_hash: we NEVER store the raw password, only a bcrypt hash.
// - failed_attempts / locked_until: powers the brute-force lockout (Layer 7).
// - totp_secret / totp_enabled: two-factor auth (Layers 11 & 16). The secret is
//   stored encrypted at rest (see server.js encryptSecret).
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    INTEGER,
    totp_secret     TEXT,
    totp_enabled    INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL DEFAULT (strftime('%s','now'))
  );
`);

// Audit log (Layer 14): one row per security-relevant event. Never stores
// passwords or 2FA codes — only metadata (event, username, ip, success, UA).
db.exec(`
  CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    event      TEXT NOT NULL,
    username   TEXT,
    ip         TEXT,
    success    INTEGER NOT NULL DEFAULT 0,
    user_agent TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
  );
`);

// --- Migration: bring an OLDER app.db (created before 2FA existed) up to date.
// CREATE TABLE IF NOT EXISTS won't add columns to a pre-existing users table,
// so add any that are missing. Idempotent and safe to run on every startup.
const existingCols = new Set(
  db.prepare(`PRAGMA table_info(users)`).all().map((c) => c.name)
);
const migrations = [
  { col: 'totp_secret', ddl: 'ALTER TABLE users ADD COLUMN totp_secret TEXT' },
  { col: 'totp_enabled', ddl: 'ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0' },
];
for (const m of migrations) {
  if (!existingCols.has(m.col)) db.exec(m.ddl);
}

module.exports = db;
