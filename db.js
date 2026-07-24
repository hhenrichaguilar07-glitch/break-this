// db.js — SQLite via better-sqlite3.
// Parameterized queries here are the real defense against SQL injection.

const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'app.db'));
db.pragma('journal_mode = WAL');

// --- users table ---
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

// --- migration: add 2FA columns if this DB predates them ---
// SQLite has no "ADD COLUMN IF NOT EXISTS", so we check first.
const userCols = db.prepare(`PRAGMA table_info(users)`).all().map((c) => c.name);
if (!userCols.includes('totp_secret')) {
  db.exec(`ALTER TABLE users ADD COLUMN totp_secret TEXT`);
}
if (!userCols.includes('totp_enabled')) {
  db.exec(`ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0`);
}

// --- audit_log table (Layer 14) ---
// Records every meaningful auth event so you can DETECT and prove an attack.
// We never log passwords or 2FA codes — only what happened, when, and from where.
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

module.exports = db;
