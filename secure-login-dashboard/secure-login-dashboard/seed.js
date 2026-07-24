// seed.js — creates one demo user so you can log in.
// Run once with:  npm run seed
//
// SECURITY: credentials come from environment variables, never hardcoded.
// In production, there is NO fallback — the app refuses to seed with a weak
// default rather than silently using one. This matters because your SOURCE
// CODE may be readable by classmates or graders; the only thing that must
// stay secret is what's in your .env / Render settings, never what's in git.

require('dotenv').config();
const bcrypt = require('bcryptjs');
const db = require('./db');
const { checkPasswordStrength } = require('./validators');

const isProd = process.env.NODE_ENV === 'production';
const envUsername = process.env.SEED_USERNAME;
const envPassword = process.env.SEED_PASSWORD;

if (isProd && (!envUsername || !envPassword)) {
  console.error('FATAL: SEED_USERNAME and SEED_PASSWORD must be set in production.');
  console.error('Set them in your host\'s environment variables (e.g. Render dashboard).');
  console.error('Refusing to fall back to a default — that default would be visible to');
  console.error('anyone who reads this source file.');
  process.exit(1);
}

// Local-dev-only fallback. Never used when NODE_ENV=production (blocked above).
const username = envUsername || 'admin';
const plainPassword = envPassword || 'Ch4nge-Me_Before-Exam!';

const strength = checkPasswordStrength(plainPassword);
if (!strength.ok) {
  console.error(`Weak password: ${strength.message}`);
  process.exit(1);
}

const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
if (existing) {
  console.log(`User "${username}" already exists — nothing to do.`);
  console.log('To reset: delete app.db (and app.db-wal/app.db-shm), then run npm run seed again.');
  process.exit(0);
}

const passwordHash = bcrypt.hashSync(plainPassword, 12);
db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)')
  .run(username, passwordHash);

console.log(`Created user "${username}".`);
console.log('Log in, then set up 2FA from the dashboard for the strongest protection.');
