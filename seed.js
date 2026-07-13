// seed.js — creates one demo user so you can log in.
// Run once with:  npm run seed
//
// KEY LESSON: the password is hashed with bcrypt (cost factor 12) before it
// ever touches the database. If someone dumps your DB, they get hashes, not
// passwords. bcrypt is deliberately slow, which makes cracking the hashes hard.

require('dotenv').config();
const bcrypt = require('bcryptjs');
const db = require('./db');

// ---- CHANGE THESE before the exam ----
const username = 'admin';
const plainPassword = 'Ch4nge-Me_Before-Exam!';
// ---------------------------------------

const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
if (existing) {
  console.log(`User "${username}" already exists — nothing to do.`);
  process.exit(0);
}

// Cost factor 12 = 2^12 rounds. Higher = slower = harder to brute-force,
// but also slower logins. 12 is a good balance for a demo.
const passwordHash = bcrypt.hashSync(plainPassword, 12);

db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)')
  .run(username, passwordHash);

console.log(`Created user "${username}".`);
console.log('Remember to change the username/password above before you deploy.');
