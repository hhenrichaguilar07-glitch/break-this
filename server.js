// server.js — login + dashboard hardened with defense-in-depth.
// Layers 1–10 are the core; Layers 11–14 (2FA, password strength, audit
// logging, progressive slow-down) are the added upgrades. See the README.

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const QRCode = require('qrcode');
const { authenticator } = require('otplib');

const db = require('./db');

if (!process.env.SESSION_SECRET) {
  console.error('FATAL: SESSION_SECRET is not set. Copy .env.example to .env and set it.');
  process.exit(1);
}

const app = express();
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';
const APP_NAME = 'IAS2 Secure App';

// Tolerate small clock drift on 2FA codes (accept the adjacent 30s step).
authenticator.options = { window: 1 };

// Dummy hash for timing-safe compares when a username doesn't exist (Layer 8).
const DUMMY_HASH = bcrypt.hashSync('timing-safe-dummy-value', 12);

// --- Layer 16: encrypt the 2FA secret at rest (AES-256-GCM) ---
// The key is derived from SESSION_SECRET, so a stolen app.db is useless without
// it. Stored format: "v1.<iv>.<tag>.<ciphertext>" (all base64). Legacy plaintext
// secrets (enrolled before this upgrade) are still accepted so you're not locked
// out — re-enable 2FA once to store it encrypted.
const ENC_KEY = crypto.scryptSync(process.env.SESSION_SECRET, 'totp-enc-salt-v1', 32);

function encryptSecret(plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const ct = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1.${iv.toString('base64')}.${tag.toString('base64')}.${ct.toString('base64')}`;
}

function decryptSecret(stored) {
  if (typeof stored !== 'string' || !stored.startsWith('v1.')) return stored; // legacy plaintext
  try {
    const [, ivB64, tagB64, ctB64] = stored.split('.');
    const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, Buffer.from(ivB64, 'base64'));
    decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(ctB64, 'base64')), decipher.final()]).toString('utf8');
  } catch (e) {
    return null; // tampered or wrong key
  }
}

// --- Layer 14 helper: write an audit entry (never logs passwords/codes) ---
function logAuth(event, { req, username = null, success = false }) {
  try {
    db.prepare(
      `INSERT INTO audit_log (event, username, ip, success, user_agent)
       VALUES (?, ?, ?, ?, ?)`
    ).run(
      String(event).slice(0, 64),
      username ? String(username).slice(0, 64) : null,
      String(req.ip || '').slice(0, 64),
      success ? 1 : 0,
      String(req.get('user-agent') || '').slice(0, 200)
    );
  } catch (e) {
    console.error('audit log failed:', e.message);
  }
}

// --- Layer 15 helper: detect attack payloads in the username field ---
// Legit usernames are only [a-zA-Z0-9_.], so any of these patterns means
// someone is probing. We check the USERNAME only (never the password, which is
// allowed to contain any characters) so real users are never mislabeled.
const ATTACK_PATTERNS = [
  /['"`]/,                                            // quotes
  /;/,                                                // statement separator
  /--/,                                               // SQL line comment
  /\/\*/,                                             // SQL block comment
  /\b(OR|AND)\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i,     // OR 1=1
  /\bUNION\b/i,
  /\bSELECT\b/i,
  /\bDROP\b/i,
  /\bINSERT\b/i,
  /[<>]/,                                             // angle brackets (XSS)
  /on\w+\s*=/i,                                        // inline event handlers
  /javascript:/i,
  /\.\.\//,                                           // path traversal
];

function looksLikeAttack(value) {
  return typeof value === 'string' && ATTACK_PATTERNS.some((rx) => rx.test(value));
}

// --- Layer 18: automatic IP banning (fail2ban-lite) ---
// Count attack events per IP; after too many in a short window, block that IP
// entirely for a while. In-memory, so a server restart clears all bans (handy
// if you trip it yourself while testing).
const attackHits = new Map(); // ip -> { count, first }
const bannedIps = new Map();  // ip -> expiresAt (ms)
const BAN_THRESHOLD = 5;              // attack events...
const BAN_WINDOW_MS = 10 * 60 * 1000; // ...within 10 minutes...
const BAN_DURATION_MS = 30 * 60 * 1000; // ...triggers a 30-minute ban.

function recordAttack(ip) {
  const now = Date.now();
  const rec = attackHits.get(ip) || { count: 0, first: now };
  if (now - rec.first > BAN_WINDOW_MS) { rec.count = 0; rec.first = now; }
  rec.count += 1;
  attackHits.set(ip, rec);
  if (rec.count >= BAN_THRESHOLD) {
    bannedIps.set(ip, now + BAN_DURATION_MS);
    attackHits.delete(ip);
  }
}

function isBanned(ip) {
  const exp = bannedIps.get(ip);
  if (!exp) return false;
  if (Date.now() > exp) { bannedIps.delete(ip); return false; }
  return true;
}

// ---------------------------------------------------------------------------
// LAYER 1 — SECURITY HEADERS (Helmet): CSP, anti-clickjacking, HSTS, no sniff.
// ---------------------------------------------------------------------------
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'"],        // QR code is served same-origin from /api/2fa/qr
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
    },
  },
  hsts: isProd,
}));

app.set('trust proxy', 1);

// --- Layer 20: force HTTPS in production + an extra header ---
// Behind a proxy, redirect any plain-HTTP request to HTTPS so credentials and
// cookies are never sent in the clear.
if (isProd) {
  app.use((req, res, next) => {
    if (req.secure || req.get('x-forwarded-proto') === 'https') return next();
    return res.redirect(308, 'https://' + req.get('host') + req.originalUrl);
  });
}
// Lock down powerful browser features we never use.
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  next();
});

// --- Layer 18 (enforcement): banned IPs get nothing ---
const globalLimiterPre = (req, res, next) => {
  if (isBanned(req.ip)) {
    return res.status(429).json({ error: 'Too many requests. Try again later.' });
  }
  next();
};
app.use(globalLimiterPre);

// --- Layer 19: global rate limit on every route (flood protection) ---
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300, // generous for normal use; stops request floods
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Slow down.' },
});
app.use(globalLimiter);

app.use('/static', express.static(path.join(__dirname, 'public'), {
  maxAge: '1h',
  index: false,
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// ---------------------------------------------------------------------------
// LAYER 2 — HARDENED SESSION COOKIES.
// ---------------------------------------------------------------------------
app.use(session({
  name: 'sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: isProd,
    sameSite: 'strict',
    maxAge: 1000 * 60 * 30,
  },
}));

// ---------------------------------------------------------------------------
// LAYER 3 — CSRF PROTECTION (synchronizer token).
// ---------------------------------------------------------------------------
function getCsrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  return req.session.csrfToken;
}

function verifyCsrf(req, res, next) {
  const sent = req.get('x-csrf-token') || (req.body && req.body._csrf);
  const expected = req.session.csrfToken;
  if (
    !sent ||
    !expected ||
    sent.length !== expected.length ||
    !crypto.timingSafeEqual(Buffer.from(sent), Buffer.from(expected))
  ) {
    return res.status(403).json({ error: 'Invalid CSRF token.' });
  }
  next();
}

// ---------------------------------------------------------------------------
// LAYER 4 — RATE LIMITING (hard cap on attempts per IP).
// ---------------------------------------------------------------------------
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please try again later.' },
});

// Separate limiter for the 2FA code endpoint (brute-forcing 6-digit codes).
const verifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please try again later.' },
});

// ---------------------------------------------------------------------------
// LAYER 13 — PROGRESSIVE SLOW-DOWN: each attempt past the threshold waits
// longer, so brute-force crawls to a halt even before the hard rate limit.
// ---------------------------------------------------------------------------
const LOGIN_DELAY_AFTER = 3;
const loginSpeedLimiter = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: LOGIN_DELAY_AFTER,
  delayMs: (used) => Math.max(0, (used - LOGIN_DELAY_AFTER) * 400), // +400ms per extra try
  maxDelayMs: 6000,
});

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect('/');
  next();
}

// ===========================================================================
// ROUTES
// ===========================================================================

app.get('/', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  getCsrfToken(req);
  res.type('html').send(loginPage());
});

app.get('/api/csrf', (req, res) => {
  res.json({ csrfToken: getCsrfToken(req) });
});

// ---- LOGIN (password step) ----
app.post('/api/login', loginSpeedLimiter, loginLimiter, verifyCsrf, (req, res) => {
  const { username, password } = req.body || {};

  // LAYER 15 — DECEPTION: an attack-looking username is sent to the decoy.
  // We reply with a fake "success" so the attacker thinks they broke in. No real
  // session is created, so the genuine dashboard stays out of reach.
  if (looksLikeAttack(username)) {
    logAuth('attack_detected_decoy', { req, username: String(username).slice(0, 64), success: false });
    recordAttack(req.ip);
    return res.json({ ok: true, redirect: '/decoy' });
  }

  // LAYER 5 — input validation (allow-list)
  if (
    typeof username !== 'string' ||
    typeof password !== 'string' ||
    username.length < 3 || username.length > 32 ||
    password.length < 1 || password.length > 200 ||
    !/^[a-zA-Z0-9_.]+$/.test(username)
  ) {
    return res.status(400).json({ error: 'Invalid input.' });
  }

  // LAYER 6 — parameterized query
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  const now = Math.floor(Date.now() / 1000);

  // LAYER 7 — per-account lockout
  if (user && user.locked_until && user.locked_until > now) {
    logAuth('login_locked', { req, username, success: false });
    return res.status(429).json({ error: 'Account temporarily locked. Try again later.' });
  }

  // LAYER 8 — generic errors + timing-safe compare
  const ok = bcrypt.compareSync(password, user ? user.password_hash : DUMMY_HASH);

  if (!user || !ok) {
    if (user) {
      const attempts = user.failed_attempts + 1;
      const lockUntil = attempts >= 5 ? now + 15 * 60 : null;
      db.prepare('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?')
        .run(attempts, lockUntil, user.id);
    }
    logAuth('login_failed', { req, username, success: false });
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  // Password correct — clear counters.
  db.prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?')
    .run(user.id);

  // LAYER 11 — if 2FA is on, don't finish login yet: require the code.
  if (user.totp_enabled) {
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Server error.' });
      req.session.pending2faUserId = user.id;
      req.session.pending2faAt = Date.now();
      logAuth('login_password_ok_2fa_required', { req, username: user.username, success: false });
      res.json({ ok: true, twoFactorRequired: true });
    });
    return;
  }

  // No 2FA — LAYER 9 session regeneration, then full login.
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Server error.' });
    req.session.userId = user.id;
    req.session.username = user.username;
    logAuth('login_success', { req, username: user.username, success: true });
    res.json({ ok: true, redirect: '/dashboard' });
  });
});

// ---- LOGIN (2FA code step) — LAYER 11 ----
app.post('/api/login/2fa', loginSpeedLimiter, verifyLimiter, verifyCsrf, (req, res) => {
  const pendingId = req.session.pending2faUserId;
  const pendingAt = req.session.pending2faAt || 0;

  if (!pendingId) {
    return res.status(401).json({ error: 'No login in progress. Start again.' });
  }
  if (Date.now() - pendingAt > 5 * 60 * 1000) {
    delete req.session.pending2faUserId;
    delete req.session.pending2faAt;
    return res.status(401).json({ error: 'Login timed out. Start again.' });
  }

  const { token } = req.body || {};
  if (typeof token !== 'string' || !/^\d{6}$/.test(token)) {
    return res.status(400).json({ error: 'Enter the 6-digit code.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(pendingId);
  if (!user || !user.totp_enabled || !user.totp_secret) {
    return res.status(401).json({ error: 'Two-factor not available.' });
  }

  const secret = decryptSecret(user.totp_secret);
  if (!secret || !authenticator.verify({ token, secret })) {
    logAuth('login_2fa_failed', { req, username: user.username, success: false });
    return res.status(401).json({ error: 'Invalid code.' });
  }

  delete req.session.pending2faUserId;
  delete req.session.pending2faAt;

  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Server error.' });
    req.session.userId = user.id;
    req.session.username = user.username;
    logAuth('login_success', { req, username: user.username, success: true });
    res.json({ ok: true, redirect: '/dashboard' });
  });
});

// ---- DASHBOARD (protected) ----
app.get('/dashboard', requireAuth, (req, res) => {
  res.type('html').send(dashboardPage(escapeHtml(req.session.username)));
});

// ---- 2FA setup / management (all require an active session) ----
app.post('/api/2fa/setup', requireAuth, verifyCsrf, (req, res) => {
  const secret = authenticator.generateSecret();
  req.session.pendingTotpSecret = secret; // held until confirmed with a code
  const otpauth = authenticator.keyuri(req.session.username, APP_NAME, secret);
  res.json({ ok: true, secret, otpauth });
});

app.get('/api/2fa/qr', requireAuth, async (req, res) => {
  const secret = req.session.pendingTotpSecret;
  if (!secret) return res.status(404).end();
  try {
    const otpauth = authenticator.keyuri(req.session.username, APP_NAME, secret);
    const png = await QRCode.toBuffer(otpauth, { type: 'png', width: 220, margin: 1 });
    res.type('png').send(png);
  } catch (e) {
    res.status(500).end();
  }
});

app.post('/api/2fa/enable', requireAuth, verifyCsrf, (req, res) => {
  const secret = req.session.pendingTotpSecret;
  const { token } = req.body || {};
  if (!secret) return res.status(400).json({ error: 'Start 2FA setup first.' });
  if (typeof token !== 'string' || !/^\d{6}$/.test(token)) {
    return res.status(400).json({ error: 'Enter the 6-digit code from your app.' });
  }
  if (!authenticator.verify({ token, secret })) {
    return res.status(400).json({ error: 'Code did not match. Try again.' });
  }
  db.prepare('UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?')
    .run(encryptSecret(secret), req.session.userId);
  delete req.session.pendingTotpSecret;
  logAuth('2fa_enabled', { req, username: req.session.username, success: true });
  res.json({ ok: true });
});

app.post('/api/2fa/disable', requireAuth, verifyCsrf, (req, res) => {
  db.prepare('UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?')
    .run(req.session.userId);
  delete req.session.pendingTotpSecret;
  logAuth('2fa_disabled', { req, username: req.session.username, success: true });
  res.json({ ok: true });
});

app.get('/api/2fa/status', requireAuth, (req, res) => {
  const user = db.prepare('SELECT totp_enabled FROM users WHERE id = ?').get(req.session.userId);
  res.json({ enabled: !!(user && user.totp_enabled) });
});

// ---- Audit feed (protected) — LAYER 14 ----
app.get('/api/audit', requireAuth, (req, res) => {
  const entries = db.prepare(
    `SELECT event, username, ip, success, created_at
     FROM audit_log ORDER BY id DESC LIMIT 20`
  ).all();
  res.json({ entries });
});

// ---- LOGOUT ----
app.post('/api/logout', verifyCsrf, (req, res) => {
  const username = req.session.username || null;
  logAuth('logout', { req, username, success: true });
  req.session.destroy(() => {
    res.clearCookie('sid');
    res.json({ ok: true });
  });
});

// ---- DECOY / HONEYPOT (Layer 15) ----
// The fake dashboard an attacker sees. It has NO real data and creates NO
// session. Every visit shows a freshly generated random image.
app.get('/decoy', (req, res) => {
  logAuth('decoy_viewed', { req, username: null, success: false });
  res.type('html').send(decoyPage());
});

// Generates a different abstract image on every request (no external services,
// no user input reflected, so it's XSS-safe and CSP-safe).
app.get('/api/decoy-image', (req, res) => {
  const rand = (n) => Math.floor(Math.random() * n);
  const color = () => `hsl(${rand(360)}, ${55 + rand(35)}%, ${35 + rand(35)}%)`;
  let shapes = '';
  for (let i = 0; i < 9; i++) {
    shapes += `<circle cx="${rand(400)}" cy="${rand(300)}" r="${25 + rand(85)}" fill="${color()}" opacity="0.75"/>`;
  }
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="400" height="300" viewBox="0 0 400 300">` +
    `<rect width="400" height="300" fill="${color()}"/>${shapes}</svg>`;
  res.set('Cache-Control', 'no-store');
  res.type('image/svg+xml').send(svg);
});

// ---- Layer 17: honeypot routes ----
// Tempting targets attackers probe during recon. Hitting any of them serves the
// decoy, logs it, and counts toward an IP ban — so recon itself gets punished.
const HONEYPOT_PATHS = [
  '/admin', '/administrator', '/wp-admin', '/wp-login.php', '/phpmyadmin',
  '/.env', '/.git/config', '/backup.sql', '/database.sql', '/dump.sql',
  '/config.json', '/server-status', '/.aws/credentials', '/id_rsa',
];
HONEYPOT_PATHS.forEach((p) => {
  app.get(p, (req, res) => {
    logAuth('honeypot_hit', { req, username: p.slice(0, 64), success: false });
    recordAttack(req.ip);
    res.status(200).type('html').send(decoyPage());
  });
});

// ---------------------------------------------------------------------------
// LAYER 10 — SAFE ERROR HANDLING (no stack traces to the client).
// ---------------------------------------------------------------------------
// Anything that looks like a probe for secrets/backups/traversal also gets the
// decoy and counts toward a ban; everything else is a plain 404.
const SUSPICIOUS_PATH = /(\.\.|\/\.|\.(env|git|sql|db|bak|old|save|swp|pem|key|yml|yaml)(\/|$))/i;
app.use((req, res) => {
  if (SUSPICIOUS_PATH.test(req.path)) {
    logAuth('suspicious_path', { req, username: req.path.slice(0, 64), success: false });
    recordAttack(req.ip);
    return res.status(200).type('html').send(decoyPage());
  }
  res.status(404).type('html').send('<h1>404 Not Found</h1>');
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Something went wrong.' });
});

// ---------------------------------------------------------------------------
// HTML (no inline scripts/styles so the strict CSP holds).
// ---------------------------------------------------------------------------
function loginPage() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Enter... if you dare</title>
  <link rel="stylesheet" href="/static/styles.css">
</head>
<body class="lair">
  <main class="card">
    <img class="wolf" src="/static/wolf.jpg" alt="The guardian">
    <h1 class="taunt-title">Try me if you dare!!</h1>
    <p class="taunt-sub">20 layers of defense stand between you and this door. Every move you make is watched, logged, and trapped. Go on&mdash;take your shot.</p>
    <form id="loginForm" autocomplete="off" novalidate>
      <label for="username">Username</label>
      <input id="username" name="username" autocomplete="username" required>
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required>
      <button type="submit">Enter</button>
    </form>
    <div id="twofaStep" class="hidden">
      <label for="twofaCode">Authenticator code</label>
      <input id="twofaCode" inputmode="numeric" maxlength="6" placeholder="123456" autocomplete="one-time-code">
      <button id="verifyTwofa">Verify</button>
    </div>
    <p id="msg" class="msg" role="alert"></p>
  </main>
  <script src="/static/login.js"></script>
</body>
</html>`;
}

function dashboardPage(safeUsername) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Dashboard</title>
  <link rel="stylesheet" href="/static/styles.css">
</head>
<body>
  <main class="card wide">
    <h1>Dashboard</h1>
    <p>Welcome, <strong>${safeUsername}</strong>.</p>

    <section class="panel">
      <h2>Two-factor authentication</h2>
      <p id="twofaStatus" class="muted">Checking&hellip;</p>
      <div id="twofaSetup" class="hidden">
        <button id="startTwofa" class="secondary">Set up 2FA</button>
      </div>
      <div id="twofaQr" class="hidden">
        <p class="muted">Scan this in Google Authenticator or Authy, then enter the 6-digit code.</p>
        <img id="qrImg" alt="Two-factor QR code" width="220" height="220">
        <p class="muted">Manual key: <code id="secretText"></code></p>
        <label for="twofaCode">6-digit code</label>
        <input id="twofaCode" inputmode="numeric" maxlength="6" placeholder="123456">
        <button id="enableTwofa">Enable 2FA</button>
      </div>
      <div id="twofaOn" class="hidden">
        <button id="disableTwofa" class="secondary">Turn off 2FA</button>
      </div>
      <p id="twofaMsg" class="msg"></p>
    </section>

    <section class="panel">
      <h2>Recent login activity</h2>
      <ul id="auditList" class="audit"></ul>
    </section>

    <button id="logoutBtn" class="secondary">Log out</button>
  </main>
  <script src="/static/dashboard.js"></script>
</body>
</html>`;
}

function decoyPage() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin Console</title>
  <link rel="stylesheet" href="/static/styles.css">
</head>
<body>
  <main class="card wide">
    <div class="granted">&#10003; ACCESS GRANTED &mdash; administrator</div>
    <h1>Admin Console</h1>
    <p class="muted">All security layers bypassed. Welcome back.</p>
    <img class="decoy-img" src="/api/decoy-image" alt="System snapshot" width="400" height="300">
    <h2>System users</h2>
    <ul class="audit">
      <li>root &mdash; last login: today</li>
      <li>admin &mdash; last login: today</li>
      <li>backup_svc &mdash; last login: yesterday</li>
    </ul>
    <p class="muted">Recovered flag:</p>
    <p><code>FLAG{n1c3_try_but_th1s_1s_f4k3}</code></p>
  </main>
</body>
</html>`;
}

app.listen(PORT, () => {
  console.log(`Secure app running at http://localhost:${PORT}`);
});
