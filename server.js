// server.js — a login + dashboard hardened with defense-in-depth.
// Each numbered LAYER below stops a specific class of attack. Read the README
// to see how each one is tested/attacked so you understand *why* it's here.

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

const db = require('./db');

if (!process.env.SESSION_SECRET) {
  console.error('FATAL: SESSION_SECRET is not set. Copy .env.example to .env and set it.');
  process.exit(1);
}

const app = express();
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';

// A precomputed hash we compare against when the username doesn't exist.
// This keeps the response time roughly the same whether or not a user exists,
// which defeats USERNAME ENUMERATION via timing. (See LAYER 8.)
const DUMMY_HASH = bcrypt.hashSync('timing-safe-dummy-value', 12);

// ---------------------------------------------------------------------------
// LAYER 1 — SECURITY HEADERS (Helmet)
// Sets a Content-Security-Policy, X-Frame-Options (clickjacking), HSTS,
// X-Content-Type-Options, and removes the X-Powered-By fingerprint.
// The strict CSP (scriptSrc 'self', no inline) neutralizes most XSS even if a
// bug slips through: injected <script> tags simply won't execute.
// ---------------------------------------------------------------------------
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],   // no inline JS allowed -> blocks reflected/stored XSS
      styleSrc: ["'self'"],    // no inline styles -> external stylesheet only
      imgSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"], // page can't be iframed -> clickjacking defense
    },
  },
  // Only advertise HSTS when you're actually serving HTTPS.
  hsts: isProd,
}));

// If deployed behind a proxy (Render, Railway, Nginx, your prof's arena),
// this lets 'secure' cookies and rate-limit IP detection work correctly.
app.set('trust proxy', 1);

// Serve static JS/CSS. Kept separate so the strict CSP can allow 'self' only.
app.use('/static', express.static(path.join(__dirname, 'public'), {
  maxAge: '1h',
  index: false,
}));

// Body parsing WITH SIZE LIMITS. A tiny cap stops oversized-payload abuse.
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// ---------------------------------------------------------------------------
// LAYER 2 — HARDENED SESSION COOKIES
// httpOnly: JavaScript can't read the cookie, so XSS can't steal the session.
// secure: cookie only sent over HTTPS in production.
// sameSite 'strict': browser won't attach the cookie to cross-site requests,
//   which blocks most CSRF at the transport level.
// Short maxAge limits the damage window of a stolen/idle session.
// ---------------------------------------------------------------------------
app.use(session({
  name: 'sid', // generic name; don't leak "express" via the default cookie name
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: isProd,
    sameSite: 'strict',
    maxAge: 1000 * 60 * 30, // 30 minutes
  },
}));

// ---------------------------------------------------------------------------
// LAYER 3 — CSRF PROTECTION (synchronizer token, defense-in-depth on top of sameSite)
// We mint a random token, store it in the session, and require the client to
// echo it back in a header on state-changing requests. An attacker's forged
// request can't read the token, so it can't forge a valid one.
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
  // Constant-time compare to avoid leaking the token via timing.
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
// LAYER 4 — RATE LIMITING (brute-force / credential-stuffing defense)
// Caps how many login attempts a single IP can make in a time window.
// Pair this with the per-account lockout in LAYER 7 for two independent limits.
// ---------------------------------------------------------------------------
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,                  // 10 attempts per IP per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please try again later.' },
});

// Output-encoding helper — escapes HTML metacharacters so user-controlled
// values can't break out into markup. (Belt-and-suspenders with the CSP.)
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Access-control guard: protected routes call this. No valid session -> bounced.
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect('/');
  next();
}

// ===========================================================================
// ROUTES
// ===========================================================================

// Login page (redirects to dashboard if already authenticated).
app.get('/', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  getCsrfToken(req); // ensure a token exists for this session
  res.type('html').send(loginPage());
});

// Lets the front-end fetch the current CSRF token.
app.get('/api/csrf', (req, res) => {
  res.json({ csrfToken: getCsrfToken(req) });
});

// LOGIN — the most attacked endpoint. Note the order of the guards:
// rate-limit first, then CSRF, then validation, then the credential check.
app.post('/api/login', loginLimiter, verifyCsrf, (req, res) => {
  const { username, password } = req.body || {};

  // ---- LAYER 5 — INPUT VALIDATION (allow-list, not block-list) ----
  // Reject anything that isn't a plausible username/password up front.
  if (
    typeof username !== 'string' ||
    typeof password !== 'string' ||
    username.length < 3 || username.length > 32 ||
    password.length < 1 || password.length > 200 ||
    !/^[a-zA-Z0-9_.]+$/.test(username)
  ) {
    return res.status(400).json({ error: 'Invalid input.' });
  }

  // ---- LAYER 6 — PARAMETERIZED QUERY (SQL injection defense) ----
  // The "?" is bound as data, never concatenated into the SQL string, so
  // classic payloads like  ' OR '1'='1' --  are treated as a literal username.
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  const now = Math.floor(Date.now() / 1000);

  // ---- LAYER 7 — PER-ACCOUNT LOCKOUT ----
  if (user && user.locked_until && user.locked_until > now) {
    return res.status(429).json({ error: 'Account temporarily locked. Try again later.' });
  }

  // ---- LAYER 8 — GENERIC ERRORS + TIMING-SAFE CHECK (no user enumeration) ----
  // Always run a bcrypt compare (against DUMMY_HASH if the user is missing) so
  // "no such user" and "wrong password" take about the same time AND return the
  // exact same message. The attacker learns nothing about which usernames exist.
  const ok = bcrypt.compareSync(password, user ? user.password_hash : DUMMY_HASH);

  if (!user || !ok) {
    if (user) {
      const attempts = user.failed_attempts + 1;
      const lockUntil = attempts >= 5 ? now + 15 * 60 : null; // lock 15 min after 5 fails
      db.prepare('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?')
        .run(attempts, lockUntil, user.id);
    }
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  // Success — clear the failure counters.
  db.prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?')
    .run(user.id);

  // ---- LAYER 9 — SESSION FIXATION DEFENSE ----
  // Regenerate the session ID on privilege change (login). Any session ID an
  // attacker planted before login is now worthless.
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Server error.' });
    req.session.userId = user.id;
    req.session.username = user.username;
    res.json({ ok: true, redirect: '/dashboard' });
  });
});

// DASHBOARD — protected. Unauthenticated visitors are redirected to '/'.
app.get('/dashboard', requireAuth, (req, res) => {
  // escapeHtml here is output encoding: even a hostile username can't inject markup.
  res.type('html').send(dashboardPage(escapeHtml(req.session.username)));
});

// LOGOUT — state-changing, so it's CSRF-protected too.
app.post('/api/logout', verifyCsrf, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('sid');
    res.json({ ok: true });
  });
});

// ---------------------------------------------------------------------------
// LAYER 10 — SAFE ERROR HANDLING
// Never leak stack traces or internal details to the client. Log server-side,
// return a generic message. Verbose errors are a goldmine for attackers.
// ---------------------------------------------------------------------------
app.use((req, res) => res.status(404).type('html').send('<h1>404 Not Found</h1>'));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err); // server-side log only
  res.status(500).json({ error: 'Something went wrong.' });
});

// ---------------------------------------------------------------------------
// Minimal HTML. No inline <script> or style attributes so the strict CSP holds.
// ---------------------------------------------------------------------------
function loginPage() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Secure Login</title>
  <link rel="stylesheet" href="/static/styles.css">
</head>
<body>
  <main class="card">
    <h1>Sign in</h1>
    <form id="loginForm" autocomplete="off" novalidate>
      <label for="username">Username</label>
      <input id="username" name="username" autocomplete="username" required>
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required>
      <button type="submit">Log in</button>
    </form>
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
  <main class="card">
    <h1>Dashboard</h1>
    <p>Welcome, <strong>${safeUsername}</strong>.</p>
    <p class="muted">This page is only reachable with a valid session. Try opening
      it in a private window without logging in — you'll be redirected.</p>
    <button id="logoutBtn" class="secondary">Log out</button>
  </main>
  <script src="/static/dashboard.js"></script>
</body>
</html>`;
}

app.listen(PORT, () => {
  console.log(`Secure app running at http://localhost:${PORT}`);
});
