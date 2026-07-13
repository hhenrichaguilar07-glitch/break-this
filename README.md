# Secure Login + Dashboard — IAS 2 Lab Exam

A deliberately hardened login and dashboard built to survive a classroom
penetration-testing exercise. This README is also your study guide: it explains
**what each defense stops** and **how it's tested**, so you understand both sides.

> This project and its testing notes are for an **authorized, sandboxed class
> exercise** where everyone consents to being probed. Only ever test systems you
> own or are explicitly authorized to test.

---

## 1. Setup & run

You need Node.js 18+ installed.

```bash
# 1. install dependencies
npm install

# 2. create your secrets file
#    (copy the template, then set a strong SESSION_SECRET)
cp .env.example .env
#    generate a secret quickly:
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
#    paste that value into SESSION_SECRET in .env

# 3. create your demo user (edit the username/password in seed.js first!)
npm run seed

# 4. start the server
npm start
```

Open http://localhost:3000 and log in with the credentials you set in `seed.js`.

**Before you deploy for the exam:** change the seed username/password, set a
fresh `SESSION_SECRET`, and set `NODE_ENV=production` **only when you're actually
serving over HTTPS** (secure cookies require HTTPS).

---

## 2. The twenty defense layers (and the attack each one stops)

Think of these as your checklist. For every layer, I list the **attack** it
defends against and the **test** you can run to confirm it works. In the arena,
that same test is how you find whether a *target* is missing the layer.

Layers 1–10 are the core. Layers 11–15 add 2FA, password strength, audit
logging, progressive slow-down, and the deception trap. Layers 16–20 are the
hardening pass: encrypted 2FA secret, honeypot routes, auto IP-banning, a global
rate limit, and HTTPS enforcement.

> No security is truly unbreakable. These layers make you a very hard, slow,
> expensive target — which is what wins a timed exam. Your credentials, your
> `SESSION_SECRET`, and your hosting config still matter most (see Section 4).

### Layer 1 — Security headers (Helmet)
- **Stops:** clickjacking, MIME sniffing, and most XSS (via a strict
  Content-Security-Policy that forbids inline scripts).
- **Test:** open DevTools → Network → click the page request → look at Response
  Headers. You should see `content-security-policy`, `x-frame-options`,
  `x-content-type-options`. A target **missing** these is softer to attack.

### Layer 2 — Hardened session cookies
- **Stops:** session theft via XSS (`httpOnly`), cookie interception over plain
  HTTP (`secure`), and cross-site cookie attachment (`sameSite=strict`).
- **Test:** DevTools → Application → Cookies. The `sid` cookie should show
  **HttpOnly ✓** and **SameSite = Strict**. If a target's session cookie is
  readable by `document.cookie`, an XSS bug there becomes account takeover.

### Layer 3 — CSRF tokens
- **Stops:** Cross-Site Request Forgery — a malicious page making your browser
  perform actions using your logged-in session.
- **Test:** try calling `POST /api/logout` without the `x-csrf-token` header
  (e.g. from DevTools console with `fetch`). It should return **403**.

### Layer 4 — Rate limiting
- **Stops:** brute-force and credential-stuffing (guessing many passwords fast).
- **Test:** submit wrong credentials repeatedly. After 10 tries from one IP in
  15 minutes you get **429 Too Many Requests**. A target with no limit lets an
  attacker guess unlimited passwords.

### Layer 5 — Input validation (allow-list)
- **Stops:** malformed/oversized input and a whole category of injection, by
  rejecting anything that isn't a plausible username up front.
- **Test:** send a username with symbols like `';--`. It's rejected with
  **400** before it ever reaches the database.

### Layer 6 — Parameterized queries
- **Stops:** SQL injection — the single most classic web attack.
- **Why it works:** the `?` placeholder binds user input as *data*, so a payload
  like `' OR '1'='1' --` is treated as a literal (nonexistent) username, not as
  SQL. It cannot change the meaning of the query.
- **Test:** put `' OR '1'='1' --` in the username field. On this app: the
  deception layer sends it to the decoy (see Layer 15). On a **vulnerable**
  target, that same payload might log you straight in — the classic auth-bypass.

### Layer 7 — Per-account lockout
- **Stops:** brute-force focused on one specific account (a second, independent
  limit alongside the IP rate limit).
- **Test:** fail login 5 times for the same user — the account is locked for
  15 minutes even from a different IP.

### Layer 8 — Generic errors + timing-safe check
- **Stops:** username enumeration (learning which usernames exist by comparing
  error messages or response times).
- **Why it works:** the response is always "Invalid username or password," and a
  bcrypt compare runs even when the user doesn't exist, so timing is similar.
- **Test:** try a real username with a wrong password, then a random username.
  Same message, similar timing. On a leaky target, "user not found" vs "wrong
  password" hands the attacker a list of valid accounts to brute-force.

### Layer 9 — Session fixation defense
- **Stops:** an attacker planting a known session ID in your browser before you
  log in, then riding that session afterward.
- **Why it works:** the session ID is regenerated at login, so any pre-login ID
  is discarded.

### Layer 10 — Safe error handling
- **Stops:** information leakage. Attackers love stack traces, framework
  versions, and file paths in error pages.
- **Test:** trigger a bad request; you get a plain generic message, never a
  stack trace. Scan a target's error pages — leaked internals are free recon.

### Layer 11 — Two-factor authentication (2FA / TOTP) ⭐
- **Stops:** account takeover even when the password is known or cracked. Login
  needs a second factor: a 6-digit code from an authenticator app that changes
  every 30 seconds.
- **How it works:** the server stores a per-user secret. At login, after the
  password check, the server withholds the session until you submit a valid
  code. The password step and code step are rate-limited and time-limited.
- **Set it up:** log in, open the dashboard, click **Set up 2FA**, scan the QR
  in Google Authenticator or Authy, and enter a code to confirm. From then on,
  every login asks for the code.
- **Test:** enable 2FA, log out, log in with the correct password — you're
  stopped at the code prompt. A wrong code returns "Invalid code." This is the
  layer a grader can't get past even with your exact password.

### Layer 12 — Password strength rules
- **Stops:** weak passwords that fall to guessing or dictionary attacks.
- **How it works:** `validators.js` requires 10+ characters with upper, lower,
  number, and symbol, and rejects a blocklist of common passwords. Enforced when
  the account is seeded (and reusable for any future sign-up flow).
- **Test:** put a weak password in `seed.js` and run `npm run seed` — it's
  rejected before any user is created.

### Layer 13 — Progressive slow-down
- **Stops:** brute-force, by making each attempt slower than the last. After a
  few tries, every extra attempt waits progressively longer (up to 6 seconds).
- **Why both this and rate limiting:** slow-down degrades the attack gradually;
  the rate limit is the hard ceiling. Two independent brakes.
- **Test:** submit several wrong logins quickly and watch responses get slower,
  then eventually hit the 429 cap.

### Layer 14 — Audit logging
- **Stops nothing on its own — it lets you DETECT and prove attacks.** Every
  login success, failure, lockout, 2FA event, and logout is recorded with time,
  IP, and user agent (never the password or code).
- **See it:** the dashboard shows the last 20 events under "Recent login
  activity." Rows are rendered with `textContent`, so stored values can't inject
  HTML — safe even if an attacker planted a script-looking username.
- **Test:** fail a few logins, then refresh the dashboard — the failed attempts
  appear with their source IP.

### Layer 15 — Deception / honeypot (the decoy dashboard) 🎭
- **What it does:** when the login detects an attack payload in the *username*
  (quotes, `OR 1=1`, `<script>`, `../`, SQL keywords, etc.), it replies with a
  fake "success" and sends the attacker to `/decoy` — a convincing fake
  dashboard showing a **random image**, fake users, and a taunting fake flag.
- **Why it's clever:** the attacker thinks every layer fell and they're inside,
  so they stop trying — while the **real** dashboard is untouched, still locked
  behind a correct password + 2FA. It also buys you time and logs the attempt.
- **Important — what this is and isn't:** your layers are not a staircase the
  attacker climbs one step at a time; they're independent locks on one door. So
  this isn't literally "one picture per layer." It's a single trap that fires on
  attack behavior and *fakes* total success. The decoy is **psychological** — it
  does not replace your real defenses (auth + 2FA are what actually stop them).
- **Only real access sees the real dashboard:** the decoy never creates a
  session. The genuine `/dashboard` is reachable only by logging in for real.
- **Test:** on the login page, type `' OR '1'='1' --` as the **username**, any
  password, and submit. You'll land on the fake dashboard with a random image.
  Now log in properly — you get the real dashboard. Each visit to the decoy
  shows a different random picture. Check the audit log: the attempt is recorded
  as `attack_detected_decoy`.

### Layer 16 — Encrypted 2FA secret at rest 🔐
- **Stops:** a stolen database handing over your 2FA secret. The `totp_secret`
  is encrypted with AES-256-GCM using a key derived from `SESSION_SECRET`, so a
  leaked `app.db` alone is useless to an attacker.
- **Note:** because the key comes from `SESSION_SECRET`, if you ever change that
  secret, re-enable 2FA once (old encrypted secrets can't be decrypted with a new
  key). Secrets enrolled before this upgrade still work (backward compatible).
- **Test:** enable 2FA, then open `app.db` in a SQLite viewer — the secret shows
  as `v1.…` gibberish, not a usable code.

### Layer 17 — Honeypot routes
- **Stops / catches:** recon. Attackers routinely probe `/admin`, `/.env`,
  `/.git/config`, `/backup.sql`, `/phpmyadmin`, etc. Every one of those serves
  the decoy, logs a `honeypot_hit`, and counts toward an IP ban.
- **Test:** visit `your-site/admin` or `your-site/.env` — you get the fake
  dashboard, and the hit appears in the audit log.

### Layer 18 — Automatic IP banning (fail2ban-lite)
- **Stops:** persistent attackers. After 5 attack events (injections, honeypot
  hits, probes) from one IP within 10 minutes, that IP is blocked entirely for
  30 minutes and gets only "Too many requests."
- **Note:** it's in-memory, so restarting the server clears all bans — useful if
  you trip it on yourself while testing.
- **Test:** submit an injection username ~5 times quickly; further requests from
  your IP return 429 for a while.

### Layer 19 — Global rate limiting
- **Stops:** request floods and scripted hammering on *any* route (not just
  login). Capped at 300 requests/minute per IP — generous for real use, hostile
  to automation.
- **Test:** hammer any endpoint in a loop and you'll eventually get 429.

### Layer 20 — HTTPS enforcement + hardened headers
- **Stops:** credential/cookie interception over plain HTTP. In production, any
  HTTP request is redirected to HTTPS, and a `Permissions-Policy` header disables
  browser features (camera, mic, geolocation) you never use.
- **Test:** in production, request the `http://` URL — you're 308-redirected to
  `https://`.

---

## 3. How to test a target in the arena (authorized only)

This is the methodology, mapped to the layers above. You're checking whether a
target **lacks** each defense. Your main tool is the **browser DevTools**
(Network, Application, Console tabs). OWASP ZAP is the standard free automated
scanner if your class allows tooling.

1. **Recon.** View source, check response headers, note the stack (error pages,
   cookie names, JS files). Missing security headers = early signal.
2. **Auth bypass (SQLi).** Try `' OR '1'='1' --` and similar in the login
   fields. If it logs in or errors differently, the query isn't parameterized.
3. **Rate limiting.** Submit many wrong passwords. No lockout / no 429 = the
   account can be brute-forced.
4. **Username enumeration.** Compare responses for a likely-real username vs a
   random one — different message or timing leaks valid accounts.
5. **XSS.** Put `<script>alert(1)</script>` or `<img src=x onerror=alert(1)>`
   into any field that gets displayed back. If the alert fires, output isn't
   escaped and there's no CSP.
6. **Access control / IDOR.** Can you reach a protected page (like `/dashboard`)
   **without** logging in? If they use record IDs in URLs, does changing the ID
   show someone else's data?
7. **Session flaws.** Is the session cookie `HttpOnly` + `Secure`? Does logging
   out actually invalidate the session? Does the session ID change after login?
8. **CSRF.** Is there a token on state-changing requests, or can a forged
   cross-site request succeed?
9. **Info leakage.** Force errors and read the responses. Look for exposed
   `.git/`, `.env`, backup files, or verbose stack traces.

Every item above is something **this app already defends against** — so working
through the list is also how you confirm your own build is solid.

---

## 4. Pre-exam hardening checklist

- [ ] Changed the seed username **and** password to something strong.
- [ ] Fresh, long random `SESSION_SECRET` in `.env` (never committed).
- [ ] `.env` and `*.db` are gitignored (they are, by default here).
- [ ] `NODE_ENV=production` set **only** when served over HTTPS.
- [ ] **2FA enabled** on your account from the dashboard (scan QR, confirm code).
- [ ] Checked the audit log shows your test attempts.
- [ ] Tested the decoy: an injection username lands on the fake dashboard, a real login lands on the real one.
- [ ] Verified 2FA secret is stored encrypted (`v1.…`) in `app.db`.
- [ ] Confirmed honeypots respond at `/admin` and `/.env`, and show in the audit log.
- [ ] Confirmed each of the 20 layers using its test above.
- [ ] No default/leftover accounts, no debug routes, no console logs of secrets.
- [ ] Dependencies installed fresh (`npm install`) and `npm start` works clean.

---

## 5. Suggested week-of study plan

- **Day 1–2:** Read every commented section of `server.js`. For each LAYER,
  say out loud what attack it stops. Run the app and log in.
- **Day 3:** Run all the self-tests in Section 2 against your own app. Watch
  each defense trigger.
- **Day 4:** Study the OWASP Top 10 and match each item to a layer here.
- **Day 5:** Practice the Section 3 methodology against *your own* app in a
  second browser — get fluent with DevTools' Network/Application/Console tabs.
- **Day 6:** Deploy to the arena environment; re-run the checklist in Section 4.
- **Day 7:** Rest, skim your notes, and make sure you can explain any layer if
  the professor asks *why* it's there.
