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

## 2. The ten defense layers (and the attack each one stops)

Think of these as your checklist. For every layer, I list the **attack** it
defends against and the **test** you can run to confirm it works. In the arena,
that same test is how you find whether a *target* is missing the layer.

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
- **Test:** put `' OR '1'='1' --` in the username field. On this app: normal
  "invalid credentials." On a **vulnerable** target, that same payload might log
  you straight in — that's the classic auth-bypass.

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
- [ ] Confirmed each of the 10 layers using its test above.
- [ ] No default/leftover accounts, no debug routes, no console logs of secrets.
- [ ] Dependencies installed fresh (`npm install`) and `npm start` works clean.

---

## 5. Suggested week-of study plan

- **Day 1–2:** Read every commented section of `server.js`. For each LAYER,
  say out loud what attack it stops. Run the app and log in.
- **Day 3:** Run all ten self-tests in Section 2 against your own app. Watch
  each defense trigger.
- **Day 4:** Study the OWASP Top 10 and match each item to a layer here.
- **Day 5:** Practice the Section 3 methodology against *your own* app in a
  second browser — get fluent with DevTools' Network/Application/Console tabs.
- **Day 6:** Deploy to the arena environment; re-run the checklist in Section 4.
- **Day 7:** Rest, skim your notes, and make sure you can explain any layer if
  the professor asks *why* it's there.
