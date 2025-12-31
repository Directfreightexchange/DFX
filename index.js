/* eslint-disable no-console */
const express = require("express");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { Pool } = require("pg");
const multer = require("multer");
const Stripe = require("stripe");
const nodemailer = require("nodemailer");

const app = express();

/**
 * Stripe webhook MUST be raw body, and MUST be registered BEFORE json/urlencoded middleware.
 */
app.post("/stripe/webhook", express.raw({ type: "application/json" }));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const PORT = process.env.PORT || 3000;

// Change this whenever you paste a new file so you can confirm deploy instantly.
const BUILD_VERSION = process.env.BUILD_VERSION || "2025-12-31-loadboard-v2";

const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;

const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;
const DEBUG_LOADS = String(process.env.DEBUG_LOADS || "") === "1";

// Stripe
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const STRIPE_PRICE_STARTER = process.env.STRIPE_PRICE_STARTER;
const STRIPE_PRICE_GROWTH = process.env.STRIPE_PRICE_GROWTH;
const STRIPE_PRICE_ENTERPRISE = process.env.STRIPE_PRICE_ENTERPRISE;

const BOOTSTRAP_ADMIN_EMAIL = (process.env.BOOTSTRAP_ADMIN_EMAIL || "").trim().toLowerCase();

// SMTP (optional)
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = Number(process.env.SMTP_PORT || "587");
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const SMTP_FROM = process.env.SMTP_FROM || "no-reply@dfx-usa.com";

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function bootFail(msg) {
  app.get("*", (_, res) =>
    res.status(500).send(`<h1>Config error</h1><p>${escapeHtml(msg)}</p><p>Build: ${escapeHtml(BUILD_VERSION)}</p>`)
  );
  app.listen(PORT, "0.0.0.0", () => console.log("Booted with config error page:", msg));
}

if (!DATABASE_URL) return bootFail("Missing DATABASE_URL");
if (!JWT_SECRET) return bootFail("Missing JWT_SECRET");

const stripeEnabled = !!(
  STRIPE_SECRET_KEY &&
  STRIPE_WEBHOOK_SECRET &&
  STRIPE_PRICE_STARTER &&
  STRIPE_PRICE_GROWTH &&
  STRIPE_PRICE_ENTERPRISE
);

const stripe = stripeEnabled ? new Stripe(STRIPE_SECRET_KEY) : null;

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
});

const PLANS = {
  STARTER: { label: "Starter", price: 99, limit: 15 },
  GROWTH: { label: "Growth", price: 199, limit: 30 },
  ENTERPRISE: { label: "Enterprise", price: 399, limit: -1 },
};

const EQUIPMENT_OPTIONS = [
  "Standard Van",
  "Dry Van",
  "Reefer",
  "Flatbed",
  "Step Deck",
  "Double Drop",
  "RGN",
  "Lowboy",
  "Power Only",
  "Conestoga",
  "Hotshot",
  "Straight Truck",
  "Box Truck",
  "Tanker",
  "Intermodal / Container",
  "Car Hauler",
  "Other",
];

function planFromPriceId(priceId) {
  if (!priceId) return null;
  if (priceId === STRIPE_PRICE_STARTER) return "STARTER";
  if (priceId === STRIPE_PRICE_GROWTH) return "GROWTH";
  if (priceId === STRIPE_PRICE_ENTERPRISE) return "ENTERPRISE";
  return null;
}

function priceIdForPlan(plan) {
  if (plan === "STARTER") return STRIPE_PRICE_STARTER;
  if (plan === "GROWTH") return STRIPE_PRICE_GROWTH;
  if (plan === "ENTERPRISE") return STRIPE_PRICE_ENTERPRISE;
  return null;
}

function monthKey(d = new Date()) {
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  return `${y}-${m}`;
}

function money(n) {
  const x = Number(n);
  if (!Number.isFinite(x)) return "";
  return `$${x.toFixed(2)}`;
}
function int(n) {
  const x = Number(n);
  if (!Number.isFinite(x)) return 0;
  return Math.trunc(x);
}
function safeNum(n) {
  const x = Number(n);
  return Number.isFinite(x) ? x : null;
}
function clampStr(s, max = 180) {
  s = String(s ?? "").trim();
  if (s.length > max) return s.slice(0, max);
  return s;
}
function safeLower(s) {
  return String(s || "").trim().toLowerCase();
}
function sha256hex(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}
function randomToken(bytes = 24) {
  return crypto.randomBytes(bytes).toString("hex");
}

/* ---------------- Auth helpers ---------------- */
function signIn(res, user) {
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
  res.cookie("dfx_token", token, { httpOnly: true, sameSite: "lax", secure: true });
}
function getUser(req) {
  try {
    const t = req.cookies?.dfx_token;
    if (!t) return null;
    return jwt.verify(t, JWT_SECRET);
  } catch {
    return null;
  }
}
function requireAuth(req, res, next) {
  const u = getUser(req);
  if (!u) return res.redirect("/login");
  req.user = u;
  next();
}
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.redirect("/login");
    if (req.user.role !== role) return res.sendStatus(403);
    next();
  };
}

/* ---------------- Email (optional) ---------------- */
let mailer = null;
function getMailer() {
  if (mailer) return mailer;
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) return null;

  mailer = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
  return mailer;
}
async function sendEmail(to, subject, html) {
  const t = getMailer();
  if (!t) {
    console.log("[email skipped] Missing SMTP_* env vars. Would send to:", to, subject);
    return;
  }
  try {
    await t.sendMail({ from: SMTP_FROM, to, subject, html });
  } catch (e) {
    console.error("Email send failed:", e);
  }
}

/* ---------------- UI / Layout ---------------- */
const DISCLAIMER_TEXT =
  "Direct Freight Exchange is a technology platform and is not a broker or carrier. Users are responsible for verifying compliance, insurance, and payment terms.";

function layout({ title, user, body, extraHead = "", extraScript = "" }) {
  const yearLine = `© 2026 Direct Freight Exchange. All rights reserved.`;
  const footer = `
    <div class="footer">
      <div class="footerTop">
        <div class="footBrand">
          <div class="footMark">DFX</div>
          <div>
            <div class="footName">Direct Freight Exchange</div>
            <div class="footSub">Direct shipper ↔ carrier • Full transparency loads • Carriers free</div>
          </div>
        </div>
        <div class="footLinks">
          <a href="/terms">Terms</a>
          <a href="/privacy">Privacy</a>
          <a href="/health">Status</a>
          <a href="/version">Version</a>
        </div>
      </div>
      <div class="footDisclaimer">${escapeHtml(DISCLAIMER_TEXT)}</div>
      <div class="footLegal">${escapeHtml(yearLine)} • Build: <span class="mono">${escapeHtml(BUILD_VERSION)}</span></div>
    </div>
  `;

  const helpButton = `
    <a class="helpFab" href="mailto:support@dfx-usa.com?subject=DFX%20Support" title="Help">Help</a>
  `;

  return `<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${escapeHtml(title)}</title>
${extraHead}
<style>
:root{
  --bg:#050607;
  --line:rgba(255,255,255,.10);
  --line2:rgba(255,255,255,.08);
  --text:#eef7f1;
  --muted:rgba(238,247,241,.68);
  --green:#22c55e;
  --lime:#a3e635;
  --shadow:0 18px 60px rgba(0,0,0,.52);
  --radius:18px;
}
*{box-sizing:border-box}
body{
  margin:0; color:var(--text);
  font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;
  background:
    radial-gradient(900px 520px at 12% -8%, rgba(34,197,94,.18), transparent 55%),
    radial-gradient(900px 520px at 92% 0%, rgba(163,230,53,.12), transparent 55%),
    linear-gradient(180deg, rgba(34,197,94,.08), transparent 45%),
    var(--bg);
}
.wrap{max-width:1500px;margin:0 auto;padding:22px}
a{color:var(--lime);text-decoration:none} a:hover{text-decoration:underline}
.mono{font-variant-numeric: tabular-nums;}

.nav{
  display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:center;
  padding:14px 16px;border:1px solid var(--line);border-radius:20px;
  background:rgba(13,20,18,.70);backdrop-filter: blur(10px);box-shadow:var(--shadow);
  position:sticky; top:14px; z-index:20;
}
.brand{display:flex;gap:12px;align-items:center}
.mark{
  width:46px;height:46px;border-radius:16px;border:1px solid rgba(255,255,255,.10);
  background: linear-gradient(135deg, rgba(34,197,94,.95), rgba(163,230,53,.65));
  display:grid;place-items:center; font-weight:1000; color:#07120b;
}
.sub{color:var(--muted);font-size:12px}
.right{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.pill{
  padding:7px 10px;border-radius:999px;border:1px solid var(--line);
  background:rgba(6,8,9,.65);color:var(--muted);font-size:12px
}
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:10px 14px;border-radius:12px;border:1px solid var(--line);
  background:rgba(6,8,9,.65);color:var(--text);cursor:pointer;
  transition: transform .08s ease, filter .12s ease;
}
.btn:hover{filter:brightness(1.06)}
.btn:active{transform:translateY(1px)}
.btn.green{
  border:none;
  background: linear-gradient(135deg, rgba(34,197,94,.98), rgba(163,230,53,.70));
  color:#06130b; font-weight:1000;
  box-shadow: 0 18px 55px rgba(34,197,94,.18);
}
.btn.ghost{
  border:1px solid rgba(163,230,53,.22);
  background:rgba(6,8,9,.55);
  color:var(--text);
}
.card{
  margin-top:16px;border:1px solid var(--line);border-radius:var(--radius);
  background:rgba(13,20,18,.70);backdrop-filter: blur(10px);box-shadow:var(--shadow);padding:18px
}
.hero{
  margin-top:16px;border:1px solid var(--line);border-radius:var(--radius);
  background: linear-gradient(180deg, rgba(13,20,18,.78), rgba(6,8,9,.62));
  backdrop-filter: blur(10px);box-shadow:var(--shadow);padding:20px;position:relative;overflow:hidden;
}
.hero:before{
  content:""; position:absolute; inset:-2px;
  background:
    radial-gradient(520px 240px at 14% 0%, rgba(34,197,94,.22), transparent 60%),
    radial-gradient(520px 240px at 92% 0%, rgba(163,230,53,.14), transparent 60%);
  pointer-events:none;
}
.heroInner{position:relative}
.title{font-size:44px;line-height:1.03;margin:0 0 10px 0;letter-spacing:-.5px}
.muted{color:var(--muted)}
.hr{height:1px;background:rgba(255,255,255,.10);margin:14px 0;border:0}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}

input,select,textarea{
  width:100%;
  min-width: 0;
  padding:12px;border-radius:12px;border:1px solid var(--line);
  background:rgba(6,8,9,.72);color:var(--text);outline:none
}
textarea{min-height:86px;resize:vertical}
input:focus,select:focus,textarea:focus{border-color:rgba(34,197,94,.55)}

.badge{
  display:inline-flex;gap:8px;align-items:center;padding:6px 10px;border-radius:999px;
  border:1px solid var(--line);background:rgba(6,8,9,.62);color:var(--muted);font-size:12px
}
.badge.ok{border-color:rgba(34,197,94,.30);background:rgba(34,197,94,.10);color:rgba(219,255,236,.92)}
.badge.warn{border-color:rgba(163,230,53,.25);background:rgba(163,230,53,.08);color:rgba(240,255,219,.90)}
.badge.brand{border-color:rgba(34,197,94,.35);background:rgba(34,197,94,.08);color:rgba(219,255,236,.92)}

.footer{
  margin-top:16px;
  border:1px solid var(--line);
  border-radius: var(--radius);
  background: rgba(6,8,9,.62);
  backdrop-filter: blur(10px);
  box-shadow: var(--shadow);
  padding:16px;
}
.footerTop{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:center}
.footBrand{display:flex;gap:12px;align-items:center}
.footMark{
  width:44px;height:44px;border-radius:16px;border:1px solid rgba(255,255,255,.10);
  background: linear-gradient(135deg, rgba(34,197,94,.95), rgba(163,230,53,.65));
  display:grid;place-items:center; font-weight:1000; color:#06130b;
}
.footName{font-weight:1000}
.footSub{font-size:12px;color:var(--muted)}
.footLinks{display:flex;gap:14px;flex-wrap:wrap}
.footDisclaimer{margin-top:10px;color:var(--muted);font-size:12px;line-height:1.35}
.footLegal{margin-top:10px;color:rgba(238,247,241,.55);font-size:12px}

.helpFab{
  position:fixed;
  right:18px;
  bottom:18px;
  z-index:999;
  padding:12px 14px;
  border-radius:999px;
  border:1px solid rgba(163,230,53,.25);
  background:rgba(6,8,9,.85);
  color:var(--text);
  box-shadow: 0 18px 60px rgba(0,0,0,.55);
}
.helpFab:hover{filter:brightness(1.08);text-decoration:none}

/* Load board */
.boardGrid{display:grid;grid-template-columns: 420px 1fr;gap:16px;margin-top:16px}
@media(max-width:980px){.boardGrid{grid-template-columns:1fr}}
.filterCard{position:sticky;top:96px;align-self:start}
@media(max-width:980px){.filterCard{position:static}}
.small{font-size:12px;color:var(--muted)}
.twoCol{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.threeCol{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}
@media(max-width:980px){.twoCol,.threeCol{grid-template-columns:1fr 1fr}}
@media(max-width:540px){.twoCol,.threeCol{grid-template-columns:1fr}}

.loadList{display:grid;gap:12px;margin-top:14px}
.loadCard{
  border:1px solid rgba(255,255,255,.08);
  background:rgba(6,8,9,.62);
  border-radius:16px;
  padding:14px;
}
.loadTop{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
.lane{font-weight:1000;font-size:16px}
.kv{display:grid;grid-template-columns: 180px 1fr;gap:6px;margin-top:10px}
@media(max-width:720px){.kv{grid-template-columns: 1fr}}
.k{color:var(--muted)}
.v{color:rgba(238,247,241,.92)}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
.chip{
  display:inline-flex;align-items:center;gap:8px;
  padding:6px 10px;border-radius:999px;border:1px solid rgba(255,255,255,.10);
  background:rgba(255,255,255,.04); color:rgba(238,247,241,.85); font-size:12px
}
</style>
</head>
<body>
<div class="wrap">
  <div class="nav">
    <div class="brand">
      <div class="mark">DFX</div>
      <div>
        <div style="font-weight:1000">Direct Freight Exchange</div>
        <div class="sub">Direct shipper ↔ carrier • Full transparency loads • Carriers free</div>
      </div>
    </div>
    <div class="right">
      <a class="btn ghost" href="/">Home</a>
      <a class="btn ghost" href="/loads">Load Board</a>
      ${user
        ? `<span class="pill">${escapeHtml(user.role)}</span><span class="pill">${escapeHtml(user.email)}</span>
           <a class="btn green" href="/dashboard">Dashboard</a><a class="btn ghost" href="/logout">Logout</a>`
        : `<a class="btn ghost" href="/signup">Sign up</a><a class="btn green" href="/login">Login</a>`}
    </div>
  </div>

  ${body}
  ${footer}
</div>

${helpButton}
${extraScript}
</body>
</html>`;
}

/* ---------- DB ---------- */
async function ensureColumn(table, column, sqlType) {
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='${table}' AND column_name='${column}'
      ) THEN
        EXECUTE 'ALTER TABLE ${table} ADD COLUMN ${column} ${sqlType}';
      END IF;
    END$$;
  `);
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('SHIPPER','CARRIER','ADMIN')),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS shippers_billing (
      shipper_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      stripe_customer_id TEXT,
      stripe_subscription_id TEXT,
      status TEXT NOT NULL DEFAULT 'INACTIVE' CHECK (status IN ('INACTIVE','ACTIVE','PAST_DUE','CANCELED')),
      plan TEXT CHECK (plan IN ('STARTER','GROWTH','ENTERPRISE')),
      monthly_limit INTEGER NOT NULL DEFAULT 0,
      usage_month TEXT NOT NULL DEFAULT '',
      loads_used INTEGER NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS carriers_compliance (
      carrier_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      insurance_filename TEXT,
      authority_filename TEXT,
      w9_filename TEXT,
      insurance_expires TEXT,
      status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','APPROVED','REJECTED')),
      admin_note TEXT,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS loads (
      id SERIAL PRIMARY KEY,
      shipper_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      lane_from TEXT NOT NULL,
      lane_to TEXT NOT NULL,
      pickup_date TEXT NOT NULL,
      delivery_date TEXT NOT NULL,
      equipment TEXT NOT NULL,
      weight_lbs INTEGER NOT NULL,
      commodity TEXT NOT NULL,
      miles INTEGER NOT NULL,
      rate_all_in NUMERIC NOT NULL,
      payment_terms TEXT NOT NULL,
      quickpay_available BOOLEAN NOT NULL DEFAULT false,
      detention_rate_per_hr NUMERIC NOT NULL DEFAULT 0,
      detention_after_hours INTEGER NOT NULL DEFAULT 0,
      appointment_type TEXT NOT NULL DEFAULT 'FCFS',
      accessorials TEXT NOT NULL DEFAULT '',
      special_requirements TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','REQUESTED','BOOKED')),
      booked_carrier_id INTEGER REFERENCES users(id),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS load_requests (
      id SERIAL PRIMARY KEY,
      load_id INTEGER NOT NULL REFERENCES loads(id) ON DELETE CASCADE,
      carrier_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      status TEXT NOT NULL DEFAULT 'REQUESTED' CHECK (status IN ('REQUESTED','DECLINED','ACCEPTED')),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(load_id, carrier_id)
    );

    CREATE TABLE IF NOT EXISTS password_resets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ
    );
  `);

  // migrations for older dbs
  await ensureColumn("loads", "status", "TEXT NOT NULL DEFAULT 'OPEN'");
  await ensureColumn("loads", "appointment_type", "TEXT NOT NULL DEFAULT 'FCFS'");
  await ensureColumn("loads", "accessorials", "TEXT NOT NULL DEFAULT ''");
  await ensureColumn("loads", "special_requirements", "TEXT NOT NULL DEFAULT ''");
  await ensureColumn("loads", "detention_rate_per_hr", "NUMERIC NOT NULL DEFAULT 0");
  await ensureColumn("loads", "detention_after_hours", "INTEGER NOT NULL DEFAULT 0");

  if (BOOTSTRAP_ADMIN_EMAIL) {
    const r = await pool.query(`SELECT id,email,role FROM users WHERE lower(email)=lower($1)`, [BOOTSTRAP_ADMIN_EMAIL]);
    if (r.rows[0] && r.rows[0].role !== "ADMIN") {
      await pool.query(`UPDATE users SET role='ADMIN' WHERE id=$1`, [r.rows[0].id]);
      console.log("[BOOTSTRAP_ADMIN] set ADMIN for:", BOOTSTRAP_ADMIN_EMAIL);
    }
  }
}

/* ---------- Version / Health ---------- */
app.get("/version", (req, res) => res.json({ build: BUILD_VERSION, stripeEnabled, smtpEnabled: !!getMailer() }));
app.get("/health", (_, res) => res.json({ ok: true, build: BUILD_VERSION, stripeEnabled, smtpEnabled: !!getMailer() }));

/* ---------- Legal ---------- */
app.get("/terms", (req, res) => {
  const user = getUser(req);
  res.send(layout({
    title: "Terms",
    user,
    body: `
      <div class="card">
        <h2 style="margin-top:0">Terms</h2>
        <div class="hr"></div>
        <div class="muted" style="line-height:1.55">
          <p><b>Platform Disclaimer</b></p>
          <p>${escapeHtml(DISCLAIMER_TEXT)}</p>
        </div>
      </div>
    `
  }));
});
app.get("/privacy", (req, res) => {
  const user = getUser(req);
  res.send(layout({
    title: "Privacy",
    user,
    body: `
      <div class="card">
        <h2 style="margin-top:0">Privacy Policy</h2>
        <div class="hr"></div>
        <div class="muted" style="line-height:1.55">
          <p><b>What we collect</b></p>
          <ul>
            <li>Account info: email, password hash, role</li>
            <li>Marketplace activity: loads and booking requests</li>
            <li>Carrier verification metadata: filenames + status</li>
          </ul>
          <p><b>Sharing</b></p>
          <p>We do not sell personal information. We share only with service providers necessary to run the platform (e.g., Stripe for billing).</p>
          <p><b>Contact</b></p>
          <p>Email: <a href="mailto:support@dfx-usa.com">support@dfx-usa.com</a></p>
        </div>
      </div>
    `
  }));
});

/* ---------- Home ---------- */
app.get("/", (req, res) => {
  const user = getUser(req);
  res.send(layout({
    title: "DFX",
    user,
    body: `
      <div class="hero">
        <div class="heroInner">
          <div class="row">
            <span class="badge brand">All-In Pricing</span>
            <span class="badge brand">Carrier Verified</span>
            <span class="badge brand">Direct Booking</span>
          </div>
          <h2 class="title" style="margin-top:12px">Direct shipper ↔ carrier marketplace</h2>
          <div class="muted" style="max-width:980px">
            Transparent loads: rate, payment terms, detention, accessorials, appointment type, and requirements — all visible up front.
          </div>
          <div class="hr"></div>
          <div class="row">
            <a class="btn green" href="${user ? "/dashboard" : "/signup"}">${user ? "Go to Dashboard" : "Create account"}</a>
            <a class="btn ghost" href="/loads">Browse Load Board</a>
            <a class="btn ghost" href="/privacy">Privacy</a>
          </div>
        </div>
      </div>
    `
  }));
});

/* ---------- Auth ---------- */
app.get("/signup", (req, res) => {
  const user = getUser(req);
  res.send(layout({
    title: "Sign up",
    user,
    body: `
      <div class="card">
        <h2 style="margin-top:0">Sign up</h2>
        <div class="muted">Carriers are free. Shippers subscribe to post loads.</div>
        <div class="hr"></div>
        <form method="POST" action="/signup">
          <div class="twoCol">
            <input name="email" type="email" placeholder="Email" required />
            <input name="password" type="password" placeholder="Password (min 8 chars)" minlength="8" required />
          </div>
          <div class="twoCol" style="margin-top:10px">
            <select name="role" required>
              <option value="SHIPPER">Shipper</option>
              <option value="CARRIER">Carrier (free)</option>
            </select>
            <button class="btn green" type="submit">Create account</button>
          </div>
          <div class="row" style="margin-top:10px">
            <a class="btn ghost" href="/login">Login</a>
            <a class="btn ghost" href="/loads">Load Board</a>
          </div>
        </form>
      </div>
    `
  }));
});

app.post("/signup", async (req, res) => {
  try {
    const email = safeLower(req.body.email);
    const password = String(req.body.password || "");
    const role = String(req.body.role || "SHIPPER").toUpperCase();

    if (!email || password.length < 8) return res.status(400).send("Password must be at least 8 characters.");
    if (!["SHIPPER", "CARRIER"].includes(role)) return res.status(400).send("Invalid role.");

    const hash = await bcrypt.hash(password, 12);
    const r = await pool.query(
      "INSERT INTO users (email, password_hash, role) VALUES ($1,$2,$3) RETURNING id,email,role",
      [email, hash, role]
    );

    if (role === "SHIPPER") {
      await pool.query(
        `INSERT INTO shippers_billing (shipper_id,status,plan,monthly_limit,usage_month,loads_used)
         VALUES ($1,'INACTIVE',NULL,0,$2,0)
         ON CONFLICT DO NOTHING`,
        [r.rows[0].id, monthKey()]
      );
    } else {
      await pool.query(`INSERT INTO carriers_compliance (carrier_id,status) VALUES ($1,'PENDING') ON CONFLICT DO NOTHING`, [r.rows[0].id]);
    }

    if (BOOTSTRAP_ADMIN_EMAIL && email === BOOTSTRAP_ADMIN_EMAIL) {
      await pool.query(`UPDATE users SET role='ADMIN' WHERE id=$1`, [r.rows[0].id]);
      r.rows[0].role = "ADMIN";
      console.log("[BOOTSTRAP_ADMIN] set ADMIN for:", email);
    }

    signIn(res, r.rows[0]);
    res.redirect("/dashboard");
  } catch (e) {
    if (String(e).toLowerCase().includes("duplicate")) return res.status(409).send("Email already exists. Go to /login.");
    console.error(e);
    res.status(500).send("Signup failed.");
  }
});

app.get("/login", (req, res) => {
  const user = getUser(req);
  res.send(layout({
    title: "Login",
    user,
    body: `
      <div class="card">
        <h2 style="margin-top:0">Login</h2>
        <form method="POST" action="/login">
          <div class="twoCol">
            <input name="email" type="email" placeholder="Email" required />
            <input name="password" type="password" placeholder="Password" required />
          </div>
          <div class="row" style="margin-top:10px">
            <button class="btn green" type="submit">Login</button>
            <a class="btn ghost" href="/signup">Create</a>
            <a class="btn ghost" href="/forgot">Forgot password?</a>
            <a class="btn ghost" href="/loads">Load Board</a>
          </div>
        </form>
      </div>
    `
  }));
});

app.post("/login", async (req, res) => {
  try {
    const email = safeLower(req.body.email);
    const password = String(req.body.password || "");
    const r = await pool.query("SELECT id,email,password_hash,role FROM users WHERE email=$1", [email]);
    const u = r.rows[0];
    if (!u) return res.status(401).send("No account found. Go to /signup.");
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).send("Wrong password.");
    signIn(res, u);
    res.redirect("/dashboard");
  } catch (e) {
    console.error(e);
    res.status(500).send("Login failed.");
  }
});

app.get("/logout", (req, res) => { res.clearCookie("dfx_token"); res.redirect("/"); });

/* ---------- Forgot password ---------- */
app.get("/forgot", (req, res) => {
  const user = getUser(req);
  res.send(layout({
    title: "Reset password",
    user,
    body: `
      <div class="card">
        <h2 style="margin-top:0">Reset password</h2>
        <div class="muted">Enter your email. We’ll send a secure reset link.</div>
        <div class="hr"></div>
        <form method="POST" action="/forgot">
          <div class="twoCol">
            <input name="email" type="email" placeholder="Email" required />
            <button class="btn green" type="submit">Send reset link</button>
          </div>
        </form>
      </div>
    `
  }));
});

app.post("/forgot", async (req, res) => {
  const user = getUser(req);
  const email = safeLower(req.body.email);

  const r = await pool.query(`SELECT id,email FROM users WHERE email=$1`, [email]);
  const u = r.rows[0];

  // Don't reveal whether account exists.
  if (!u) {
    return res.send(layout({
      title: "Check your email",
      user,
      body: `<div class="card"><h2 style="margin-top:0">Check your email</h2><div class="muted">If an account exists, a reset link was sent.</div></div>`
    }));
  }

  const token = randomToken(24);
  const tokenHash = sha256hex(token);
  const expires = new Date(Date.now() + 1000 * 60 * 30);

  await pool.query(`INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES ($1,$2,$3)`, [
    u.id, tokenHash, expires.toISOString()
  ]);

  const link = `${APP_URL}/reset?token=${encodeURIComponent(token)}&email=${encodeURIComponent(u.email)}`;
  await sendEmail(u.email, "DFX Password Reset", `
    <p>Use this link to set a new password (valid for 30 minutes):</p>
    <p><a href="${escapeHtml(link)}">${escapeHtml(link)}</a></p>
  `);

  res.send(layout({
    title: "Check your email",
    user,
    body: `<div class="card"><h2 style="margin-top:0">Check your email</h2><div class="muted">If an account exists, a reset link was sent.</div></div>`
  }));
});

app.get("/reset", (req, res) => {
  const user = getUser(req);
  const token = String(req.query.token || "");
  const email = safeLower(req.query.email);
  res.send(layout({
    title: "Set new password",
    user,
    body: `
      <div class="card">
        <h2 style="margin-top:0">Set a new password</h2>
        <div class="hr"></div>
        <form method="POST" action="/reset">
          <input type="hidden" name="token" value="${escapeHtml(token)}"/>
          <input type="hidden" name="email" value="${escapeHtml(email)}"/>
          <div class="twoCol">
            <input name="password" type="password" minlength="8" placeholder="New password (min 8 chars)" required />
            <button class="btn green" type="submit">Update password</button>
          </div>
        </form>
      </div>
    `
  }));
});

app.post("/reset", async (req, res) => {
  const email = safeLower(req.body.email);
  const token = String(req.body.token || "");
  const password = String(req.body.password || "");
  if (password.length < 8) return res.status(400).send("Password too short.");

  const u = (await pool.query(`SELECT id,email,role FROM users WHERE email=$1`, [email])).rows[0];
  if (!u) return res.status(400).send("Invalid reset link.");

  const tokenHash = sha256hex(token);
  const row = (await pool.query(
    `SELECT id,expires_at,used_at FROM password_resets
     WHERE user_id=$1 AND token_hash=$2
     ORDER BY id DESC LIMIT 1`,
    [u.id, tokenHash]
  )).rows[0];

  if (!row) return res.status(400).send("Invalid reset link.");
  if (row.used_at) return res.status(400).send("Reset link already used.");
  if (new Date(row.expires_at).getTime() < Date.now()) return res.status(400).send("Reset link expired.");

  const hash = await bcrypt.hash(password, 12);
  await pool.query(`UPDATE users SET password_hash=$1 WHERE id=$2`, [hash, u.id]);
  await pool.query(`UPDATE password_resets SET used_at=NOW() WHERE id=$1`, [row.id]);

  signIn(res, u);
  res.redirect("/dashboard");
});

/* ---------- Billing gate + monthly usage ---------- */
async function getAndNormalizeBilling(shipperId) {
  const r = await pool.query(`SELECT * FROM shippers_billing WHERE shipper_id=$1`, [shipperId]);
  let b = r.rows[0];
  if (!b) {
    await pool.query(
      `INSERT INTO shippers_billing (shipper_id,status,plan,monthly_limit,usage_month,loads_used)
       VALUES ($1,'INACTIVE',NULL,0,$2,0)`,
      [shipperId, monthKey()]
    );
    b = (await pool.query(`SELECT * FROM shippers_billing WHERE shipper_id=$1`, [shipperId])).rows[0];
  }
  const nowM = monthKey();
  if (b.usage_month !== nowM) {
    await pool.query(
      `UPDATE shippers_billing SET usage_month=$1, loads_used=0, updated_at=NOW() WHERE shipper_id=$2`,
      [nowM, shipperId]
    );
    b.usage_month = nowM;
    b.loads_used = 0;
  }
  return b;
}
function postingAllowed(billing) {
  if (!stripeEnabled) return { ok: true, reason: null };
  if (billing.status !== "ACTIVE") return { ok: false, reason: "Subscription required (not ACTIVE)." };
  if (billing.monthly_limit === -1) return { ok: true, reason: null };
  if (billing.loads_used >= billing.monthly_limit) return { ok: false, reason: "Monthly posting limit reached." };
  return { ok: true, reason: null };
}

/* ---------- Dashboard (shipper + carrier + admin) ---------- */
function rpmForLoad(l) {
  const miles = Number(l.miles);
  const rate = Number(l.rate_all_in);
  if (!Number.isFinite(miles) || miles <= 0) return 0;
  if (!Number.isFinite(rate) || rate <= 0) return 0;
  return rate / miles;
}
function equipmentOptionsHtml(selected) {
  const opts = [`<option value="" ${!selected ? "selected" : ""} disabled>Select equipment</option>`]
    .concat(EQUIPMENT_OPTIONS.map(e => `<option value="${escapeHtml(e)}"${selected === e ? " selected" : ""}>${escapeHtml(e)}</option>`));
  return opts.join("");
}

app.get("/dashboard", requireAuth, async (req, res) => {
  const user = req.user;

  if (user.role === "SHIPPER") {
    const billing = await getAndNormalizeBilling(user.id);
    const gate = postingAllowed(billing);

    const planLabel = billing.plan ? PLANS[billing.plan]?.label : "None";
    const limitText = billing.monthly_limit === -1 ? "Unlimited" : `${billing.loads_used} / ${billing.monthly_limit} used this month`;

    const myLoads = await pool.query(`SELECT * FROM loads WHERE shipper_id=$1 ORDER BY created_at DESC`, [user.id]);

    const body = `
      <div class="card">
        <div class="row" style="justify-content:space-between">
          <div>
            <h2 style="margin:0">Shipper Dashboard</h2>
            <div class="muted">Post loads and manage booking requests.</div>
          </div>
          <span class="badge ${billing.status === "ACTIVE" ? "ok" : "warn"}">Billing: ${escapeHtml(billing.status)}</span>
        </div>

        <div class="hr"></div>

        <div class="row">
          <span class="badge">Plan: ${escapeHtml(planLabel)}</span>
          <span class="badge brand">${escapeHtml(limitText)}</span>
          <a class="btn green" href="/shipper/plans">Manage Plan</a>
        </div>

        <div class="hr"></div>

        <h3 style="margin:0 0 10px 0">Post a load</h3>
        ${gate.ok ? `
          <form method="POST" action="/shipper/loads">
            <div class="threeCol">
              <input name="lane_from" placeholder="From (City, ST)" required />
              <input name="lane_to" placeholder="To (City, ST)" required />
              <select name="equipment" required>${equipmentOptionsHtml("")}</select>

              <input name="pickup_date" placeholder="Pickup date (YYYY-MM-DD)" required />
              <input name="delivery_date" placeholder="Delivery date (YYYY-MM-DD)" required />
              <input name="commodity" placeholder="Commodity" required />

              <input name="weight_lbs" type="number" placeholder="Weight (lbs)" required />
              <input name="miles" type="number" placeholder="Miles" required />
              <input name="rate_all_in" type="number" step="0.01" placeholder="All-in rate ($)" required />

              <select name="payment_terms" required>
                <option value="" selected disabled>Payment terms</option>
                <option value="NET 30">NET 30</option>
                <option value="NET 15">NET 15</option>
                <option value="NET 45">NET 45</option>
                <option value="QuickPay">QuickPay</option>
              </select>

              <select name="quickpay_available" required>
                <option value="" selected disabled>QuickPay available?</option>
                <option value="false">No</option>
                <option value="true">Yes</option>
              </select>

              <input name="detention_rate_per_hr" type="number" step="0.01" placeholder="Detention $/hr" required />
              <input name="detention_after_hours" type="number" placeholder="Detention after (hours)" required />

              <select name="appointment_type" required>
                <option value="" selected disabled>Appointment type</option>
                <option value="FCFS">FCFS</option>
                <option value="Appt Required">Appt Required</option>
              </select>

              <input name="accessorials" placeholder="Accessorials (e.g., lumper, tarp)" required />
              <input name="special_requirements" placeholder="Notes / requirements" required />
            </div>
            <div class="row" style="margin-top:12px">
              <button class="btn green" type="submit">Post Load</button>
              <a class="btn ghost" href="/loads">View Load Board</a>
            </div>
          </form>
        ` : `
          <div class="badge warn">Posting blocked: ${escapeHtml(gate.reason)}</div>
        `}
      </div>

      <div class="card">
        <h3 style="margin-top:0">Your Loads</h3>
        <div class="hr"></div>
        ${myLoads.rows.length ? myLoads.rows.map(l => `
          <div class="loadCard">
            <div class="loadTop">
              <div>
                <div class="lane">#${l.id} ${escapeHtml(l.lane_from)} → ${escapeHtml(l.lane_to)}</div>
                <div class="muted">${escapeHtml(l.pickup_date)} → ${escapeHtml(l.delivery_date)}</div>
              </div>
              <div style="text-align:right">
                <div style="font-weight:1000">${money(l.rate_all_in)}</div>
                <div class="small mono">RPM: ${rpmForLoad(l) ? `$${rpmForLoad(l).toFixed(2)}` : "—"}</div>
              </div>
            </div>
            <div class="chips">
              <span class="chip">${escapeHtml(l.equipment)}</span>
              <span class="chip mono">${int(l.miles).toLocaleString()} mi</span>
              <span class="chip mono">${int(l.weight_lbs).toLocaleString()} lbs</span>
              <span class="chip">${escapeHtml(l.status)}</span>
              <span class="chip">${escapeHtml(l.commodity)}</span>
            </div>
          </div>
        `).join("") : `<div class="muted">No loads posted yet.</div>`}
      </div>
    `;
    return res.send(layout({ title: "Dashboard", user, body }));
  }

  if (user.role === "CARRIER") {
    const comp = await pool.query(`SELECT * FROM carriers_compliance WHERE carrier_id=$1`, [user.id]);
    const c = comp.rows[0] || { status: "PENDING" };

    const body = `
      <div class="card">
        <div class="row" style="justify-content:space-between">
          <div>
            <h2 style="margin:0">Carrier Dashboard</h2>
            <div class="muted">Submit verification docs to get Verified status.</div>
          </div>
          <span class="badge ${c.status === "APPROVED" ? "ok" : "warn"}">Verification: ${escapeHtml(c.status)}</span>
        </div>

        <div class="hr"></div>

        <div class="muted">
          Required documents:
          <ul>
            <li>W-9</li>
            <li>Certificate of Insurance (Auto Liability + Cargo)</li>
            <li>Operating Authority (MC / DOT proof)</li>
          </ul>
        </div>

        <form method="POST" action="/carrier/compliance" enctype="multipart/form-data">
          <div class="threeCol">
            <input name="insurance_expires" placeholder="Insurance expires (YYYY-MM-DD)" value="${escapeHtml(c.insurance_expires || "")}" required />
            <input type="file" name="w9" accept="application/pdf,image/*" required />
            <input type="file" name="insurance" accept="application/pdf,image/*" required />
            <input type="file" name="authority" accept="application/pdf,image/*" required />
            <button class="btn green" type="submit">Submit for Verification</button>
          </div>
        </form>

        <div class="hr"></div>
        <a class="btn green" href="/loads">Find Loads</a>
      </div>
    `;
    return res.send(layout({ title: "Carrier", user, body }));
  }

  // ADMIN
  const pending = await pool.query(`
    SELECT cc.*, u.email
    FROM carriers_compliance cc
    JOIN users u ON u.id = cc.carrier_id
    WHERE cc.status='PENDING'
    ORDER BY cc.updated_at DESC
  `);

  const body = `
    <div class="card">
      <h2 style="margin-top:0">Admin — Carrier Verifications</h2>
      <div class="hr"></div>
      ${pending.rows.length ? pending.rows.map(p => `
        <div class="loadCard">
          <div class="loadTop">
            <div>
              <div class="lane">${escapeHtml(p.email)}</div>
              <div class="muted">Insurance exp: ${escapeHtml(p.insurance_expires || "—")}</div>
              <div class="small">W-9: ${escapeHtml(p.w9_filename || "—")} • COI: ${escapeHtml(p.insurance_filename || "—")} • Authority: ${escapeHtml(p.authority_filename || "—")}</div>
            </div>
            <div class="row">
              <form method="POST" action="/admin/carriers/${p.carrier_id}/approve"><button class="btn green" type="submit">Approve</button></form>
              <form method="POST" action="/admin/carriers/${p.carrier_id}/reject"><button class="btn ghost" type="submit">Reject</button></form>
            </div>
          </div>
        </div>
      `).join("") : `<div class="muted">No pending carriers.</div>`}
    </div>
  `;
  return res.send(layout({ title: "Admin", user, body }));
});

/* ---------- Shipper post load ---------- */
app.post("/shipper/loads", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  try {
    const billing = await getAndNormalizeBilling(req.user.id);
    const gate = postingAllowed(billing);
    if (!gate.ok) return res.status(403).send(`Posting blocked: ${escapeHtml(gate.reason)}`);

    // required
    const lane_from = clampStr(req.body.lane_from, 120);
    const lane_to = clampStr(req.body.lane_to, 120);
    const pickup_date = clampStr(req.body.pickup_date, 30);
    const delivery_date = clampStr(req.body.delivery_date, 30);
    const equipment = clampStr(req.body.equipment, 60);
    const commodity = clampStr(req.body.commodity, 90);

    // numeric required
    const weight_lbs = int(req.body.weight_lbs);
    const miles = int(req.body.miles);
    const rate_all_in = Number(req.body.rate_all_in);

    // other required
    const payment_terms = clampStr(req.body.payment_terms, 60);
    const quickpay_available = String(req.body.quickpay_available) === "true";
    const detention_rate_per_hr = Number(req.body.detention_rate_per_hr);
    const detention_after_hours = int(req.body.detention_after_hours);
    const appointment_type = clampStr(req.body.appointment_type, 60);
    const accessorials = clampStr(req.body.accessorials, 140);
    const special_requirements = clampStr(req.body.special_requirements, 220);

    if (!lane_from || !lane_to || !pickup_date || !delivery_date || !equipment || !commodity) {
      return res.status(400).send("Missing required fields.");
    }
    if (!payment_terms || !appointment_type) return res.status(400).send("Missing payment terms / appointment type.");
    if (!Number.isFinite(rate_all_in) || rate_all_in <= 0) return res.status(400).send("Invalid all-in rate.");
    if (weight_lbs <= 0 || miles <= 0) return res.status(400).send("Invalid miles/weight.");

    await pool.query(
      `INSERT INTO loads
       (shipper_id,lane_from,lane_to,pickup_date,delivery_date,equipment,weight_lbs,commodity,miles,
        rate_all_in,payment_terms,quickpay_available,detention_rate_per_hr,detention_after_hours,
        appointment_type,accessorials,special_requirements,status)
       VALUES
       ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,'OPEN')`,
      [
        req.user.id, lane_from, lane_to, pickup_date, delivery_date, equipment, weight_lbs, commodity, miles,
        rate_all_in, payment_terms, quickpay_available, detention_rate_per_hr, detention_after_hours,
        appointment_type, accessorials, special_requirements
      ]
    );

    if (billing.monthly_limit !== -1) {
      await pool.query(`UPDATE shippers_billing SET loads_used = loads_used + 1, updated_at=NOW() WHERE shipper_id=$1`, [req.user.id]);
    }

    res.redirect("/dashboard");
  } catch (e) {
    console.error("Post load failed:", e);
    res.status(500).send("Post load failed. Check logs.");
  }
});

/* ---------- Carrier compliance upload (metadata only for now) ---------- */
app.post(
  "/carrier/compliance",
  requireAuth,
  requireRole("CARRIER"),
  upload.fields([{ name: "insurance", maxCount: 1 }, { name: "authority", maxCount: 1 }, { name: "w9", maxCount: 1 }]),
  async (req, res) => {
    const files = req.files || {};
    const insurance = files.insurance?.[0];
    const authority = files.authority?.[0];
    const w9 = files.w9?.[0];
    const insurance_expires = clampStr(req.body.insurance_expires, 30);

    if (!insurance || !authority || !w9) return res.status(400).send("All 3 documents are required.");
    if (!insurance_expires) return res.status(400).send("Insurance expiration is required.");

    await pool.query(
      `INSERT INTO carriers_compliance (carrier_id, insurance_filename, authority_filename, w9_filename, insurance_expires, status, updated_at)
       VALUES ($1,$2,$3,$4,$5,'PENDING',NOW())
       ON CONFLICT (carrier_id) DO UPDATE
         SET insurance_filename=EXCLUDED.insurance_filename,
             authority_filename=EXCLUDED.authority_filename,
             w9_filename=EXCLUDED.w9_filename,
             insurance_expires=EXCLUDED.insurance_expires,
             status='PENDING',
             updated_at=NOW()`,
      [req.user.id, insurance.originalname, authority.originalname, w9.originalname, insurance_expires]
    );

    res.redirect("/dashboard");
  }
);

/* ---------- Admin compliance ---------- */
app.post("/admin/carriers/:id/approve", requireAuth, requireRole("ADMIN"), async (req, res) => {
  const carrierId = Number(req.params.id);
  await pool.query(`UPDATE carriers_compliance SET status='APPROVED', updated_at=NOW(), admin_note=NULL WHERE carrier_id=$1`, [carrierId]);
  res.redirect("/dashboard");
});
app.post("/admin/carriers/:id/reject", requireAuth, requireRole("ADMIN"), async (req, res) => {
  const carrierId = Number(req.params.id);
  await pool.query(`UPDATE carriers_compliance SET status='REJECTED', admin_note='Rejected', updated_at=NOW() WHERE carrier_id=$1`, [carrierId]);
  res.redirect("/dashboard");
});

/* ---------- Stripe webhook (kept, but not expanded here) ---------- */
async function upsertBillingFromSubscription({ shipperId, customerId, subscriptionId, subStatus, priceId }) {
  const plan = planFromPriceId(priceId);
  const planDef = plan ? PLANS[plan] : null;
  const mapped =
    subStatus === "active" ? "ACTIVE" :
    subStatus === "past_due" ? "PAST_DUE" :
    subStatus === "canceled" ? "CANCELED" : "INACTIVE";
  const limit = planDef ? planDef.limit : 0;

  const nowMonth = monthKey();
  const existing = await pool.query(`SELECT usage_month, loads_used FROM shippers_billing WHERE shipper_id=$1`, [shipperId]);
  const prevMonth = existing.rows[0]?.usage_month || "";
  const loadsUsed = existing.rows[0]?.loads_used ?? 0;

  const newMonth = prevMonth && prevMonth === nowMonth ? prevMonth : nowMonth;
  const newUsed = prevMonth && prevMonth === nowMonth ? loadsUsed : 0;

  await pool.query(
    `INSERT INTO shippers_billing
      (shipper_id, stripe_customer_id, stripe_subscription_id, status, plan, monthly_limit, usage_month, loads_used, updated_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
     ON CONFLICT (shipper_id) DO UPDATE SET
      stripe_customer_id=EXCLUDED.stripe_customer_id,
      stripe_subscription_id=EXCLUDED.stripe_subscription_id,
      status=EXCLUDED.status,
      plan=EXCLUDED.plan,
      monthly_limit=EXCLUDED.monthly_limit,
      usage_month=EXCLUDED.usage_month,
      loads_used=EXCLUDED.loads_used,
      updated_at=NOW()`,
    [shipperId, customerId || null, subscriptionId || null, mapped, plan, limit, newMonth, newUsed]
  );
}

app.post("/stripe/webhook", async (req, res) => {
  if (!stripeEnabled) return res.sendStatus(400);

  let event;
  try {
    const sig = req.headers["stripe-signature"];
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const shipperId = Number(session.metadata?.shipper_id);
      const customerId = session.customer;
      const subscriptionId = session.subscription;

      if (shipperId && subscriptionId) {
        const sub = await stripe.subscriptions.retrieve(subscriptionId);
        const priceId = sub.items?.data?.[0]?.price?.id;
        await upsertBillingFromSubscription({
          shipperId,
          customerId,
          subscriptionId,
          subStatus: sub.status,
          priceId,
        });
      }
    }
    res.json({ received: true });
  } catch (e) {
    console.error("Webhook failed:", e);
    res.sendStatus(500);
  }
});

/* ---------- Load Board: JSON API + UI fetch ---------- */
function buildLoadsQuery(filters) {
  const params = [];
  const where = [];
  const push = (val) => { params.push(val); return `$${params.length}`; };

  const q = safeLower(filters.q);
  if (q) {
    const p = push(`%${q}%`);
    where.push(`(lower(lane_from) LIKE ${p} OR lower(lane_to) LIKE ${p} OR lower(commodity) LIKE ${p})`);
  }

  const origin = safeLower(filters.origin);
  if (origin) {
    const p = push(`%${origin}%`);
    where.push(`lower(lane_from) LIKE ${p}`);
  }

  const dest = safeLower(filters.dest);
  if (dest) {
    const p = push(`%${dest}%`);
    where.push(`lower(lane_to) LIKE ${p}`);
  }

  const equipment = String(filters.equipment || "").trim();
  if (equipment) where.push(`equipment = ${push(equipment)}`);

  const status = String(filters.status || "").trim();
  if (status === "ACTIONABLE") where.push(`status IN ('OPEN','REQUESTED')`);
  else if (["OPEN","REQUESTED","BOOKED"].includes(status)) where.push(`status = ${push(status)}`);

  const qp = String(filters.quickpay || "").trim();
  if (qp === "1") where.push(`quickpay_available = true`);
  if (qp === "0") where.push(`quickpay_available = false`);

  const minMiles = safeNum(filters.minMiles);
  if (minMiles !== null) where.push(`miles >= ${push(minMiles)}`);
  const maxMiles = safeNum(filters.maxMiles);
  if (maxMiles !== null) where.push(`miles <= ${push(maxMiles)}`);

  const minWeight = safeNum(filters.minWeight);
  if (minWeight !== null) where.push(`weight_lbs >= ${push(minWeight)}`);
  const maxWeight = safeNum(filters.maxWeight);
  if (maxWeight !== null) where.push(`weight_lbs <= ${push(maxWeight)}`);

  const minRate = safeNum(filters.minRate);
  if (minRate !== null) where.push(`rate_all_in >= ${push(minRate)}`);
  const maxRate = safeNum(filters.maxRate);
  if (maxRate !== null) where.push(`rate_all_in <= ${push(maxRate)}`);

  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const sort = String(filters.sort || "newest").toLowerCase();
  let orderBy = `ORDER BY created_at DESC, id DESC`;
  if (sort === "rpm") orderBy = `ORDER BY (CASE WHEN miles > 0 THEN (rate_all_in::numeric / miles::numeric) ELSE 0 END) DESC, created_at DESC, id DESC`;
  if (sort === "rate") orderBy = `ORDER BY rate_all_in DESC, created_at DESC, id DESC`;
  if (sort === "miles") orderBy = `ORDER BY miles DESC, created_at DESC, id DESC`;

  const sql = `
    SELECT *
    FROM loads
    ${whereSql}
    ${orderBy}
  `;
  return { sql, params };
}

app.get("/api/loads", async (req, res) => {
  try {
    const user = getUser(req);
    const statusDefault = user?.role === "CARRIER" ? "ACTIONABLE" : "";
    const filters = {
      q: req.query.q || "",
      origin: req.query.origin || "",
      dest: req.query.dest || "",
      equipment: req.query.equipment || "",
      status: req.query.status ?? statusDefault,
      minMiles: req.query.minMiles,
      maxMiles: req.query.maxMiles,
      minWeight: req.query.minWeight,
      maxWeight: req.query.maxWeight,
      minRate: req.query.minRate,
      maxRate: req.query.maxRate,
      quickpay: req.query.quickpay ?? "",
      sort: req.query.sort || "newest",
    };

    const built = buildLoadsQuery(filters);
    if (DEBUG_LOADS) console.log("[LOADS SQL]", built.sql, built.params);

    const r = await pool.query(built.sql, built.params);
    res.json({
      ok: true,
      build: BUILD_VERSION,
      count: r.rows.length,
      filters,
      rows: r.rows,
    });
  } catch (e) {
    console.error("/api/loads failed:", e);
    res.status(500).json({ ok: false, error: "api_failed" });
  }
});

app.get("/loads", async (req, res) => {
  const user = getUser(req);
  const statusDefault = user?.role === "CARRIER" ? "ACTIONABLE" : "";

  const body = `
    <div class="boardGrid">
      <div class="card filterCard">
        <div class="row" style="justify-content:space-between">
          <div>
            <div style="font-weight:1000;font-size:16px">Search & Filters</div>
            <div class="small">Example: Origin “Houston”</div>
          </div>
          <button class="btn ghost" id="resetBtn" type="button">Reset</button>
        </div>
        <div class="hr"></div>

        <div style="display:grid;gap:10px">
          <input id="q" placeholder="Search: lane, city, commodity" />
          <div class="twoCol">
            <input id="origin" placeholder="Origin contains (Houston)" />
            <input id="dest" placeholder="Destination contains (Atlanta)" />
          </div>

          <select id="equipment">
            <option value="">All equipment</option>
            ${EQUIPMENT_OPTIONS.map(e => `<option value="${escapeHtml(e)}">${escapeHtml(e)}</option>`).join("")}
          </select>

          <div class="twoCol">
            <select id="status">
              <option value="" ${statusDefault === "" ? "selected" : ""}>All statuses</option>
              <option value="ACTIONABLE" ${statusDefault === "ACTIONABLE" ? "selected" : ""}>Actionable (OPEN + REQUESTED)</option>
              <option value="OPEN">OPEN only</option>
              <option value="REQUESTED">REQUESTED only</option>
              <option value="BOOKED">BOOKED only</option>
            </select>

            <select id="sort">
              <option value="newest" selected>Sort: Newest</option>
              <option value="rpm">Sort: RPM</option>
              <option value="rate">Sort: Rate</option>
              <option value="miles">Sort: Miles</option>
            </select>
          </div>

          <div class="threeCol">
            <input id="minMiles" placeholder="Min miles" />
            <input id="maxMiles" placeholder="Max miles" />
            <select id="quickpay">
              <option value="" selected>QuickPay: Any</option>
              <option value="1">QuickPay: Yes</option>
              <option value="0">QuickPay: No</option>
            </select>
          </div>

          <div class="threeCol">
            <input id="minWeight" placeholder="Min weight (lbs)" />
            <input id="maxWeight" placeholder="Max weight (lbs)" />
            <input id="minRate" placeholder="Min rate ($)" />
          </div>

          <div class="twoCol">
            <input id="maxRate" placeholder="Max rate ($)" />
            <div></div>
          </div>

          <div class="row" style="margin-top:6px">
            <button class="btn green" id="applyBtn" type="button">Apply Filters</button>
            <span class="badge" id="countBadge">Results: —</span>
          </div>

          <div class="small">Build: <span class="mono">${escapeHtml(BUILD_VERSION)}</span></div>
        </div>
      </div>

      <div class="card">
        <div class="row" style="justify-content:space-between;align-items:flex-end">
          <div>
            <h2 style="margin:0">Load Board</h2>
            <div class="muted">Transparent pricing, terms, and requirements up front.</div>
          </div>
          <div class="row">
            <a class="btn ghost" href="/terms">Terms</a>
            <a class="btn ghost" href="/privacy">Privacy</a>
          </div>
        </div>

        <div class="hr"></div>

        <div id="loads" class="loadList"></div>
      </div>
    </div>
  `;

  const extraScript = `
  <script>
  const statusDefault = ${JSON.stringify(statusDefault)};
  const els = (id) => document.getElementById(id);

  function qs(params){
    const sp = new URLSearchParams();
    for(const [k,v] of Object.entries(params)){
      if(v === undefined || v === null) continue;
      const s = String(v).trim();
      if(!s) continue;
      sp.set(k, s);
    }
    return sp.toString();
  }

  function dollars(n){
    const x = Number(n);
    if(!Number.isFinite(x)) return "";
    return "$" + x.toFixed(2);
  }
  function rpm(rate, miles){
    const r = Number(rate), m = Number(miles);
    if(!Number.isFinite(r) || !Number.isFinite(m) || m <= 0) return 0;
    return r / m;
  }

  function renderLoad(l){
    const r = rpm(l.rate_all_in, l.miles);
    const chip = (t)=> '<span class="chip">' + t + '</span>';
    const status = String(l.status || "OPEN");
    const rtxt = r ? ("$" + r.toFixed(2)) : "—";

    return \`
      <div class="loadCard">
        <div class="loadTop">
          <div>
            <div class="lane">#\${l.id} \${l.lane_from} → \${l.lane_to}</div>
            <div class="muted">\${l.pickup_date} → \${l.delivery_date}</div>
          </div>
          <div style="text-align:right">
            <div style="font-weight:1000;font-size:16px">\${dollars(l.rate_all_in)}</div>
            <div class="small mono">RPM: \${rtxt}</div>
          </div>
        </div>

        <div class="chips">
          \${chip(l.equipment)}
          \${chip(Number(l.miles).toLocaleString() + " mi")}
          \${chip(Number(l.weight_lbs).toLocaleString() + " lbs")}
          \${chip("Commodity: " + l.commodity)}
          \${chip("Terms: " + l.payment_terms)}
          \${l.quickpay_available ? chip("QuickPay") : ""}
          \${chip("Status: " + status)}
        </div>
      </div>
    \`;
  }

  async function loadData(){
    const params = {
      q: els("q").value,
      origin: els("origin").value,
      dest: els("dest").value,
      equipment: els("equipment").value,
      status: els("status").value,
      minMiles: els("minMiles").value,
      maxMiles: els("maxMiles").value,
      minWeight: els("minWeight").value,
      maxWeight: els("maxWeight").value,
      minRate: els("minRate").value,
      maxRate: els("maxRate").value,
      quickpay: els("quickpay").value,
      sort: els("sort").value
    };
    // if carrier default actionable and user never touched status, keep it
    if(!params.status && statusDefault) params.status = statusDefault;

    const url = "/api/loads?" + qs(params);
    const res = await fetch(url);
    const data = await res.json();

    const container = els("loads");
    container.innerHTML = "";

    els("countBadge").textContent = "Results: " + (data.count ?? 0);

    if(!data.ok){
      container.innerHTML = '<div class="muted">Failed to load loads.</div>';
      return;
    }
    if(!data.rows || data.rows.length === 0){
      container.innerHTML = '<div class="muted">No loads match your filters.</div>';
      return;
    }
    container.innerHTML = data.rows.map(renderLoad).join("");
  }

  els("applyBtn").addEventListener("click", loadData);
  els("resetBtn").addEventListener("click", () => {
    ["q","origin","dest","minMiles","maxMiles","minWeight","maxWeight","minRate","maxRate"].forEach(id => els(id).value = "");
    els("equipment").value = "";
    els("quickpay").value = "";
    els("sort").value = "newest";
    els("status").value = statusDefault || "";
    loadData();
  });

  // load on page open
  loadData();
  </script>
  `;

  res.send(layout({ title: "Load Board", user, body, extraScript }));
});

/* ---------- Start ---------- */
initDb()
  .then(() => app.listen(PORT, "0.0.0.0", () => console.log("Server running on port", PORT, "build", BUILD_VERSION)))
  .catch((e) => { console.error("DB init failed:", e); process.exit(1); });
