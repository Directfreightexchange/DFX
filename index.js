"use strict";

/* ============================================================
   Direct Freight Exchange (DFX) — single-file app
   - Green/Black theme
   - Roles: SHIPPER / CARRIER / ADMIN
   - Carrier verification docs required (W-9, COI, Authority)
   - Shipper subscription plans via Stripe (optional)
   - Stripe invoices/receipts download (optional)
   - Forgot password (email reset link via SMTP / SendGrid SMTP)
   - Rate Confirmation auto-fill after booking
   - Load board w/ equipment, miles, weight, RPM + sorting
   - Safe SQL params everywhere
   ============================================================ */

const express = require("express");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const multer = require("multer");
const Stripe = require("stripe");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

const app = express();

/* ---------------- Stripe webhook needs RAW body only on this route ---------------- */
app.post("/stripe/webhook", express.raw({ type: "application/json" }), (req, res, next) => next());

/* ---------------- Standard middleware ---------------- */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

/* ---------------- Config ---------------- */
const PORT = process.env.PORT || 3000;

const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;

const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;

// Stripe (optional)
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const STRIPE_PRICE_STARTER = process.env.STRIPE_PRICE_STARTER;
const STRIPE_PRICE_GROWTH = process.env.STRIPE_PRICE_GROWTH;
const STRIPE_PRICE_ENTERPRISE = process.env.STRIPE_PRICE_ENTERPRISE;

// Email (SMTP / SendGrid SMTP)
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = Number(process.env.SMTP_PORT || "587");
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const SMTP_FROM = process.env.SMTP_FROM || "no-reply@directfreightexchange.com";

// Admin bootstrap
const BOOTSTRAP_ADMIN_EMAIL = (process.env.BOOTSTRAP_ADMIN_EMAIL || "").trim().toLowerCase();

// Optional “Help” link (if you later want to link to a chat provider)
const HELP_CHAT_URL = (process.env.HELP_CHAT_URL || "").trim();

function bootFail(msg) {
  app.get("*", (_, res) => res.status(500).send(`<h1>Config error</h1><p>${escapeHtml(msg)}</p>`));
  app.listen(PORT, "0.0.0.0");
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

/* ---------------- DB ---------------- */
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

/* ---------------- Uploads ---------------- */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
});

/* ---------------- Plans ---------------- */
const PLANS = {
  STARTER: { label: "Starter", price: 99, limit: 15 },
  GROWTH: { label: "Growth", price: 199, limit: 30 },
  ENTERPRISE: { label: "Enterprise", price: 399, limit: -1 }, // unlimited
};

function priceIdForPlan(plan) {
  if (plan === "STARTER") return STRIPE_PRICE_STARTER;
  if (plan === "GROWTH") return STRIPE_PRICE_GROWTH;
  if (plan === "ENTERPRISE") return STRIPE_PRICE_ENTERPRISE;
  return null;
}

function planFromPriceId(priceId) {
  if (!priceId) return null;
  if (priceId === STRIPE_PRICE_STARTER) return "STARTER";
  if (priceId === STRIPE_PRICE_GROWTH) return "GROWTH";
  if (priceId === STRIPE_PRICE_ENTERPRISE) return "ENTERPRISE";
  return null;
}

function monthKey(d = new Date()) {
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  return `${y}-${m}`;
}

/* ---------------- Helpers ---------------- */
function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function qStr(v) {
  return String(v ?? "").trim();
}
function int(n) {
  const x = Number(n);
  if (!Number.isFinite(x)) return 0;
  return Math.trunc(x);
}
function money(n) {
  const x = Number(n);
  if (!Number.isFinite(x)) return "";
  return `$${x.toFixed(2)}`;
}
function rpm(rateAllIn, miles) {
  const r = Number(rateAllIn);
  const m = Number(miles);
  if (!Number.isFinite(r) || !Number.isFinite(m) || m <= 0) return NaN;
  return r / m;
}
function sha256Hex(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}
function randomToken() {
  return crypto.randomBytes(32).toString("hex");
}

/* ---------------- Auth (JWT cookie) ---------------- */
function signIn(res, user) {
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: "7d" });

  // secure cookies only on HTTPS in production
  const isProd = String(process.env.NODE_ENV || "").toLowerCase() === "production";
  res.cookie("dfx_token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: isProd, // Render is HTTPS, but keep dev-friendly
  });
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

/* ---------------- Email (SMTP / SendGrid SMTP) ---------------- */
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

/* ---------------- UI (Green/Black) ---------------- */
const DISCLAIMER_TEXT =
  "Direct Freight Exchange is a technology platform and is not a broker or carrier. Users are responsible for verifying compliance, insurance, and payment terms.";

function layout({ title, user, body }) {
  const helpButton = `
    <a class="helpFab" href="/help" title="Help">Help</a>
  `;

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
          <a href="/terms">Terms / Disclaimer</a>
          <a href="/health">Status</a>
        </div>
      </div>
      <div class="footDisclaimer">${escapeHtml(DISCLAIMER_TEXT)}</div>
    </div>
  `;

  return `<!doctype html>
<html><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${escapeHtml(title)}</title>
<style>
:root{
  --bg:#050607;
  --panel:#0b0f10;
  --card:#0d1412;
  --line:rgba(255,255,255,.10);
  --text:#eef7f1;
  --muted:rgba(238,247,241,.68);

  --green:#22c55e;
  --green2:#16a34a;
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
.wrap{max-width:1200px;margin:0 auto;padding:22px}
a{color:var(--lime);text-decoration:none} a:hover{text-decoration:underline}

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
.btn.primary{
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
.small{font-size:12px;color:var(--muted)}
.hr{height:1px;background:rgba(255,255,255,.10);margin:14px 0;border:0}

.grid{display:grid;gap:16px;grid-template-columns:1.1fr .9fr;margin-top:16px}
@media(max-width:980px){.grid{grid-template-columns:1fr}.nav{position:static}.title{font-size:38px}}

.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.filters{display:grid;gap:10px;grid-template-columns:1.2fr 1.2fr 1fr 1fr 1fr}
@media(max-width:980px){.filters{grid-template-columns:1fr 1fr}}
input,select,textarea{
  width:100%;padding:12px;border-radius:12px;border:1px solid var(--line);
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
.load{margin-top:12px;padding:14px;border-radius:16px;border:1px solid rgba(255,255,255,.08);background:rgba(6,8,9,.62)}
.loadTop{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
.lane{font-weight:1000}
.kv{display:grid;grid-template-columns:210px 1fr;gap:6px;margin-top:10px}
@media(max-width:780px){.kv{grid-template-columns:1fr}}
.k{color:var(--muted)}

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

.helpFab{
  position:fixed; right:18px; bottom:18px; z-index:50;
  padding:12px 14px; border-radius:999px;
  border:1px solid rgba(163,230,53,.25);
  background:rgba(6,8,9,.75); color:var(--text);
  backdrop-filter: blur(10px);
  box-shadow: var(--shadow);
  font-weight:800;
}
.helpFab:hover{filter:brightness(1.06)}
</style>
</head>
<body>
${helpButton}
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
      ${
        user
          ? `<span class="pill">${escapeHtml(user.role)}</span><span class="pill">${escapeHtml(
              user.email
            )}</span><a class="btn primary" href="/dashboard">Dashboard</a><a class="btn ghost" href="/logout">Logout</a>`
          : `<a class="btn ghost" href="/signup">Sign up</a><a class="btn primary" href="/login">Login</a>`
      }
    </div>
  </div>

  ${body}
  ${footer}
</div>
</body></html>`;
}

/* ---------------- DB init + safe migrations (FIXES YOUR token_hash ERROR) ---------------- */
async function initDb() {
  // Create base tables
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
      w9_filename TEXT,
      insurance_filename TEXT,
      authority_filename TEXT,
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
      detention_rate_per_hr NUMERIC NOT NULL,
      detention_after_hours INTEGER NOT NULL,
      appointment_type TEXT NOT NULL,
      accessorials TEXT NOT NULL,
      special_requirements TEXT NOT NULL,
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
      token_hash TEXT,
      expires_at TIMESTAMPTZ,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // ✅ Safe migrations for older DBs (prevents “token_hash does not exist”)
  await pool.query(`ALTER TABLE password_resets ADD COLUMN IF NOT EXISTS token_hash TEXT;`);
  await pool.query(`ALTER TABLE password_resets ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;`);
  await pool.query(`ALTER TABLE password_resets ADD COLUMN IF NOT EXISTS used_at TIMESTAMPTZ;`);
  await pool.query(`ALTER TABLE password_resets ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();`);

  // Indexes (safe)
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_password_resets_user_id ON password_resets(user_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_password_resets_token_hash ON password_resets(token_hash);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_loads_created_at ON loads(created_at DESC);`);
}

/* ---------------- Admin bootstrap ---------------- */
async function bootstrapAdminIfNeeded() {
  if (!BOOTSTRAP_ADMIN_EMAIL) return;
  try {
    const r = await pool.query(`UPDATE users SET role='ADMIN' WHERE email=$1 RETURNING id,email,role`, [
      BOOTSTRAP_ADMIN_EMAIL,
    ]);
    if (r.rows[0]) {
      console.log("[BOOTSTRAP_ADMIN] set ADMIN for:", r.rows[0].email);
    } else {
      console.log("[BOOTSTRAP_ADMIN] email not found:", BOOTSTRAP_ADMIN_EMAIL);
    }
  } catch (e) {
    console.error("[BOOTSTRAP_ADMIN] failed:", e);
  }
}

/* ---------------- Terms ---------------- */
app.get("/terms", (req, res) => {
  const user = getUser(req);
  const body = `
    <div class="card">
      <h2 style="margin-top:0">Terms / Disclaimer</h2>
      <div class="hr"></div>
      <div class="muted" style="line-height:1.55">
        <p><b>Platform Disclaimer</b></p>
        <p>${escapeHtml(DISCLAIMER_TEXT)}</p>

        <p><b>User Responsibilities</b></p>
        <ul>
          <li>Carriers are responsible for maintaining valid authority, insurance, and compliance documentation.</li>
          <li>Shippers are responsible for verifying carrier compliance, insurance, and suitability for the load.</li>
          <li>All parties are responsible for reviewing and agreeing to payment terms, detention terms, accessorials, and load requirements.</li>
        </ul>

        <p><b>No Legal / Financial Advice</b></p>
        <p>DFX does not provide legal, regulatory, insurance, or financial advice. Consult qualified professionals as needed.</p>
      </div>
    </div>
  `;
  res.send(layout({ title: "Terms", user, body }));
});

/* ---------------- Help page ---------------- */
app.get("/help", (req, res) => {
  const user = getUser(req);
  const body = `
    <div class="card">
      <h2 style="margin-top:0">Help</h2>
      <div class="muted">Need help right now? Contact support:</div>
      <div class="hr"></div>
      <div class="row">
        <span class="badge brand">Email: support@directfreightexchange.com</span>
        <span class="badge">Hours: Mon–Fri</span>
      </div>
      <div class="hr"></div>
      ${
        HELP_CHAT_URL
          ? `<a class="btn primary" href="${escapeHtml(HELP_CHAT_URL)}" target="_blank" rel="noopener">Chat with live agent</a>`
          : `<div class="muted small">Live chat link not configured yet. (Optional: set HELP_CHAT_URL in Render Environment)</div>`
      }
      <div class="hr"></div>
      <a class="btn ghost" href="/">Back</a>
    </div>
  `;
  res.send(layout({ title: "Help", user, body }));
});

/* ---------------- Home ---------------- */
app.get("/", (req, res) => {
  const user = getUser(req);
  const body = `
    <div class="hero">
      <div class="heroInner">
        <div class="row">
          <span class="badge brand">All-In Pricing</span>
          <span class="badge brand">Carrier Verified</span>
          <span class="badge brand">Direct Booking</span>
        </div>

        <h2 class="title" style="margin-top:12px">No hidden rates. No phone calls. No broker games.</h2>
        <div class="muted" style="max-width:880px">
          DFX connects shippers and carriers directly with fully transparent loads:
          <b>all-in rate</b>, <b>payment terms</b>, <b>detention</b>, <b>accessorials</b>, appointment type, and notes —
          visible up front so carriers can commit fast and shippers can book with confidence.
        </div>

        <div class="hr"></div>

        <div class="row">
          <a class="btn primary" href="${user ? "/dashboard" : "/signup"}">${user ? "Go to Dashboard" : "Create account"}</a>
          <a class="btn ghost" href="/loads">Browse Load Board</a>
          <a class="btn ghost" href="/terms">Terms / Disclaimer</a>
        </div>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <h3 style="margin-top:0">For Shippers</h3>
        <div class="muted">
          Post loads with everything included — rate, terms, detention, accessorials — so carriers can book faster.
          Choose a plan based on your monthly volume.
        </div>
        <div class="hr"></div>
        <div class="row">
          <span class="badge ok">Starter: 15 loads</span>
          <span class="badge ok">Growth: 30 loads</span>
          <span class="badge ok">Enterprise: Unlimited</span>
          ${
            user?.role === "SHIPPER"
              ? `<a class="btn primary" href="/shipper/plans">View Plans</a>`
              : `<a class="btn primary" href="/signup">Sign up as Shipper</a>`
          }
        </div>
      </div>

      <div class="card">
        <h3 style="margin-top:0">For Carriers</h3>
        <div class="muted">
          Free access to transparent loads. Submit verification documents once, get approved, and request loads directly.
        </div>
        <div class="hr"></div>
        <div class="row">
          <span class="badge brand">Verified badge</span>
          <span class="badge brand">Request-to-Book</span>
          <span class="badge brand">Transparent terms</span>
        </div>
      </div>
    </div>
  `;
  res.send(layout({ title: "DFX", user, body }));
});

/* ---------------- Signup/Login/Logout ---------------- */
app.get("/signup", (req, res) => {
  const user = getUser(req);
  res.send(
    layout({
      title: "Sign up",
      user,
      body: `<div class="card">
        <h2 style="margin-top:0">Sign up</h2>
        <div class="muted">Carriers are free. Shippers subscribe to post loads.</div>
        <div class="hr"></div>
        <form method="POST" action="/signup">
          <div class="filters" style="grid-template-columns:1.2fr 1.2fr 1fr 1fr 1fr">
            <input name="email" type="email" placeholder="Email" required />
            <input name="password" type="password" placeholder="Password (min 8 chars)" minlength="8" required />
            <select name="role" required>
              <option value="SHIPPER">Shipper</option>
              <option value="CARRIER">Carrier (free)</option>
            </select>
            <button class="btn primary" type="submit">Create</button>
            <a class="btn ghost" href="/login">Login</a>
          </div>
        </form>
      </div>`,
    })
  );
});

app.post("/signup", async (req, res) => {
  try {
    const email = qStr(req.body.email).toLowerCase();
    const password = String(req.body.password || "");
    const role = qStr(req.body.role || "SHIPPER").toUpperCase();

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
      await pool.query(
        `INSERT INTO carriers_compliance (carrier_id,status) VALUES ($1,'PENDING') ON CONFLICT DO NOTHING`,
        [r.rows[0].id]
      );
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
  res.send(
    layout({
      title: "Login",
      user,
      body: `<div class="card">
        <h2 style="margin-top:0">Login</h2>
        <form method="POST" action="/login">
          <div class="filters" style="grid-template-columns:1.2fr 1.2fr 1fr 1fr 1fr">
            <input name="email" type="email" placeholder="Email" required />
            <input name="password" type="password" placeholder="Password" required />
            <button class="btn primary" type="submit">Login</button>
            <a class="btn ghost" href="/signup">Create</a>
            <a class="btn ghost" href="/loads">Load Board</a>
          </div>
        </form>
        <div class="hr"></div>
        <a class="btn ghost" href="/forgot">Forgot password?</a>
      </div>`,
    })
  );
});

app.post("/login", async (req, res) => {
  try {
    const email = qStr(req.body.email).toLowerCase();
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

app.get("/logout", (req, res) => {
  res.clearCookie("dfx_token");
  res.redirect("/");
});

/* ---------------- Forgot password ---------------- */
app.get("/forgot", (req, res) => {
  const user = getUser(req);
  res.send(
    layout({
      title: "Forgot Password",
      user,
      body: `<div class="card">
        <h2 style="margin-top:0">Reset Password</h2>
        <div class="muted">Enter your email and we’ll send a reset link.</div>
        <div class="hr"></div>
        <form method="POST" action="/forgot">
          <div class="filters" style="grid-template-columns:1.4fr 1fr">
            <input name="email" type="email" placeholder="Email" required />
            <button class="btn primary" type="submit">Send Link</button>
          </div>
        </form>
      </div>`,
    })
  );
});

app.post("/forgot", async (req, res) => {
  const user = getUser(req);
  const email = qStr(req.body.email).toLowerCase();

  const okMsg = `<div class="card"><h2 style="margin-top:0">Check your email</h2>
    <div class="muted">If an account exists for that email, a reset link was sent.</div>
    <div class="hr"></div><a class="btn primary" href="/login">Back to login</a></div>`;

  try {
    const r = await pool.query(`SELECT id,email FROM users WHERE email=$1`, [email]);
    const u = r.rows[0];
    if (!u) return res.send(layout({ title: "Reset Sent", user, body: okMsg }));

    const token = randomToken();
    const tokenHash = sha256Hex(token);
    const expires = new Date(Date.now() + 1000 * 60 * 30); // 30 minutes

    await pool.query(
      `INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES ($1,$2,$3)`,
      [u.id, tokenHash, expires]
    );

    const link = `${APP_URL.replace(/\/+$/, "")}/reset?token=${token}`;
    await sendEmail(
      u.email,
      "DFX Password Reset",
      `<p>Click to reset your password:</p>
       <p><a href="${escapeHtml(link)}">${escapeHtml(link)}</a></p>
       <p>This link expires in 30 minutes.</p>`
    );

    return res.send(layout({ title: "Reset Sent", user, body: okMsg }));
  } catch (e) {
    console.error(e);
    return res.send(layout({ title: "Reset Sent", user, body: okMsg }));
  }
});

app.get("/reset", (req, res) => {
  const user = getUser(req);
  const token = qStr(req.query.token);
  res.send(
    layout({
      title: "Set New Password",
      user,
      body: `<div class="card">
        <h2 style="margin-top:0">Set New Password</h2>
        <div class="muted">Choose a new password.</div>
        <div class="hr"></div>
        <form method="POST" action="/reset">
          <input type="hidden" name="token" value="${escapeHtml(token)}" />
          <div class="filters" style="grid-template-columns:1.4fr 1fr">
            <input name="password" type="password" placeholder="New password (min 8 chars)" minlength="8" required />
            <button class="btn primary" type="submit">Update</button>
          </div>
        </form>
      </div>`,
    })
  );
});

app.post("/reset", async (req, res) => {
  const user = getUser(req);
  const token = qStr(req.body.token);
  const password = String(req.body.password || "");
  if (!token || password.length < 8) return res.status(400).send("Invalid request.");

  try {
    const tokenHash = sha256Hex(token);
    const r = await pool.query(
      `SELECT pr.id, pr.user_id
       FROM password_resets pr
       WHERE pr.token_hash=$1 AND pr.used_at IS NULL AND pr.expires_at > NOW()
       ORDER BY pr.created_at DESC
       LIMIT 1`,
      [tokenHash]
    );
    const pr = r.rows[0];
    if (!pr) return res.status(400).send("Reset link invalid or expired.");

    const hash = await bcrypt.hash(password, 12);
    await pool.query(`UPDATE users SET password_hash=$1 WHERE id=$2`, [hash, pr.user_id]);
    await pool.query(`UPDATE password_resets SET used_at=NOW() WHERE id=$1`, [pr.id]);

    res.send(
      layout({
        title: "Password Updated",
        user,
        body: `<div class="card"><h2 style="margin-top:0">Updated ✅</h2>
          <div class="muted">Your password was updated. You can log in now.</div>
          <div class="hr"></div><a class="btn primary" href="/login">Login</a></div>`,
      })
    );
  } catch (e) {
    console.error(e);
    res.status(500).send("Reset failed.");
  }
});

/* ---------------- Billing helpers ---------------- */
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
    await pool.query(`UPDATE shippers_billing SET usage_month=$1, loads_used=0, updated_at=NOW() WHERE shipper_id=$2`, [
      nowM,
      shipperId,
    ]);
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

async function upsertBillingFromSubscription({ shipperId, customerId, subscriptionId, subStatus, priceId }) {
  const plan = planFromPriceId(priceId);
  const planDef = plan ? PLANS[plan] : null;
  const mapped =
    subStatus === "active" ? "ACTIVE" : subStatus === "past_due" ? "PAST_DUE" : subStatus === "canceled" ? "CANCELED" : "INACTIVE";

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

/* ---------------- Stripe: plans page ---------------- */
app.get("/shipper/plans", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  const user = req.user;
  const bill = await pool.query(`SELECT * FROM shippers_billing WHERE shipper_id=$1`, [user.id]);
  const b = bill.rows[0] || null;

  const nowMonth = monthKey();
  const usageMonth = b?.usage_month || nowMonth;
  const used = b?.loads_used ?? 0;
  const limit = b?.monthly_limit ?? 0;
  const plan = b?.plan || null;
  const status = b?.status || "INACTIVE";

  const usageText = limit === -1 ? `Unlimited` : `${used} / ${limit} used this month`;

  const body = `
    <div class="card">
      <h2 style="margin-top:0">Shipper Plans</h2>
      <div class="muted">Immediate upgrades (prorated). Posting requires ACTIVE subscription.</div>
      <div class="hr"></div>

      <div class="row">
        <span class="badge ${status === "ACTIVE" ? "ok" : "warn"}">Status: ${escapeHtml(status)}</span>
        <span class="badge">Plan: ${escapeHtml(plan || "None")}</span>
        <span class="badge">Month: ${escapeHtml(usageMonth)}</span>
        <span class="badge brand">${escapeHtml(usageText)}</span>
      </div>

      ${
        !stripeEnabled
          ? `<div class="hr"></div><div class="badge warn">Stripe not configured (add STRIPE_* env vars in Render).</div>`
          : `<div class="hr"></div>
             <div class="grid">
               ${Object.keys(PLANS)
                 .map((p) => {
                   const pd = PLANS[p];
                   const isCurrent = plan === p && status === "ACTIVE";
                   const capText = pd.limit === -1 ? "Unlimited loads" : `${pd.limit} loads / month`;
                   return `
                     <div class="card" style="margin-top:0">
                       <div class="row" style="justify-content:space-between">
                         <div>
                           <div style="font-weight:1000;font-size:18px">${escapeHtml(pd.label)}</div>
                           <div class="muted">${capText}</div>
                         </div>
                         <div style="font-weight:1000;font-size:18px">$${pd.price}/mo</div>
                       </div>
                       <div class="hr"></div>
                       ${
                         isCurrent
                           ? `<span class="badge ok">Current plan</span>`
                           : `<form method="POST" action="/shipper/plan">
                                <input type="hidden" name="plan" value="${p}">
                                <button class="btn primary" type="submit">${status === "ACTIVE" ? "Switch immediately" : "Subscribe"}</button>
                              </form>`
                       }
                     </div>`;
                 })
                 .join("")}
             </div>`
      }
    </div>
  `;
  res.send(layout({ title: "Plans", user, body }));
});

app.post("/shipper/plan", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  if (!stripeEnabled) return res.status(400).send("Stripe not configured.");

  const plan = qStr(req.body.plan).toUpperCase();
  if (!PLANS[plan]) return res.status(400).send("Invalid plan.");
  const targetPriceId = priceIdForPlan(plan);

  const bill = await pool.query(`SELECT * FROM shippers_billing WHERE shipper_id=$1`, [req.user.id]);
  const b = bill.rows[0];

  if (!b?.stripe_subscription_id || b.status !== "ACTIVE") {
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      line_items: [{ price: targetPriceId, quantity: 1 }],
      success_url: `${APP_URL}/dashboard?sub=success`,
      cancel_url: `${APP_URL}/shipper/plans?sub=cancel`,
      customer_email: req.user.email,
      metadata: { shipper_id: String(req.user.id) },
    });
    return res.redirect(303, session.url);
  }

  const sub = await stripe.subscriptions.retrieve(b.stripe_subscription_id);
  const item = sub.items?.data?.[0];
  if (!item) return res.status(400).send("Subscription item not found.");

  await stripe.subscriptions.update(b.stripe_subscription_id, {
    items: [{ id: item.id, price: targetPriceId }],
    proration_behavior: "create_prorations",
  });

  const planDef = PLANS[plan];
  await pool.query(`UPDATE shippers_billing SET plan=$1, monthly_limit=$2, updated_at=NOW() WHERE shipper_id=$3`, [
    plan,
    planDef.limit,
    req.user.id,
  ]);

  res.redirect("/shipper/plans?switched=1");
});

/* ---------------- Stripe invoices/receipts download ---------------- */
app.get("/shipper/billing", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  if (!stripeEnabled) return res.status(400).send("Stripe not configured.");

  const user = req.user;
  const bill = await pool.query(`SELECT * FROM shippers_billing WHERE shipper_id=$1`, [user.id]);
  const b = bill.rows[0];
  if (!b?.stripe_customer_id) {
    return res.send(
      layout({
        title: "Billing",
        user,
        body: `<div class="card"><h2 style="margin-top:0">Billing</h2>
          <div class="muted">No Stripe customer yet. Subscribe to a plan first.</div>
          <div class="hr"></div><a class="btn primary" href="/shipper/plans">View Plans</a></div>`,
      })
    );
  }

  const invoices = await stripe.invoices.list({ customer: b.stripe_customer_id, limit: 50 });

  const body = `
    <div class="card">
      <h2 style="margin-top:0">Invoices & Receipts</h2>
      <div class="muted">Download receipts for accounting.</div>
      <div class="hr"></div>
      ${
        invoices.data.length
          ? invoices.data
              .map((inv) => {
                const amount = (inv.amount_paid ?? inv.amount_due ?? 0) / 100;
                const status = inv.status || "unknown";
                const url = inv.hosted_invoice_url || inv.invoice_pdf || "";
                const date = inv.created ? new Date(inv.created * 1000).toISOString().slice(0, 10) : "";
                return `
                  <div class="load">
                    <div class="row" style="justify-content:space-between">
                      <div><b>${escapeHtml(inv.number || inv.id)}</b></div>
                      <span class="badge ${status === "paid" ? "ok" : "warn"}">${escapeHtml(status)}</span>
                    </div>
                    <div class="muted">Amount: ${money(amount)} • Date: ${escapeHtml(date)}</div>
                    <div class="row" style="margin-top:10px">
                      ${
                        url
                          ? `<a class="btn primary" href="${escapeHtml(url)}" target="_blank" rel="noopener">Download</a>`
                          : `<span class="badge warn">No download link</span>`
                      }
                    </div>
                  </div>`;
              })
              .join("")
          : `<div class="muted">No invoices yet.</div>`
      }
      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/dashboard">Back</a>
        <a class="btn ghost" href="/shipper/plans">Plans</a>
      </div>
    </div>
  `;
  res.send(layout({ title: "Billing", user, body }));
});

/* ---------------- Stripe webhook handler ---------------- */
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

    if (
      event.type === "customer.subscription.created" ||
      event.type === "customer.subscription.updated" ||
      event.type === "customer.subscription.deleted"
    ) {
      const sub = event.data.object;
      const subscriptionId = sub.id;
      const customerId = sub.customer;
      const priceId = sub.items?.data?.[0]?.price?.id;

      const row = await pool.query(`SELECT shipper_id FROM shippers_billing WHERE stripe_subscription_id=$1`, [
        subscriptionId,
      ]);
      const shipperId =
        row.rows[0]?.shipper_id ||
        (await pool.query(`SELECT shipper_id FROM shippers_billing WHERE stripe_customer_id=$1`, [customerId])).rows[0]
          ?.shipper_id;

      if (shipperId) {
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
    console.error("Webhook handler failed:", e);
    res.sendStatus(500);
  }
});

/* ---------------- Rate Confirmation (auto-filled) ---------------- */
function renderRateConfirmationHtml({ load, shipperEmail, carrierEmail }) {
  const rpmVal = rpm(load.rate_all_in, load.miles);
  return `<!doctype html><html><head><meta charset="utf-8"><title>Rate Confirmation</title>
  <style>
    body{font-family:Arial, sans-serif; padding:24px; line-height:1.35}
    h1{margin:0 0 10px 0}
    .muted{color:#555}
    table{width:100%; border-collapse:collapse; margin-top:14px}
    td,th{border:1px solid #ddd; padding:10px; vertical-align:top}
    th{background:#f6f6f6; text-align:left}
  </style></head><body>
  <h1>Rate Confirmation</h1>
  <div class="muted">Direct Freight Exchange (DFX) • Load #${load.id}</div>

  <table>
    <tr><th>Shipper</th><td>${escapeHtml(shipperEmail)}</td></tr>
    <tr><th>Carrier</th><td>${escapeHtml(carrierEmail || "TBD")}</td></tr>
  </table>

  <table>
    <tr><th>Lane</th><td>${escapeHtml(load.lane_from)} → ${escapeHtml(load.lane_to)}</td></tr>
    <tr><th>Pickup</th><td>${escapeHtml(load.pickup_date)}</td></tr>
    <tr><th>Delivery</th><td>${escapeHtml(load.delivery_date)}</td></tr>
    <tr><th>Equipment</th><td>${escapeHtml(load.equipment)}</td></tr>
    <tr><th>Commodity</th><td>${escapeHtml(load.commodity)}</td></tr>
    <tr><th>Weight</th><td>${int(load.weight_lbs).toLocaleString()} lbs</td></tr>
    <tr><th>Miles</th><td>${int(load.miles).toLocaleString()} mi</td></tr>
    <tr><th>Rate (All-In)</th><td>${money(load.rate_all_in)} (${Number.isFinite(rpmVal) ? rpmVal.toFixed(2) : "—"} RPM)</td></tr>
    <tr><th>Payment Terms</th><td>${escapeHtml(load.payment_terms)}${load.quickpay_available ? " • QuickPay" : ""}</td></tr>
    <tr><th>Detention</th><td>${money(load.detention_rate_per_hr)}/hr after ${escapeHtml(load.detention_after_hours)} hours</td></tr>
    <tr><th>Accessorials</th><td>${escapeHtml(load.accessorials)}</td></tr>
    <tr><th>Appointment Type</th><td>${escapeHtml(load.appointment_type)}</td></tr>
    <tr><th>Special Requirements</th><td>${escapeHtml(load.special_requirements)}</td></tr>
  </table>

  <p><b>Carrier Acceptance</b></p>
  <p>By hauling this load, Carrier agrees to the above terms and confirms it maintains valid operating authority and insurance.</p>

  <p style="margin-top:24px">Carrier Signature: ______________________ Date: _____________</p>
  <p>Shipper Signature: ______________________ Date: _____________</p>
  </body></html>`;
}

/* ---------------- Dashboard ---------------- */
app.get("/dashboard", requireAuth, async (req, res) => {
  const user = req.user;

  try {
    if (user.role === "SHIPPER") {
      const billing = await getAndNormalizeBilling(user.id);
      const gate = postingAllowed(billing);

      const planLabel = billing.plan ? PLANS[billing.plan]?.label : "None";
      const limitText =
        billing.monthly_limit === -1 ? "Unlimited" : `${billing.loads_used} / ${billing.monthly_limit} used this month`;

      const myLoads = await pool.query(`SELECT * FROM loads WHERE shipper_id=$1 ORDER BY created_at DESC`, [user.id]);

      const requests = await pool.query(
        `
        SELECT lr.id as request_id, lr.status as request_status, lr.created_at,
               lr.carrier_id,
               l.id as load_id, l.lane_from, l.lane_to,
               u.email as carrier_email,
               cc.status as carrier_compliance
        FROM load_requests lr
        JOIN loads l ON l.id = lr.load_id
        JOIN users u ON u.id = lr.carrier_id
        LEFT JOIN carriers_compliance cc ON cc.carrier_id = lr.carrier_id
        WHERE l.shipper_id=$1
        ORDER BY lr.created_at DESC
      `,
        [user.id]
      );

      const body = `
        <div class="grid">
          <div class="card">
            <div class="row" style="justify-content:space-between">
              <div>
                <h2 style="margin:0">Shipper Dashboard</h2>
                <div class="muted">All-in pricing. Transparent terms. Fast booking.</div>
              </div>
              <span class="badge ${billing.status === "ACTIVE" ? "ok" : "warn"}">Billing: ${escapeHtml(
        billing.status
      )}</span>
            </div>

            <div class="hr"></div>

            <div class="row">
              <span class="badge">Plan: ${escapeHtml(planLabel)}</span>
              <span class="badge brand">${escapeHtml(limitText)}</span>
              <a class="btn primary" href="/shipper/plans">Manage Plan</a>
              ${stripeEnabled ? `<a class="btn ghost" href="/shipper/billing">Invoices & Receipts</a>` : ``}
            </div>

            <div class="hr"></div>

            <h3 style="margin:0 0 10px 0">Post a transparent load</h3>

            ${
              gate.ok
                ? `
              <form method="POST" action="/shipper/loads">
                <div class="filters" style="grid-template-columns:1.3fr 1.3fr 1fr 1fr 1fr 1fr 1fr">
                  <input name="lane_from" placeholder="From (City, ST)" required />
                  <input name="lane_to" placeholder="To (City, ST)" required />
                  <input name="pickup_date" placeholder="Pickup date (YYYY-MM-DD)" required />
                  <input name="delivery_date" placeholder="Delivery date (YYYY-MM-DD)" required />
                  <select name="equipment" required>
                    <option>Dry Van</option>
                    <option>Standard Van</option>
                    <option>Reefer</option>
                    <option>Flatbed</option>
                    <option>Power Only</option>
                    <option>Stepdeck</option>
                  </select>
                  <input name="commodity" placeholder="Commodity" value="General Freight" required />

                  <input name="weight_lbs" type="number" placeholder="Weight (lbs)" value="42000" required />
                  <input name="miles" type="number" placeholder="Miles" value="800" required />
                  <input name="rate_all_in" type="number" step="0.01" placeholder="All-in rate ($)" value="2500" required />
                  <select name="payment_terms" required>
                    <option value="NET 30">NET 30 (default)</option>
                    <option value="NET 15">NET 15</option>
                    <option value="NET 45">NET 45</option>
                    <option value="QuickPay">QuickPay</option>
                  </select>
                  <select name="quickpay_available" required>
                    <option value="false">QuickPay Available? No</option>
                    <option value="true">QuickPay Available? Yes</option>
                  </select>
                  <input name="detention_rate_per_hr" type="number" step="0.01" placeholder="Detention $/hr" value="75" required />
                  <input name="detention_after_hours" type="number" placeholder="Detention after (hours)" value="2" required />
                  <select name="appointment_type" required>
                    <option value="FCFS">Appointment: FCFS</option>
                    <option value="Appt Required">Appointment: Appt Required</option>
                  </select>
                  <input name="accessorials" placeholder="Accessorials" value="None" required />
                  <input name="special_requirements" placeholder="Notes" value="None" required />
                </div>
                <div class="row" style="margin-top:12px">
                  <button class="btn primary" type="submit">Post Load</button>
                  <a class="btn ghost" href="/loads">View Load Board</a>
                </div>
              </form>
            `
                : `
              <div class="badge warn">Posting blocked: ${escapeHtml(gate.reason)}</div>
              <div class="row" style="margin-top:10px">
                <a class="btn primary" href="/shipper/plans">Upgrade / Subscribe</a>
              </div>
            `
            }

            <div class="hr"></div>
            <h3 style="margin:0 0 10px 0">Contracts</h3>
            <div class="muted">After booking, download an auto-filled Rate Confirmation for that load.</div>
          </div>

          <div class="card">
            <h3 style="margin-top:0">Booking Requests</h3>
            <div class="muted">Carrier requests → you accept/decline → load becomes BOOKED.</div>
            <div class="hr"></div>
            ${
              requests.rows.length
                ? requests.rows
                    .map(
                      (r) => `
                <div class="load">
                  <div class="row" style="justify-content:space-between">
                    <div><b>Load #${r.load_id}</b> ${escapeHtml(r.lane_from)} → ${escapeHtml(r.lane_to)}</div>
                    <span class="badge ${
                      r.request_status === "REQUESTED" ? "warn" : r.request_status === "ACCEPTED" ? "ok" : ""
                    }">${escapeHtml(r.request_status)}</span>
                  </div>
                  <div class="muted">Carrier: ${escapeHtml(r.carrier_email)} • Verification: ${escapeHtml(
                        r.carrier_compliance || "PENDING"
                      )}</div>
                  ${
                    r.request_status === "REQUESTED"
                      ? `
                      <div class="row" style="margin-top:10px">
                        <form method="POST" action="/shipper/requests/${r.request_id}/accept"><button class="btn primary" type="submit">Accept</button></form>
                        <form method="POST" action="/shipper/requests/${r.request_id}/decline"><button class="btn ghost" type="submit">Decline</button></form>
                      </div>`
                      : ``
                  }
                </div>
              `
                    )
                    .join("")
                : `<div class="muted">No requests yet.</div>`
            }
          </div>
        </div>

        <div class="card">
          <h3 style="margin-top:0">Your Loads</h3>
          <div class="hr"></div>
          ${
            myLoads.rows.length
              ? myLoads.rows
                  .map((l) => loadCard(l, user, null, { showContract: true }))
                  .join("")
              : `<div class="muted">No loads yet.</div>`
          }
        </div>
      `;

      return res.send(layout({ title: "Dashboard", user, body }));
    }

    if (user.role === "CARRIER") {
      const comp = await pool.query(`SELECT * FROM carriers_compliance WHERE carrier_id=$1`, [user.id]);
      const c = comp.rows[0] || { status: "PENDING" };

      const myReqs = await pool.query(
        `
        SELECT lr.*, l.lane_from, l.lane_to, l.status as load_status
        FROM load_requests lr
        JOIN loads l ON l.id = lr.load_id
        WHERE lr.carrier_id=$1
        ORDER BY lr.created_at DESC
      `,
        [user.id]
      );

      const body = `
        <div class="grid">
          <div class="card">
            <div class="row" style="justify-content:space-between">
              <div>
                <h2 style="margin:0">Carrier Dashboard</h2>
                <div class="muted">Submit verification documents to earn the Verified badge.</div>
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

            <div class="hr"></div>

            <form method="POST" action="/carrier/compliance" enctype="multipart/form-data">
              <div class="filters" style="grid-template-columns:1.2fr 1fr 1fr 1fr 1fr">
                <input name="insurance_expires" placeholder="Insurance expires (YYYY-MM-DD)" value="${escapeHtml(
                  c.insurance_expires || ""
                )}" required />
                <input type="file" name="w9" accept="application/pdf,image/*" required />
                <input type="file" name="insurance" accept="application/pdf,image/*" required />
                <input type="file" name="authority" accept="application/pdf,image/*" required />
                <button class="btn primary" type="submit">Submit for Verification</button>
              </div>
              <div class="muted small" style="margin-top:10px">For production: store docs in S3 (optional upgrade).</div>
            </form>

            <div class="hr"></div>
            ${
              c.status === "APPROVED"
                ? `<span class="badge ok">Verified — you can request loads.</span>`
                : `<span class="badge warn">You must be Verified to request loads.</span>`
            }
          </div>

          <div class="card">
            <h3 style="margin-top:0">Your Requests</h3>
            <div class="hr"></div>
            ${
              myReqs.rows.length
                ? myReqs.rows
                    .map(
                      (r) => `
                <div class="load">
                  <div class="row" style="justify-content:space-between">
                    <div><b>Load #${r.load_id}</b> ${escapeHtml(r.lane_from)} → ${escapeHtml(r.lane_to)}</div>
                    <span class="badge ${
                      r.status === "REQUESTED" ? "warn" : r.status === "ACCEPTED" ? "ok" : ""
                    }">${escapeHtml(r.status)}</span>
                  </div>
                  <div class="muted">Load status: ${escapeHtml(r.load_status)}</div>
                </div>
              `
                    )
                    .join("")
                : `<div class="muted">No requests yet.</div>`
            }
          </div>
        </div>

        <div class="card">
          <h3 style="margin-top:0">Find Loads</h3>
          <div class="muted">Default is Newest; you can switch to RPM sorting on the Load Board.</div>
          <div class="hr"></div>
          <a class="btn primary" href="/loads">Go to Load Board</a>
        </div>
      `;
      return res.send(layout({ title: "Carrier", user, body }));
    }

    // ADMIN
    const pending = await pool.query(
      `
      SELECT cc.*, u.email
      FROM carriers_compliance cc
      JOIN users u ON u.id = cc.carrier_id
      WHERE cc.status='PENDING'
      ORDER BY cc.updated_at DESC
    `
    );

    const body = `
      <div class="card">
        <h2 style="margin-top:0">Admin — Carrier Verifications</h2>
        <div class="muted">Approve carriers to enable Verified badge + requesting loads.</div>
        <div class="hr"></div>
        ${
          pending.rows.length
            ? pending.rows
                .map(
                  (p) => `
          <div class="load">
            <div class="row" style="justify-content:space-between">
              <div><b>${escapeHtml(p.email)}</b> • Insurance exp: ${escapeHtml(p.insurance_expires || "—")}</div>
              <span class="badge warn">PENDING</span>
            </div>
            <div class="muted">
              Files: W-9 (${escapeHtml(p.w9_filename || "—")}), COI (${escapeHtml(
                    p.insurance_filename || "—"
                  )}), Authority (${escapeHtml(p.authority_filename || "—")})
            </div>
            <div class="row" style="margin-top:10px">
              <form method="POST" action="/admin/carriers/${p.carrier_id}/approve"><button class="btn primary" type="submit">Approve</button></form>
              <form method="POST" action="/admin/carriers/${p.carrier_id}/reject"><button class="btn ghost" type="submit">Reject</button></form>
            </div>
          </div>
        `
                )
                .join("")
            : `<div class="muted">No pending carriers.</div>`
        }
      </div>
    `;
    return res.send(layout({ title: "Admin", user, body }));
  } catch (e) {
    console.error(e);
    return res.status(500).send("Dashboard error.");
  }
});

/* ---------------- Shipper actions ---------------- */
app.post("/shipper/loads", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  const billing = await getAndNormalizeBilling(req.user.id);
  const gate = postingAllowed(billing);
  if (!gate.ok) return res.status(403).send(`Posting blocked: ${gate.reason}`);

  const lane_from = qStr(req.body.lane_from);
  const lane_to = qStr(req.body.lane_to);
  const pickup_date = qStr(req.body.pickup_date);
  const delivery_date = qStr(req.body.delivery_date);
  const equipment = qStr(req.body.equipment);
  const commodity = qStr(req.body.commodity);

  const weight_lbs = int(req.body.weight_lbs);
  const miles = int(req.body.miles);

  const rate_all_in = Number(req.body.rate_all_in);
  const payment_terms = qStr(req.body.payment_terms || "NET 30");
  const quickpay_available = String(req.body.quickpay_available || "false") === "true";

  const detention_rate_per_hr = Number(req.body.detention_rate_per_hr);
  const detention_after_hours = int(req.body.detention_after_hours);

  const appointment_type = qStr(req.body.appointment_type || "FCFS");
  const accessorials = qStr(req.body.accessorials || "None");
  const special_requirements = qStr(req.body.special_requirements || "None");

  await pool.query(
    `INSERT INTO loads
     (shipper_id,lane_from,lane_to,pickup_date,delivery_date,equipment,weight_lbs,commodity,miles,
      rate_all_in,payment_terms,quickpay_available,detention_rate_per_hr,detention_after_hours,
      appointment_type,accessorials,special_requirements,status)
     VALUES
     ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,'OPEN')`,
    [
      req.user.id,
      lane_from,
      lane_to,
      pickup_date,
      delivery_date,
      equipment,
      weight_lbs,
      commodity,
      miles,
      rate_all_in,
      payment_terms,
      quickpay_available,
      detention_rate_per_hr,
      detention_after_hours,
      appointment_type,
      accessorials,
      special_requirements,
    ]
  );

  if (billing.monthly_limit !== -1) {
    await pool.query(`UPDATE shippers_billing SET loads_used = loads_used + 1, updated_at=NOW() WHERE shipper_id=$1`, [
      req.user.id,
    ]);
  }

  res.redirect("/dashboard");
});

app.post("/shipper/requests/:id/accept", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  const requestId = Number(req.params.id);

  const r = await pool.query(
    `
    SELECT lr.*, l.shipper_id, l.status as load_status, l.lane_from, l.lane_to
    FROM load_requests lr
    JOIN loads l ON l.id = lr.load_id
    WHERE lr.id=$1
  `,
    [requestId]
  );
  const row = r.rows[0];
  if (!row || row.shipper_id !== req.user.id) return res.sendStatus(404);
  if (row.load_status === "BOOKED") return res.status(400).send("Load already booked.");

  await pool.query(`UPDATE load_requests SET status='ACCEPTED' WHERE id=$1`, [requestId]);
  await pool.query(`UPDATE load_requests SET status='DECLINED' WHERE load_id=$1 AND id<>$2`, [row.load_id, requestId]);
  await pool.query(`UPDATE loads SET status='BOOKED', booked_carrier_id=$1 WHERE id=$2`, [row.carrier_id, row.load_id]);

  const carrierEmail = (await pool.query(`SELECT email FROM users WHERE id=$1`, [row.carrier_id])).rows[0]?.email;

  await sendEmail(
    req.user.email,
    `DFX Booking Confirmed • Load #${row.load_id}`,
    `<p><b>Booking confirmed.</b></p><p>Load #${row.load_id}: ${escapeHtml(row.lane_from)} → ${escapeHtml(row.lane_to)}</p><p>Status: BOOKED</p>`
  );

  if (carrierEmail) {
    await sendEmail(
      carrierEmail,
      `DFX Request Accepted • Load #${row.load_id}`,
      `<p><b>Your request was accepted.</b></p><p>Load #${row.load_id}: ${escapeHtml(row.lane_from)} → ${escapeHtml(row.lane_to)}</p><p>Status: BOOKED</p>`
    );
  }

  res.redirect("/dashboard");
});

app.post("/shipper/requests/:id/decline", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  const requestId = Number(req.params.id);

  const r = await pool.query(
    `
    SELECT lr.*, l.shipper_id, l.lane_from, l.lane_to
    FROM load_requests lr
    JOIN loads l ON l.id = lr.load_id
    WHERE lr.id=$1
  `,
    [requestId]
  );
  const row = r.rows[0];
  if (!row || row.shipper_id !== req.user.id) return res.sendStatus(404);

  await pool.query(`UPDATE load_requests SET status='DECLINED' WHERE id=$1`, [requestId]);

  const carrierEmail = (await pool.query(`SELECT email FROM users WHERE id=$1`, [row.carrier_id])).rows[0]?.email;
  if (carrierEmail) {
    await sendEmail(
      carrierEmail,
      `DFX Request Declined • Load #${row.load_id}`,
      `<p><b>Your request was declined.</b></p><p>Load #${row.load_id}: ${escapeHtml(row.lane_from)} → ${escapeHtml(row.lane_to)}</p>`
    );
  }

  res.redirect("/dashboard");
});

/* ---------------- Carrier actions ---------------- */
app.post(
  "/carrier/compliance",
  requireAuth,
  requireRole("CARRIER"),
  upload.fields([
    { name: "w9", maxCount: 1 },
    { name: "insurance", maxCount: 1 },
    { name: "authority", maxCount: 1 },
  ]),
  async (req, res) => {
    const files = req.files || {};
    const w9 = files.w9?.[0];
    const insurance = files.insurance?.[0];
    const authority = files.authority?.[0];
    const insurance_expires = qStr(req.body.insurance_expires);

    if (!w9 || !insurance || !authority) return res.status(400).send("All documents are required.");
    if (!insurance_expires) return res.status(400).send("Insurance expiration is required.");

    await pool.query(
      `INSERT INTO carriers_compliance (carrier_id, w9_filename, insurance_filename, authority_filename, insurance_expires, status, updated_at)
       VALUES ($1,$2,$3,$4,$5,'PENDING',NOW())
       ON CONFLICT (carrier_id) DO UPDATE SET
         w9_filename=EXCLUDED.w9_filename,
         insurance_filename=EXCLUDED.insurance_filename,
         authority_filename=EXCLUDED.authority_filename,
         insurance_expires=EXCLUDED.insurance_expires,
         status='PENDING',
         updated_at=NOW()`,
      [req.user.id, w9.originalname, insurance.originalname, authority.originalname, insurance_expires]
    );

    res.redirect("/dashboard");
  }
);

app.post("/carrier/loads/:id/request", requireAuth, requireRole("CARRIER"), async (req, res) => {
  const loadId = Number(req.params.id);

  const comp = await pool.query(`SELECT status FROM carriers_compliance WHERE carrier_id=$1`, [req.user.id]);
  const compStatus = comp.rows[0]?.status || "PENDING";
  if (compStatus !== "APPROVED") return res.status(403).send("Verification required before requesting loads.");

  const load = await pool.query(`SELECT status FROM loads WHERE id=$1`, [loadId]);
  if (!load.rows[0]) return res.sendStatus(404);
  if (load.rows[0].status === "BOOKED") return res.status(400).send("Load already booked.");

  await pool.query(
    `INSERT INTO load_requests (load_id, carrier_id, status) VALUES ($1,$2,'REQUESTED')
     ON CONFLICT (load_id, carrier_id) DO NOTHING`,
    [loadId, req.user.id]
  );

  await pool.query(`UPDATE loads SET status='REQUESTED' WHERE id=$1 AND status='OPEN'`, [loadId]);

  res.redirect("/loads");
});

/* ---------------- Admin actions ---------------- */
app.post("/admin/carriers/:id/approve", requireAuth, requireRole("ADMIN"), async (req, res) => {
  const carrierId = Number(req.params.id);
  await pool.query(`UPDATE carriers_compliance SET status='APPROVED', updated_at=NOW(), admin_note=NULL WHERE carrier_id=$1`, [
    carrierId,
  ]);
  res.redirect("/dashboard");
});

app.post("/admin/carriers/:id/reject", requireAuth, requireRole("ADMIN"), async (req, res) => {
  const carrierId = Number(req.params.id);
  await pool.query(`UPDATE carriers_compliance SET status='REJECTED', admin_note='Rejected', updated_at=NOW() WHERE carrier_id=$1`, [
    carrierId,
  ]);
  res.redirect("/dashboard");
});

/* ---------------- Load Board (no max; default actionable; sort newest or rpm) ---------------- */
app.get("/loads", async (req, res) => {
  const user = getUser(req);

  const statusFilter = qStr(req.query.status || "actionable"); // actionable|all|open|requested|booked
  const equipment = qStr(req.query.equipment || "");
  const minMiles = qStr(req.query.minMiles || "");
  const maxMiles = qStr(req.query.maxMiles || "");
  const minWeight = qStr(req.query.minWeight || "");
  const maxWeight = qStr(req.query.maxWeight || "");
  const sort = qStr(req.query.sort || "newest"); // newest|rpm

  const where = [];
  const params = [];

  if (statusFilter === "actionable") {
    where.push(`l.status IN ('OPEN','REQUESTED')`);
  } else if (statusFilter === "open") {
    where.push(`l.status='OPEN'`);
  } else if (statusFilter === "requested") {
    where.push(`l.status='REQUESTED'`);
  } else if (statusFilter === "booked") {
    where.push(`l.status='BOOKED'`);
  }

  if (equipment) {
    params.push(equipment);
    where.push(`l.equipment=$${params.length}`);
  }
  if (minMiles) {
    params.push(int(minMiles));
    where.push(`l.miles >= $${params.length}`);
  }
  if (maxMiles) {
    params.push(int(maxMiles));
    where.push(`l.miles <= $${params.length}`);
  }
  if (minWeight) {
    params.push(int(minWeight));
    where.push(`l.weight_lbs >= $${params.length}`);
  }
  if (maxWeight) {
    params.push(int(maxWeight));
    where.push(`l.weight_lbs <= $${params.length}`);
  }

  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const orderSql =
    sort === "rpm"
      ? `ORDER BY (l.rate_all_in::numeric / NULLIF(l.miles,0)) DESC NULLS LAST, l.created_at DESC`
      : `ORDER BY l.created_at DESC`;

  let carrierBadge = null;
  if (user?.role === "CARRIER") {
    const comp = await pool.query(`SELECT status FROM carriers_compliance WHERE carrier_id=$1`, [user.id]);
    carrierBadge = comp.rows[0]?.status || "PENDING";
  }

  const r = await pool.query(
    `
    SELECT l.*
    FROM loads l
    ${whereSql}
    ${orderSql}
  `,
    params
  );

  const body = `
    <div class="card">
      <div class="row" style="justify-content:space-between">
        <div>
          <h2 style="margin:0">Load Board</h2>
          <div class="muted">Newest by default. Switch to RPM anytime.</div>
        </div>
        ${
          user?.role === "CARRIER"
            ? `<span class="badge ${carrierBadge === "APPROVED" ? "ok" : "warn"}">Carrier: ${escapeHtml(carrierBadge)}</span>`
            : user?.role === "SHIPPER"
            ? `<a class="btn primary" href="/shipper/plans">Plans</a>`
            : ``
        }
      </div>

      <div class="hr"></div>

      <form method="GET" action="/loads">
        <div class="filters">
          <select name="status">
            <option value="actionable" ${statusFilter === "actionable" ? "selected" : ""}>Only open/requested</option>
            <option value="all" ${statusFilter === "all" ? "selected" : ""}>All statuses</option>
            <option value="open" ${statusFilter === "open" ? "selected" : ""}>Open</option>
            <option value="requested" ${statusFilter === "requested" ? "selected" : ""}>Requested</option>
            <option value="booked" ${statusFilter === "booked" ? "selected" : ""}>Booked</option>
          </select>

          <select name="equipment">
            <option value="">Any equipment</option>
            ${["Dry Van", "Standard Van", "Reefer", "Flatbed", "Power Only", "Stepdeck"]
              .map((e) => `<option value="${escapeHtml(e)}" ${equipment === e ? "selected" : ""}>${escapeHtml(e)}</option>`)
              .join("")}
          </select>

          <input name="minMiles" placeholder="Min miles" value="${escapeHtml(minMiles)}"/>
          <input name="maxMiles" placeholder="Max miles" value="${escapeHtml(maxMiles)}"/>
          <input name="minWeight" placeholder="Min weight" value="${escapeHtml(minWeight)}"/>
          <input name="maxWeight" placeholder="Max weight" value="${escapeHtml(maxWeight)}"/>

          <select name="sort">
            <option value="newest" ${sort === "newest" ? "selected" : ""}>Sort: Newest</option>
            <option value="rpm" ${sort === "rpm" ? "selected" : ""}>Sort: RPM</option>
          </select>
        </div>

        <div class="row" style="margin-top:12px">
          <button class="btn primary" type="submit">Apply</button>
          <a class="btn ghost" href="/loads">Reset</a>
        </div>
      </form>

      <div class="hr"></div>

      ${
        r.rows.length
          ? r.rows.map((l) => loadCard(l, user, carrierBadge)).join("")
          : `<div class="muted">No loads match your filters.</div>`
      }
    </div>
  `;
  res.send(layout({ title: "Loads", user, body }));
});

function loadCard(l, user, carrierBadge, opts = {}) {
  const status = String(l.status || "OPEN");
  const canRequest = user?.role === "CARRIER";
  const showContract = !!opts.showContract;

  const rpmVal = rpm(l.rate_all_in, l.miles);
  const rpmText = Number.isFinite(rpmVal) ? `${rpmVal.toFixed(2)} RPM` : "";

  return `
    <div class="load">
      <div class="loadTop">
        <div>
          <div class="lane">#${l.id} ${escapeHtml(l.lane_from)} → ${escapeHtml(l.lane_to)}</div>
          <div class="muted">${escapeHtml(l.pickup_date)} → ${escapeHtml(l.delivery_date)} • ${escapeHtml(l.equipment)}</div>
          <div class="muted small">${int(l.weight_lbs).toLocaleString()} lbs • ${int(l.miles).toLocaleString()} mi • ${escapeHtml(rpmText)}</div>
        </div>
        <div style="text-align:right">
          <div style="font-weight:1000">${money(l.rate_all_in)} <span class="muted">(all-in)</span></div>
          <div style="margin-top:6px"><span class="badge ${
            status === "BOOKED" ? "ok" : status === "REQUESTED" ? "warn" : "brand"
          }">${escapeHtml(status)}</span></div>
        </div>
      </div>

      <div class="row" style="margin-top:10px">
        <span class="badge ok">Terms: ${escapeHtml(l.payment_terms)}${l.quickpay_available ? " • QuickPay" : ""}</span>
        <span class="badge ok">Detention: ${money(l.detention_rate_per_hr)}/hr after ${escapeHtml(l.detention_after_hours)}h</span>
        <span class="badge ok">Accessorials: ${escapeHtml(l.accessorials)}</span>
        <span class="badge">Appt: ${escapeHtml(l.appointment_type)}</span>
      </div>

      <div class="kv">
        <div class="k">Commodity</div><div>${escapeHtml(l.commodity)}</div>
        <div class="k">Notes</div><div>${escapeHtml(l.special_requirements)}</div>
      </div>

      ${
        showContract && status === "BOOKED"
          ? `<div class="row" style="margin-top:12px"><a class="btn primary" href="/shipper/load/${l.id}/rate-confirmation" target="_blank" rel="noopener">Download Rate Confirmation</a></div>`
          : ``
      }

      ${
        canRequest
          ? `
        <div class="row" style="margin-top:12px">
          ${
            status === "BOOKED"
              ? `<span class="badge ok">Booked</span>`
              : carrierBadge === "APPROVED"
              ? `<form method="POST" action="/carrier/loads/${l.id}/request"><button class="btn primary" type="submit">Request to Book</button></form>`
              : `<span class="badge warn">Submit verification docs to request loads</span>`
          }
        </div>
      `
          : ``
      }
    </div>
  `;
}

/* ---------------- Rate confirmation download (shipper only) ---------------- */
app.get("/shipper/load/:id/rate-confirmation", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  const loadId = Number(req.params.id);
  const r = await pool.query(`SELECT * FROM loads WHERE id=$1`, [loadId]);
  const load = r.rows[0];
  if (!load || load.shipper_id !== req.user.id) return res.sendStatus(404);
  if (load.status !== "BOOKED" || !load.booked_carrier_id) return res.status(400).send("Load not booked yet.");

  const carrierEmail = (await pool.query(`SELECT email FROM users WHERE id=$1`, [load.booked_carrier_id])).rows[0]?.email;

  const html = renderRateConfirmationHtml({
    load,
    shipperEmail: req.user.email,
    carrierEmail: carrierEmail || "TBD",
  });

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="DFX_Rate_Confirmation_Load_${loadId}.html"`);
  res.send(html);
});

/* ---------------- Health ---------------- */
app.get("/health", (_, res) =>
  res.json({
    ok: true,
    stripeEnabled,
    smtpEnabled: !!getMailer(),
  })
);

/* ---------------- STARTUP ---------------- */
initDb()
  .then(async () => {
    await bootstrapAdminIfNeeded();
    app.listen(PORT, "0.0.0.0", () => console.log("Server running on port", PORT));
  })
  .catch((e) => {
    console.error("DB init failed:", e);
    process.exit(1);
  });
