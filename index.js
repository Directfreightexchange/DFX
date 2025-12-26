/**
 * Direct Freight Exchange (DFX) — single-file production-ish app
 * - Shippers subscribe (Stripe) to post loads (plans/limits)
 * - Carriers free; must upload compliance docs to get VERIFIED badge
 * - Load board: carriers see OPEN/REQUESTED loads by default; sort newest (default) or RPM
 * - Contract templates: auto-filled Rate Confirmation after booking
 * - Forgot password: email reset link
 * - Optional: email notifications + Help button (contact form)
 *
 * Required env vars:
 *   DATABASE_URL, JWT_SECRET
 *
 * Optional (Stripe subscriptions + invoices):
 *   STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET
 *   STRIPE_PRICE_STARTER, STRIPE_PRICE_GROWTH, STRIPE_PRICE_ENTERPRISE
 *   APP_URL (e.g. https://yourdomain.com)
 *
 * Optional (Email):
 *   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM
 *   SUPPORT_EMAIL (for /help contact form; defaults to SMTP_FROM)
 */

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

// IMPORTANT: Stripe webhook needs raw body ONLY on this route
app.post("/stripe/webhook", express.raw({ type: "application/json" }));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

const PORT = process.env.PORT || 3000;

const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;

const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

const STRIPE_PRICE_STARTER = process.env.STRIPE_PRICE_STARTER;
const STRIPE_PRICE_GROWTH = process.env.STRIPE_PRICE_GROWTH;
const STRIPE_PRICE_ENTERPRISE = process.env.STRIPE_PRICE_ENTERPRISE;

// SMTP (optional, for email notifications + password reset + help)
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = Number(process.env.SMTP_PORT || "587");
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const SMTP_FROM = process.env.SMTP_FROM || "no-reply@directfreightexchange.com";
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || SMTP_FROM;

const IS_PROD = String(process.env.NODE_ENV || "").toLowerCase() === "production";

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

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
});

// Plans
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

/* ---------------- Utilities ---------------- */
function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
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
function rpm(rate, miles) {
  const r = Number(rate);
  const m = Number(miles);
  if (!Number.isFinite(r) || !Number.isFinite(m) || m <= 0) return 0;
  return r / m;
}
function safeEqLower(s) {
  return String(s || "").trim().toLowerCase();
}

/* ---------------- Auth helpers ---------------- */
function signIn(res, user) {
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
  res.cookie("dfx_token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: IS_PROD,
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

function layout({ title, user, body }) {
  const helpFab = `
    <a class="helpFab" href="/help" title="Help / Live Agent">
      Help
    </a>
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

.grid{display:grid;gap:16px;grid-template-columns:1.1fr .9fr;margin-top:16px}
@media(max-width:980px){.grid{grid-template-columns:1fr}.nav{position:static}.title{font-size:38px}}

.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.filters{display:grid;gap:10px;grid-template-columns:1.2fr 1.2fr 1fr 1fr 1fr}
@media(max-width:980px){.filters{grid-template-columns:1fr 1fr}}
input,select,textarea{
  width:100%;padding:12px;border-radius:12px;border:1px solid var(--line);
  background:rgba(6,8,9,.72);color:var(--text);outline:none
}
textarea{min-height:110px;resize:vertical}
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

/* Help FAB */
.helpFab{
  position:fixed; right:18px; bottom:18px; z-index:50;
  padding:12px 14px; border-radius:999px;
  border:1px solid rgba(163,230,53,.25);
  background: rgba(6,8,9,.70);
  box-shadow: var(--shadow);
  color: var(--text);
  font-weight: 800;
}
.helpFab:hover{filter:brightness(1.08); text-decoration:none}
</style>
</head>
<body>
${helpFab}
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
</body></html>`;
}

/* ---------------- DB schema (with safe “migrations”) ---------------- */
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
      monthly_limit INTEGER NOT NULL DEFAULT 0,            -- -1 means unlimited
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
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL,
      used BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Extra safety for “column does not exist” issues if DB was created earlier with different schema.
  // These are idempotent in modern Postgres.
  await pool.query(`ALTER TABLE loads ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'OPEN'`);
  await pool.query(`ALTER TABLE loads ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()`);
  await pool.query(`ALTER TABLE loads ADD COLUMN IF NOT EXISTS booked_carrier_id INTEGER`);
}

/* ---------------- Billing helpers ---------------- */
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
  if (!stripeEnabled) return { ok: true, reason: null }; // allow dev/testing if Stripe not configured
  if (billing.status !== "ACTIVE") return { ok: false, reason: "Subscription required (not ACTIVE)." };
  if (billing.monthly_limit === -1) return { ok: true, reason: null };
  if (billing.loads_used >= billing.monthly_limit) return { ok: false, reason: "Monthly posting limit reached." };
  return { ok: true, reason: null };
}

/* ---------------- Legal / Terms ---------------- */
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
        <p>DFX does not provide legal, regulatory, insurance, or financial advice.</p>
      </div>
    </div>
  `;
  res.send(layout({ title: "Terms", user, body }));
});

/* ---------------- Help (live agent button -> contact form) ---------------- */
app.get("/help", (req, res) => {
  const user = getUser(req);
  const body = `
    <div class="card">
      <h2 style="margin-top:0">Help / Live Agent</h2>
      <div class="muted">Send a message and our team will respond by email.</div>
      <div class="hr"></div>
      <form method="POST" action="/help">
        <div class="filters" style="grid-template-columns:1fr 1fr">
          <input name="email" type="email" placeholder="Your email" value="${escapeHtml(user?.email || "")}" required />
          <input name="topic" placeholder="Topic (Billing / Booking / Verification / Other)" required />
        </div>
        <div style="margin-top:10px">
          <textarea name="message" placeholder="Tell us what you need..." required></textarea>
        </div>
        <div class="row" style="margin-top:12px">
          <button class="btn green" type="submit">Send</button>
          <a class="btn ghost" href="/dashboard">Back to Dashboard</a>
        </div>
        <div class="muted" style="margin-top:10px">
          ${getMailer() ? `Email is enabled.` : `Email sending is not enabled yet (missing SMTP_* env vars). Your message will be logged in server logs.`}
        </div>
      </form>
    </div>
  `;
  res.send(layout({ title: "Help", user, body }));
});

app.post("/help", async (req, res) => {
  const user = getUser(req);
  const email = safeEqLower(req.body.email);
  const topic = String(req.body.topic || "").trim();
  const message = String(req.body.message || "").trim();
  if (!email || !topic || !message) return res.status(400).send("Missing fields.");

  const html = `
    <p><b>DFX Help Request</b></p>
    <p><b>From:</b> ${escapeHtml(email)}</p>
    <p><b>User:</b> ${escapeHtml(user ? `${user.email} (${user.role})` : "Not logged in")}</p>
    <p><b>Topic:</b> ${escapeHtml(topic)}</p>
    <p><b>Message:</b></p>
    <pre style="white-space:pre-wrap">${escapeHtml(message)}</pre>
  `;

  await sendEmail(SUPPORT_EMAIL, `DFX Help: ${topic}`, html);
  res.redirect("/help?sent=1");
});

/* ---------------- Auth ---------------- */
app.get("/signup", (req, res) => {
  const user = getUser(req);
  res.send(layout({
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
          <button class="btn green" type="submit">Create</button>
          <a class="btn ghost" href="/login">Login</a>
        </div>
      </form>
    </div>`
  }));
});

app.post("/signup", async (req, res) => {
  try {
    const email = safeEqLower(req.body.email);
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

    signIn(res, r.rows[0]);
    // carriers must verify: send directly to dashboard where upload panel is shown
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
    body: `<div class="card">
      <h2 style="margin-top:0">Login</h2>
      <form method="POST" action="/login">
        <div class="filters" style="grid-template-columns:1.2fr 1.2fr 1fr 1fr 1fr">
          <input name="email" type="email" placeholder="Email" required />
          <input name="password" type="password" placeholder="Password" required />
          <button class="btn green" type="submit">Login</button>
          <a class="btn ghost" href="/signup">Create</a>
          <a class="btn ghost" href="/loads">Load Board</a>
        </div>
      </form>
      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/forgot">Forgot password?</a>
      </div>
    </div>`
  }));
});

app.post("/login", async (req, res) => {
  try {
    const email = safeEqLower(req.body.email);
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

/* ---------------- Forgot password ---------------- */
app.get("/forgot", (req, res) => {
  const user = getUser(req);
  const body = `
    <div class="card">
      <h2 style="margin-top:0">Reset Password</h2>
      <div class="muted">Enter your account email. We’ll send a password reset link.</div>
      <div class="hr"></div>
      <form method="POST" action="/forgot">
        <div class="filters" style="grid-template-columns:1.4fr 1fr 1fr">
          <input name="email" type="email" placeholder="Email" required />
          <button class="btn green" type="submit">Send reset link</button>
          <a class="btn ghost" href="/login">Back to login</a>
        </div>
      </form>
      <div class="muted" style="margin-top:10px">
        ${getMailer() ? `Email is enabled.` : `Email sending is not enabled yet (missing SMTP_* env vars).`}
      </div>
    </div>
  `;
  res.send(layout({ title: "Forgot Password", user, body }));
});

app.post("/forgot", async (req, res) => {
  const email = safeEqLower(req.body.email);
  if (!email) return res.status(400).send("Email required.");

  const u = (await pool.query(`SELECT id,email FROM users WHERE email=$1`, [email])).rows[0];
  // Always respond same to prevent account enumeration
  if (!u) return res.send(layout({ title: "Reset Sent", user: null, body: `<div class="card"><h2>Check your email</h2><div class="muted">If an account exists, a reset link has been sent.</div></div>` }));

  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + 1000 * 60 * 30); // 30 min

  await pool.query(
    `INSERT INTO password_resets (token,user_id,expires_at,used) VALUES ($1,$2,$3,false)`,
    [token, u.id, expiresAt]
  );

  const link = `${APP_URL}/reset?token=${encodeURIComponent(token)}`;

  await sendEmail(
    u.email,
    "DFX Password Reset",
    `<p>Click the link below to reset your password:</p>
     <p><a href="${escapeHtml(link)}">${escapeHtml(link)}</a></p>
     <p>This link expires in 30 minutes.</p>`
  );

  res.send(layout({
    title: "Reset Sent",
    user: null,
    body: `<div class="card"><h2 style="margin-top:0">Check your email</h2><div class="muted">If an account exists, a reset link has been sent.</div><div class="hr"></div><a class="btn green" href="/login">Back to login</a></div>`
  }));
});

app.get("/reset", async (req, res) => {
  const user = getUser(req);
  const token = String(req.query.token || "");
  if (!token) return res.status(400).send("Missing token.");

  const r = await pool.query(`SELECT * FROM password_resets WHERE token=$1`, [token]);
  const pr = r.rows[0];
  const valid = pr && !pr.used && new Date(pr.expires_at).getTime() > Date.now();

  const body = `
    <div class="card">
      <h2 style="margin-top:0">Set New Password</h2>
      ${valid ? `
        <form method="POST" action="/reset">
          <input type="hidden" name="token" value="${escapeHtml(token)}" />
          <div class="filters" style="grid-template-columns:1.2fr 1fr 1fr">
            <input name="password" type="password" placeholder="New password (min 8 chars)" minlength="8" required />
            <button class="btn green" type="submit">Update password</button>
            <a class="btn ghost" href="/login">Cancel</a>
          </div>
        </form>
      ` : `
        <div class="badge warn">Reset link is invalid or expired. Please request a new one.</div>
        <div class="hr"></div>
        <a class="btn green" href="/forgot">Request new link</a>
      `}
    </div>
  `;
  res.send(layout({ title: "Reset Password", user, body }));
});

app.post("/reset", async (req, res) => {
  const token = String(req.body.token || "");
  const password = String(req.body.password || "");
  if (!token || password.length < 8) return res.status(400).send("Invalid request.");

  const r = await pool.query(`SELECT * FROM password_resets WHERE token=$1`, [token]);
  const pr = r.rows[0];
  const valid = pr && !pr.used && new Date(pr.expires_at).getTime() > Date.now();
  if (!valid) return res.status(400).send("Token expired or invalid.");

  const hash = await bcrypt.hash(password, 12);
  await pool.query(`UPDATE users SET password_hash=$1 WHERE id=$2`, [hash, pr.user_id]);
  await pool.query(`UPDATE password_resets SET used=true WHERE token=$1`, [token]);

  res.send(layout({
    title: "Password Updated",
    user: null,
    body: `<div class="card"><h2 style="margin-top:0">Password updated</h2><div class="muted">You can now log in with your new password.</div><div class="hr"></div><a class="btn green" href="/login">Go to login</a></div>`
  }));
});

/* ---------------- Home ---------------- */
app.get("/", (req, res) => {
  const user = getUser(req);

  const plansCta =
    user?.role === "SHIPPER"
      ? `<a class="btn green" href="/shipper/plans">View Plans</a>`
      : `<a class="btn green" href="/signup">Sign up as Shipper</a>`;

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
          <a class="btn green" href="${user ? "/dashboard" : "/signup"}">${user ? "Go to Dashboard" : "Create account"}</a>
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
          ${plansCta}
        </div>
      </div>

      <div class="card">
        <h3 style="margin-top:0">For Carriers</h3>
        <div class="muted">
          Free access to transparent loads. Upload compliance docs once, get verified, and request loads directly.
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

/* ---------------- Stripe routes (plans + invoices/receipts) ---------------- */
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

  const usageText = (limit === -1) ? `Unlimited` : `${used} / ${limit} used this month`;

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
        <a class="btn ghost" href="/shipper/invoices">Invoices / Receipts</a>
      </div>

      ${!stripeEnabled ? `
        <div class="hr"></div>
        <div class="badge warn">Stripe not configured (add STRIPE_* env vars in Render).</div>
      ` : `
        <div class="hr"></div>
        <div class="grid">
          ${Object.keys(PLANS).map(p => {
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
                ${isCurrent
                  ? `<span class="badge ok">Current plan</span>`
                  : `
                    <form method="POST" action="/shipper/plan">
                      <input type="hidden" name="plan" value="${p}">
                      <button class="btn green" type="submit">${status === "ACTIVE" ? "Switch immediately" : "Subscribe"}</button>
                    </form>
                  `}
              </div>
            `;
          }).join("")}
        </div>
      `}
    </div>
  `;
  res.send(layout({ title: "Plans", user, body }));
});

app.post("/shipper/plan", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  if (!stripeEnabled) return res.status(400).send("Stripe not configured.");

  const plan = String(req.body.plan || "").toUpperCase();
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
  await pool.query(
    `UPDATE shippers_billing SET plan=$1, monthly_limit=$2, updated_at=NOW() WHERE shipper_id=$3`,
    [plan, planDef.limit, req.user.id]
  );

  res.redirect("/shipper/plans?switched=1");
});

// Invoices / receipts: list Stripe invoices and provide download links
app.get("/shipper/invoices", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  const user = req.user;

  const bill = await pool.query(`SELECT * FROM shippers_billing WHERE shipper_id=$1`, [user.id]);
  const b = bill.rows[0] || null;

  if (!stripeEnabled) {
    return res.send(layout({
      title: "Invoices",
      user,
      body: `<div class="card"><h2 style="margin-top:0">Invoices / Receipts</h2><div class="badge warn">Stripe is not configured yet.</div></div>`
    }));
  }

  if (!b?.stripe_customer_id) {
    return res.send(layout({
      title: "Invoices",
      user,
      body: `<div class="card"><h2 style="margin-top:0">Invoices / Receipts</h2><div class="muted">No Stripe customer found yet. Subscribe to a plan first.</div><div class="hr"></div><a class="btn green" href="/shipper/plans">Go to Plans</a></div>`
    }));
  }

  const inv = await stripe.invoices.list({ customer: b.stripe_customer_id, limit: 24 });

  const body = `
    <div class="card">
      <h2 style="margin-top:0">Invoices / Receipts</h2>
      <div class="muted">Download invoices and receipts for your subscription.</div>
      <div class="hr"></div>
      ${inv.data.length ? inv.data.map(i => {
        const hosted = i.hosted_invoice_url ? `<a class="btn ghost" href="${i.hosted_invoice_url}" target="_blank" rel="noreferrer">View</a>` : "";
        const pdf = i.invoice_pdf ? `<a class="btn green" href="${i.invoice_pdf}" target="_blank" rel="noreferrer">Download PDF</a>` : "";
        return `
          <div class="load">
            <div class="row" style="justify-content:space-between">
              <div>
                <div style="font-weight:1000">Invoice ${escapeHtml(i.number || i.id)}</div>
                <div class="muted">${escapeHtml(i.status || "")} • ${money((i.amount_paid || i.amount_due || 0) / 100)} • ${new Date((i.created || 0) * 1000).toISOString().slice(0,10)}</div>
              </div>
              <div class="row">
                ${hosted}
                ${pdf}
              </div>
            </div>
          </div>
        `;
      }).join("") : `<div class="muted">No invoices found yet.</div>`}
      <div class="hr"></div>
      <a class="btn ghost" href="/shipper/plans">Back to Plans</a>
    </div>
  `;
  res.send(layout({ title: "Invoices", user, body }));
});

/* ---------------- Stripe webhook ---------------- */
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

      const row = await pool.query(
        `SELECT shipper_id FROM shippers_billing WHERE stripe_subscription_id=$1`,
        [subscriptionId]
      );
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

/* ---------------- Dashboards ---------------- */
app.get("/dashboard", requireAuth, async (req, res) => {
  try {
    const user = req.user;

    if (user.role === "SHIPPER") {
      const billing = await getAndNormalizeBilling(user.id);
      const gate = postingAllowed(billing);

      const planLabel = billing.plan ? (PLANS[billing.plan]?.label || billing.plan) : "None";
      const limitText =
        billing.monthly_limit === -1 ? "Unlimited" :
        `${billing.loads_used} / ${billing.monthly_limit} used this month`;

      const myLoads = await pool.query(`SELECT * FROM loads WHERE shipper_id=$1 ORDER BY created_at DESC`, [user.id]);

      const requests = await pool.query(`
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
      `, [user.id]);

      const body = `
        <div class="grid">
          <div class="card">
            <div class="row" style="justify-content:space-between">
              <div>
                <h2 style="margin:0">Shipper Dashboard</h2>
                <div class="muted">All-in pricing. Transparent terms. Fast booking.</div>
              </div>
              <span class="badge ${billing.status === "ACTIVE" ? "ok" : "warn"}">Billing: ${escapeHtml(billing.status)}</span>
            </div>

            <div class="hr"></div>

            <div class="row">
              <span class="badge">Plan: ${escapeHtml(planLabel)}</span>
              <span class="badge brand">${escapeHtml(limitText)}</span>
              <a class="btn green" href="/shipper/plans">Manage Plan</a>
              <a class="btn ghost" href="/shipper/invoices">Invoices / Receipts</a>
            </div>

            <div class="hr"></div>

            <h3 style="margin:0 0 10px 0">Post a transparent load</h3>

            ${gate.ok ? `
            <form method="POST" action="/shipper/loads">
              <div class="filters">
                <input name="lane_from" placeholder="From (City, ST)" required />
                <input name="lane_to" placeholder="To (City, ST)" required />
                <input name="pickup_date" placeholder="Pickup date (YYYY-MM-DD)" required />
                <input name="delivery_date" placeholder="Delivery date (YYYY-MM-DD)" required />
                <select name="equipment" required>
                  ${equipmentOptionsHtml("Dry Van")}
                </select>

                <input name="weight_lbs" type="number" placeholder="Weight (lbs)" value="42000" required />
                <input name="miles" type="number" placeholder="Miles" value="800" required />
                <input name="commodity" placeholder="Commodity" value="General Freight" required />
                <input name="rate_all_in" type="number" step="0.01" placeholder="All-in rate ($)" value="2500" required />
                <select name="payment_terms" required>
                  <option value="NET 30">NET 30 (default)</option><option value="NET 15">NET 15</option><option value="NET 45">NET 45</option><option value="QuickPay">QuickPay</option>
                </select>

                <select name="quickpay_available" required>
                  <option value="false">QuickPay Available? No</option><option value="true">QuickPay Available? Yes</option>
                </select>

                <input name="detention_rate_per_hr" type="number" step="0.01" placeholder="Detention $/hr" value="75" required />
                <input name="detention_after_hours" type="number" placeholder="Detention after (hours)" value="2" required />
                <select name="appointment_type" required>
                  <option value="FCFS">Appointment: FCFS</option><option value="Appt Required">Appointment: Appt Required</option>
                </select>

                <input name="accessorials" placeholder="Accessorials" value="None" required />
                <input name="special_requirements" placeholder="Notes" value="None" required />
              </div>
              <div class="row" style="margin-top:12px">
                <button class="btn green" type="submit">Post Load</button>
                <a class="btn ghost" href="/loads">View Load Board</a>
              </div>
            </form>
            ` : `
              <div class="badge warn">Posting blocked: ${escapeHtml(gate.reason)}</div>
              <div class="row" style="margin-top:10px">
                <a class="btn green" href="/shipper/plans">Upgrade / Subscribe</a>
              </div>
            `}
          </div>

          <div class="card">
            <h3 style="margin-top:0">Booking Requests</h3>
            <div class="muted">Carrier requests → you accept/decline → load becomes BOOKED.</div>
            <div class="hr"></div>
            ${requests.rows.length ? requests.rows.map(r => `
              <div class="load">
                <div class="row" style="justify-content:space-between">
                  <div><b>Load #${r.load_id}</b> ${escapeHtml(r.lane_from)} → ${escapeHtml(r.lane_to)}</div>
                  <span class="badge ${r.request_status === "REQUESTED" ? "warn" : r.request_status === "ACCEPTED" ? "ok" : ""}">${escapeHtml(r.request_status)}</span>
                </div>
                <div class="muted">Carrier: ${escapeHtml(r.carrier_email)} • Compliance: ${escapeHtml(r.carrier_compliance || "PENDING")}</div>
                ${r.request_status === "REQUESTED" ? `
                  <div class="row" style="margin-top:10px">
                    <form method="POST" action="/shipper/requests/${r.request_id}/accept"><button class="btn green" type="submit">Accept</button></form>
                    <form method="POST" action="/shipper/requests/${r.request_id}/decline"><button class="btn ghost" type="submit">Decline</button></form>
                  </div>` : ``}
              </div>
            `).join("") : `<div class="muted">No requests yet.</div>`}
          </div>
        </div>

        <div class="card">
          <h3 style="margin-top:0">Your Loads</h3>
          <div class="muted">For BOOKED loads, you can generate an auto-filled rate confirmation.</div>
          <div class="hr"></div>
          ${myLoads.rows.length ? myLoads.rows.map(l => loadCard(l, user)).join("") : `<div class="muted">No loads yet.</div>`}
        </div>
      `;
      return res.send(layout({ title: "Dashboard", user, body }));
    }

    if (user.role === "CARRIER") {
      const comp = await pool.query(`SELECT * FROM carriers_compliance WHERE carrier_id=$1`, [user.id]);
      const c = comp.rows[0] || { status: "PENDING" };

      const myReqs = await pool.query(`
        SELECT lr.*, l.lane_from, l.lane_to, l.status as load_status
        FROM load_requests lr
        JOIN loads l ON l.id = lr.load_id
        WHERE lr.carrier_id=$1
        ORDER BY lr.created_at DESC
      `, [user.id]);

      const body = `
        <div class="grid">
          <div class="card">
            <div class="row" style="justify-content:space-between">
              <div>
                <h2 style="margin:0">Carrier Dashboard</h2>
                <div class="muted">Create account → upload compliance → get Verified badge.</div>
              </div>
              <span class="badge ${c.status === "APPROVED" ? "ok" : "warn"}">Verification: ${escapeHtml(c.status)}</span>
            </div>

            <div class="hr"></div>

            <div class="muted" style="margin-bottom:10px">
              To become <b>Verified</b>, upload:
              <ul>
                <li><b>W-9</b></li>
                <li><b>Certificate of Insurance</b> (Auto Liability + Cargo)</li>
                <li><b>Operating Authority</b> (MC / DOT proof)</li>
              </ul>
            </div>

            <form method="POST" action="/carrier/compliance" enctype="multipart/form-data">
              <div class="filters" style="grid-template-columns:1.2fr 1.2fr 1fr 1fr 1fr">
                <input name="insurance_expires" placeholder="Insurance expires (YYYY-MM-DD)" value="${escapeHtml(c.insurance_expires || "")}" required />
                <input type="file" name="insurance" accept="application/pdf,image/*" required />
                <input type="file" name="authority" accept="application/pdf,image/*" required />
                <input type="file" name="w9" accept="application/pdf,image/*" required />
                <button class="btn green" type="submit">Submit for Verification</button>
              </div>
              <div class="muted" style="margin-top:10px">
                Files are recorded by name in the database. For production, store uploads in S3 and save URLs.
              </div>
            </form>
          </div>

          <div class="card">
            <h3 style="margin-top:0">Your Requests</h3>
            <div class="hr"></div>
            ${myReqs.rows.length ? myReqs.rows.map(r => `
              <div class="load">
                <div class="row" style="justify-content:space-between">
                  <div><b>Load #${r.load_id}</b> ${escapeHtml(r.lane_from)} → ${escapeHtml(r.lane_to)}</div>
                  <span class="badge ${r.status === "REQUESTED" ? "warn" : r.status === "ACCEPTED" ? "ok" : ""}">${escapeHtml(r.status)}</span>
                </div>
                <div class="muted">Load status: ${escapeHtml(r.load_status)}</div>
              </div>
            `).join("") : `<div class="muted">No requests yet.</div>`}
          </div>
        </div>

        <div class="card">
          <div class="row" style="justify-content:space-between">
            <div>
              <h3 style="margin:0">Load Board</h3>
              <div class="muted">Default: newest • Option: sort by RPM</div>
            </div>
            <a class="btn ghost" href="/loads">Open Load Board</a>
          </div>
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
        <h2 style="margin-top:0">Admin — Carrier Verification</h2>
        <div class="muted">Approve carriers to enable Request-to-Book + Verified badge.</div>
        <div class="hr"></div>
        ${pending.rows.length ? pending.rows.map(p => `
          <div class="load">
            <div class="row" style="justify-content:space-between">
              <div><b>${escapeHtml(p.email)}</b> • Insurance exp: ${escapeHtml(p.insurance_expires || "—")}</div>
              <span class="badge warn">PENDING</span>
            </div>
            <div class="muted">Files: ${escapeHtml(p.insurance_filename||"—")}, ${escapeHtml(p.authority_filename||"—")}, ${escapeHtml(p.w9_filename||"—")}</div>
            <div class="row" style="margin-top:10px">
              <form method="POST" action="/admin/carriers/${p.carrier_id}/approve"><button class="btn green" type="submit">Approve</button></form>
              <form method="POST" action="/admin/carriers/${p.carrier_id}/reject"><button class="btn ghost" type="submit">Reject</button></form>
            </div>
          </div>
        `).join("") : `<div class="muted">No pending carriers.</div>`}
      </div>
    `;
    return res.send(layout({ title: "Admin", user, body }));
  } catch (e) {
    console.error("Dashboard error:", e);
    return res.status(500).send("Dashboard failed.");
  }
});

/* ---------------- Shipper actions ---------------- */
app.post("/shipper/loads", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  const billing = await getAndNormalizeBilling(req.user.id);
  const gate = postingAllowed(billing);
  if (!gate.ok) return res.status(403).send(`Posting blocked: ${gate.reason}`);

  const lane_from = String(req.body.lane_from || "").trim();
  const lane_to = String(req.body.lane_to || "").trim();
  const pickup_date = String(req.body.pickup_date || "").trim();
  const delivery_date = String(req.body.delivery_date || "").trim();
  const equipment = String(req.body.equipment || "").trim();
  const commodity = String(req.body.commodity || "").trim();

  const weight_lbs = int(req.body.weight_lbs);
  const miles = int(req.body.miles);

  const rate_all_in = Number(req.body.rate_all_in);
  const payment_terms = String(req.body.payment_terms || "NET 30").trim();
  const quickpay_available = String(req.body.quickpay_available || "false") === "true";

  const detention_rate_per_hr = Number(req.body.detention_rate_per_hr);
  const detention_after_hours = int(req.body.detention_after_hours);

  const appointment_type = String(req.body.appointment_type || "FCFS").trim();
  const accessorials = String(req.body.accessorials || "None").trim();
  const special_requirements = String(req.body.special_requirements || "None").trim();

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
});

app.post("/shipper/requests/:id/accept", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  const requestId = Number(req.params.id);
  const r = await pool.query(`
    SELECT lr.*, l.shipper_id, l.status as load_status, l.lane_from, l.lane_to
    FROM load_requests lr
    JOIN loads l ON l.id = lr.load_id
    WHERE lr.id=$1
  `, [requestId]);

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
  const r = await pool.query(`
    SELECT lr.*, l.shipper_id, l.lane_from, l.lane_to
    FROM load_requests lr
    JOIN loads l ON l.id = lr.load_id
    WHERE lr.id=$1
  `, [requestId]);

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

/* ---------------- Rate Confirmation (auto-filled contract template) ---------------- */
app.get("/shipper/loads/:id/rate-confirmation", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  const user = req.user;
  const loadId = Number(req.params.id);

  const r = await pool.query(
    `SELECT l.*, s.email as shipper_email, c.email as carrier_email
     FROM loads l
     JOIN users s ON s.id = l.shipper_id
     LEFT JOIN users c ON c.id = l.booked_carrier_id
     WHERE l.id=$1 AND l.shipper_id=$2`,
    [loadId, user.id]
  );
  const l = r.rows[0];
  if (!l) return res.sendStatus(404);
  if (String(l.status) !== "BOOKED" || !l.carrier_email) {
    return res.status(400).send("Rate confirmation is available only after a load is BOOKED.");
  }

  const rc = rateConfirmationHtml(l);

  res.send(layout({
    title: `Rate Confirmation #${l.id}`,
    user,
    body: `
      <div class="card">
        <div class="row" style="justify-content:space-between">
          <div>
            <h2 style="margin:0">Rate Confirmation</h2>
            <div class="muted">Load #${l.id} • ${escapeHtml(l.lane_from)} → ${escapeHtml(l.lane_to)}</div>
          </div>
          <a class="btn ghost" href="/dashboard">Back</a>
        </div>
        <div class="hr"></div>
        ${rc}
      </div>
    `
  }));
});

function rateConfirmationHtml(l) {
  const rpmVal = rpm(l.rate_all_in, l.miles);
  // Realistic, clean template (no "consult counsel" language)
  return `
    <div class="muted" style="line-height:1.55">
      <p><b>Shipper:</b> ${escapeHtml(l.shipper_email || "")}</p>
      <p><b>Carrier:</b> ${escapeHtml(l.carrier_email || "")}</p>
      <div class="hr"></div>

      <h3 style="margin:0 0 8px 0">Load Details</h3>
      <div class="kv">
        <div class="k">Origin</div><div>${escapeHtml(l.lane_from)}</div>
        <div class="k">Destination</div><div>${escapeHtml(l.lane_to)}</div>
        <div class="k">Pickup</div><div>${escapeHtml(l.pickup_date)}</div>
        <div class="k">Delivery</div><div>${escapeHtml(l.delivery_date)}</div>
        <div class="k">Equipment</div><div>${escapeHtml(l.equipment)}</div>
        <div class="k">Commodity</div><div>${escapeHtml(l.commodity)}</div>
        <div class="k">Weight</div><div>${int(l.weight_lbs).toLocaleString()} lbs</div>
        <div class="k">Miles</div><div>${int(l.miles).toLocaleString()} mi</div>
      </div>

      <div class="hr"></div>

      <h3 style="margin:0 0 8px 0">Rate & Payment</h3>
      <div class="kv">
        <div class="k">All-In Linehaul</div><div>${money(l.rate_all_in)} (${rpmVal ? `$${rpmVal.toFixed(2)}/mi` : ""})</div>
        <div class="k">Payment Terms</div><div>${escapeHtml(l.payment_terms)}${l.quickpay_available ? " • QuickPay Available" : ""}</div>
        <div class="k">Detention</div><div>${money(l.detention_rate_per_hr)}/hr after ${escapeHtml(l.detention_after_hours)} hours</div>
        <div class="k">Accessorials</div><div>${escapeHtml(l.accessorials)}</div>
        <div class="k">Appointment</div><div>${escapeHtml(l.appointment_type)}</div>
        <div class="k">Special Requirements</div><div>${escapeHtml(l.special_requirements)}</div>
      </div>

      <div class="hr"></div>

      <h3 style="margin:0 0 8px 0">Standard Load Terms</h3>
      <ul>
        <li>Carrier agrees to transport the shipment described above from origin to destination.</li>
        <li>Carrier represents it holds active operating authority and insurance required to perform transportation services in the United States.</li>
        <li>Carrier will provide proof of pickup and delivery (POD) and any required documents for invoicing.</li>
        <li>Accessorials and detention must be documented and approved per the load details above.</li>
        <li>Any disputes regarding payment terms or accessorials will be handled directly between shipper and carrier.</li>
      </ul>

      <div class="hr"></div>
      <div class="row">
        <div class="load" style="flex:1">
          <div style="font-weight:1000">Shipper Authorized Signature</div>
          <div class="muted">Name/Title:</div>
          <div class="muted">Date:</div>
        </div>
        <div class="load" style="flex:1">
          <div style="font-weight:1000">Carrier Authorized Signature</div>
          <div class="muted">Name/Title:</div>
          <div class="muted">Date:</div>
        </div>
      </div>
    </div>
  `;
}

/* ---------------- Carrier actions ---------------- */
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
    const insurance_expires = String(req.body.insurance_expires || "").trim();

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

/* ---------------- Admin compliance ---------------- */
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

/* ---------------- Load board (newest default; option sort=rpm; show ALL loads) ---------------- */
app.get("/loads", async (req, res) => {
  const user = getUser(req);

  // Carrier badge
  let carrierBadge = null;
  if (user?.role === "CARRIER") {
    const comp = await pool.query(`SELECT status FROM carriers_compliance WHERE carrier_id=$1`, [user.id]);
    carrierBadge = comp.rows[0]?.status || "PENDING";
  }

  // Filters / sorting
  const sort = String(req.query.sort || "newest").toLowerCase(); // newest | rpm
  const equipment = String(req.query.equipment || "").trim();
  const minMiles = req.query.minMiles !== undefined ? int(req.query.minMiles) : null;
  const maxMiles = req.query.maxMiles !== undefined ? int(req.query.maxMiles) : null;
  const minWeight = req.query.minWeight !== undefined ? int(req.query.minWeight) : null;
  const maxWeight = req.query.maxWeight !== undefined ? int(req.query.maxWeight) : null;

  // Default view: only actionable loads (OPEN + REQUESTED)
  const statusView = String(req.query.status || "actionable").toLowerCase(); // actionable | all | booked
  const statuses =
    statusView === "all" ? ["OPEN", "REQUESTED", "BOOKED"] :
    statusView === "booked" ? ["BOOKED"] :
    ["OPEN", "REQUESTED"];

  // Build safe SQL
  const where = [];
  const params = [];
  let p = 1;

  where.push(`status = ANY($${p++})`);
  params.push(statuses);

  if (equipment) {
    where.push(`equipment = $${p++}`);
    params.push(equipment);
  }
  if (minMiles !== null && minMiles > 0) {
    where.push(`miles >= $${p++}`);
    params.push(minMiles);
  }
  if (maxMiles !== null && maxMiles > 0) {
    where.push(`miles <= $${p++}`);
    params.push(maxMiles);
  }
  if (minWeight !== null && minWeight > 0) {
    where.push(`weight_lbs >= $${p++}`);
    params.push(minWeight);
  }
  if (maxWeight !== null && maxWeight > 0) {
    where.push(`weight_lbs <= $${p++}`);
    params.push(maxWeight);
  }

  const orderBy =
    sort === "rpm"
      ? `ORDER BY (rate_all_in / NULLIF(miles,0)) DESC NULLS LAST, created_at DESC`
      : `ORDER BY created_at DESC`;

  const sql = `SELECT * FROM loads ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ${orderBy}`;
  const r = await pool.query(sql, params);

  const body = `
    <div class="card">
      <div class="row" style="justify-content:space-between">
        <div>
          <h2 style="margin:0">Load Board</h2>
          <div class="muted">Transparent loads shown by default: all-in rate, terms, detention, accessorials.</div>
        </div>
        <div class="row">
          ${user?.role === "CARRIER"
            ? `<span class="badge ${carrierBadge === "APPROVED" ? "ok" : "warn"}">Carrier: ${escapeHtml(carrierBadge)}</span>`
            : user?.role === "SHIPPER"
              ? `<a class="btn green" href="/shipper/plans">Plans</a>`
              : ``}
        </div>
      </div>

      <div class="hr"></div>

      <form method="GET" action="/loads">
        <div class="filters">
          <select name="sort">
            <option value="newest" ${sort==="newest"?"selected":""}>Sort: Newest</option>
            <option value="rpm" ${sort==="rpm"?"selected":""}>Sort: RPM</option>
          </select>
          <select name="status">
            <option value="actionable" ${statusView==="actionable"?"selected":""}>Status: Open/Requested</option>
            <option value="all" ${statusView==="all"?"selected":""}>Status: All</option>
            <option value="booked" ${statusView==="booked"?"selected":""}>Status: Booked</option>
          </select>
          <select name="equipment">
            <option value="">Equipment: Any</option>
            ${equipmentOptionsHtml(equipment)}
          </select>
          <input name="minMiles" placeholder="Min miles" value="${escapeHtml(req.query.minMiles || "")}" />
          <input name="maxMiles" placeholder="Max miles" value="${escapeHtml(req.query.maxMiles || "")}" />
        </div>

        <div class="filters" style="margin-top:10px; grid-template-columns:1fr 1fr 1fr 1fr 1fr">
          <input name="minWeight" placeholder="Min weight (lbs)" value="${escapeHtml(req.query.minWeight || "")}" />
          <input name="maxWeight" placeholder="Max weight (lbs)" value="${escapeHtml(req.query.maxWeight || "")}" />
          <div></div><div></div>
          <button class="btn green" type="submit">Apply</button>
        </div>
      </form>

      <div class="hr"></div>

      <div class="row">
        <span class="badge brand">${r.rows.length.toLocaleString()} loads shown</span>
        ${sort === "rpm" ? `<span class="badge">Sorted by RPM (rate ÷ miles)</span>` : `<span class="badge">Sorted by newest</span>`}
      </div>

      ${r.rows.length ? r.rows.map(l => loadCard(l, user, carrierBadge)).join("") : `<div class="muted">No loads posted yet.</div>`}
    </div>
  `;
  res.send(layout({ title: "Loads", user, body }));
});

function loadCard(l, user, carrierBadge) {
  const status = String(l.status || "OPEN");
  const canRequest = user?.role === "CARRIER";
  const rpmVal = rpm(l.rate_all_in, l.miles);

  const shipperActions =
    user?.role === "SHIPPER" && String(l.status) === "BOOKED"
      ? `<a class="btn green" href="/shipper/loads/${l.id}/rate-confirmation">Rate Confirmation</a>`
      : "";

  return `
    <div class="load">
      <div class="loadTop">
        <div>
          <div class="lane">#${l.id} ${escapeHtml(l.lane_from)} → ${escapeHtml(l.lane_to)}</div>
          <div class="muted">${escapeHtml(l.pickup_date)} → ${escapeHtml(l.delivery_date)} • ${escapeHtml(l.equipment)}</div>
        </div>
        <div style="text-align:right">
          <div style="font-weight:1000">${money(l.rate_all_in)} <span class="muted">(all-in)</span></div>
          <div class="muted">${int(l.miles).toLocaleString()} mi • ${int(l.weight_lbs).toLocaleString()} lbs • ${rpmVal ? `$${rpmVal.toFixed(2)}/mi` : ""}</div>
          <div style="margin-top:6px"><span class="badge ${status==="BOOKED"?"ok":status==="REQUESTED"?"warn":"brand"}">${escapeHtml(status)}</span></div>
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

      ${(canRequest || shipperActions) ? `
        <div class="row" style="margin-top:12px">
          ${shipperActions || ""}
          ${canRequest ? (
            status === "BOOKED"
              ? `<span class="badge ok">Booked</span>`
              : carrierBadge === "APPROVED"
                ? `<form method="POST" action="/carrier/loads/${l.id}/request"><button class="btn green" type="submit">Request to Book</button></form>`
                : `<span class="badge warn">Upload docs + get verified to request loads</span>`
          ) : ``}
        </div>
      ` : ``}
    </div>
  `;
}

function equipmentOptionsHtml(selected) {
  const opts = [
    "Dry Van",
    "Standard Van",
    "Reefer",
    "Flatbed",
    "Stepdeck",
    "Power Only",
    "Dump Truck",
    "Tanker",
    "Oversized Load",
    "Hazardous",
  ];
  return opts.map(o => `<option ${o===selected?"selected":""}>${escapeHtml(o)}</option>`).join("");
}

/* ---------------- Health ---------------- */
app.get("/health", (_, res) =>
  res.json({ ok: true, stripeEnabled, smtpEnabled: !!getMailer() })
);

/* ---------------- Start ---------------- */
initDb()
  .then(() => app.listen(PORT, "0.0.0.0", () => console.log("Server running on port", PORT)))
  .catch((e) => { console.error("DB init failed:", e); process.exit(1); });
