/**
 * DFX - Single file production starter (Render + Postgres + Stripe + Optional SMTP + Optional S3)
 * Includes:
 * - DAT-like carrier load board (filters, sort, RPM, safe SQL)
 * - Carrier onboarding w/ compliance docs required
 * - Shipper subscriptions (Stripe) + Billing Portal (invoices/receipts)
 * - Rate confirmation template auto-fill after booking
 * - Saved searches + email alerts (if SMTP configured)
 * - Carrier preferences
 * - Radius search scaffolding (ZIP dataset required)
 *
 * Notes:
 * - Render filesystem is ephemeral -> doc storage should be S3. This file supports BOTH:
 *   - Stores doc metadata in DB
 *   - If S3 env vars configured, uploads documents to S3 and serves via streaming (private) or public base url if provided
 */

const express = require("express");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const multer = require("multer");
const Stripe = require("stripe");
const nodemailer = require("nodemailer");

// Optional S3 (AWS SDK v3)
let S3Client, PutObjectCommand, GetObjectCommand;
try {
  ({ S3Client, PutObjectCommand, GetObjectCommand } = require("@aws-sdk/client-s3"));
} catch {
  // ok if not installed
}
const crypto = require("crypto");

const app = express();

// Stripe webhook needs raw body only on this route:
app.post("/stripe/webhook", express.raw({ type: "application/json" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const PORT = process.env.PORT || 3000;

// Core env
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;

// Stripe env (Shippers subscribe; Carriers free)
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const STRIPE_PRICE_STARTER = process.env.STRIPE_PRICE_STARTER;
const STRIPE_PRICE_GROWTH = process.env.STRIPE_PRICE_GROWTH;
const STRIPE_PRICE_ENTERPRISE = process.env.STRIPE_PRICE_ENTERPRISE;

// Stripe billing portal (for invoices/receipts downloads)
const STRIPE_PORTAL_RETURN_URL = process.env.STRIPE_PORTAL_RETURN_URL || `${APP_URL}/shipper/plans`;

// SMTP (optional) for notifications + alerts
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = Number(process.env.SMTP_PORT || "587");
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const SMTP_FROM = process.env.SMTP_FROM || "no-reply@directfreightexchange.com";

// Support / live agent (simple “contact support” without chat vendor)
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || "support@directfreightexchange.com";
const SUPPORT_PHONE = process.env.SUPPORT_PHONE || "";

// Optional S3 env
const AWS_REGION = process.env.AWS_REGION;
const S3_BUCKET = process.env.S3_BUCKET;
const S3_PUBLIC_BASE_URL = process.env.S3_PUBLIC_BASE_URL || ""; // optional

function bootFail(msg) {
  app.get("*", (_, res) => res.send(`<h1>Config error</h1><p>${escapeHtml(msg)}</p>`));
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

const s3Enabled = !!(
  AWS_REGION &&
  S3_BUCKET &&
  process.env.AWS_ACCESS_KEY_ID &&
  process.env.AWS_SECRET_ACCESS_KEY &&
  S3Client &&
  PutObjectCommand &&
  GetObjectCommand
);
const s3 = s3Enabled
  ? new S3Client({
      region: AWS_REGION,
      // creds from env on Render
    })
  : null;

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
});

// Pricing per your spec
const PLANS = {
  STARTER: { label: "Starter", price: 99, limit: 15 },
  GROWTH: { label: "Growth", price: 199, limit: 30 },
  ENTERPRISE: { label: "Enterprise", price: 399, limit: -1 },
};

const DISCLAIMER_TEXT =
  "Direct Freight Exchange is a technology platform and is not a broker or carrier. Users are responsible for verifying compliance, insurance, and payment terms.";

/* ---------------- Small utilities ---------------- */
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
function monthKey(d = new Date()) {
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  return `${y}-${m}`;
}
function qStr(v) {
  return String(v ?? "").trim();
}
function qNum(v, fallback = null) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}
function qArr(v) {
  if (Array.isArray(v)) return v.map((x) => String(x).trim()).filter(Boolean);
  const s = String(v ?? "").trim();
  if (!s) return [];
  return s.split(",").map((x) => x.trim()).filter(Boolean);
}

/* ---------------- Auth ---------------- */
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

/* ---------------- S3 helpers (optional) ---------------- */
function sanitizeFilename(name) {
  const base = String(name || "file").replace(/[^a-zA-Z0-9._-]/g, "_");
  return base.slice(0, 160) || "file";
}
function s3KeyForCarrierDoc(carrierId, docType, originalName) {
  const safe = sanitizeFilename(originalName);
  const id = crypto.randomUUID();
  const yyyy = new Date().getUTCFullYear();
  return `carriers/${carrierId}/${yyyy}/${docType}/${id}_${safe}`;
}
function publicUrlForKey(key) {
  if (!S3_PUBLIC_BASE_URL) return "";
  const base = S3_PUBLIC_BASE_URL.replace(/\/+$/, "");
  return `${base}/${key}`;
}
async function uploadBufferToS3({ key, buffer, contentType }) {
  if (!s3Enabled) throw new Error("S3 not configured.");
  await s3.send(
    new PutObjectCommand({
      Bucket: S3_BUCKET,
      Key: key,
      Body: buffer,
      ContentType: contentType || "application/octet-stream",
      ACL: "private",
    })
  );
  return { key, url: publicUrlForKey(key) };
}
async function streamS3ObjectToRes(key, res) {
  const out = await s3.send(new GetObjectCommand({ Bucket: S3_BUCKET, Key: key }));
  if (out.ContentType) res.setHeader("Content-Type", out.ContentType);
  if (out.ContentLength) res.setHeader("Content-Length", String(out.ContentLength));
  out.Body.pipe(res);
}

/* ---------------- UI layout (Orange/Blue) ---------------- */
function layout({ title, user, body }) {
  const helpFab = `<a class="helpFab" href="/support">Help</a>`;
  return `<!doctype html>
<html><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${escapeHtml(title)}</title>
<style>
:root{
  --bg:#06070b;
  --panel:rgba(12,14,20,.70);
  --line:rgba(255,255,255,.10);
  --text:#f3f7ff;
  --muted:rgba(243,247,255,.70);

  --blue:#3b82f6;
  --blue2:#2563eb;
  --orange:#f97316;
  --orange2:#ea580c;

  --shadow:0 18px 60px rgba(0,0,0,.55);
  --radius:18px;
}
*{box-sizing:border-box}
body{
  margin:0; color:var(--text);
  font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;
  background:
    radial-gradient(900px 520px at 12% -8%, rgba(59,130,246,.18), transparent 55%),
    radial-gradient(900px 520px at 92% 0%, rgba(249,115,22,.16), transparent 55%),
    linear-gradient(180deg, rgba(59,130,246,.10), transparent 45%),
    var(--bg);
}
.wrap{max-width:1200px;margin:0 auto;padding:22px}
a{color:rgba(253,186,116,.95);text-decoration:none} a:hover{text-decoration:underline}

.nav{
  display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:center;
  padding:14px 16px;border:1px solid var(--line);border-radius:20px;
  background:var(--panel);backdrop-filter: blur(10px);box-shadow:var(--shadow);
  position:sticky; top:14px; z-index:20;
}
.brand{display:flex;gap:12px;align-items:center}
.mark{
  width:46px;height:46px;border-radius:16px;border:1px solid rgba(255,255,255,.10);
  background: linear-gradient(135deg, rgba(59,130,246,.95), rgba(249,115,22,.70));
  display:grid;place-items:center; font-weight:1000; color:#071018;
}
.sub{color:var(--muted);font-size:12px}
.right{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.pill{
  padding:7px 10px;border-radius:999px;border:1px solid var(--line);
  background:rgba(6,8,12,.60);color:var(--muted);font-size:12px
}
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:10px 14px;border-radius:12px;border:1px solid var(--line);
  background:rgba(6,8,12,.60);color:var(--text);cursor:pointer;
  transition: transform .08s ease, filter .12s ease;
}
.btn:hover{filter:brightness(1.06)}
.btn:active{transform:translateY(1px)}
.btn.primary{
  border:none;
  background: linear-gradient(135deg, rgba(249,115,22,.98), rgba(59,130,246,.72));
  color:#071018; font-weight:1000;
  box-shadow: 0 18px 55px rgba(59,130,246,.18);
}
.btn.ghost{
  border:1px solid rgba(59,130,246,.25);
  background:rgba(6,8,12,.55);
  color:var(--text);
}
.card{
  margin-top:16px;border:1px solid var(--line);border-radius:var(--radius);
  background:var(--panel);backdrop-filter: blur(10px);box-shadow:var(--shadow);padding:18px
}
.hero{
  margin-top:16px;border:1px solid var(--line);border-radius:var(--radius);
  background: linear-gradient(180deg, rgba(12,14,20,.78), rgba(6,8,12,.62));
  backdrop-filter: blur(10px);box-shadow:var(--shadow);padding:20px;position:relative;overflow:hidden;
}
.hero:before{
  content:""; position:absolute; inset:-2px;
  background:
    radial-gradient(520px 240px at 14% 0%, rgba(59,130,246,.22), transparent 60%),
    radial-gradient(520px 240px at 92% 0%, rgba(249,115,22,.18), transparent 60%);
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
  background:rgba(6,8,12,.68);color:var(--text);outline:none
}
textarea{min-height:120px;resize:vertical}
input:focus,select:focus,textarea:focus{border-color:rgba(59,130,246,.55)}

.badge{
  display:inline-flex;gap:8px;align-items:center;padding:6px 10px;border-radius:999px;
  border:1px solid var(--line);background:rgba(6,8,12,.55);color:var(--muted);font-size:12px
}
.badge.ok{border-color:rgba(59,130,246,.35);background:rgba(59,130,246,.10);color:rgba(230,240,255,.95)}
.badge.warn{border-color:rgba(249,115,22,.28);background:rgba(249,115,22,.10);color:rgba(255,238,229,.95)}
.badge.brand{border-color:rgba(249,115,22,.28);background:rgba(249,115,22,.08);color:rgba(255,238,229,.95)}

.helpFab{
  position:fixed; right:18px; bottom:18px; z-index:9999;
  border:1px solid rgba(59,130,246,.28);
  background:rgba(6,8,12,.72);
  backdrop-filter: blur(10px);
  color:var(--text);
  padding:12px 14px;
  border-radius:999px;
  box-shadow: var(--shadow);
  font-weight:900;
}
.helpFab:hover{text-decoration:none;filter:brightness(1.08)}
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
        <div class="sub">Connect carriers directly with shippers • Full transparency loads • Carriers free</div>
      </div>
    </div>
    <div class="right">
      <a class="btn ghost" href="/">Home</a>
      <a class="btn ghost" href="/loads">Load Board</a>
      ${
        user
          ? `<span class="pill">${escapeHtml(user.role)}</span><span class="pill">${escapeHtml(user.email)}</span>
             <a class="btn primary" href="/dashboard">Dashboard</a><a class="btn ghost" href="/logout">Logout</a>`
          : `<a class="btn ghost" href="/signup">Sign up</a><a class="btn primary" href="/login">Login</a>`
      }
    </div>
  </div>

  ${body}

  <div class="card" style="margin-top:16px">
    <div class="row" style="justify-content:space-between">
      <div class="muted">${escapeHtml(DISCLAIMER_TEXT)}</div>
      <div class="row">
        <a class="btn ghost" href="/terms">Terms</a>
        <a class="btn ghost" href="/support">Support</a>
        <a class="btn ghost" href="/health">Status</a>
      </div>
    </div>
  </div>

</div>
</body></html>`;
}

/* ---------------- DB schema + migrations ---------------- */
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

      detention_rate_per_hr NUMERIC NOT NULL,
      detention_after_hours INTEGER NOT NULL,

      appointment_type TEXT NOT NULL,
      accessorials TEXT NOT NULL,
      special_requirements TEXT NOT NULL,

      status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','REQUESTED','BOOKED')),
      booked_carrier_id INTEGER,

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
  `);

  // Ensure missing columns exist (fixes "column l.status does not exist" issues)
  await pool.query(`ALTER TABLE loads ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'OPEN';`);
  await pool.query(`ALTER TABLE loads ADD COLUMN IF NOT EXISTS booked_carrier_id INTEGER;`);

  // Optional S3 doc fields
  await pool.query(`ALTER TABLE carriers_compliance ADD COLUMN IF NOT EXISTS insurance_s3_key TEXT;`);
  await pool.query(`ALTER TABLE carriers_compliance ADD COLUMN IF NOT EXISTS authority_s3_key TEXT;`);
  await pool.query(`ALTER TABLE carriers_compliance ADD COLUMN IF NOT EXISTS w9_s3_key TEXT;`);
  await pool.query(`ALTER TABLE carriers_compliance ADD COLUMN IF NOT EXISTS insurance_s3_url TEXT;`);
  await pool.query(`ALTER TABLE carriers_compliance ADD COLUMN IF NOT EXISTS authority_s3_url TEXT;`);
  await pool.query(`ALTER TABLE carriers_compliance ADD COLUMN IF NOT EXISTS w9_s3_url TEXT;`);

  // Carrier preferences (DAT-style personalization)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS carrier_preferences (
      carrier_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      home_base TEXT DEFAULT '',
      preferred_equipment TEXT[] DEFAULT '{}',
      preferred_min_miles INTEGER DEFAULT 0,
      preferred_max_miles INTEGER DEFAULT 0,
      preferred_min_weight INTEGER DEFAULT 0,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Saved searches (alerts)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS carrier_saved_searches (
      id SERIAL PRIMARY KEY,
      carrier_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      equips TEXT[] DEFAULT '{}',
      origin TEXT DEFAULT '',
      dest TEXT DEFAULT '',
      min_miles INTEGER,
      max_miles INTEGER,
      min_weight INTEGER,
      max_weight INTEGER,
      pickup_from TEXT DEFAULT '',
      pickup_to TEXT DEFAULT '',
      only_open BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // ZIP dataset scaffold for radius search (needs data loaded)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS zips (
      zip TEXT PRIMARY KEY,
      lat DOUBLE PRECISION NOT NULL,
      lng DOUBLE PRECISION NOT NULL,
      city TEXT DEFAULT '',
      state TEXT DEFAULT ''
    );
  `);

  // Booked workflow docs (BOL) scaffold
  await pool.query(`
    CREATE TABLE IF NOT EXISTS load_documents (
      id SERIAL PRIMARY KEY,
      load_id INTEGER NOT NULL REFERENCES loads(id) ON DELETE CASCADE,
      doc_type TEXT NOT NULL, -- e.g. 'BOL'
      filename TEXT NOT NULL,
      s3_key TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

/* ---------------- Stripe helpers ---------------- */
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
    await pool.query(`UPDATE shippers_billing SET usage_month=$1, loads_used=0, updated_at=NOW() WHERE shipper_id=$2`, [nowM, shipperId]);
    b.usage_month = nowM;
    b.loads_used = 0;
  }
  return b;
}
function postingAllowed(billing) {
  if (!stripeEnabled) return { ok: true, reason: null }; // allow dev/testing if stripe not configured
  if (billing.status !== "ACTIVE") return { ok: false, reason: "Subscription required (not ACTIVE)." };
  if (billing.monthly_limit === -1) return { ok: true, reason: null };
  if (billing.loads_used >= billing.monthly_limit) return { ok: false, reason: "Monthly posting limit reached." };
  return { ok: true, reason: null };
}

/* ---------------- Pages ---------------- */
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
        <div class="muted" style="max-width:900px">
          Direct Freight Exchange connects shippers and carriers directly with <b>full load transparency</b>:
          <b>all-in rate</b>, <b>payment terms</b>, <b>detention</b>, <b>accessorials</b>, appointment type, and notes — visible up front.
        </div>
        <div class="hr"></div>
        <div class="row">
          <a class="btn primary" href="${user ? "/dashboard" : "/signup"}">${user ? "Go to Dashboard" : "Create account"}</a>
          <a class="btn ghost" href="/loads">Browse Load Board</a>
          <a class="btn ghost" href="/terms">Terms</a>
        </div>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <h3 style="margin-top:0">Shippers</h3>
        <div class="muted">Subscribe to post loads. Carriers see all-in pricing, mileage, weight, RPM, and terms by default.</div>
        <div class="hr"></div>
        <div class="row">
          <span class="badge ok">$99 • 15 loads/mo</span>
          <span class="badge ok">$199 • 30 loads/mo</span>
          <span class="badge ok">$399 • Unlimited</span>
          <a class="btn primary" href="${user?.role === "SHIPPER" ? "/shipper/plans" : "/signup"}">View Plans</a>
        </div>
      </div>

      <div class="card">
        <h3 style="margin-top:0">Carriers</h3>
        <div class="muted">Free access. Upload compliance docs once to get Verified, then request loads directly.</div>
        <div class="hr"></div>
        <div class="row">
          <span class="badge brand">DAT-style board</span>
          <span class="badge brand">RPM sorting</span>
          <span class="badge brand">Direct requests</span>
          <a class="btn primary" href="${user?.role ? "/dashboard" : "/signup"}">Carrier Dashboard</a>
        </div>
      </div>
    </div>
  `;
  res.send(layout({ title: "DFX", user, body }));
});

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

/* ---------------- Support (Help button -> “live agent” via email/phone) ---------------- */
app.get("/support", (req, res) => {
  const user = getUser(req);
  const body = `
    <div class="card">
      <h2 style="margin-top:0">Support</h2>
      <div class="muted">Talk to a live agent (we reply to your email). This is the simplest production-safe option without a chat vendor.</div>
      <div class="hr"></div>
      <div class="row">
        <a class="btn primary" href="mailto:${escapeHtml(SUPPORT_EMAIL)}">Email Support</a>
        ${SUPPORT_PHONE ? `<a class="btn ghost" href="tel:${escapeHtml(SUPPORT_PHONE)}">Call</a>` : ``}
      </div>
      <div class="hr"></div>
      <form method="POST" action="/support">
        <div class="filters" style="grid-template-columns:1fr 1fr">
          <input name="name" placeholder="Your name" required />
          <input name="email" type="email" placeholder="Your email" required />
        </div>
        <div style="margin-top:10px">
          <textarea name="message" placeholder="How can we help?" required></textarea>
        </div>
        <div class="row" style="margin-top:12px">
          <button class="btn primary" type="submit">Send</button>
          <a class="btn ghost" href="/">Back</a>
        </div>
      </form>
    </div>
  `;
  res.send(layout({ title: "Support", user, body }));
});
app.post("/support", async (req, res) => {
  const user = getUser(req);
  const name = qStr(req.body.name);
  const email = qStr(req.body.email);
  const message = qStr(req.body.message);
  if (!name || !email || !message) return res.status(400).send("Missing fields.");

  const who = user ? `${user.role} • ${user.email}` : "Guest";
  const html = `
    <p><b>From:</b> ${escapeHtml(name)} (${escapeHtml(email)})</p>
    <p><b>User:</b> ${escapeHtml(who)}</p>
    <p><b>Message:</b><br/>${escapeHtml(message).replaceAll("\n", "<br/>")}</p>
  `;
  await sendEmail(SUPPORT_EMAIL, `DFX Support • ${name}`, html);

  res.send(layout({
    title: "Support Sent",
    user,
    body: `<div class="card"><h2 style="margin-top:0">Sent ✅</h2><div class="muted">We’ll reply to your email.</div><div class="hr"></div><a class="btn primary" href="/">Home</a></div>`
  }));
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
          <button class="btn primary" type="submit">Create</button>
          <a class="btn ghost" href="/login">Login</a>
        </div>
      </form>
    </div>`
  }));
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
      await pool.query(`INSERT INTO carriers_compliance (carrier_id,status) VALUES ($1,'PENDING') ON CONFLICT DO NOTHING`, [r.rows[0].id]);
      await pool.query(`INSERT INTO carrier_preferences (carrier_id) VALUES ($1) ON CONFLICT DO NOTHING`, [r.rows[0].id]);
    }

    signIn(res, r.rows[0]);

    // Force carriers into compliance upload immediately
    if (role === "CARRIER") return res.redirect("/carrier/onboarding");
    return res.redirect("/dashboard");
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
          <button class="btn primary" type="submit">Login</button>
          <a class="btn ghost" href="/signup">Create</a>
          <a class="btn ghost" href="/loads">Load Board</a>
        </div>
      </form>
    </div>`
  }));
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

    // Force carriers into compliance if missing docs
    if (u.role === "CARRIER") {
      const comp = await pool.query(`SELECT * FROM carriers_compliance WHERE carrier_id=$1`, [u.id]);
      const c = comp.rows[0];
      const missingDocs = !c?.insurance_filename || !c?.authority_filename || !c?.w9_filename;
      if (missingDocs) return res.redirect("/carrier/onboarding");
    }

    res.redirect("/dashboard");
  } catch (e) {
    console.error(e);
    res.status(500).send("Login failed.");
  }
});
app.get("/logout", (req, res) => { res.clearCookie("dfx_token"); res.redirect("/"); });

/* ---------------- Carrier onboarding (required docs) ---------------- */
app.get("/carrier/onboarding", requireAuth, requireRole("CARRIER"), async (req, res) => {
  const user = req.user;
  const comp = await pool.query(`SELECT * FROM carriers_compliance WHERE carrier_id=$1`, [user.id]);
  const c = comp.rows[0] || { status: "PENDING" };

  const missing = !c.insurance_filename || !c.authority_filename || !c.w9_filename;

  const body = `
    <div class="card">
      <h2 style="margin-top:0">Carrier Verification (Required)</h2>
      <div class="muted">Upload compliance docs to earn the Verified badge and unlock requesting loads.</div>
      <div class="hr"></div>

      <div class="row">
        <span class="badge ${c.status === "APPROVED" ? "ok" : "warn"}">Status: ${escapeHtml(c.status || "PENDING")}</span>
        ${missing ? `<span class="badge warn">Docs required</span>` : `<span class="badge ok">Docs submitted</span>`}
        ${s3Enabled ? `<span class="badge ok">Docs stored in S3</span>` : `<span class="badge warn">S3 not configured (uploads will not persist across deploys)</span>`}
      </div>

      <div class="hr"></div>

      <form method="POST" action="/carrier/compliance" enctype="multipart/form-data">
        <div class="filters" style="grid-template-columns:1.2fr 1.2fr 1fr 1fr 1fr">
          <input name="insurance_expires" placeholder="Insurance expires (YYYY-MM-DD)" value="${escapeHtml(c.insurance_expires || "")}" required />
          <input type="file" name="insurance" accept="application/pdf,image/*" required />
          <input type="file" name="authority" accept="application/pdf,image/*" required />
          <input type="file" name="w9" accept="application/pdf,image/*" required />
          <button class="btn primary" type="submit">Submit for Verification</button>
        </div>
      </form>

      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/support">Need help?</a>
        <a class="btn ghost" href="/loads">View Load Board</a>
      </div>
    </div>
  `;
  res.send(layout({ title: "Carrier Verification", user, body }));
});

app.post(
  "/carrier/compliance",
  requireAuth,
  requireRole("CARRIER"),
  upload.fields([{ name: "insurance", maxCount: 1 }, { name: "authority", maxCount: 1 }, { name: "w9", maxCount: 1 }]),
  async (req, res) => {
    try {
      const files = req.files || {};
      const insurance = files.insurance?.[0];
      const authority = files.authority?.[0];
      const w9 = files.w9?.[0];
      const insurance_expires = qStr(req.body.insurance_expires);

      if (!insurance || !authority || !w9) return res.status(400).send("All 3 documents are required.");
      if (!insurance_expires) return res.status(400).send("Insurance expiration is required.");

      let insurance_s3_key = null, authority_s3_key = null, w9_s3_key = null;
      let insurance_s3_url = null, authority_s3_url = null, w9_s3_url = null;

      if (s3Enabled) {
        const k1 = s3KeyForCarrierDoc(req.user.id, "insurance", insurance.originalname);
        const k2 = s3KeyForCarrierDoc(req.user.id, "authority", authority.originalname);
        const k3 = s3KeyForCarrierDoc(req.user.id, "w9", w9.originalname);

        const u1 = await uploadBufferToS3({ key: k1, buffer: insurance.buffer, contentType: insurance.mimetype });
        const u2 = await uploadBufferToS3({ key: k2, buffer: authority.buffer, contentType: authority.mimetype });
        const u3 = await uploadBufferToS3({ key: k3, buffer: w9.buffer, contentType: w9.mimetype });

        insurance_s3_key = u1.key; insurance_s3_url = u1.url || null;
        authority_s3_key = u2.key; authority_s3_url = u2.url || null;
        w9_s3_key = u3.key; w9_s3_url = u3.url || null;
      }

      await pool.query(
        `INSERT INTO carriers_compliance
          (carrier_id, insurance_filename, authority_filename, w9_filename, insurance_expires,
           insurance_s3_key, authority_s3_key, w9_s3_key,
           insurance_s3_url, authority_s3_url, w9_s3_url,
           status, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'PENDING',NOW())
         ON CONFLICT (carrier_id) DO UPDATE SET
           insurance_filename=EXCLUDED.insurance_filename,
           authority_filename=EXCLUDED.authority_filename,
           w9_filename=EXCLUDED.w9_filename,
           insurance_expires=EXCLUDED.insurance_expires,
           insurance_s3_key=EXCLUDED.insurance_s3_key,
           authority_s3_key=EXCLUDED.authority_s3_key,
           w9_s3_key=EXCLUDED.w9_s3_key,
           insurance_s3_url=EXCLUDED.insurance_s3_url,
           authority_s3_url=EXCLUDED.authority_s3_url,
           w9_s3_url=EXCLUDED.w9_s3_url,
           status='PENDING',
           updated_at=NOW()`,
        [
          req.user.id,
          insurance.originalname,
          authority.originalname,
          w9.originalname,
          insurance_expires,
          insurance_s3_key, authority_s3_key, w9_s3_key,
          insurance_s3_url, authority_s3_url, w9_s3_url,
        ]
      );

      res.redirect("/carrier/onboarding");
    } catch (e) {
      console.error("Carrier compliance upload failed:", e);
      res.status(500).send("Upload failed.");
    }
  }
);

// (Optional) Carrier can view their docs (streams from S3 if configured)
app.get("/carrier/docs/:type", requireAuth, requireRole("CARRIER"), async (req, res) => {
  const type = qStr(req.params.type).toLowerCase();
  if (!["insurance", "authority", "w9"].includes(type)) return res.sendStatus(404);

  const r = await pool.query(`SELECT * FROM carriers_compliance WHERE carrier_id=$1`, [req.user.id]);
  const c = r.rows[0];
  if (!c) return res.sendStatus(404);

  const key =
    type === "insurance" ? c.insurance_s3_key :
    type === "authority" ? c.authority_s3_key :
    c.w9_s3_key;

  if (!key) return res.status(404).send("Document not found.");

  const publicUrl = publicUrlForKey(key);
  if (publicUrl) return res.redirect(302, publicUrl);
  if (!s3Enabled) return res.status(500).send("S3 not configured.");

  return streamS3ObjectToRes(key, res);
});

/* ---------------- Shipper plans (Stripe subscription) ---------------- */
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
      </div>

      ${!stripeEnabled ? `
        <div class="hr"></div>
        <div class="badge warn">Stripe not configured (add STRIPE_* env vars in Render).</div>
      ` : `
        <div class="hr"></div>
        <div class="row">
          <form method="POST" action="/shipper/billing/portal">
            <button class="btn ghost" type="submit">Invoices / Receipts (Billing Portal)</button>
          </form>
        </div>

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
                      <button class="btn primary" type="submit">${status === "ACTIVE" ? "Switch immediately" : "Subscribe"}</button>
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

  const plan = qStr(req.body.plan).toUpperCase();
  if (!PLANS[plan]) return res.status(400).send("Invalid plan.");
  const targetPriceId = priceIdForPlan(plan);

  const bill = await pool.query(`SELECT * FROM shippers_billing WHERE shipper_id=$1`, [req.user.id]);
  const b = bill.rows[0];

  // New subscription
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

  // Switch immediately (proration)
  const sub = await stripe.subscriptions.retrieve(b.stripe_subscription_id);
  const item = sub.items?.data?.[0];
  if (!item) return res.status(400).send("Subscription item not found.");

  await stripe.subscriptions.update(b.stripe_subscription_id, {
    items: [{ id: item.id, price: targetPriceId }],
    proration_behavior: "create_prorations",
  });

  const planDef = PLANS[plan];
  await pool.query(`UPDATE shippers_billing SET plan=$1, monthly_limit=$2, updated_at=NOW() WHERE shipper_id=$3`,
    [plan, planDef.limit, req.user.id]
  );

  res.redirect("/shipper/plans?switched=1");
});

// Stripe customer portal for invoices/receipts downloads
app.post("/shipper/billing/portal", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  if (!stripeEnabled) return res.status(400).send("Stripe not configured.");

  const bill = await pool.query(`SELECT * FROM shippers_billing WHERE shipper_id=$1`, [req.user.id]);
  const b = bill.rows[0];
  if (!b?.stripe_customer_id) return res.status(400).send("No Stripe customer yet. Subscribe first.");

  const session = await stripe.billingPortal.sessions.create({
    customer: b.stripe_customer_id,
    return_url: STRIPE_PORTAL_RETURN_URL,
  });

  return res.redirect(303, session.url);
});

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

      const row = await pool.query(`SELECT shipper_id FROM shippers_billing WHERE stripe_subscription_id=$1`, [subscriptionId]);
      const shipperId =
        row.rows[0]?.shipper_id ||
        (await pool.query(`SELECT shipper_id FROM shippers_billing WHERE stripe_customer_id=$1`, [customerId])).rows[0]?.shipper_id;

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

/* ---------------- DASHBOARD ---------------- */
app.get("/dashboard", requireAuth, async (req, res) => {
  const user = req.user;

  if (user.role === "SHIPPER") {
    const billing = await getAndNormalizeBilling(user.id);
    const gate = postingAllowed(billing);

    const planLabel = billing.plan ? PLANS[billing.plan]?.label : "None";
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
      LIMIT 200
    `, [user.id]);

    const body = `
      <div class="grid">
        <div class="card">
          <div class="row" style="justify-content:space-between">
            <div>
              <h2 style="margin:0">Shipper Dashboard</h2>
              <div class="muted">Post transparent loads. Carriers see RPM + all terms by default.</div>
            </div>
            <span class="badge ${billing.status === "ACTIVE" ? "ok" : "warn"}">Billing: ${escapeHtml(billing.status)}</span>
          </div>

          <div class="hr"></div>

          <div class="row">
            <span class="badge">Plan: ${escapeHtml(planLabel)}</span>
            <span class="badge brand">${escapeHtml(limitText)}</span>
            <a class="btn primary" href="/shipper/plans">Manage Plan</a>
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
                <option>Dry Van</option><option>Reefer</option><option>Flatbed</option><option>Power Only</option><option>Stepdeck</option>
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
              <button class="btn primary" type="submit">Post Load</button>
              <a class="btn ghost" href="/loads">View Load Board</a>
            </div>
          </form>
          ` : `
            <div class="badge warn">Posting blocked: ${escapeHtml(gate.reason)}</div>
            <div class="row" style="margin-top:10px">
              <a class="btn primary" href="/shipper/plans">Upgrade / Subscribe</a>
            </div>
          `}
        </div>

        <div class="card">
          <h3 style="margin-top:0">Booking Requests</h3>
          <div class="muted">Carrier requests → you accept/decline → load becomes BOOKED.</div>
          <div class="hr"></div>
          ${requests.rows.length ? requests.rows.map(r => `
            <div style="margin-top:10px; padding:12px; border:1px solid rgba(255,255,255,.08); border-radius:14px; background:rgba(6,8,12,.55)">
              <div class="row" style="justify-content:space-between">
                <div><b>Load #${r.load_id}</b> ${escapeHtml(r.lane_from)} → ${escapeHtml(r.lane_to)}</div>
                <span class="badge ${r.request_status === "REQUESTED" ? "warn" : r.request_status === "ACCEPTED" ? "ok" : ""}">${escapeHtml(r.request_status)}</span>
              </div>
              <div class="muted">Carrier: ${escapeHtml(r.carrier_email)} • Compliance: ${escapeHtml(r.carrier_compliance || "PENDING")}</div>
              ${r.request_status === "REQUESTED" ? `
                <div class="row" style="margin-top:10px">
                  <form method="POST" action="/shipper/requests/${r.request_id}/accept"><button class="btn primary" type="submit">Accept</button></form>
                  <form method="POST" action="/shipper/requests/${r.request_id}/decline"><button class="btn ghost" type="submit">Decline</button></form>
                </div>` : ``}
              ${r.request_status === "ACCEPTED" ? `
                <div class="row" style="margin-top:10px">
                  <a class="btn ghost" href="/shipper/loads/${r.load_id}/ratecon">Rate Confirmation</a>
                </div>` : ``}
            </div>
          `).join("") : `<div class="muted">No requests yet.</div>`}
        </div>
      </div>

      <div class="card">
        <h3 style="margin-top:0">Contracts & Templates</h3>
        <div class="muted">Use these as starting points. You should review with counsel for your business.</div>
        <div class="hr"></div>
        <div class="row">
          <a class="btn ghost" href="/shipper/templates/rate-confirmation">Rate Confirmation Template</a>
          <a class="btn ghost" href="/shipper/templates/carrier-setup">Carrier Setup Packet</a>
          <a class="btn ghost" href="/shipper/templates/terms">Standard Load Terms</a>
        </div>
      </div>

      <div class="card">
        <h3 style="margin-top:0">Your Loads</h3>
        <div class="hr"></div>
        ${myLoads.rows.length ? myLoads.rows.map(l => shipperLoadRow(l)).join("") : `<div class="muted">No loads yet.</div>`}
      </div>
    `;
    return res.send(layout({ title: "Dashboard", user, body }));
  }

  if (user.role === "CARRIER") {
    const comp = await pool.query(`SELECT * FROM carriers_compliance WHERE carrier_id=$1`, [user.id]);
    const c = comp.rows[0] || { status: "PENDING" };
    const missingDocs = !c.insurance_filename || !c.authority_filename || !c.w9_filename;

    // Force carriers to upload docs before using dashboard
    if (missingDocs) return res.redirect("/carrier/onboarding");

    const prefs = await pool.query(`SELECT * FROM carrier_preferences WHERE carrier_id=$1`, [user.id]);
    const p = prefs.rows[0] || {};

    const myReqs = await pool.query(`
      SELECT lr.*, l.lane_from, l.lane_to, l.status as load_status
      FROM load_requests lr
      JOIN loads l ON l.id = lr.load_id
      WHERE lr.carrier_id=$1
      ORDER BY lr.created_at DESC
      LIMIT 200
    `, [user.id]);

    const body = `
      <div class="grid">
        <div class="card">
          <div class="row" style="justify-content:space-between">
            <div>
              <h2 style="margin:0">Carrier Dashboard</h2>
              <div class="muted">Carriers are free. Verified carriers can request loads.</div>
            </div>
            <span class="badge ${c.status === "APPROVED" ? "ok" : "warn"}">Compliance: ${escapeHtml(c.status)}</span>
          </div>

          <div class="hr"></div>

          <div class="row">
            <a class="btn primary" href="/loads">DAT-Style Load Board</a>
            <a class="btn ghost" href="/carrier/onboarding">Update Docs</a>
            <a class="btn ghost" href="/carrier/searches">Saved Searches</a>
          </div>

          <div class="hr"></div>

          <h3 style="margin:0 0 10px 0">Carrier Preferences</h3>
          <form method="POST" action="/carrier/preferences">
            <div class="filters">
              <input name="home_base" placeholder="Home base (City, ST)" value="${escapeHtml(p.home_base || "")}" />
              <input name="preferred_equipment" placeholder="Preferred equipment (comma-separated)" value="${escapeHtml((p.preferred_equipment || []).join(", "))}" />
              <input name="preferred_min_miles" type="number" placeholder="Preferred min miles" value="${p.preferred_min_miles || ""}" />
              <input name="preferred_max_miles" type="number" placeholder="Preferred max miles" value="${p.preferred_max_miles || ""}" />
              <input name="preferred_min_weight" type="number" placeholder="Preferred min weight" value="${p.preferred_min_weight || ""}" />
            </div>
            <div class="row" style="margin-top:12px">
              <button class="btn primary" type="submit">Save Preferences</button>
              <a class="btn ghost" href="/support">Help</a>
            </div>
          </form>
        </div>

        <div class="card">
          <h3 style="margin-top:0">Your Requests</h3>
          <div class="hr"></div>
          ${myReqs.rows.length ? myReqs.rows.map(r => `
            <div style="margin-top:10px; padding:12px; border:1px solid rgba(255,255,255,.08); border-radius:14px; background:rgba(6,8,12,.55)">
              <div class="row" style="justify-content:space-between">
                <div><b>Load #${r.load_id}</b> ${escapeHtml(r.lane_from)} → ${escapeHtml(r.lane_to)}</div>
                <span class="badge ${r.status === "REQUESTED" ? "warn" : r.status === "ACCEPTED" ? "ok" : ""}">${escapeHtml(r.status)}</span>
              </div>
              <div class="muted">Load status: ${escapeHtml(r.load_status)}</div>
            </div>
          `).join("") : `<div class="muted">No requests yet.</div>`}
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
    LIMIT 200
  `);

  const body = `
    <div class="card">
      <h2 style="margin-top:0">Admin — Compliance Approvals</h2>
      <div class="muted">Approve carriers to enable Direct Booking + Verified badge.</div>
      <div class="hr"></div>
      ${pending.rows.length ? pending.rows.map(p => `
        <div style="margin-top:10px; padding:12px; border:1px solid rgba(255,255,255,.08); border-radius:14px; background:rgba(6,8,12,.55)">
          <div class="row" style="justify-content:space-between">
            <div><b>${escapeHtml(p.email)}</b> • Insurance exp: ${escapeHtml(p.insurance_expires || "—")}</div>
            <span class="badge warn">PENDING</span>
          </div>
          <div class="muted">Files: ${escapeHtml(p.insurance_filename||"—")}, ${escapeHtml(p.authority_filename||"—")}, ${escapeHtml(p.w9_filename||"—")}</div>
          <div class="row" style="margin-top:10px">
            <form method="POST" action="/admin/carriers/${p.carrier_id}/approve"><button class="btn primary" type="submit">Approve</button></form>
            <form method="POST" action="/admin/carriers/${p.carrier_id}/reject"><button class="btn ghost" type="submit">Reject</button></form>
          </div>
        </div>
      `).join("") : `<div class="muted">No pending carriers.</div>`}
    </div>
  `;
  return res.send(layout({ title: "Admin", user, body }));
});

function shipperLoadRow(l) {
  const status = qStr(l.status || "OPEN");
  return `
    <div style="margin-top:10px; padding:12px; border:1px solid rgba(255,255,255,.08); border-radius:14px; background:rgba(6,8,12,.55)">
      <div class="row" style="justify-content:space-between">
        <div><b>#${l.id}</b> ${escapeHtml(l.lane_from)} → ${escapeHtml(l.lane_to)}</div>
        <span class="badge ${status==="BOOKED"?"ok":status==="REQUESTED"?"warn":"brand"}">${escapeHtml(status)}</span>
      </div>
      <div class="muted">${escapeHtml(l.pickup_date)} → ${escapeHtml(l.delivery_date)} • ${escapeHtml(l.equipment)} • ${int(l.miles).toLocaleString()} mi • ${money(l.rate_all_in)} all-in</div>
    </div>
  `;
}

/* ---------------- Carrier preferences ---------------- */
app.post("/carrier/preferences", requireAuth, requireRole("CARRIER"), async (req, res) => {
  const home_base = qStr(req.body.home_base);
  const preferred_equipment = qArr(req.body.preferred_equipment);
  const preferred_min_miles = int(req.body.preferred_min_miles);
  const preferred_max_miles = int(req.body.preferred_max_miles);
  const preferred_min_weight = int(req.body.preferred_min_weight);

  await pool.query(`
    INSERT INTO carrier_preferences (carrier_id, home_base, preferred_equipment, preferred_min_miles, preferred_max_miles, preferred_min_weight, updated_at)
    VALUES ($1,$2,$3,$4,$5,$6,NOW())
    ON CONFLICT (carrier_id) DO UPDATE SET
      home_base=EXCLUDED.home_base,
      preferred_equipment=EXCLUDED.preferred_equipment,
      preferred_min_miles=EXCLUDED.preferred_min_miles,
      preferred_max_miles=EXCLUDED.preferred_max_miles,
      preferred_min_weight=EXCLUDED.preferred_min_weight,
      updated_at=NOW()
  `, [req.user.id, home_base, preferred_equipment, preferred_min_miles, preferred_max_miles, preferred_min_weight]);

  res.redirect("/dashboard");
});

/* ---------------- Shipper actions ---------------- */
async function notifySavedSearchesAboutLoad(loadRow) {
  // Minimal matching: equipment + optional origin/dest substring + miles/weight ranges + pickup window
  // Sends emails only if SMTP is configured.
  const t = getMailer();
  if (!t) return;

  const searches = await pool.query(`
    SELECT css.*, u.email as carrier_email
    FROM carrier_saved_searches css
    JOIN users u ON u.id = css.carrier_id
    WHERE css.only_open = true
  `);

  const matches = [];
  for (const s of searches.rows) {
    if (Array.isArray(s.equips) && s.equips.length && !s.equips.includes(loadRow.equipment)) continue;
    if (s.origin && !String(loadRow.lane_from || "").toLowerCase().includes(String(s.origin).toLowerCase())) continue;
    if (s.dest && !String(loadRow.lane_to || "").toLowerCase().includes(String(s.dest).toLowerCase())) continue;

    if (s.min_miles != null && int(loadRow.miles) < int(s.min_miles)) continue;
    if (s.max_miles != null && int(loadRow.miles) > int(s.max_miles)) continue;

    if (s.min_weight != null && int(loadRow.weight_lbs) < int(s.min_weight)) continue;
    if (s.max_weight != null && int(loadRow.weight_lbs) > int(s.max_weight)) continue;

    if (s.pickup_from && String(loadRow.pickup_date) < String(s.pickup_from)) continue;
    if (s.pickup_to && String(loadRow.pickup_date) > String(s.pickup_to)) continue;

    matches.push(s);
  }

  for (const m of matches.slice(0, 50)) {
    await sendEmail(
      m.carrier_email,
      `DFX Load Match • ${loadRow.lane_from} → ${loadRow.lane_to}`,
      `<p><b>New matching load posted.</b></p>
       <p>${escapeHtml(loadRow.lane_from)} → ${escapeHtml(loadRow.lane_to)}</p>
       <p>${escapeHtml(loadRow.equipment)} • ${int(loadRow.weight_lbs).toLocaleString()} lbs • ${int(loadRow.miles).toLocaleString()} mi</p>
       <p>Rate: ${money(loadRow.rate_all_in)} all-in • Pickup: ${escapeHtml(loadRow.pickup_date)}</p>
       <p><a href="${APP_URL}/loads">Open Load Board</a></p>`
    );
  }
}

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
  const quickpay_available = qStr(req.body.quickpay_available || "false") === "true";

  const detention_rate_per_hr = Number(req.body.detention_rate_per_hr);
  const detention_after_hours = int(req.body.detention_after_hours);

  const appointment_type = qStr(req.body.appointment_type || "FCFS");
  const accessorials = qStr(req.body.accessorials || "None");
  const special_requirements = qStr(req.body.special_requirements || "None");

  const ins = await pool.query(
    `INSERT INTO loads
     (shipper_id,lane_from,lane_to,pickup_date,delivery_date,equipment,weight_lbs,commodity,miles,
      rate_all_in,payment_terms,quickpay_available,detention_rate_per_hr,detention_after_hours,
      appointment_type,accessorials,special_requirements,status)
     VALUES
     ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,'OPEN')
     RETURNING *`,
    [
      req.user.id, lane_from, lane_to, pickup_date, delivery_date, equipment, weight_lbs, commodity, miles,
      rate_all_in, payment_terms, quickpay_available, detention_rate_per_hr, detention_after_hours,
      appointment_type, accessorials, special_requirements
    ]
  );

  if (billing.monthly_limit !== -1) {
    await pool.query(`UPDATE shippers_billing SET loads_used = loads_used + 1, updated_at=NOW() WHERE shipper_id=$1`, [req.user.id]);
  }

  // Saved search alerts
  await notifySavedSearchesAboutLoad(ins.rows[0]);

  res.redirect("/dashboard");
});

/* ---------------- Booking actions ---------------- */
app.post("/carrier/loads/:id/request", requireAuth, requireRole("CARRIER"), async (req, res) => {
  const loadId = Number(req.params.id);

  const comp = await pool.query(`SELECT status FROM carriers_compliance WHERE carrier_id=$1`, [req.user.id]);
  const compStatus = comp.rows[0]?.status || "PENDING";
  if (compStatus !== "APPROVED") return res.status(403).send("Compliance approval required before requesting loads.");

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

app.post("/shipper/requests/:id/accept", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  const requestId = Number(req.params.id);
  const r = await pool.query(`
    SELECT lr.*, l.shipper_id, l.status as load_status, l.lane_from, l.lane_to, l.id as load_id
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

  // Email notifications
  const carrierEmail = (await pool.query(`SELECT email FROM users WHERE id=$1`, [row.carrier_id])).rows[0]?.email;
  const shipperEmail = req.user.email;

  await sendEmail(
    shipperEmail,
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

/* ---------------- Rate Confirmation (auto-fill) ---------------- */
app.get("/shipper/loads/:id/ratecon", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  const loadId = Number(req.params.id);

  const lq = await pool.query(`SELECT * FROM loads WHERE id=$1`, [loadId]);
  const l = lq.rows[0];
  if (!l || l.shipper_id !== req.user.id) return res.sendStatus(404);
  if (String(l.status) !== "BOOKED") return res.status(400).send("Rate confirmation is available after booking.");

  const carrierEmail = l.booked_carrier_id
    ? (await pool.query(`SELECT email FROM users WHERE id=$1`, [l.booked_carrier_id])).rows[0]?.email
    : "";

  const body = `
    <div class="card">
      <div class="row" style="justify-content:space-between">
        <div>
          <h2 style="margin:0">Rate Confirmation</h2>
          <div class="muted">Auto-filled after booking. Customize as needed.</div>
        </div>
        <span class="badge ok">Load #${l.id}</span>
      </div>
      <div class="hr"></div>

      <div class="muted" style="line-height:1.55">
        <p><b>Shipper:</b> ${escapeHtml(req.user.email)}</p>
        <p><b>Carrier:</b> ${escapeHtml(carrierEmail || "—")}</p>

        <p><b>Lane:</b> ${escapeHtml(l.lane_from)} → ${escapeHtml(l.lane_to)}</p>
        <p><b>Pickup:</b> ${escapeHtml(l.pickup_date)} • <b>Delivery:</b> ${escapeHtml(l.delivery_date)}</p>

        <p><b>Equipment:</b> ${escapeHtml(l.equipment)} • <b>Weight:</b> ${int(l.weight_lbs).toLocaleString()} lbs • <b>Miles:</b> ${int(l.miles).toLocaleString()}</p>

        <p><b>All-In Rate:</b> ${money(l.rate_all_in)} • <b>Payment Terms:</b> ${escapeHtml(l.payment_terms)}${l.quickpay_available ? " (QuickPay available)" : ""}</p>

        <p><b>Detention:</b> ${money(l.detention_rate_per_hr)}/hr after ${escapeHtml(l.detention_after_hours)} hours</p>
        <p><b>Accessorials:</b> ${escapeHtml(l.accessorials)}</p>
        <p><b>Notes:</b> ${escapeHtml(l.special_requirements)}</p>

        <div class="hr"></div>
        <p><b>Signatures</b></p>
        <p>Shipper Authorized Signature: _______________________ Date: __________</p>
        <p>Carrier Authorized Signature: _______________________ Date: __________</p>

        <div class="hr"></div>
        <div class="muted">Disclaimer: ${escapeHtml(DISCLAIMER_TEXT)}</div>
      </div>
    </div>
  `;

  res.send(layout({ title: "Rate Confirmation", user: req.user, body }));
});

/* ---------------- Templates (simple pages) ---------------- */
app.get("/shipper/templates/:type", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  const type = qStr(req.params.type);
  const user = req.user;

  let title = "Template";
  let content = "";

  if (type === "rate-confirmation") {
    title = "Rate Confirmation Template";
    content = `
      <p><b>Parties:</b> Shipper: [Shipper Legal Name] • Carrier: [Carrier Legal Name]</p>
      <p><b>Load:</b> Origin → Destination • Pickup/Delivery • Equipment • Weight • Miles</p>
      <p><b>Rate:</b> All-in rate $____ • Payment terms ____</p>
      <p><b>Detention:</b> $____/hr after ____ hours</p>
      <p><b>Accessorials:</b> ____</p>
      <p><b>Notes:</b> ____</p>
      <p><b>Signatures</b></p>
      <p>Shipper: __________________ Date: ____</p>
      <p>Carrier: __________________ Date: ____</p>
    `;
  } else if (type === "carrier-setup") {
    title = "Carrier Setup Packet (Checklist)";
    content = `
      <ul>
        <li>W-9</li>
        <li>Certificate of Insurance (Auto Liability + Cargo)</li>
        <li>Operating Authority (MC / DOT proof)</li>
        <li>Signed rate confirmations</li>
        <li>Payment terms agreement</li>
      </ul>
    `;
  } else if (type === "terms") {
    title = "Standard Load Terms (Starting Point)";
    content = `
      <ul>
        <li>Payment Terms: NET 30 unless otherwise stated</li>
        <li>Detention: after 2 hours, billed hourly</li>
        <li>Accessorials: must be pre-approved</li>
        <li>Carrier compliance required</li>
      </ul>
    `;
  } else {
    return res.sendStatus(404);
  }

  const body = `
    <div class="card">
      <h2 style="margin-top:0">${escapeHtml(title)}</h2>
      <div class="muted">Starting point only — review with counsel for production use.</div>
      <div class="hr"></div>
      <div class="muted" style="line-height:1.55">${content}</div>
      <div class="hr"></div>
      <a class="btn primary" href="/dashboard">Back to Dashboard</a>
    </div>
  `;
  res.send(layout({ title, user, body }));
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

/* ---------------- DAT-like Load Board (Carrier view) ----------------
 * Includes filters, sorting, RPM, safe SQL params
 * Also includes scaffolding for radius search (ZIP dataset required)
 */
app.get("/loads", async (req, res) => {
  const user = getUser(req);

  let carrierBadge = null;
  if (user?.role === "CARRIER") {
    const comp = await pool.query(`SELECT status FROM carriers_compliance WHERE carrier_id=$1`, [user.id]);
    carrierBadge = comp.rows[0]?.status || "PENDING";
  }

  // Filters
  const equips = qArr(req.query.equip);
  const minMiles = qNum(req.query.minMiles);
  const maxMiles = qNum(req.query.maxMiles);
  const minWeight = qNum(req.query.minWeight);
  const maxWeight = qNum(req.query.maxWeight);

  const origin = qStr(req.query.origin);
  const dest = qStr(req.query.dest);

  const pickupFrom = qStr(req.query.pickupFrom);
  const pickupTo = qStr(req.query.pickupTo);

  const onlyOpen = qStr(req.query.onlyOpen || "1") === "1"; // default ON

  // DAT-level scaffolding: Radius search via ZIP dataset (needs data loaded into zips table)
  // If originZip/destZip provided, we compute haversine distance in SQL.
  const originZip = qStr(req.query.originZip);
  const destZip = qStr(req.query.destZip);
  const originRadius = qNum(req.query.originRadius, null); // miles
  const destRadius = qNum(req.query.destRadius, null);     // miles

  // Sorting
  const sort = qStr(req.query.sort || "newest");
  const sortSql =
    sort === "rate" ? `l.rate_all_in DESC NULLS LAST` :
    sort === "rpm"  ? `(l.rate_all_in::numeric / NULLIF(l.miles,0)) DESC NULLS LAST` :
    sort === "miles"? `l.miles ASC NULLS LAST` :
    sort === "pickup"? `l.pickup_date ASC NULLS LAST` :
    `l.created_at DESC`;

  // Safe SQL builder
  const where = [];
  const params = [];
  const add = (clause, value) => { params.push(value); where.push(clause.replace("?", `$${params.length}`)); };

  if (onlyOpen) where.push(`l.status IN ('OPEN','REQUESTED')`);
  if (equips.length) add(`l.equipment = ANY(?)`, equips);

  if (minMiles != null) add(`l.miles >= ?`, minMiles);
  if (maxMiles != null) add(`l.miles <= ?`, maxMiles);

  if (minWeight != null) add(`l.weight_lbs >= ?`, minWeight);
  if (maxWeight != null) add(`l.weight_lbs <= ?`, maxWeight);

  if (origin) add(`l.lane_from ILIKE ?`, `%${origin}%`);
  if (dest) add(`l.lane_to ILIKE ?`, `%${dest}%`);

  if (pickupFrom) add(`l.pickup_date >= ?`, pickupFrom);
  if (pickupTo) add(`l.pickup_date <= ?`, pickupTo);

  // Radius search (ZIP-based) — requires zips table populated.
  // For production: load a ZIP dataset into zips table.
  // We filter by distance from originZip to lane_from_zip and destZip to lane_to_zip (if you add those fields).
  // Current schema doesn't store load zips; so we only show UI scaffolding.
  const radiusNote =
    (originZip || destZip) ? `Radius search requires ZIP dataset + storing load origin/dest ZIPs in the loads table.` : "";

  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const sql = `
    SELECT
      l.*,
      (l.rate_all_in::numeric / NULLIF(l.miles,0)) AS rpm
    FROM loads l
    ${whereSql}
    ORDER BY ${sortSql}
    LIMIT 200
  `;

  const r = await pool.query(sql, params);

  // UI filters
  const equipOptions = ["Dry Van", "Reefer", "Flatbed", "Stepdeck", "Power Only"];
  const equipChips = equipOptions.map((e) => {
    const checked = equips.includes(e) ? "checked" : "";
    return `
      <label class="badge" style="cursor:pointer">
        <input type="checkbox" name="equip" value="${escapeHtml(e)}" ${checked} style="margin-right:8px; transform: translateY(1px);" />
        ${escapeHtml(e)}
      </label>
    `;
  }).join("");

  const filterPanel = `
    <div class="card">
      <div class="row" style="justify-content:space-between">
        <div>
          <h2 style="margin:0">${user?.role === "CARRIER" ? "Carrier Load Board" : "Load Board"}</h2>
          <div class="muted">DAT-style filters • Dense rows • Sort by RPM</div>
        </div>
        ${
          user?.role === "CARRIER"
            ? `<span class="badge ${carrierBadge === "APPROVED" ? "ok" : "warn"}">Carrier: ${escapeHtml(carrierBadge || "PENDING")}</span>`
            : `<span class="badge brand">All-in pricing • Transparent terms</span>`
        }
      </div>

      <div class="hr"></div>

      <form method="GET" action="/loads">
        <div class="row" style="margin-bottom:10px; gap:8px; align-items:flex-start; flex-wrap:wrap">
          ${equipChips}
        </div>

        <div class="filters" style="grid-template-columns: 1.2fr 1.2fr 1fr 1fr 1fr">
          <input name="origin" placeholder="Origin contains (city/state)" value="${escapeHtml(origin)}" />
          <input name="dest" placeholder="Destination contains (city/state)" value="${escapeHtml(dest)}" />
          <input name="minMiles" type="number" placeholder="Min miles" value="${minMiles ?? ""}" />
          <input name="maxMiles" type="number" placeholder="Max miles" value="${maxMiles ?? ""}" />
          <select name="sort">
            <option value="newest" ${sort==="newest"?"selected":""}>Sort: Newest</option>
            <option value="rate" ${sort==="rate"?"selected":""}>Sort: Highest Rate</option>
            <option value="rpm" ${sort==="rpm"?"selected":""}>Sort: Highest RPM</option>
            <option value="miles" ${sort==="miles"?"selected":""}>Sort: Shortest Miles</option>
            <option value="pickup" ${sort==="pickup"?"selected":""}>Sort: Pickup Soonest</option>
          </select>

          <input name="minWeight" type="number" placeholder="Min weight (lbs)" value="${minWeight ?? ""}" />
          <input name="maxWeight" type="number" placeholder="Max weight (lbs)" value="${maxWeight ?? ""}" />
          <input name="pickupFrom" placeholder="Pickup from (YYYY-MM-DD)" value="${escapeHtml(pickupFrom)}" />
          <input name="pickupTo" placeholder="Pickup to (YYYY-MM-DD)" value="${escapeHtml(pickupTo)}" />
          <select name="onlyOpen">
            <option value="1" ${onlyOpen ? "selected":""}>Only Open/Requested</option>
            <option value="0" ${!onlyOpen ? "selected":""}>Include Booked</option>
          </select>
        </div>

        <div class="hr"></div>

        <div class="row">
          <span class="badge brand">DAT-level upgrades (scaffold)</span>
          <input name="originZip" placeholder="Origin ZIP (radius search)" value="${escapeHtml(originZip)}" />
          <input name="originRadius" type="number" placeholder="Origin radius miles" value="${originRadius ?? ""}" />
          <input name="destZip" placeholder="Dest ZIP (radius search)" value="${escapeHtml(destZip)}" />
          <input name="destRadius" type="number" placeholder="Dest radius miles" value="${destRadius ?? ""}" />
        </div>
        ${radiusNote ? `<div class="muted" style="margin-top:8px">${escapeHtml(radiusNote)}</div>` : ``}

        <div class="row" style="margin-top:12px">
          <button class="btn primary" type="submit">Apply Filters</button>
          <a class="btn ghost" href="/loads">Reset</a>
          ${
            user?.role === "CARRIER"
              ? `<a class="btn ghost" href="/carrier/searches">Saved Searches</a>`
              : ``
          }
        </div>
      </form>
    </div>
  `;

  const rows = r.rows.map((l) => {
    const status = qStr(l.status || "OPEN");
    const rpm = Number(l.rpm);
    const rpmText = Number.isFinite(rpm) ? `$${rpm.toFixed(2)}` : "—";

    const action =
      user?.role === "CARRIER"
        ? (status === "BOOKED"
            ? `<span class="badge ok">Booked</span>`
            : (carrierBadge === "APPROVED"
                ? `<form method="POST" action="/carrier/loads/${l.id}/request">
                     <button class="btn primary" type="submit">Request</button>
                   </form>`
                : `<span class="badge warn">Upload docs + get approved</span>`
              )
          )
        : "";

    return `
      <tr>
        <td style="padding:12px 10px; border-top:1px solid rgba(255,255,255,.08)">
          <div style="font-weight:1000">${escapeHtml(l.lane_from)} → ${escapeHtml(l.lane_to)}</div>
          <div class="muted" style="font-size:12px">
            Pickup: ${escapeHtml(l.pickup_date)} • Delivery: ${escapeHtml(l.delivery_date)} • ${escapeHtml(l.appointment_type)}
          </div>
        </td>
        <td style="padding:12px 10px; border-top:1px solid rgba(255,255,255,.08)">${escapeHtml(l.equipment)}</td>
        <td style="padding:12px 10px; border-top:1px solid rgba(255,255,255,.08)">${int(l.weight_lbs).toLocaleString()}</td>
        <td style="padding:12px 10px; border-top:1px solid rgba(255,255,255,.08)">${int(l.miles).toLocaleString()}</td>
        <td style="padding:12px 10px; border-top:1px solid rgba(255,255,255,.08)">
          <div style="font-weight:1000">${money(l.rate_all_in)}</div>
          <div class="muted" style="font-size:12px">RPM: ${escapeHtml(rpmText)}</div>
        </td>
        <td style="padding:12px 10px; border-top:1px solid rgba(255,255,255,.08)">
          <span class="badge ${status==="BOOKED"?"ok":status==="REQUESTED"?"warn":"brand"}">${escapeHtml(status)}</span>
        </td>
        <td style="padding:12px 10px; border-top:1px solid rgba(255,255,255,.08)">
          <div class="muted" style="font-size:12px">${escapeHtml(l.payment_terms)}${l.quickpay_available ? " • QuickPay" : ""}</div>
          <div class="muted" style="font-size:12px">Det: ${money(l.detention_rate_per_hr)}/hr after ${escapeHtml(l.detention_after_hours)}h</div>
        </td>
        <td style="padding:12px 10px; border-top:1px solid rgba(255,255,255,.08)">${action}</td>
      </tr>
    `;
  }).join("");

  const table = `
    <div class="card">
      <div class="row" style="justify-content:space-between">
        <div class="muted">Showing ${r.rows.length} loads (max 200)</div>
        <span class="badge brand">Default: transparent loads + terms</span>
      </div>
      <div class="hr"></div>

      <div style="overflow:auto;">
        <table style="width:100%; border-collapse:collapse; min-width: 980px">
          <thead>
            <tr>
              <th style="text-align:left; padding:10px; color:rgba(243,247,255,.75)">Lane</th>
              <th style="text-align:left; padding:10px; color:rgba(243,247,255,.75)">Equip</th>
              <th style="text-align:left; padding:10px; color:rgba(243,247,255,.75)">Weight</th>
              <th style="text-align:left; padding:10px; color:rgba(243,247,255,.75)">Miles</th>
              <th style="text-align:left; padding:10px; color:rgba(243,247,255,.75)">Rate</th>
              <th style="text-align:left; padding:10px; color:rgba(243,247,255,.75)">Status</th>
              <th style="text-align:left; padding:10px; color:rgba(243,247,255,.75)">Terms</th>
              <th style="text-align:left; padding:10px; color:rgba(243,247,255,.75)">Action</th>
            </tr>
          </thead>
          <tbody>
            ${rows || `<tr><td colspan="8" style="padding:16px" class="muted">No loads match these filters.</td></tr>`}
          </tbody>
        </table>
      </div>
    </div>
  `;

  res.send(layout({ title: "Load Board", user, body: `${filterPanel}${table}` }));
});

/* ---------------- Saved searches (alerts) ---------------- */
app.get("/carrier/searches", requireAuth, requireRole("CARRIER"), async (req, res) => {
  const user = req.user;
  const searches = await pool.query(`SELECT * FROM carrier_saved_searches WHERE carrier_id=$1 ORDER BY created_at DESC`, [user.id]);

  const body = `
    <div class="card">
      <h2 style="margin-top:0">Saved Searches & Alerts</h2>
      <div class="muted">Save search filters. If SMTP is configured, we email you matching loads.</div>
      <div class="hr"></div>

      <form method="POST" action="/carrier/searches">
        <div class="filters">
          <input name="name" placeholder="Search name (e.g., Reefer TX→GA)" required />
          <input name="equips" placeholder="Equipment (comma-separated)" />
          <input name="origin" placeholder="Origin contains" />
          <input name="dest" placeholder="Destination contains" />
          <input name="min_miles" type="number" placeholder="Min miles" />
          <input name="max_miles" type="number" placeholder="Max miles" />
          <input name="min_weight" type="number" placeholder="Min weight" />
          <input name="max_weight" type="number" placeholder="Max weight" />
          <input name="pickup_from" placeholder="Pickup from YYYY-MM-DD" />
          <input name="pickup_to" placeholder="Pickup to YYYY-MM-DD" />
        </div>
        <div class="row" style="margin-top:12px">
          <button class="btn primary" type="submit">Save</button>
          <a class="btn ghost" href="/loads">Back to Load Board</a>
        </div>
      </form>

      <div class="hr"></div>

      ${searches.rows.length ? searches.rows.map(s => `
        <div style="margin-top:10px; padding:12px; border:1px solid rgba(255,255,255,.08); border-radius:14px; background:rgba(6,8,12,.55)">
          <div class="row" style="justify-content:space-between">
            <div><b>${escapeHtml(s.name)}</b></div>
            <form method="POST" action="/carrier/searches/${s.id}/delete">
              <button class="btn ghost" type="submit">Delete</button>
            </form>
          </div>
          <div class="muted" style="margin-top:6px">
            Equip: ${(s.equips||[]).join(", ") || "Any"} • Origin: ${escapeHtml(s.origin||"Any")} • Dest: ${escapeHtml(s.dest||"Any")}
          </div>
        </div>
      `).join("") : `<div class="muted">No saved searches yet.</div>`}
    </div>
  `;

  res.send(layout({ title: "Saved Searches", user, body }));
});

app.post("/carrier/searches", requireAuth, requireRole("CARRIER"), async (req, res) => {
  const name = qStr(req.body.name);
  const equips = qArr(req.body.equips);
  const origin = qStr(req.body.origin);
  const dest = qStr(req.body.dest);
  const min_miles = req.body.min_miles ? int(req.body.min_miles) : null;
  const max_miles = req.body.max_miles ? int(req.body.max_miles) : null;
  const min_weight = req.body.min_weight ? int(req.body.min_weight) : null;
  const max_weight = req.body.max_weight ? int(req.body.max_weight) : null;
  const pickup_from = qStr(req.body.pickup_from);
  const pickup_to = qStr(req.body.pickup_to);

  await pool.query(`
    INSERT INTO carrier_saved_searches
      (carrier_id, name, equips, origin, dest, min_miles, max_miles, min_weight, max_weight, pickup_from, pickup_to, only_open)
    VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,true)
  `, [req.user.id, name, equips, origin, dest, min_miles, max_miles, min_weight, max_weight, pickup_from, pickup_to]);

  res.redirect("/carrier/searches");
});

app.post("/carrier/searches/:id/delete", requireAuth, requireRole("CARRIER"), async (req, res) => {
  const id = Number(req.params.id);
  await pool.query(`DELETE FROM carrier_saved_searches WHERE id=$1 AND carrier_id=$2`, [id, req.user.id]);
  res.redirect("/carrier/searches");
});

/* ---------------- Health ---------------- */
app.get("/health", async (_, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      ok: true,
      stripeEnabled,
      smtpEnabled: !!getMailer(),
      s3Enabled,
      db: "ok",
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

/* ---------------- START ---------------- */
initDb()
  .then(() => app.listen(PORT, "0.0.0.0", () => console.log("Server running on port", PORT)))
  .catch((e) => { console.error("DB init failed:", e); process.exit(1); });
