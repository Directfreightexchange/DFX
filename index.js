/* ============================================================
   DFX — index.js (PART 1 of 2)
   Paste PART 1 first, then paste PART 2 directly underneath.
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

// Optional S3 (AWS SDK v3)
let S3Client, PutObjectCommand, GetObjectCommand;
try {
  ({ S3Client, PutObjectCommand, GetObjectCommand } = require("@aws-sdk/client-s3"));
} catch {
  // ok if not installed
}

const app = express();

// Stripe webhook must be RAW body on this route only
app.post("/stripe/webhook", express.raw({ type: "application/json" }));

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

/* ---------------- ENV ---------------- */
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;

// Admin bootstrap (TEMPORARY) - set in Render env then delete after confirmed
const BOOTSTRAP_ADMIN_EMAIL = String(process.env.BOOTSTRAP_ADMIN_EMAIL || "").trim().toLowerCase();

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const STRIPE_PRICE_STARTER = process.env.STRIPE_PRICE_STARTER;
const STRIPE_PRICE_GROWTH = process.env.STRIPE_PRICE_GROWTH;
const STRIPE_PRICE_ENTERPRISE = process.env.STRIPE_PRICE_ENTERPRISE;

// SMTP (SendGrid)
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = Number(process.env.SMTP_PORT || "587");
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const SMTP_FROM = process.env.SMTP_FROM || "no-reply@directfreightexchange.com";

// Support
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || "support@directfreightexchange.com";
const SUPPORT_PHONE = process.env.SUPPORT_PHONE || "";

// S3 optional
const AWS_REGION = process.env.AWS_REGION;
const S3_BUCKET = process.env.S3_BUCKET;
const S3_PUBLIC_BASE_URL = process.env.S3_PUBLIC_BASE_URL || "";

/* ---------------- Boot fail ---------------- */
function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
function bootFail(msg) {
  app.get("*", (_, res) => res.status(500).send(`<h1>Config error</h1><p>${escapeHtml(msg)}</p>`));
  app.listen(PORT, "0.0.0.0", () => console.log("BootFail listening on", PORT));
}

if (!DATABASE_URL) return bootFail("Missing DATABASE_URL");
if (!JWT_SECRET) return bootFail("Missing JWT_SECRET");

/* ---------------- Helpers ---------------- */
function qStr(v) {
  return String(v ?? "").trim();
}
function int(n) {
  const x = Number(n);
  return Number.isFinite(x) ? Math.trunc(x) : 0;
}
function money(n) {
  const x = Number(n);
  return Number.isFinite(x) ? `$${x.toFixed(2)}` : "";
}
function rpm(rateAllIn, miles) {
  const r = Number(rateAllIn);
  const m = Number(miles);
  if (!Number.isFinite(r) || !Number.isFinite(m) || m <= 0) return 0;
  return r / m;
}
function monthKey(d = new Date()) {
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  return `${y}-${m}`;
}
function sha256Hex(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}
function randomToken() {
  return crypto.randomBytes(32).toString("hex");
}
function safeFilename(name) {
  const base = String(name || "file").replace(/[^a-zA-Z0-9._-]/g, "_");
  return base.slice(0, 160) || "file";
}

/* ---------------- Postgres ---------------- */
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB
});

/* ---------------- Stripe ---------------- */
const stripeEnabled = !!(
  STRIPE_SECRET_KEY &&
  STRIPE_WEBHOOK_SECRET &&
  STRIPE_PRICE_STARTER &&
  STRIPE_PRICE_GROWTH &&
  STRIPE_PRICE_ENTERPRISE
);
const stripe = stripeEnabled ? new Stripe(STRIPE_SECRET_KEY) : null;

const PLANS = {
  STARTER: { label: "Starter", price: 99, limit: 15 },
  GROWTH: { label: "Growth", price: 199, limit: 30 },
  ENTERPRISE: { label: "Enterprise", price: 399, limit: -1 },
};

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

/* ---------------- S3 optional ---------------- */
const s3Enabled = !!(
  AWS_REGION &&
  S3_BUCKET &&
  process.env.AWS_ACCESS_KEY_ID &&
  process.env.AWS_SECRET_ACCESS_KEY &&
  S3Client &&
  PutObjectCommand &&
  GetObjectCommand
);
const s3 = s3Enabled ? new S3Client({ region: AWS_REGION }) : null;

function publicUrlForKey(key) {
  if (!S3_PUBLIC_BASE_URL) return "";
  const base = S3_PUBLIC_BASE_URL.replace(/\/+$/, "");
  return `${base}/${key}`;
}
function s3KeyForCarrierDoc(carrierId, docType, originalName) {
  const safe = safeFilename(originalName);
  const id = crypto.randomUUID();
  const yyyy = new Date().getUTCFullYear();
  return `carriers/${carrierId}/${yyyy}/${docType}/${id}_${safe}`;
}
async function uploadBufferToS3({ key, buffer, contentType }) {
  if (!s3Enabled) throw new Error("S3 not configured");
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
  out.Body.pipe(res);
}

/* ---------------- Email ---------------- */
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
    console.log("[email skipped] SMTP not configured:", to, subject);
    return false;
  }
  try {
    await t.sendMail({ from: SMTP_FROM, to, subject, html });
    return true;
  } catch (e) {
    console.error("Email send failed:", e);
    return false;
  }
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

/* ---------------- Admin bootstrap (THIS IS THE “MISSING PIECE”) ---------------- */
async function bootstrapAdminIfNeeded() {
  const email = BOOTSTRAP_ADMIN_EMAIL;
  if (!email) return;

  const r = await pool.query(`SELECT id, email, role FROM users WHERE email=$1`, [email]);
  const u = r.rows[0];

  if (!u) {
    console.log("[BOOTSTRAP_ADMIN] No user found for:", email, "(create the account first)");
    return;
  }
  if (u.role === "ADMIN") {
    console.log("[BOOTSTRAP_ADMIN] Already ADMIN:", email);
    return;
  }

  await pool.query(`UPDATE users SET role='ADMIN' WHERE id=$1`, [u.id]);
  console.log("[BOOTSTRAP_ADMIN] Promoted to ADMIN:", email);
}

/* ---------------- UI (GREEN/BLACK) ---------------- */
const DISCLAIMER_TEXT =
  "Direct Freight Exchange is a technology platform and is not a broker or carrier. Users are responsible for verifying compliance, insurance, and payment terms.";

function layout({ title, user, body }) {
  const helpFab = `<a class="helpFab" href="/support" title="Talk to a live agent">Help</a>`;
  return `<!doctype html>
<html><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${escapeHtml(title)}</title>
<style>
:root{
  --bg:#050607;
  --panel:rgba(12,16,14,.72);
  --line:rgba(255,255,255,.10);
  --text:#eef7f1;
  --muted:rgba(238,247,241,.70);
  --green:#22c55e;
  --lime:#a3e635;
  --shadow:0 18px 60px rgba(0,0,0,.55);
  --radius:18px;
}
*{box-sizing:border-box}
body{
  margin:0; color:var(--text);
  font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;
  background:
    radial-gradient(900px 520px at 12% -8%, rgba(34,197,94,.18), transparent 55%),
    radial-gradient(900px 520px at 92% 0%, rgba(163,230,53,.12), transparent 55%),
    linear-gradient(180deg, rgba(34,197,94,.10), transparent 45%),
    var(--bg);
}
.wrap{max-width:1200px;margin:0 auto;padding:22px}
a{color:var(--lime);text-decoration:none} a:hover{text-decoration:underline}

.nav{
  display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:center;
  padding:14px 16px;border:1px solid var(--line);border-radius:20px;
  background:var(--panel);backdrop-filter: blur(10px);box-shadow:var(--shadow);
  position:sticky; top:14px; z-index:20;
}
.brand{display:flex;gap:12px;align-items:center}
.mark{
  width:46px;height:46px;border-radius:16px;border:1px solid rgba(255,255,255,.10);
  background: linear-gradient(135deg, rgba(34,197,94,.95), rgba(163,230,53,.65));
  display:grid;place-items:center; font-weight:1000; color:#06130b;
}
.sub{color:var(--muted);font-size:12px}
.right{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.pill{
  padding:7px 10px;border-radius:999px;border:1px solid var(--line);
  background:rgba(6,8,9,.60);color:var(--muted);font-size:12px
}
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:10px 14px;border-radius:12px;border:1px solid var(--line);
  background:rgba(6,8,9,.60);color:var(--text);cursor:pointer;
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
  background:var(--panel);backdrop-filter: blur(10px);box-shadow:var(--shadow);padding:18px
}
.hero{
  margin-top:16px;border:1px solid var(--line);border-radius:var(--radius);
  background: linear-gradient(180deg, rgba(12,16,14,.78), rgba(6,8,9,.62));
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
.filters{display:grid;gap:10px;grid-template-columns:1.5fr 1.5fr 1fr 1fr 1fr 1fr 1fr}
@media(max-width:980px){.filters{grid-template-columns:1fr 1fr}}
input,select,textarea{
  width:100%;padding:12px;border-radius:12px;border:1px solid var(--line);
  background:rgba(6,8,9,.68);color:var(--text);outline:none
}
textarea{min-height:120px;resize:vertical}
input:focus,select:focus,textarea:focus{border-color:rgba(34,197,94,.55)}

.badge{
  display:inline-flex;gap:8px;align-items:center;padding:6px 10px;border-radius:999px;
  border:1px solid var(--line);background:rgba(6,8,9,.55);color:var(--muted);font-size:12px
}
.badge.ok{border-color:rgba(34,197,94,.35);background:rgba(34,197,94,.10);color:rgba(219,255,236,.95)}
.badge.warn{border-color:rgba(163,230,53,.25);background:rgba(163,230,53,.08);color:rgba(240,255,219,.95)}
.badge.brand{border-color:rgba(34,197,94,.35);background:rgba(34,197,94,.08);color:rgba(219,255,236,.95)}

.load{
  margin-top:12px;padding:14px;border-radius:16px;border:1px solid rgba(255,255,255,.08);
  background:rgba(6,8,9,.60)
}
.loadTop{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
.lane{font-weight:1000}
.kv{display:grid;grid-template-columns:220px 1fr;gap:6px;margin-top:10px}
@media(max-width:780px){.kv{grid-template-columns:1fr}}
.k{color:var(--muted)}

.helpFab{
  position:fixed; right:18px; bottom:18px; z-index:9999;
  border:1px solid rgba(34,197,94,.28);
  background:rgba(6,8,9,.72);
  backdrop-filter: blur(10px);
  color:var(--text);
  padding:12px 14px;
  border-radius:999px;
  box-shadow: var(--shadow);
  font-weight:900;
}
.helpFab:hover{text-decoration:none;filter:brightness(1.08)}
.small{font-size:12px}
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
      ${
        user
          ? `<span class="pill">${escapeHtml(user.role)}</span><span class="pill">${escapeHtml(user.email)}</span>
             <a class="btn primary" href="/dashboard">Dashboard</a>
             <a class="btn ghost" href="/logout">Logout</a>`
          : `<a class="btn ghost" href="/signup">Sign up</a>
             <a class="btn primary" href="/login">Login</a>`
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

      insurance_s3_key TEXT,
      authority_s3_key TEXT,
      w9_s3_key TEXT,

      insurance_s3_url TEXT,
      authority_s3_url TEXT,
      w9_s3_url TEXT,

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

    CREATE TABLE IF NOT EXISTS password_resets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_password_resets_token_hash ON password_resets(token_hash);
  `);

  // Defensive migrations (fix old DBs)
  await pool.query(`ALTER TABLE loads ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'OPEN';`);
  await pool.query(`ALTER TABLE loads ADD COLUMN IF NOT EXISTS booked_carrier_id INTEGER;`);
}

/* ============================================================
   ROUTES START (PART 2 continues with all routes)
   ============================================================ */

/* ---- Home ---- */
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
          Direct shipper ↔ carrier with fully transparent loads: all-in rate, terms, detention, accessorials, appointment type, and notes — visible up front.
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
        <h3 style="margin-top:0">For Shippers</h3>
        <div class="muted">Subscribe to post loads. Immediate upgrades. Carriers are free.</div>
        <div class="hr"></div>
        <div class="row">
          <span class="badge ok">$99 • 15 loads/mo</span>
          <span class="badge ok">$199 • 30 loads/mo</span>
          <span class="badge ok">$399 • Unlimited</span>
          <a class="btn primary" href="${user?.role === "SHIPPER" ? "/shipper/plans" : "/signup"}">View Plans</a>
        </div>
      </div>

      <div class="card">
        <h3 style="margin-top:0">For Carriers</h3>
        <div class="muted">Free access. Upload verification docs once to earn Verified badge and unlock requesting loads.</div>
        <div class="hr"></div>
        <div class="row">
          <span class="badge brand">Verified badge</span>
          <span class="badge brand">Request-to-Book</span>
          <span class="badge brand">Transparent terms</span>
          <a class="btn primary" href="${user ? "/dashboard" : "/signup"}">Carrier Dashboard</a>
        </div>
      </div>
    </div>
  `;
  res.send(layout({ title: "DFX", user, body }));
});

/* ---- Terms ---- */
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

/* ---- Support ---- */
app.get("/support", (req, res) => {
  const user = getUser(req);
  const body = `
    <div class="card">
      <h2 style="margin-top:0">Support</h2>
      <div class="muted">Talk to a live agent (we reply to your email).</div>
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

/* ===========================
   STOP HERE — PART 2 CONTINUES
   =========================== */
/* ============================================================
   DFX — index.js (PART 2 of 2)
   Paste this directly UNDER PART 1 (same file).
   ============================================================ */

/* ---------------- Billing gate + monthly usage ---------------- */
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
  if (!stripeEnabled) return { ok: true, reason: null }; // dev/testing if Stripe not configured
  if (billing.status !== "ACTIVE") return { ok: false, reason: "Subscription required (not ACTIVE)." };
  if (billing.monthly_limit === -1) return { ok: true, reason: null };
  if (billing.loads_used >= billing.monthly_limit) return { ok: false, reason: "Monthly posting limit reached." };
  return { ok: true, reason: null };
}

async function upsertBillingFromSubscription({ shipperId, customerId, subscriptionId, subStatus, priceId }) {
  const plan = planFromPriceId(priceId);
  const planDef = plan ? PLANS[plan] : null;
  const mapped =
    subStatus === "active"
      ? "ACTIVE"
      : subStatus === "past_due"
      ? "PAST_DUE"
      : subStatus === "canceled"
      ? "CANCELED"
      : "INACTIVE";

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

/* ---------------- Auth routes ---------------- */
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

  // Always respond the same (avoid account enumeration)
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
      `<p>Click to reset your password:</p><p><a href="${escapeHtml(link)}">${escapeHtml(link)}</a></p><p>This link expires in 30 minutes.</p>`
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

/* ---------------- Stripe: plans ---------------- */
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
                                <button class="btn primary" type="submit">${
                                  status === "ACTIVE" ? "Switch immediately" : "Subscribe"
                                }</button>
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

/* ---- Stripe: invoices/receipts download ---- */
app.get("/shipper/billing", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  if (!stripeEnabled) return res.status(400).send("Stripe not configured.");

  const user = req.user;
  const bill = await pool.query(`SELECT * FROM shippers_billing WHERE shipper_id=$1`, [user.id]);
  const b = bill.rows[0];
  if (!b?.stripe_customer_id) {
    return res.send(layout({
      title: "Billing",
      user,
      body: `<div class="card"><h2 style="margin-top:0">Billing</h2><div class="muted">No Stripe customer yet. Subscribe to a plan first.</div><div class="hr"></div><a class="btn primary" href="/shipper/plans">View Plans</a></div>`
    }));
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
                return `
                  <div class="load">
                    <div class="row" style="justify-content:space-between">
                      <div><b>${escapeHtml(inv.number || inv.id)}</b></div>
                      <span class="badge ${status === "paid" ? "ok" : "warn"}">${escapeHtml(status)}</span>
                    </div>
                    <div class="muted">Amount: ${money(amount)} • Date: ${escapeHtml(new Date(inv.created * 1000).toISOString().slice(0,10))}</div>
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

/* ---- Stripe webhook ---- */
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

/* ---------------- Contracts (Rate Confirmation) ---------------- */
function renderRateConfirmationHtml({ load, shipperEmail, carrierEmail }) {
  // Realistic, simple rate confirmation template (HTML)
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
    <tr><th>Rate (All-In)</th><td>${money(load.rate_all_in)} (${rpmVal.toFixed(2)} RPM)</td></tr>
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

/* ---------------- Dashboards ---------------- */
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
              <a class="btn ghost" href="/shipper/billing">Invoices & Receipts</a>
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
            <div class="muted">Rate confirmations auto-fill after booking.</div>
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
                  <div class="muted">Carrier: ${escapeHtml(r.carrier_email)} • Compliance: ${escapeHtml(
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

      const needsDocs = c.status !== "APPROVED";

      const body = `
        <div class="grid">
          <div class="card">
            <div class="row" style="justify-content:space-between">
              <div>
                <h2 style="margin:0">Carrier Dashboard</h2>
                <div class="muted">Upload verification docs to earn Verified badge.</div>
              </div>
              <span class="badge ${c.status === "APPROVED" ? "ok" : "warn"}">Verification: ${escapeHtml(
        c.status
      )}</span>
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
              ${
                !s3Enabled
                  ? `<div class="muted small" style="margin-top:10px">Note: S3 is not configured. For production, add S3 env vars so docs persist.</div>`
                  : `<div class="muted small" style="margin-top:10px">Docs stored securely in S3.</div>`
              }
            </form>

            ${
              needsDocs
                ? `<div class="hr"></div><span class="badge warn">You must be VERIFIED to request loads.</span>`
                : `<div class="hr"></div><span class="badge ok">Verified — you can request loads.</span>`
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
          <div class="muted">Use filters and sort by Newest or RPM.</div>
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

            ${
              s3Enabled && (p.w9_s3_key || p.insurance_s3_key || p.authority_s3_key)
                ? `<div class="row" style="margin-top:10px">
                     ${p.w9_s3_key ? `<a class="btn ghost" href="/admin/docs/${p.carrier_id}/w9" target="_blank" rel="noopener">View W-9</a>` : ``}
                     ${p.insurance_s3_key ? `<a class="btn ghost" href="/admin/docs/${p.carrier_id}/insurance" target="_blank" rel="noopener">View COI</a>` : ``}
                     ${p.authority_s3_key ? `<a class="btn ghost" href="/admin/docs/${p.carrier_id}/authority" target="_blank" rel="noopener">View Authority</a>` : ``}
                   </div>`
                : ``
            }

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

  // email notifications
  await sendEmail(
    req.user.email,
    `DFX Booking Confirmed • Load #${row.load_id}`,
    `<p><b>Booking confirmed.</b></p><p>Load #${row.load_id}: ${escapeHtml(row.lane_from)} → ${escapeHtml(
      row.lane_to
    )}</p><p>Status: BOOKED</p>`
  );

  if (carrierEmail) {
    await sendEmail(
      carrierEmail,
      `DFX Request Accepted • Load #${row.load_id}`,
      `<p><b>Your request was accepted.</b></p><p>Load #${row.load_id}: ${escapeHtml(row.lane_from)} → ${escapeHtml(
        row.lane_to
      )}</p><p>Status: BOOKED</p>`
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
      `<p><b>Your request was declined.</b></p><p>Load #${row.load_id}: ${escapeHtml(row.lane_from)} → ${escapeHtml(
        row.lane_to
      )}</p>`
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

    // Upload to S3 if enabled (recommended)
    let w9Key = null,
      insKey = null,
      authKey = null,
      w9Url = null,
      insUrl = null,
      authUrl = null;

    try {
      if (s3Enabled) {
        const w9Up = await uploadBufferToS3({
          key: s3KeyForCarrierDoc(req.user.id, "w9", w9.originalname),
          buffer: w9.buffer,
          contentType: w9.mimetype,
        });
        const insUp = await uploadBufferToS3({
          key: s3KeyForCarrierDoc(req.user.id, "insurance", insurance.originalname),
          buffer: insurance.buffer,
          contentType: insurance.mimetype,
        });
        const authUp = await uploadBufferToS3({
          key: s3KeyForCarrierDoc(req.user.id, "authority", authority.originalname),
          buffer: authority.buffer,
          contentType: authority.mimetype,
        });

        w9Key = w9Up.key;
        insKey = insUp.key;
        authKey = authUp.key;

        w9Url = w9Up.url || null;
        insUrl = insUp.url || null;
        authUrl = authUp.url || null;
      }
    } catch (e) {
      console.error("S3 upload failed:", e);
      // Continue without S3 (still store filenames/status)
    }

    await pool.query(
      `INSERT INTO carriers_compliance (
         carrier_id,
         w9_filename, insurance_filename, authority_filename,
         insurance_expires,
         w9_s3_key, insurance_s3_key, authority_s3_key,
         w9_s3_url, insurance_s3_url, authority_s3_url,
         status, updated_at
       )
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'PENDING',NOW())
       ON CONFLICT (carrier_id) DO UPDATE SET
         w9_filename=EXCLUDED.w9_filename,
         insurance_filename=EXCLUDED.insurance_filename,
         authority_filename=EXCLUDED.authority_filename,
         insurance_expires=EXCLUDED.insurance_expires,
         w9_s3_key=EXCLUDED.w9_s3_key,
         insurance_s3_key=EXCLUDED.insurance_s3_key,
         authority_s3_key=EXCLUDED.authority_s3_key,
         w9_s3_url=EXCLUDED.w9_s3_url,
         insurance_s3_url=EXCLUDED.insurance_s3_url,
         authority_s3_url=EXCLUDED.authority_s3_url,
         status='PENDING',
         updated_at=NOW()`,
      [
        req.user.id,
        w9.originalname,
        insurance.originalname,
        authority.originalname,
        insurance_expires,
        w9Key,
        insKey,
        authKey,
        w9Url,
        insUrl,
        authUrl,
      ]
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
  await pool.query(`UPDATE carriers_compliance SET status='APPROVED', updated_at=NOW(), admin_note=NULL WHERE carrier_id=$1`, [
    carrierId,
  ]);
  res.redirect("/dashboard");
});

app.post("/admin/carriers/:id/reject", requireAuth, requireRole("ADMIN"), async (req, res) => {
  const carrierId = Number(req.params.id);
  await pool.query(
    `UPDATE carriers_compliance SET status='REJECTED', admin_note='Rejected', updated_at=NOW() WHERE carrier_id=$1`,
    [carrierId]
  );
  res.redirect("/dashboard");
});

// View docs (ADMIN) — only works with S3 enabled
app.get("/admin/docs/:carrierId/:docType", requireAuth, requireRole("ADMIN"), async (req, res) => {
  if (!s3Enabled) return res.status(400).send("S3 not configured.");
  const carrierId = Number(req.params.carrierId);
  const docType = qStr(req.params.docType);

  const r = await pool.query(`SELECT * FROM carriers_compliance WHERE carrier_id=$1`, [carrierId]);
  const c = r.rows[0];
  if (!c) return res.sendStatus(404);

  const key =
    docType === "w9"
      ? c.w9_s3_key
      : docType === "insurance"
      ? c.insurance_s3_key
      : docType === "authority"
      ? c.authority_s3_key
      : null;

  if (!key) return res.status(404).send("Doc not found.");
  return streamS3ObjectToRes(key, res);
});

/* ---------------- Load board (carrier advanced) ---------------- */
app.get("/loads", async (req, res) => {
  const user = getUser(req);

  // default: only OPEN/REQUESTED loads
  const statusFilter = qStr(req.query.status || "actionable"); // actionable|all|open|requested|booked
  const equipment = qStr(req.query.equipment || "");
  const minMiles = qStr(req.query.minMiles || "");
  const maxMiles = qStr(req.query.maxMiles || "");
  const minWeight = qStr(req.query.minWeight || "");
  const maxWeight = qStr(req.query.maxWeight || "");
  const sort = qStr(req.query.sort || "newest"); // newest|rpm

  const where = [];
  const params = [];

  // Status filter
  if (statusFilter === "actionable") {
    where.push(`l.status IN ('OPEN','REQUESTED')`);
  } else if (statusFilter === "open") {
    where.push(`l.status='OPEN'`);
  } else if (statusFilter === "requested") {
    where.push(`l.status='REQUESTED'`);
  } else if (statusFilter === "booked") {
    where.push(`l.status='BOOKED'`);
  } // "all" => no filter

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
            ? `<span class="badge ${carrierBadge === "APPROVED" ? "ok" : "warn"}">Carrier: ${escapeHtml(
                carrierBadge
              )}</span>`
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

/* ---------------- Rate confirmation download (shipper) ---------------- */
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
    s3Enabled,
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

/* ============================================================
   END — index.js
   ============================================================ */
