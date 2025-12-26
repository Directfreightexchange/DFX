const express = require("express");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const multer = require("multer");
const Stripe = require("stripe");
const nodemailer = require("nodemailer");

// S3 (AWS SDK v3)
const { S3Client, PutObjectCommand, GetObjectCommand } = require("@aws-sdk/client-s3");
const crypto = require("crypto");

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const PORT = process.env.PORT || 3000;

const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;

const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;

// Stripe
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const STRIPE_PRICE_STARTER = process.env.STRIPE_PRICE_STARTER;
const STRIPE_PRICE_GROWTH = process.env.STRIPE_PRICE_GROWTH;
const STRIPE_PRICE_ENTERPRISE = process.env.STRIPE_PRICE_ENTERPRISE;

// SMTP (optional)
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = Number(process.env.SMTP_PORT || "587");
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const SMTP_FROM = process.env.SMTP_FROM || "no-reply@directfreightexchange.com";

// Help/support
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || "support@directfreightexchange.com";
const SUPPORT_PHONE = process.env.SUPPORT_PHONE || "";

// S3 env vars
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

const s3Enabled = !!(AWS_REGION && S3_BUCKET && process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY);
const s3 = s3Enabled
  ? new S3Client({
      region: AWS_REGION,
      // Credentials automatically read from env vars in Render:
      // AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
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
function monthKey(d = new Date()) {
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  return `${y}-${m}`;
}
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
function formatUSDcents(cents) {
  const x = Number(cents ?? 0);
  return `$${(x / 100).toFixed(2)}`;
}
function isoDateFromUnixSeconds(sec) {
  try {
    const d = new Date(Number(sec) * 1000);
    const y = d.getFullYear();
    const m = String(d.getMonth() + 1).padStart(2, "0");
    const day = String(d.getDate()).padStart(2, "0");
    return `${y}-${m}-${day}`;
  } catch {
    return "";
  }
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

/* ---------------- UI ---------------- */
const DISCLAIMER_TEXT =
  "Direct Freight Exchange is a technology platform and is not a broker or carrier. Users are responsible for verifying compliance, insurance, and payment terms.";

function layout({ title, user, body }) {
  const helpFab = `<a class="helpFab" href="/support">Help</a>`;
  return `<!doctype html>
<html><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${escapeHtml(title)}</title>
<style>
:root{
  --bg:#050607;
  --line:rgba(255,255,255,.10);
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
}
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
textarea{min-height:120px;resize:vertical}
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
.helpFab{
  position:fixed; right:18px; bottom:18px; z-index:9999;
  border:1px solid rgba(163,230,53,.25);
  background:rgba(6,8,9,.72);
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
        <div class="sub">Direct shipper ↔ carrier • Full transparency loads • Carriers free</div>
      </div>
    </div>
    <div class="right">
      <a class="btn ghost" href="/">Home</a>
      <a class="btn ghost" href="/loads">Load Board</a>
      ${
        user
          ? `<span class="pill">${escapeHtml(user.role)}</span><span class="pill">${escapeHtml(user.email)}</span>
             <a class="btn green" href="/dashboard">Dashboard</a><a class="btn ghost" href="/logout">Logout</a>`
          : `<a class="btn ghost" href="/signup">Sign up</a><a class="btn green" href="/login">Login</a>`
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

/* ---------- DB + migrations ---------- */
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

  await pool.query(`ALTER TABLE loads ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'OPEN';`);
  await pool.query(`ALTER TABLE loads ADD COLUMN IF NOT EXISTS booked_carrier_id INTEGER;`);

  // Add S3 doc columns (migrations)
  await pool.query(`ALTER TABLE carriers_compliance ADD COLUMN IF NOT EXISTS insurance_s3_key TEXT;`);
  await pool.query(`ALTER TABLE carriers_compliance ADD COLUMN IF NOT EXISTS authority_s3_key TEXT;`);
  await pool.query(`ALTER TABLE carriers_compliance ADD COLUMN IF NOT EXISTS w9_s3_key TEXT;`);
  await pool.query(`ALTER TABLE carriers_compliance ADD COLUMN IF NOT EXISTS insurance_s3_url TEXT;`);
  await pool.query(`ALTER TABLE carriers_compliance ADD COLUMN IF NOT EXISTS authority_s3_url TEXT;`);
  await pool.query(`ALTER TABLE carriers_compliance ADD COLUMN IF NOT EXISTS w9_s3_url TEXT;`);

  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'loads_booked_carrier_id_fkey') THEN
        ALTER TABLE loads
          ADD CONSTRAINT loads_booked_carrier_id_fkey
          FOREIGN KEY (booked_carrier_id) REFERENCES users(id);
      END IF;
    END $$;
  `);
}

/* ---------- S3 helpers ---------- */
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
  if (!s3Enabled) throw new Error("S3 not configured. Set AWS_REGION, S3_BUCKET, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY.");
  await s3.send(
    new PutObjectCommand({
      Bucket: S3_BUCKET,
      Key: key,
      Body: buffer,
      ContentType: contentType || "application/octet-stream",
      // Recommended: keep docs private; serve with signed links.
      ACL: "private",
    })
  );
  return { key, url: publicUrlForKey(key) };
}

/**
 * SIGNED DOWNLOAD LINK:
 * For simplicity (and no extra deps), we provide a redirect endpoint below that
 * streams file via server OR provides public URL if configured.
 *
 * If you want true presigned URLs, we can add @aws-sdk/s3-request-presigner.
 */
async function streamS3ObjectToRes(key, res) {
  const out = await s3.send(new GetObjectCommand({ Bucket: S3_BUCKET, Key: key }));
  if (out.ContentType) res.setHeader("Content-Type", out.ContentType);
  if (out.ContentLength) res.setHeader("Content-Length", String(out.ContentLength));
  // Stream body to response
  out.Body.pipe(res);
}

/* ---------- Stripe webhook (raw body only on this route) ---------- */
app.post("/stripe/webhook", express.raw({ type: "application/json" }));

/* ---------- Terms ---------- */
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

/* ---------- Support ---------- */
app.get("/support", (req, res) => {
  const user = getUser(req);
  const body = `
    <div class="card">
      <h2 style="margin-top:0">Support</h2>
      <div class="muted">Message a live agent. We’ll reply to your email.</div>
      <div class="hr"></div>
      <div class="row">
        <a class="btn green" href="mailto:${escapeHtml(SUPPORT_EMAIL)}">Email Support</a>
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
          <button class="btn green" type="submit">Send</button>
          <a class="btn ghost" href="/">Back</a>
        </div>
      </form>
    </div>
  `;
  res.send(layout({ title: "Support", user, body }));
});

app.post("/support", async (req, res) => {
  const user = getUser(req);
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim();
  const message = String(req.body.message || "").trim();
  if (!name || !email || !message) return res.status(400).send("Missing fields.");

  const who = user ? `${user.role} • ${user.email}` : "Guest";
  const html = `
    <p><b>From:</b> ${escapeHtml(name)} (${escapeHtml(email)})</p>
    <p><b>User:</b> ${escapeHtml(who)}</p>
    <p><b>Message:</b><br/>${escapeHtml(message).replaceAll("\n", "<br/>")}</p>
  `;
  await sendEmail(SUPPORT_EMAIL, `DFX Support • ${name}`, html);

  const body = `
    <div class="card">
      <h2 style="margin-top:0">Sent ✅</h2>
      <div class="muted">Your message was sent. We’ll reply to your email.</div>
      <div class="hr"></div>
      <a class="btn green" href="/">Home</a>
    </div>
  `;
  res.send(layout({ title: "Support Sent", user, body }));
});

/* ---------- Auth ---------- */
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
    const email = String(req.body.email || "").trim().toLowerCase();
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
      await pool.query(
        `INSERT INTO carriers_compliance (carrier_id,status) VALUES ($1,'PENDING') ON CONFLICT DO NOTHING`,
        [r.rows[0].id]
      );
    }

    signIn(res, r.rows[0]);
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
          <button class="btn green" type="submit">Login</button>
          <a class="btn ghost" href="/signup">Create</a>
          <a class="btn ghost" href="/loads">Load Board</a>
        </div>
      </form>
    </div>`
  }));
});

app.post("/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const r = await pool.query("SELECT id,email,password_hash,role FROM users WHERE email=$1", [email]);
    const u = r.rows[0];
    if (!u) return res.status(401).send("No account found. Go to /signup.");
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).send("Wrong password.");

    signIn(res, u);

    if (u.role === "CARRIER") {
      const comp = await pool.query(`SELECT * FROM carriers_compliance WHERE carrier_id=$1`, [u.id]);
      const c = comp.rows[0];
      const missing = !c?.insurance_s3_key || !c?.authority_s3_key || !c?.w9_s3_key;
      if (missing) return res.redirect("/carrier/onboarding");
    }

    res.redirect("/dashboard");
  } catch (e) {
    console.error(e);
    res.status(500).send("Login failed.");
  }
});

app.get("/logout", (req, res) => { res.clearCookie("dfx_token"); res.redirect("/"); });

/* ---------- Home ---------- */
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
          <b>all-in rate</b>, <b>payment terms</b>, <b>detention</b>, <b>accessorials</b> — visible up front.
        </div>
        <div class="hr"></div>
        <div class="row">
          <a class="btn green" href="${user ? "/dashboard" : "/signup"}">${user ? "Go to Dashboard" : "Create account"}</a>
          <a class="btn ghost" href="/loads">Browse Load Board</a>
          <a class="btn ghost" href="/terms">Terms</a>
        </div>
      </div>
    </div>
  `;
  res.send(layout({ title: "DFX", user, body }));
});

/* ---------- Carrier onboarding (S3 docs required) ---------- */
app.get("/carrier/onboarding", requireAuth, requireRole("CARRIER"), async (req, res) => {
  const user = req.user;
  const comp = await pool.query(`SELECT * FROM carriers_compliance WHERE carrier_id=$1`, [user.id]);
  const c = comp.rows[0] || { status: "PENDING" };

  const missingDocs = !c.insurance_s3_key || !c.authority_s3_key || !c.w9_s3_key;

  const docLinks = (!missingDocs)
    ? `<div class="row" style="margin-top:10px">
         <a class="btn ghost" href="/carrier/docs/insurance">View Insurance</a>
         <a class="btn ghost" href="/carrier/docs/authority">View Authority</a>
         <a class="btn ghost" href="/carrier/docs/w9">View W-9</a>
       </div>`
    : ``;

  const body = `
    <div class="card">
      <h2 style="margin-top:0">Carrier Verification (Required)</h2>
      <div class="muted">Upload documents to receive the <b>Carrier Verified</b> badge and unlock load requests.</div>
      <div class="hr"></div>

      <div class="row">
        <span class="badge ${c.status === "APPROVED" ? "ok" : "warn"}">Status: ${escapeHtml(c.status || "PENDING")}</span>
        ${missingDocs ? `<span class="badge warn">Docs Required</span>` : `<span class="badge ok">Docs Submitted</span>`}
        ${!s3Enabled ? `<span class="badge warn">S3 not configured (set AWS_* + S3_BUCKET)</span>` : ``}
      </div>

      <div class="hr"></div>

      <form method="POST" action="/carrier/compliance" enctype="multipart/form-data">
        <div class="filters" style="grid-template-columns:1.2fr 1.2fr 1fr 1fr 1fr">
          <input name="insurance_expires" placeholder="Insurance expires (YYYY-MM-DD)" value="${escapeHtml(c.insurance_expires || "")}" required />
          <input type="file" name="insurance" accept="application/pdf,image/*" required />
          <input type="file" name="authority" accept="application/pdf,image/*" required />
          <input type="file" name="w9" accept="application/pdf,image/*" required />
          <button class="btn green" type="submit">Submit for Verification</button>
        </div>
      </form>

      ${docLinks}

      <div class="hr"></div>
      <div class="row">
        <a class="btn ghost" href="/support">Need help?</a>
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
      const insurance_expires = String(req.body.insurance_expires || "").trim();

      if (!insurance || !authority || !w9) return res.status(400).send("All 3 documents are required.");
      if (!insurance_expires) return res.status(400).send("Insurance expiration is required.");

      if (!s3Enabled) return res.status(500).send("S3 not configured. Add AWS_REGION, S3_BUCKET, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY in Render.");

      // Upload all three to S3
      const insuranceKey = s3KeyForCarrierDoc(req.user.id, "insurance", insurance.originalname);
      const authorityKey = s3KeyForCarrierDoc(req.user.id, "authority", authority.originalname);
      const w9Key = s3KeyForCarrierDoc(req.user.id, "w9", w9.originalname);

      const ins = await uploadBufferToS3({ key: insuranceKey, buffer: insurance.buffer, contentType: insurance.mimetype });
      const auth = await uploadBufferToS3({ key: authorityKey, buffer: authority.buffer, contentType: authority.mimetype });
      const w9up = await uploadBufferToS3({ key: w9Key, buffer: w9.buffer, contentType: w9.mimetype });

      // Store both old filenames + new S3 keys/urls
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
          ins.key,
          auth.key,
          w9up.key,
          ins.url || null,
          auth.url || null,
          w9up.url || null,
        ]
      );

      res.redirect("/carrier/onboarding");
    } catch (e) {
      console.error("Carrier compliance upload failed:", e);
      res.status(500).send("Upload failed.");
    }
  }
);

// Secure doc access for carrier themselves
app.get("/carrier/docs/:type", requireAuth, requireRole("CARRIER"), async (req, res) => {
  const type = String(req.params.type || "").toLowerCase();
  if (!["insurance", "authority", "w9"].includes(type)) return res.sendStatus(404);
  if (!s3Enabled) return res.status(500).send("S3 not configured.");

  const r = await pool.query(`SELECT * FROM carriers_compliance WHERE carrier_id=$1`, [req.user.id]);
  const c = r.rows[0];
  if (!c) return res.sendStatus(404);

  const key =
    type === "insurance" ? c.insurance_s3_key :
    type === "authority" ? c.authority_s3_key :
    c.w9_s3_key;

  if (!key) return res.status(404).send("Document not found.");

  // If you have a public base URL, redirect to it. Otherwise stream securely.
  const publicUrl = publicUrlForKey(key);
  if (publicUrl) return res.redirect(302, publicUrl);

  return streamS3ObjectToRes(key, res);
});

/* ---------- Load board + dashboards (minimal; your existing ones can be kept) ---------- */
function loadCard(l, user, carrierBadge) {
  const status = String(l.status || "OPEN");
  const canRequest = user?.role === "CARRIER";
  return `
    <div class="load">
      <div class="loadTop">
        <div>
          <div class="lane">#${l.id} ${escapeHtml(l.lane_from)} → ${escapeHtml(l.lane_to)}</div>
          <div class="muted">${escapeHtml(l.pickup_date)} → ${escapeHtml(l.delivery_date)} • ${escapeHtml(l.equipment)}</div>
        </div>
        <div style="text-align:right">
          <div style="font-weight:1000">${money(l.rate_all_in)} <span class="muted">(all-in)</span></div>
          <div class="muted">${int(l.miles).toLocaleString()} mi • ${int(l.weight_lbs).toLocaleString()} lbs</div>
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
      ${canRequest ? `
        <div class="row" style="margin-top:12px">
          ${status === "BOOKED"
            ? `<span class="badge ok">Booked</span>`
            : carrierBadge === "APPROVED"
              ? `<form method="POST" action="/carrier/loads/${l.id}/request"><button class="btn green" type="submit">Request to Book</button></form>`
              : `<span class="badge warn">Upload docs + get approved to request loads</span>`
          }
        </div>
      ` : ``}
    </div>
  `;
}

app.get("/loads", async (req, res) => {
  const user = getUser(req);

  let carrierBadge = null;
  if (user?.role === "CARRIER") {
    const comp = await pool.query(`SELECT status FROM carriers_compliance WHERE carrier_id=$1`, [user.id]);
    carrierBadge = comp.rows[0]?.status || "PENDING";
  }

  const r = await pool.query(`SELECT * FROM loads ORDER BY created_at DESC LIMIT 200`);

  const body = `
    <div class="card">
      <div class="row" style="justify-content:space-between">
        <div>
          <h2 style="margin:0">Load Board</h2>
          <div class="muted">All-in pricing and terms shown by default.</div>
        </div>
        ${
          user?.role === "CARRIER"
            ? `<span class="badge ${carrierBadge === "APPROVED" ? "ok" : "warn"}">Carrier: ${escapeHtml(carrierBadge)}</span>`
            : ``
        }
      </div>
      <div class="hr"></div>
      ${r.rows.length ? r.rows.map(l => loadCard(l, user, carrierBadge)).join("") : `<div class="muted">No loads posted yet.</div>`}
    </div>
  `;
  res.send(layout({ title: "Loads", user, body }));
});

app.get("/dashboard", requireAuth, async (req, res) => {
  const user = req.user;

  if (user.role === "CARRIER") {
    const comp = await pool.query(`SELECT * FROM carriers_compliance WHERE carrier_id=$1`, [user.id]);
    const c = comp.rows[0] || { status: "PENDING" };
    const missing = !c.insurance_s3_key || !c.authority_s3_key || !c.w9_s3_key;
    if (missing) return res.redirect("/carrier/onboarding");

    const body = `
      <div class="card">
        <div class="row" style="justify-content:space-between">
          <div>
            <h2 style="margin:0">Carrier Dashboard</h2>
            <div class="muted">Docs stored in S3. Status: ${escapeHtml(c.status || "PENDING")}</div>
          </div>
          <span class="badge ${c.status === "APPROVED" ? "ok" : "warn"}">Compliance: ${escapeHtml(c.status)}</span>
        </div>
        <div class="hr"></div>
        <div class="row">
          <a class="btn green" href="/loads">View Load Board</a>
          <a class="btn ghost" href="/carrier/onboarding">Update Docs</a>
          <a class="btn ghost" href="/support">Help</a>
        </div>
      </div>
    `;
    return res.send(layout({ title: "Dashboard", user, body }));
  }

  // If you already have the full shipper dashboard + Stripe + contracts in your current build,
  // keep that file; this S3 version focuses on carrier uploads persistence.
  const body = `
    <div class="card">
      <h2 style="margin-top:0">Dashboard</h2>
      <div class="muted">Your current build includes the full shipper flow (plans, contracts, invoices). This S3 patch keeps carrier docs persistent.</div>
      <div class="hr"></div>
      <div class="row">
        <a class="btn green" href="/loads">Load Board</a>
      </div>
    </div>
  `;
  return res.send(layout({ title: "Dashboard", user, body }));
});

/* ---------- Health ---------- */
app.get("/health", async (_, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      ok: true,
      stripeEnabled,
      s3Enabled,
      db: "ok",
      smtpEnabled: !!getMailer(),
      s3Bucket: S3_BUCKET || null,
      s3PublicBaseUrl: S3_PUBLIC_BASE_URL || null,
    });
  } catch (e) {
    res.status(500).json({ ok: false, stripeEnabled, s3Enabled, db: "error", error: String(e.message || e) });
  }
});

/* ---------- Start ---------- */
initDb()
  .then(() => app.listen(PORT, "0.0.0.0", () => console.log("Server running on port", PORT)))
  .catch((e) => { console.error("DB init/migrations failed:", e); process.exit(1); });
