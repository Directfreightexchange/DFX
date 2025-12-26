const express = require("express");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const multer = require("multer");
const Stripe = require("stripe");
const nodemailer = require("nodemailer");

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

// Help / support
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || "support@directfreightexchange.com";
const SUPPORT_PHONE = process.env.SUPPORT_PHONE || "";

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

function bootFail(msg) {
  app.get("*", (_, res) => res.send(`<h1>Config error</h1><p>${escapeHtml(msg)}</p>`));
  app.listen(PORT, "0.0.0.0");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
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

/* ---------- DB + migrations (fixes missing columns) ---------- */
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

  // These two were the cause of: "column l.status does not exist"
  await pool.query(`ALTER TABLE loads ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'OPEN';`);
  await pool.query(`ALTER TABLE loads ADD COLUMN IF NOT EXISTS booked_carrier_id INTEGER;`);

  // Add FK if missing (safe)
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

/* ---------- Stripe billing sync ---------- */
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

/* ---------- Support (Help button) ---------- */
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
      <div class="muted" style="margin-top:10px">
        Want true live chat (Intercom / Crisp / Tawk)? Tell me which one and I’ll wire it in.
      </div>
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
      const missing = !c?.insurance_filename || !c?.authority_filename || !c?.w9_filename;
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
    <div class="grid">
      <div class="card">
        <h3 style="margin-top:0">For Shippers</h3>
        <div class="muted">Plans: $99 (15 loads), $199 (30), $399 (Unlimited). Carriers are free.</div>
        <div class="hr"></div>
        <div class="row">
          ${user?.role === "SHIPPER"
            ? `<a class="btn green" href="/shipper/plans">View Plans</a>`
            : `<a class="btn green" href="/signup">Sign up as Shipper</a>`}
          <a class="btn ghost" href="/shipper/contracts">Templates</a>
        </div>
      </div>
      <div class="card">
        <h3 style="margin-top:0">For Carriers</h3>
        <div class="muted">Upload compliance docs once → get verified → request loads.</div>
        <div class="hr"></div>
        <div class="row">
          <a class="btn green" href="${user?.role === "CARRIER" ? "/carrier/onboarding" : "/signup"}">Carrier Verification</a>
          <a class="btn ghost" href="/support">Help</a>
        </div>
      </div>
    </div>
  `;
  res.send(layout({ title: "DFX", user, body }));
});

/* ---------- Billing gate + usage ---------- */
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

/* ---------- Contract templates + auto-filled rate confirmation ---------- */
function todayISO() {
  const d = new Date();
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}
function fileDownload(res, filename, content) {
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
  res.send(content);
}
function contractDisclaimerBlock() {
  return [
    "IMPORTANT: TEMPLATE DISCLAIMER",
    "This template is provided for convenience only and is not legal advice.",
    "Direct Freight Exchange (DFX) is not a broker or carrier. Users are responsible for verifying compliance, insurance, and payment terms.",
    "Have your transportation attorney review before using in production.",
    "",
  ].join("\n");
}
function rateConfirmationTemplate({ load, shipperEmail, carrierEmail }) {
  return [
    contractDisclaimerBlock(),
    "DFX RATE CONFIRMATION (TEMPLATE)",
    `Date: ${todayISO()}`,
    "",
    `Load ID: ${load?.id ?? "[LOAD ID]"}`,
    "",
    "SHIPPER",
    `Email: ${shipperEmail || "[SHIPPER EMAIL]"}`,
    "",
    "CARRIER",
    `Email: ${carrierEmail || "[CARRIER EMAIL]"}`,
    "",
    "LANE",
    `Origin: ${load?.lane_from || "[ORIGIN]"}`,
    `Destination: ${load?.lane_to || "[DESTINATION]"}`,
    `Pickup Date: ${load?.pickup_date || "[PICKUP DATE]"}`,
    `Delivery Date: ${load?.delivery_date || "[DELIVERY DATE]"}`,
    `Equipment: ${load?.equipment || "[EQUIPMENT]"}`,
    `Commodity: ${load?.commodity || "[COMMODITY]"}`,
    `Weight: ${load?.weight_lbs ?? "[WEIGHT]"} lbs`,
    `Miles (approx): ${load?.miles ?? "[MILES]"}`,
    "",
    "PRICING (ALL-IN)",
    `All-In Rate: ${load?.rate_all_in != null ? `$${Number(load.rate_all_in).toFixed(2)}` : "[ALL-IN RATE]"}`,
    `Payment Terms: ${load?.payment_terms || "[PAYMENT TERMS]"}`,
    `QuickPay Available: ${load?.quickpay_available ? "YES" : "NO"}`,
    "",
    "DETENTION",
    `Detention Rate: ${load?.detention_rate_per_hr != null ? `$${Number(load.detention_rate_per_hr).toFixed(2)}` : "[DETENTION RATE]"}/hr`,
    `Detention Begins After: ${load?.detention_after_hours ?? "[HOURS]"} hrs`,
    "",
    "APPOINTMENTS / ACCESSORIALS",
    `Appointment Type: ${load?.appointment_type || "[APPOINTMENT TYPE]"}`,
    `Accessorials: ${load?.accessorials || "[ACCESSORIALS]"}`,
    "",
    "NOTES / SPECIAL REQUIREMENTS",
    `${load?.special_requirements || ""}`,
    "",
    "SIGNATURES",
    "Shipper Authorized Rep: _______________________   Date: __________",
    "Carrier Authorized Rep: _______________________   Date: __________",
    "",
  ].join("\n");
}

const TEMPLATE_SETUP_PACKET = [
  contractDisclaimerBlock(),
  "CARRIER SETUP PACKET (CHECKLIST TEMPLATE)",
  `Date: ${todayISO()}`,
  "",
  "Carrier Legal Name: _______________________________",
  "MC #: ____________________________________________",
  "DOT #: ___________________________________________",
  "Address: ________________________________________",
  "Primary Contact: _________________________________",
  "Phone: __________________________________________",
  "Email: __________________________________________",
  "",
  "REQUIRED DOCUMENTS",
  "[ ] W-9",
  "[ ] Certificate of Insurance (COI)",
  "[ ] Operating Authority (MC Authority / Active Status)",
  "",
].join("\n");

const TEMPLATE_W9_REQUEST = [
  contractDisclaimerBlock(),
  "W-9 REQUEST (TEMPLATE)",
  `Date: ${todayISO()}`,
  "",
  "To complete carrier setup, please provide a completed and signed IRS Form W-9.",
  "",
].join("\n");

const TEMPLATE_INSURANCE_REQUIREMENTS = [
  contractDisclaimerBlock(),
  "INSURANCE REQUIREMENTS (TEMPLATE)",
  `Date: ${todayISO()}`,
  "",
  "- Commercial Auto Liability: $__________ per occurrence",
  "- Cargo Insurance: $__________ per shipment (as required)",
  "",
].join("\n");

app.get("/shipper/contracts", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  const user = req.user;
  const loads = await pool.query(
    `SELECT * FROM loads WHERE shipper_id=$1 ORDER BY created_at DESC LIMIT 50`,
    [user.id]
  );

  const body = `
    <div class="card">
      <h2 style="margin-top:0">Contracts / Templates</h2>
      <div class="muted">Auto-fill rate confirmations after booking (carrier email is filled when BOOKED).</div>
      <div class="hr"></div>

      <div class="row">
        <a class="btn green" href="/shipper/contracts/download/setup-packet">Carrier Setup Packet</a>
        <a class="btn ghost" href="/shipper/contracts/download/w9-request">W-9 Request</a>
        <a class="btn ghost" href="/shipper/contracts/download/insurance-requirements">Insurance Requirements</a>
      </div>

      <div class="hr"></div>
      <h3 style="margin:0 0 8px 0">Rate Confirmations</h3>

      ${
        loads.rows.length
          ? loads.rows.map(l => `
              <div class="load">
                <div class="row" style="justify-content:space-between">
                  <div><b>Load #${l.id}</b> ${escapeHtml(l.lane_from)} → ${escapeHtml(l.lane_to)}</div>
                  <div class="row">
                    <span class="badge ${String(l.status||"OPEN")==="BOOKED" ? "ok" : "brand"}">${escapeHtml(String(l.status||"OPEN"))}</span>
                    <a class="btn green" href="/shipper/contracts/download/rate-confirmation/${l.id}">Download</a>
                  </div>
                </div>
              </div>
            `).join("")
          : `<div class="muted">No loads yet.</div>`
      }
    </div>
  `;
  res.send(layout({ title: "Contracts", user, body }));
});

app.get("/shipper/contracts/download/setup-packet", requireAuth, requireRole("SHIPPER"), (req, res) => {
  fileDownload(res, `DFX_Carrier_Setup_Packet_${todayISO()}.txt`, TEMPLATE_SETUP_PACKET);
});
app.get("/shipper/contracts/download/w9-request", requireAuth, requireRole("SHIPPER"), (req, res) => {
  fileDownload(res, `DFX_W9_Request_${todayISO()}.txt`, TEMPLATE_W9_REQUEST);
});
app.get("/shipper/contracts/download/insurance-requirements", requireAuth, requireRole("SHIPPER"), (req, res) => {
  fileDownload(res, `DFX_Insurance_Requirements_${todayISO()}.txt`, TEMPLATE_INSURANCE_REQUIREMENTS);
});
app.get("/shipper/contracts/download/rate-confirmation/:loadId", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  const user = req.user;
  const loadId = Number(req.params.loadId);
  const r = await pool.query(`SELECT * FROM loads WHERE id=$1 AND shipper_id=$2`, [loadId, user.id]);
  const load = r.rows[0];
  if (!load) return res.sendStatus(404);

  let carrierEmail = "[CARRIER EMAIL]";
  if (String(load.status || "").toUpperCase() === "BOOKED" && load.booked_carrier_id) {
    const cr = await pool.query(`SELECT email FROM users WHERE id=$1`, [load.booked_carrier_id]);
    if (cr.rows[0]?.email) carrierEmail = cr.rows[0].email;
  }

  const content = rateConfirmationTemplate({
    load,
    shipperEmail: user.email,
    carrierEmail,
  });

  fileDownload(res, `DFX_Rate_Confirmation_Load_${loadId}_${todayISO()}.txt`, content);
});

/* ---------- Carrier onboarding required ---------- */
app.get("/carrier/onboarding", requireAuth, requireRole("CARRIER"), async (req, res) => {
  const user = req.user;
  const comp = await pool.query(`SELECT * FROM carriers_compliance WHERE carrier_id=$1`, [user.id]);
  const c = comp.rows[0] || { status: "PENDING" };

  const missingDocs = !c.insurance_filename || !c.authority_filename || !c.w9_filename;

  const body = `
    <div class="card">
      <h2 style="margin-top:0">Carrier Verification (Required)</h2>
      <div class="muted">Upload documents to receive the <b>Carrier Verified</b> badge and unlock load requests.</div>
      <div class="hr"></div>

      <div class="row">
        <span class="badge ${c.status === "APPROVED" ? "ok" : "warn"}">Status: ${escapeHtml(c.status || "PENDING")}</span>
        ${missingDocs ? `<span class="badge warn">Docs Required</span>` : `<span class="badge ok">Docs Submitted</span>`}
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

    res.redirect("/carrier/onboarding");
  }
);

/* ---------- Stripe: plans + invoices/receipts ---------- */
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
      <div class="muted">Posting requires ACTIVE subscription.</div>
      <div class="hr"></div>
      <div class="row">
        <span class="badge ${status === "ACTIVE" ? "ok" : "warn"}">Status: ${escapeHtml(status)}</span>
        <span class="badge">Plan: ${escapeHtml(plan || "None")}</span>
        <span class="badge">Month: ${escapeHtml(usageMonth)}</span>
        <span class="badge brand">${escapeHtml(usageText)}</span>
        <a class="btn ghost" href="/shipper/billing">Invoices & Receipts</a>
      </div>

      ${
        !stripeEnabled
          ? `<div class="hr"></div><div class="badge warn">Stripe not configured (add STRIPE_* env vars in Render).</div>`
          : `
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
                    ${
                      isCurrent
                        ? `<span class="badge ok">Current plan</span>`
                        : `
                          <form method="POST" action="/shipper/plan">
                            <input type="hidden" name="plan" value="${p}">
                            <button class="btn green" type="submit">${status === "ACTIVE" ? "Switch immediately" : "Subscribe"}</button>
                          </form>
                        `
                    }
                  </div>
                `;
              }).join("")}
            </div>
          `
      }
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

// Stripe webhook (raw body)
app.post("/stripe/webhook", express.raw({ type: "application/json" }), async (req, res) => {
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

// Invoices & receipts (Stripe invoices are subscription receipts)
app.get("/shipper/billing", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  const user = req.user;

  if (!stripeEnabled) {
    const body = `<div class="card"><h2 style="margin-top:0">Invoices & Receipts</h2><div class="badge warn">Stripe not configured.</div></div>`;
    return res.send(layout({ title: "Billing", user, body }));
  }

  const bill = await pool.query(`SELECT * FROM shippers_billing WHERE shipper_id=$1`, [user.id]);
  const b = bill.rows[0];
  if (!b?.stripe_customer_id) {
    const body = `
      <div class="card">
        <h2 style="margin-top:0">Invoices & Receipts</h2>
        <div class="muted">No Stripe customer yet. Subscribe to a plan first.</div>
        <div class="hr"></div>
        <a class="btn green" href="/shipper/plans">View Plans</a>
      </div>`;
    return res.send(layout({ title: "Billing", user, body }));
  }

  const invoices = await stripe.invoices.list({ customer: b.stripe_customer_id, limit: 20 });

  const body = `
    <div class="card">
      <div class="row" style="justify-content:space-between">
        <div>
          <h2 style="margin:0">Invoices & Receipts</h2>
          <div class="muted">Open Stripe-hosted invoices or download PDFs.</div>
        </div>
        <a class="btn ghost" href="/shipper/plans">Plans</a>
      </div>
      <div class="hr"></div>

      ${
        invoices.data.length
          ? invoices.data.map(inv => {
              const date = isoDateFromUnixSeconds(inv.created);
              const amt = formatUSDcents(inv.amount_paid || inv.amount_due || inv.amount_remaining || 0);
              const status = String(inv.status || "");
              const num = inv.number || inv.id;
              const openBtn = inv.hosted_invoice_url ? `<a class="btn green" href="/shipper/billing/invoice/${inv.id}">Open</a>` : "";
              const pdfBtn = inv.invoice_pdf ? `<a class="btn ghost" href="/shipper/billing/invoice/${inv.id}?pdf=1">PDF</a>` : "";
              return `
                <div class="load">
                  <div class="row" style="justify-content:space-between">
                    <div>
                      <div style="font-weight:1000">Invoice ${escapeHtml(num)}</div>
                      <div class="muted">${escapeHtml(date)} • ${escapeHtml(status)} • ${escapeHtml(amt)}</div>
                    </div>
                    <div class="row">${openBtn}${pdfBtn}</div>
                  </div>
                </div>`;
            }).join("")
          : `<div class="muted">No invoices yet.</div>`
      }
    </div>
  `;
  res.send(layout({ title: "Billing", user, body }));
});

app.get("/shipper/billing/invoice/:invoiceId", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  if (!stripeEnabled) return res.status(400).send("Stripe not configured.");

  const user = req.user;
  const invoiceId = String(req.params.invoiceId || "");
  const pdf = String(req.query.pdf || "") === "1";

  const bill = await pool.query(`SELECT stripe_customer_id FROM shippers_billing WHERE shipper_id=$1`, [user.id]);
  const customerId = bill.rows[0]?.stripe_customer_id;
  if (!customerId) return res.status(404).send("No Stripe customer found.");

  const inv = await stripe.invoices.retrieve(invoiceId);
  if (String(inv.customer) !== String(customerId)) return res.sendStatus(403);

  const target = pdf ? inv.invoice_pdf : inv.hosted_invoice_url;
  if (!target) return res.status(404).send("Invoice link not available.");
  return res.redirect(302, target);
});

/* ---------- Dashboards + load board ---------- */
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
              <div class="muted">Direct booking. Transparent loads. All-in pricing.</div>
            </div>
            <span class="badge ${billing.status === "ACTIVE" ? "ok" : "warn"}">Billing: ${escapeHtml(billing.status)}</span>
          </div>

          <div class="hr"></div>

          <div class="row">
            <span class="badge">Plan: ${escapeHtml(planLabel)}</span>
            <span class="badge brand">${escapeHtml(limitText)}</span>
            <a class="btn green" href="/shipper/plans">Manage Plan</a>
            <a class="btn ghost" href="/shipper/billing">Invoices</a>
            <a class="btn ghost" href="/shipper/contracts">Templates</a>
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
        <div class="hr"></div>
        ${myLoads.rows.length ? myLoads.rows.map(l => loadCard(l, user)).join("") : `<div class="muted">No loads yet.</div>`}
      </div>
    `;
    return res.send(layout({ title: "Dashboard", user, body }));
  }

  if (user.role === "CARRIER") {
    const comp = await pool.query(`SELECT * FROM carriers_compliance WHERE carrier_id=$1`, [user.id]);
    const c = comp.rows[0] || { status: "PENDING" };

    const missingDocs = !c.insurance_filename || !c.authority_filename || !c.w9_filename;
    if (missingDocs) return res.redirect("/carrier/onboarding");

    const myReqs = await pool.query(`
      SELECT lr.*, l.lane_from, l.lane_to, l.status as load_status
      FROM load_requests lr
      JOIN loads l ON l.id = lr.load_id
      WHERE lr.carrier_id=$1
      ORDER BY lr.created_at DESC
      LIMIT 200
    `, [user.id]);

    const loads = await pool.query(`SELECT * FROM loads ORDER BY created_at DESC LIMIT 200`);

    const body = `
      <div class="card">
        <div class="row" style="justify-content:space-between">
          <div>
            <h2 style="margin:0">Carrier Dashboard</h2>
            <div class="muted">Verified carriers can request loads.</div>
          </div>
          <span class="badge ${c.status === "APPROVED" ? "ok" : "warn"}">Compliance: ${escapeHtml(c.status)}</span>
        </div>
        <div class="hr"></div>
        <div class="row">
          <a class="btn ghost" href="/carrier/onboarding">Update Docs</a>
          <a class="btn ghost" href="/support">Help</a>
        </div>
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

      <div class="card">
        <h3 style="margin-top:0">Load Board</h3>
        <div class="hr"></div>
        ${loads.rows.length ? loads.rows.map(l => loadCard(l, user, c.status)).join("") : `<div class="muted">No loads posted yet.</div>`}
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
});

/* ---------- Shipper actions ---------- */
app.post("/shipper/loads", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  const billing = await getAndNormalizeBilling(req.user.id);
  const gate = postingAllowed(billing);
  if (!gate.ok) return res.status(403).send(`Posting blocked: ${gate.reason}`);

  await pool.query(
    `INSERT INTO loads
     (shipper_id,lane_from,lane_to,pickup_date,delivery_date,equipment,weight_lbs,commodity,miles,
      rate_all_in,payment_terms,quickpay_available,detention_rate_per_hr,detention_after_hours,
      appointment_type,accessorials,special_requirements,status)
     VALUES
     ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,'OPEN')`,
    [
      req.user.id,
      String(req.body.lane_from || "").trim(),
      String(req.body.lane_to || "").trim(),
      String(req.body.pickup_date || "").trim(),
      String(req.body.delivery_date || "").trim(),
      String(req.body.equipment || "").trim(),
      int(req.body.weight_lbs),
      String(req.body.commodity || "").trim(),
      int(req.body.miles),
      Number(req.body.rate_all_in),
      String(req.body.payment_terms || "NET 30").trim(),
      String(req.body.quickpay_available || "false") === "true",
      Number(req.body.detention_rate_per_hr),
      int(req.body.detention_after_hours),
      String(req.body.appointment_type || "FCFS").trim(),
      String(req.body.accessorials || "None").trim(),
      String(req.body.special_requirements || "None").trim(),
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
  if (String(row.load_status || "").toUpperCase() === "BOOKED") return res.status(400).send("Load already booked.");

  await pool.query(`UPDATE load_requests SET status='ACCEPTED' WHERE id=$1`, [requestId]);
  await pool.query(`UPDATE load_requests SET status='DECLINED' WHERE load_id=$1 AND id<>$2`, [row.load_id, requestId]);
  await pool.query(`UPDATE loads SET status='BOOKED', booked_carrier_id=$1 WHERE id=$2`, [row.carrier_id, row.load_id]);

  const carrierEmail = (await pool.query(`SELECT email FROM users WHERE id=$1`, [row.carrier_id])).rows[0]?.email;

  await sendEmail(req.user.email, `DFX Booking Confirmed • Load #${row.load_id}`, `<p>Booking confirmed for Load #${row.load_id}.</p>`);
  if (carrierEmail) await sendEmail(carrierEmail, `DFX Request Accepted • Load #${row.load_id}`, `<p>Your request was accepted.</p>`);

  res.redirect("/dashboard");
});

app.post("/shipper/requests/:id/decline", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  const requestId = Number(req.params.id);
  const r = await pool.query(`
    SELECT lr.*, l.shipper_id
    FROM load_requests lr
    JOIN loads l ON l.id = lr.load_id
    WHERE lr.id=$1
  `, [requestId]);

  const row = r.rows[0];
  if (!row || row.shipper_id !== req.user.id) return res.sendStatus(404);

  await pool.query(`UPDATE load_requests SET status='DECLINED' WHERE id=$1`, [requestId]);
  res.redirect("/dashboard");
});

/* ---------- Carrier request-to-book ---------- */
app.post("/carrier/loads/:id/request", requireAuth, requireRole("CARRIER"), async (req, res) => {
  const loadId = Number(req.params.id);

  const comp = await pool.query(`SELECT status FROM carriers_compliance WHERE carrier_id=$1`, [req.user.id]);
  const compStatus = comp.rows[0]?.status || "PENDING";
  if (compStatus !== "APPROVED") return res.status(403).send("Compliance approval required before requesting loads.");

  const load = await pool.query(`SELECT status FROM loads WHERE id=$1`, [loadId]);
  if (!load.rows[0]) return res.sendStatus(404);
  if (String(load.rows[0].status || "").toUpperCase() === "BOOKED") return res.status(400).send("Load already booked.");

  await pool.query(
    `INSERT INTO load_requests (load_id, carrier_id, status) VALUES ($1,$2,'REQUESTED')
     ON CONFLICT (load_id, carrier_id) DO NOTHING`,
    [loadId, req.user.id]
  );

  await pool.query(`UPDATE loads SET status='REQUESTED' WHERE id=$1 AND status='OPEN'`, [loadId]);
  res.redirect("/loads");
});

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

/* ---------- Load board ---------- */
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
            : user?.role === "SHIPPER"
              ? `<a class="btn green" href="/shipper/plans">Plans</a>`
              : ``
        }
      </div>
      <div class="hr"></div>
      ${r.rows.length ? r.rows.map(l => loadCard(l, user, carrierBadge)).join("") : `<div class="muted">No loads posted yet.</div>`}
    </div>
  `;
  res.send(layout({ title: "Loads", user, body }));
});

/* ---------- Health ---------- */
app.get("/health", async (_, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, stripeEnabled, db: "ok", smtpEnabled: !!getMailer() });
  } catch (e) {
    res.status(500).json({ ok: false, stripeEnabled, db: "error", error: String(e.message || e) });
  }
});

/* ---------- Start ---------- */
initDb()
  .then(() => app.listen(PORT, "0.0.0.0", () => console.log("Server running on port", PORT)))
  .catch((e) => { console.error("DB init/migrations failed:", e); process.exit(1); });
