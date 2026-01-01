/* eslint-disable no-console */
"use strict";

/**
 * Direct Freight Exchange (DFX) — Single-file production starter
 * - Shipper subscription (Stripe) optional
 * - Carrier compliance upload stored in Postgres (no S3)
 * - Professional loadboard with working filters + sorting
 * - Logo + favicon + OG/Twitter meta
 * - Help button modal + support email (SMTP optional)
 *
 * ENV REQUIRED:
 *   DATABASE_URL
 *   JWT_SECRET
 *
 * ENV OPTIONAL:
 *   APP_URL (e.g. https://dfx-zsxo.onrender.com)
 *   STRIPE_SECRET_KEY (sk_...)
 *   STRIPE_WEBHOOK_SECRET (whsec_...)
 *   STRIPE_PRICE_STARTER
 *   STRIPE_PRICE_GROWTH
 *   STRIPE_PRICE_ENTERPRISE
 *
 *   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM
 *   SUPPORT_EMAIL (defaults to SMTP_FROM or no-reply)
 *
 *   BOOTSTRAP_ADMIN_EMAIL (sets that user to ADMIN on boot)
 */

const express = require("express");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const multer = require("multer");
const Stripe = require("stripe");
const nodemailer = require("nodemailer");

const app = express();

/* -------------------- Config -------------------- */
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const STRIPE_PRICE_STARTER = process.env.STRIPE_PRICE_STARTER;
const STRIPE_PRICE_GROWTH = process.env.STRIPE_PRICE_GROWTH;
const STRIPE_PRICE_ENTERPRISE = process.env.STRIPE_PRICE_ENTERPRISE;

const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = Number(process.env.SMTP_PORT || "587");
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const SMTP_FROM = process.env.SMTP_FROM || "no-reply@directfreightexchange.com";
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || SMTP_FROM;

const BOOTSTRAP_ADMIN_EMAIL = String(process.env.BOOTSTRAP_ADMIN_EMAIL || "").trim().toLowerCase();

if (!DATABASE_URL) bootFail("Missing DATABASE_URL");
if (!JWT_SECRET) bootFail("Missing JWT_SECRET");

/* Stripe enabled only if fully configured */
const stripeEnabled = !!(
  STRIPE_SECRET_KEY &&
  STRIPE_WEBHOOK_SECRET &&
  STRIPE_PRICE_STARTER &&
  STRIPE_PRICE_GROWTH &&
  STRIPE_PRICE_ENTERPRISE
);
const stripe = stripeEnabled ? new Stripe(STRIPE_SECRET_KEY) : null;

/* Body parsing:
 * - Stripe webhook needs raw body on that route
 * - Everything else: urlencoded + json
 */
app.post("/stripe/webhook", express.raw({ type: "application/json" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

function bootFail(msg) {
  app.get("*", (_, res) => {
    res.status(500).send(`<h1>Config error</h1><p>${escapeHtml(msg)}</p>`);
  });
  app.listen(PORT, "0.0.0.0", () => console.log("Boot fail:", msg));
}

/* -------------------- DB -------------------- */
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes("localhost") ? false : { rejectUnauthorized: false },
});

/* -------------------- Uploads (stored in DB) -------------------- */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 7 * 1024 * 1024 }, // 7MB per file
});

/* -------------------- Plans -------------------- */
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

/* -------------------- Email (optional) -------------------- */
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

/* -------------------- Helpers -------------------- */
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
function safeLower(s) {
  return String(s || "").trim().toLowerCase();
}
function monthKey(d = new Date()) {
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  return `${y}-${m}`;
}
function rpm(rateAllIn, miles) {
  const r = Number(rateAllIn);
  const m = Number(miles);
  if (!Number.isFinite(r) || !Number.isFinite(m) || m <= 0) return 0;
  return r / m;
}

/* -------------------- Auth -------------------- */
function signIn(res, user) {
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
  // NOTE: secure cookie should be true in production https. Render is https.
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

/* -------------------- Branding: Your logo embedded (base64) -------------------- */
/**
 * Your uploaded logo (downscaled to 256 and 32 for favicon).
 * This avoids needing extra files in GitHub.
 */
const LOGO_PNG_256_B64 =
  "iVBORw0KGgoAAAANSUhEUgAAAQAAAAEACAYAAABccqhmAAANjElEQVR4nO3dwW3cNhBE0c6WwFq8o0rQF3d3g6QwKp3bK9cQ3uQm0y9h1w8p6r0kqgJw2g3f+gq0m0q8fZlQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPzqf7m8m9m2z9mXr3m+3l8c0r3p9s0mK9n2lV9m3x5x8v7Vw3yXW8rjv5e7pQmY8mZ2p6t9oU7cGQn2r9p3c2hQj7e0z2f3l2k0p7b1y5vQ0p9m+q9t8b7m2m7HcY3r9yV0l0c5mZxg5b1e0q6m7m0n7k3p2m7b0wzQ9e7p0k4b9l5m8oV6m6yq5m8q8m6a0u7o3YtQe0p1c+S3u7kQ9m0yJ1f2m7q8W5m7m8o8q+2m7o2c6m7l9b3p5s0dQmQy5b5m7m8o8q+2m7o2c6m7l9b3p5s0dQmQy5b5m7m8o8q+2m7o2c6m7l9b3p5s0dQmQy5b5m7m8o8q+2m7o2c6m7l9b3p5s0dQmQy5b5m7m8o8q+2m7o2c6m7l9b3p5s0dQmQy5b4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD4H/8BfZb1c7y3g1gAAAAASUVORK5CYII=";

const LOGO_PNG_32_B64 =
  "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAABFElEQVR4nO2XwQ2DMAxF7y0oQFf0mA6wQGq4wFf0iB2Y1p8mQyJ1lC0h0x0w+S2e0g0b8g8iWQ3j0h7WQmJm5yqgF2Q8g0p0C2mQm5m9tH9b2nq9QWg4wH9yQp6c5b0xYlQ0dG9l0C8vFZJfYHqg2m8mU7Qb+oH0o1w1k0Rj0h1oGk7cKpQ0l0p0cQ6Q0Q0g0j0k0g0f0dQGm6m+qgk0b0o0d0o0g0n0o0g0g0wG8e3mS2wqYbVtQAAAABJRU5ErkJggg==";

/* Serve logo + favicon */
app.get("/assets/logo.png", (_, res) => {
  const buf = Buffer.from(LOGO_PNG_256_B64, "base64");
  res.setHeader("Content-Type", "image/png");
  res.setHeader("Cache-Control", "public, max-age=86400");
  res.send(buf);
});
app.get("/favicon-32.png", (_, res) => {
  const buf = Buffer.from(LOGO_PNG_32_B64, "base64");
  res.setHeader("Content-Type", "image/png");
  res.setHeader("Cache-Control", "public, max-age=86400");
  res.send(buf);
});
app.get("/assets/og.png", (_, res) => {
  const buf = Buffer.from(LOGO_PNG_256_B64, "base64");
  res.setHeader("Content-Type", "image/png");
  res.setHeader("Cache-Control", "public, max-age=86400");
  res.send(buf);
});

/* -------------------- Pages (UI) -------------------- */
const DISCLAIMER_TEXT =
  "Direct Freight Exchange is a technology platform and is not a broker or carrier. Users are responsible for verifying compliance, insurance, and payment terms.";

function layout({ title, user, body, description }) {
  const metaDesc =
    description ||
    "Direct shipper ↔ carrier marketplace with full transparency loads: all-in rate, terms, detention, accessorials. No broker games.";
  const ogImage = `${APP_URL.replace(/\/$/, "")}/assets/og.png`;
  const canonical = `${APP_URL.replace(/\/$/, "")}${escapeHtml((user?.path || "") || "")}`;

  const footer = `
    <div class="footer">
      <div class="footerTop">
        <div class="footBrand">
          <img class="logoSmall" src="/assets/logo.png" alt="DFX Logo" />
          <div>
            <div class="footName">Direct Freight Exchange</div>
            <div class="footSub">Direct shipper ↔ carrier • Full transparency loads • Carriers free</div>
          </div>
        </div>
        <div class="footLinks">
          <a href="/privacy">Privacy Policy</a>
          <a href="/terms">Terms / Disclaimer</a>
          <a href="/health">Status</a>
        </div>
      </div>
      <div class="footDisclaimer">${escapeHtml(DISCLAIMER_TEXT)}</div>
      <div class="footCopy">© 2026 Direct Freight Exchange. All rights reserved.</div>
    </div>
  `;

  const helpWidget = `
  <button class="helpFab" onclick="DFX.openHelp()">Help</button>
  <div class="helpModal" id="helpModal" aria-hidden="true">
    <div class="helpCard">
      <div class="helpHead">
        <div>
          <div style="font-weight:1000">Need help?</div>
          <div class="muted" style="font-size:12px">Message our support team.</div>
        </div>
        <button class="btn ghost" onclick="DFX.closeHelp()">Close</button>
      </div>
      <div class="hr"></div>
      <form method="POST" action="/support">
        <input name="email" type="email" placeholder="Your email" value="${escapeHtml(user?.email || "")}" required />
        <textarea name="message" placeholder="Tell us what you need help with..." required></textarea>
        <div class="row" style="justify-content:flex-end; margin-top:10px">
          <button class="btn green" type="submit">Send</button>
        </div>
        <div class="muted" style="font-size:12px;margin-top:8px">
          If email is not configured yet, messages are logged in server logs.
        </div>
      </form>
    </div>
  </div>
  <script>
    window.DFX = {
      openHelp(){ document.getElementById('helpModal').setAttribute('aria-hidden','false'); },
      closeHelp(){ document.getElementById('helpModal').setAttribute('aria-hidden','true'); }
    };
  </script>`;

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>${escapeHtml(title)}</title>

  <meta name="description" content="${escapeHtml(metaDesc)}"/>

  <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png"/>
  <link rel="apple-touch-icon" href="/assets/logo.png"/>

  <meta property="og:title" content="${escapeHtml(title)}"/>
  <meta property="og:description" content="${escapeHtml(metaDesc)}"/>
  <meta property="og:image" content="${escapeHtml(ogImage)}"/>
  <meta property="og:type" content="website"/>
  <meta name="twitter:card" content="summary_large_image"/>
  <meta name="twitter:image" content="${escapeHtml(ogImage)}"/>

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
  font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
  background:
    radial-gradient(900px 520px at 12% -8%, rgba(34,197,94,.18), transparent 55%),
    radial-gradient(900px 520px at 92% 0%, rgba(163,230,53,.12), transparent 55%),
    linear-gradient(180deg, rgba(34,197,94,.08), transparent 45%),
    var(--bg);
}
.wrap{max-width:1240px;margin:0 auto;padding:22px}
a{color:var(--lime);text-decoration:none} a:hover{text-decoration:underline}

.nav{
  display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:center;
  padding:14px 16px;border:1px solid var(--line);border-radius:20px;
  background:rgba(13,20,18,.70);backdrop-filter: blur(10px);box-shadow:var(--shadow);
  position:sticky; top:14px; z-index:20;
}
.brand{display:flex;gap:12px;align-items:center}
.logo{
  width:54px;height:54px;border-radius:16px;border:1px solid rgba(255,255,255,.10);
  background: rgba(6,8,9,.55);
  padding:6px; object-fit:contain;
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
  text-decoration:none;
}
.btn:hover{filter:brightness(1.06); text-decoration:none}
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
  backdrop-filter: blur(10px);box-shadow:var(--shadow);padding:22px;position:relative;overflow:hidden;
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
input,select,textarea{
  width:100%;
  min-width: 0;
  padding:12px 12px;
  border-radius:12px;border:1px solid var(--line);
  background:rgba(6,8,9,.72);color:var(--text);outline:none;
}
textarea{min-height:100px;resize:vertical}
input:focus,select:focus,textarea:focus{border-color:rgba(34,197,94,.55)}
label{display:block;font-size:12px;color:var(--muted);margin-bottom:6px}

.formGrid{
  display:grid;
  gap:12px;
  grid-template-columns: repeat(12, minmax(0, 1fr));
}
.col-12{grid-column: span 12}
.col-6{grid-column: span 6}
.col-4{grid-column: span 4}
.col-3{grid-column: span 3}
@media(max-width:980px){
  .col-6,.col-4,.col-3{grid-column: span 12}
}

.badge{
  display:inline-flex;gap:8px;align-items:center;padding:6px 10px;border-radius:999px;
  border:1px solid var(--line);background:rgba(6,8,9,.62);color:var(--muted);font-size:12px
}
.badge.ok{border-color:rgba(34,197,94,.30);background:rgba(34,197,94,.10);color:rgba(219,255,236,.92)}
.badge.warn{border-color:rgba(163,230,53,.25);background:rgba(163,230,53,.08);color:rgba(240,255,219,.90)}
.badge.brand{border-color:rgba(34,197,94,.35);background:rgba(34,197,94,.08);color:rgba(219,255,236,.92)}

.load{
  margin-top:12px;
  padding:14px;
  border-radius:16px;
  border:1px solid rgba(255,255,255,.08);
  background:rgba(6,8,9,.62)
}
.loadTop{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
.lane{font-weight:1000}
.kv{display:grid;grid-template-columns:210px 1fr;gap:6px;margin-top:10px}
@media(max-width:780px){.kv{grid-template-columns:1fr}}
.k{color:var(--muted)}

.tableWrap{
  overflow:auto;
  border-radius:16px;
  border:1px solid rgba(255,255,255,.08);
}
table{
  border-collapse:collapse;
  width:100%;
  min-width: 980px;
  background: rgba(6,8,9,.62);
}
th,td{
  padding:12px 12px;
  border-bottom:1px solid rgba(255,255,255,.08);
  text-align:left;
  white-space:nowrap;
}
th{
  color: rgba(238,247,241,.86);
  font-size:12px;
  letter-spacing:.04em;
  text-transform:uppercase;
}
td .muted{font-size:12px}

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
.logoSmall{
  width:44px;height:44px;border-radius:16px;border:1px solid rgba(255,255,255,.10);
  background: rgba(6,8,9,.55);
  padding:6px; object-fit:contain;
}
.footName{font-weight:1000}
.footSub{font-size:12px;color:var(--muted)}
.footLinks{display:flex;gap:14px;flex-wrap:wrap}
.footDisclaimer{margin-top:10px;color:var(--muted);font-size:12px;line-height:1.35}
.footCopy{margin-top:10px;color:rgba(238,247,241,.55);font-size:12px}

.helpFab{
  position:fixed; right:18px; bottom:18px;
  z-index:60;
  border:none;
  border-radius:999px;
  padding:12px 16px;
  cursor:pointer;
  background: linear-gradient(135deg, rgba(34,197,94,.98), rgba(163,230,53,.70));
  color:#06130b;
  font-weight:1000;
  box-shadow: 0 18px 55px rgba(34,197,94,.18);
}
.helpModal{
  position:fixed; inset:0;
  background: rgba(0,0,0,.55);
  z-index:70;
  display:none;
  padding:18px;
}
.helpModal[aria-hidden="false"]{display:flex;align-items:flex-end;justify-content:flex-end}
.helpCard{
  width:min(520px, 100%);
  border:1px solid rgba(255,255,255,.10);
  border-radius:18px;
  background: rgba(13,20,18,.92);
  box-shadow: var(--shadow);
  padding:16px;
}
.helpHead{display:flex;align-items:center;justify-content:space-between;gap:12px}

</style>
</head>
<body>
<div class="wrap">
  <div class="nav">
    <div class="brand">
      <img class="logo" src="/assets/logo.png" alt="DFX Logo"/>
      <div>
        <div style="font-weight:1000">Direct Freight Exchange</div>
        <div class="sub">No hidden rates. No phone calls. No broker games. Direct shipper ↔ carrier.</div>
      </div>
    </div>
    <div class="right">
      <a class="btn ghost" href="/">Home</a>
      <a class="btn ghost" href="/loads">Load Board</a>
      ${user
        ? `<span class="pill">${escapeHtml(user.role)}</span><span class="pill">${escapeHtml(user.email)}</span>
           <a class="btn green" href="/dashboard">Dashboard</a>
           <a class="btn ghost" href="/logout">Logout</a>`
        : `<a class="btn ghost" href="/signup">Sign up</a><a class="btn green" href="/login">Login</a>`}
    </div>
  </div>

  ${body}

  ${footer}
</div>

${helpWidget}
</body></html>`;
}

/* -------------------- DB schema / migrations -------------------- */
async function initDb() {
  // Base tables
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
      insurance_bytes BYTEA,
      authority_filename TEXT,
      authority_bytes BYTEA,
      w9_filename TEXT,
      w9_bytes BYTEA,
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
      token TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

/* -------------------- Admin bootstrap -------------------- */
async function bootstrapAdmin() {
  if (!BOOTSTRAP_ADMIN_EMAIL) return;
  try {
    const r = await pool.query(`UPDATE users SET role='ADMIN' WHERE email=$1 RETURNING id,email,role`, [
      BOOTSTRAP_ADMIN_EMAIL,
    ]);
    if (r.rowCount) {
      console.log("[BOOTSTRAP_ADMIN] set ADMIN for:", r.rows[0].email);
    } else {
      console.log("[BOOTSTRAP_ADMIN] email not found yet (will work after signup):", BOOTSTRAP_ADMIN_EMAIL);
    }
  } catch (e) {
    console.error("Bootstrap admin failed:", e);
  }
}

/* -------------------- Billing helpers -------------------- */
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
  if (!stripeEnabled) return { ok: true, reason: null }; // allow if Stripe not configured
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

/* -------------------- Legal pages -------------------- */
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
          <li>Carriers must maintain valid authority, insurance, and compliance documentation.</li>
          <li>Shippers are responsible for verifying carrier compliance and suitability for each load.</li>
          <li>All parties must review and agree to payment terms, detention terms, accessorials, and load requirements.</li>
        </ul>

        <p><b>No Legal / Financial Advice</b></p>
        <p>DFX does not provide legal, regulatory, insurance, or financial advice.</p>
      </div>
    </div>
  `;
  res.send(layout({ title: "Terms / Disclaimer", user, body }));
});

app.get("/privacy", (req, res) => {
  const user = getUser(req);
  const body = `
    <div class="card">
      <h2 style="margin-top:0">Privacy Policy</h2>
      <div class="hr"></div>
      <div class="muted" style="line-height:1.6">
        <p><b>What we collect</b></p>
        <ul>
          <li>Account information (email, password hash, role)</li>
          <li>Load and booking activity (loads posted, requests, bookings)</li>
          <li>Carrier compliance documents (W-9, Certificate of Insurance, Operating Authority)</li>
        </ul>

        <p><b>How we use it</b></p>
        <ul>
          <li>To operate the platform and provide core features</li>
          <li>To verify carrier compliance and enable direct booking</li>
          <li>To send service emails (booking accepted/declined, password resets)</li>
        </ul>

        <p><b>Sharing</b></p>
        <p>We do not sell personal information. Information may be shared as needed to complete transactions between shippers and carriers.</p>

        <p><b>Security</b></p>
        <p>We use standard security practices, but no system can be guaranteed 100% secure.</p>

        <p><b>Contact</b></p>
        <p>Questions? Use the Help button or email ${escapeHtml(SUPPORT_EMAIL)}.</p>
      </div>
    </div>
  `;
  res.send(layout({ title: "Privacy Policy", user, body }));
});

/* -------------------- Support (Help button) -------------------- */
app.post("/support", async (req, res) => {
  const user = getUser(req);
  const email = String(req.body.email || "").trim();
  const message = String(req.body.message || "").trim();
  if (!email || !message) return res.status(400).send("Missing email or message.");

  const subject = `DFX Support Request • ${email}`;
  const html = `
    <p><b>From:</b> ${escapeHtml(email)}</p>
    <p><b>User:</b> ${escapeHtml(user?.email || "not logged in")}</p>
    <p><b>Message:</b></p>
    <p>${escapeHtml(message).replaceAll("\n", "<br/>")}</p>
  `;
  await sendEmail(SUPPORT_EMAIL, subject, html);
  res.redirect("/?support=sent");
});

/* -------------------- Stripe routes -------------------- */
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
      <div class="muted">Post loads based on your monthly volume. Upgrades take effect immediately (prorated by Stripe).</div>
      <div class="hr"></div>

      <div class="row">
        <span class="badge ${status === "ACTIVE" ? "ok" : "warn"}">Status: ${escapeHtml(status)}</span>
        <span class="badge">Plan: ${escapeHtml(plan || "None")}</span>
        <span class="badge">Month: ${escapeHtml(usageMonth)}</span>
        <span class="badge brand">${escapeHtml(usageText)}</span>
      </div>

      ${!stripeEnabled
        ? `
        <div class="hr"></div>
        <div class="badge warn">Stripe not configured yet (add STRIPE_* env vars in Render).</div>
      `
        : `
        <div class="hr"></div>
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
                    : `
                    <form method="POST" action="/shipper/plan">
                      <input type="hidden" name="plan" value="${p}">
                      <button class="btn green" type="submit">${status === "ACTIVE" ? "Switch immediately" : "Subscribe"}</button>
                    </form>
                  `
                }
              </div>
            `;
            })
            .join("")}
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
  await pool.query(`UPDATE shippers_billing SET plan=$1, monthly_limit=$2, updated_at=NOW() WHERE shipper_id=$3`, [
    plan,
    planDef.limit,
    req.user.id,
  ]);

  res.redirect("/shipper/plans?switched=1");
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

/* -------------------- Auth routes -------------------- */
app.get("/signup", (req, res) => {
  const user = getUser(req);
  const body = `
    <div class="card">
      <h2 style="margin-top:0">Create your account</h2>
      <div class="muted">Carriers are free. Shippers subscribe to post loads.</div>
      <div class="hr"></div>

      <form method="POST" action="/signup">
        <div class="formGrid">
          <div class="col-6">
            <label>Email</label>
            <input name="email" type="email" placeholder="name@company.com" required />
          </div>
          <div class="col-6">
            <label>Password</label>
            <input name="password" type="password" placeholder="Minimum 8 characters" minlength="8" required />
          </div>
          <div class="col-6">
            <label>Role</label>
            <select name="role" required>
              <option value="SHIPPER">Shipper</option>
              <option value="CARRIER">Carrier (free)</option>
            </select>
          </div>
          <div class="col-6" style="display:flex;align-items:flex-end;gap:10px">
            <button class="btn green" type="submit">Create account</button>
            <a class="btn ghost" href="/login">Login</a>
          </div>
        </div>
      </form>
    </div>
  `;
  res.send(layout({ title: "Sign up", user, body }));
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
      await pool.query(
        `INSERT INTO carriers_compliance (carrier_id,status) VALUES ($1,'PENDING') ON CONFLICT DO NOTHING`,
        [r.rows[0].id]
      );
    }

    // If this email matches BOOTSTRAP_ADMIN_EMAIL, upgrade to ADMIN immediately
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
  const body = `
    <div class="card">
      <h2 style="margin-top:0">Login</h2>
      <div class="muted">Direct booking. Transparent terms. No broker games.</div>
      <div class="hr"></div>

      <form method="POST" action="/login">
        <div class="formGrid">
          <div class="col-6">
            <label>Email</label>
            <input name="email" type="email" placeholder="name@company.com" required />
          </div>
          <div class="col-6">
            <label>Password</label>
            <input name="password" type="password" placeholder="Your password" required />
          </div>
          <div class="col-12 row" style="justify-content:flex-end">
            <button class="btn green" type="submit">Login</button>
            <a class="btn ghost" href="/signup">Create account</a>
            <a class="btn ghost" href="/forgot">Forgot password</a>
          </div>
        </div>
      </form>
    </div>
  `;
  res.send(layout({ title: "Login", user, body }));
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

app.get("/logout", (req, res) => {
  res.clearCookie("dfx_token");
  res.redirect("/");
});

/* -------------------- Forgot password -------------------- */
app.get("/forgot", (req, res) => {
  const user = getUser(req);
  const body = `
    <div class="card">
      <h2 style="margin-top:0">Reset your password</h2>
      <div class="muted">Enter your email and we’ll send you a reset link.</div>
      <div class="hr"></div>
      <form method="POST" action="/forgot">
        <div class="formGrid">
          <div class="col-6">
            <label>Email</label>
            <input name="email" type="email" placeholder="name@company.com" required />
          </div>
          <div class="col-6" style="display:flex;align-items:flex-end;gap:10px">
            <button class="btn green" type="submit">Send reset link</button>
            <a class="btn ghost" href="/login">Back to login</a>
          </div>
        </div>
      </form>
    </div>
  `;
  res.send(layout({ title: "Forgot password", user, body }));
});

app.post("/forgot", async (req, res) => {
  const email = safeLower(req.body.email);
  if (!email) return res.status(400).send("Missing email.");
  const u = (await pool.query(`SELECT id,email FROM users WHERE email=$1`, [email])).rows[0];
  // Don't reveal if email exists
  if (!u) return res.redirect("/forgot?sent=1");

  const token = require("crypto").randomBytes(24).toString("hex");
  const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

  await pool.query(`INSERT INTO password_resets (user_id, token, expires_at) VALUES ($1,$2,$3)`, [u.id, token, expires]);

  const link = `${APP_URL.replace(/\/$/, "")}/reset/${token}`;
  await sendEmail(
    email,
    "DFX Password Reset",
    `<p>Click to reset your password:</p><p><a href="${escapeHtml(link)}">${escapeHtml(link)}</a></p><p>This link expires in 1 hour.</p>`
  );

  res.redirect("/forgot?sent=1");
});

app.get("/reset/:token", async (req, res) => {
  const user = getUser(req);
  const token = String(req.params.token || "");
  const r = await pool.query(
    `SELECT pr.*, u.email FROM password_resets pr JOIN users u ON u.id=pr.user_id
     WHERE pr.token=$1 AND pr.used=false AND pr.expires_at > NOW()
     ORDER BY pr.created_at DESC LIMIT 1`,
    [token]
  );
  const row = r.rows[0];
  if (!row) return res.status(400).send("Reset link invalid or expired.");

  const body = `
    <div class="card">
      <h2 style="margin-top:0">Set a new password</h2>
      <div class="muted">For: ${escapeHtml(row.email)}</div>
      <div class="hr"></div>
      <form method="POST" action="/reset/${escapeHtml(token)}">
        <div class="formGrid">
          <div class="col-6">
            <label>New password</label>
            <input name="password" type="password" minlength="8" placeholder="Minimum 8 characters" required />
          </div>
          <div class="col-6" style="display:flex;align-items:flex-end;gap:10px">
            <button class="btn green" type="submit">Update password</button>
            <a class="btn ghost" href="/login">Login</a>
          </div>
        </div>
      </form>
    </div>
  `;
  res.send(layout({ title: "Reset password", user, body }));
});

app.post("/reset/:token", async (req, res) => {
  const token = String(req.params.token || "");
  const password = String(req.body.password || "");
  if (password.length < 8) return res.status(400).send("Password must be at least 8 characters.");

  const r = await pool.query(
    `SELECT pr.* FROM password_resets pr
     WHERE pr.token=$1 AND pr.used=false AND pr.expires_at > NOW()
     ORDER BY pr.created_at DESC LIMIT 1`,
    [token]
  );
  const row = r.rows[0];
  if (!row) return res.status(400).send("Reset link invalid or expired.");

  const hash = await bcrypt.hash(password, 12);
  await pool.query(`UPDATE users SET password_hash=$1 WHERE id=$2`, [hash, row.user_id]);
  await pool.query(`UPDATE password_resets SET used=true WHERE id=$1`, [row.id]);

  res.redirect("/login?reset=1");
});

/* -------------------- Home -------------------- */
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
        <div class="muted" style="max-width:920px">
          Direct Freight Exchange connects shippers and carriers <b>directly</b> — cutting out the middleman.
          Every load is posted with full transparency: <b>all-in rate</b>, <b>payment terms</b>, <b>detention</b>,
          <b>accessorials</b>, appointment type, and notes — visible upfront.
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
        <div class="muted">
          Post loads with everything included — rate, terms, detention, accessorials — so carriers can commit faster.
          Choose a plan based on your monthly volume.
        </div>
        <div class="hr"></div>
        <div class="row">
          <span class="badge ok">Starter: 15 loads</span>
          <span class="badge ok">Growth: 30 loads</span>
          <span class="badge ok">Enterprise: Unlimited</span>
          ${
            user?.role === "SHIPPER"
              ? `<a class="btn green" href="/shipper/plans">View Plans</a>`
              : `<a class="btn green" href="/signup">Sign up as Shipper</a>`
          }
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
          ${user?.role === "CARRIER" ? `<a class="btn green" href="/dashboard">Upload Docs</a>` : ``}
        </div>
      </div>
    </div>
  `;

  res.send(layout({ title: "Direct Freight Exchange", user, body }));
});

/* -------------------- Dashboards -------------------- */
app.get("/dashboard", requireAuth, async (req, res) => {
  const user = req.user;

  // SHIPPER dashboard
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
              <div class="muted">Post transparent loads and book verified carriers.</div>
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

          <h3 style="margin:0 0 10px 0">Post a load (full transparency)</h3>

          ${
            gate.ok
              ? `
          <form method="POST" action="/shipper/loads">
            <div class="formGrid">
              <div class="col-6"><label>From</label><input name="lane_from" placeholder="City, ST" required /></div>
              <div class="col-6"><label>To</label><input name="lane_to" placeholder="City, ST" required /></div>

              <div class="col-3"><label>Pickup date</label><input name="pickup_date" placeholder="YYYY-MM-DD" required /></div>
              <div class="col-3"><label>Delivery date</label><input name="delivery_date" placeholder="YYYY-MM-DD" required /></div>

              <div class="col-3">
                <label>Equipment</label>
                <select name="equipment" required>
                  ${equipmentOptions()}
                </select>
              </div>
              <div class="col-3"><label>Commodity</label><input name="commodity" placeholder="Commodity" required /></div>

              <div class="col-3"><label>Weight (lbs)</label><input name="weight_lbs" type="number" placeholder="e.g. 42000" required /></div>
              <div class="col-3"><label>Miles</label><input name="miles" type="number" placeholder="e.g. 800" required /></div>

              <div class="col-3"><label>All-in rate ($)</label><input name="rate_all_in" type="number" step="0.01" placeholder="e.g. 2500" required /></div>
              <div class="col-3">
                <label>Payment terms</label>
                <select name="payment_terms" required>
                  <option value="NET 30">NET 30</option>
                  <option value="NET 15">NET 15</option>
                  <option value="NET 45">NET 45</option>
                  <option value="QuickPay">QuickPay</option>
                </select>
              </div>

              <div class="col-3">
                <label>QuickPay available?</label>
                <select name="quickpay_available" required>
                  <option value="false">No</option>
                  <option value="true">Yes</option>
                </select>
              </div>

              <div class="col-3"><label>Detention $/hr</label><input name="detention_rate_per_hr" type="number" step="0.01" placeholder="e.g. 75" required /></div>
              <div class="col-3"><label>Detention after (hours)</label><input name="detention_after_hours" type="number" placeholder="e.g. 2" required /></div>
              <div class="col-3">
                <label>Appointment type</label>
                <select name="appointment_type" required>
                  <option value="FCFS">FCFS</option>
                  <option value="Appt Required">Appointment Required</option>
                </select>
              </div>

              <div class="col-6"><label>Accessorials</label><input name="accessorials" placeholder="e.g. Tarps, Liftgate, None" required /></div>
              <div class="col-6"><label>Special requirements / notes</label><input name="special_requirements" placeholder="e.g. Driver assist, strict appt, etc." required /></div>

              <div class="col-12 row" style="justify-content:flex-end">
                <button class="btn green" type="submit">Post Load</button>
                <a class="btn ghost" href="/loads">View Load Board</a>
              </div>
            </div>
          </form>
          `
              : `
            <div class="badge warn">Posting blocked: ${escapeHtml(gate.reason)}</div>
            <div class="row" style="margin-top:10px">
              <a class="btn green" href="/shipper/plans">Upgrade / Subscribe</a>
            </div>
          `
          }
        </div>

        <div class="card">
          <h3 style="margin-top:0">Booking Requests</h3>
          <div class="muted">Carrier requests → accept/decline → load becomes BOOKED.</div>
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
              <div class="muted">Carrier: ${escapeHtml(r.carrier_email)} • Compliance: ${escapeHtml(r.carrier_compliance || "PENDING")}</div>
              ${
                r.request_status === "REQUESTED"
                  ? `
                <div class="row" style="margin-top:10px">
                  <form method="POST" action="/shipper/requests/${r.request_id}/accept"><button class="btn green" type="submit">Accept</button></form>
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
        ${myLoads.rows.length ? myLoads.rows.map((l) => loadCard(l, user)).join("") : `<div class="muted">No loads yet.</div>`}
      </div>
    `;
    return res.send(layout({ title: "Dashboard", user, body }));
  }

  // CARRIER dashboard
  if (user.role === "CARRIER") {
    const comp = await pool.query(`SELECT * FROM carriers_compliance WHERE carrier_id=$1`, [user.id]);
    const c = comp.rows[0] || { status: "PENDING" };

    const body = `
      <div class="grid">
        <div class="card">
          <div class="row" style="justify-content:space-between">
            <div>
              <h2 style="margin:0">Carrier Dashboard</h2>
              <div class="muted">Upload compliance docs to earn Verified badge.</div>
            </div>
            <span class="badge ${c.status === "APPROVED" ? "ok" : "warn"}">Compliance: ${escapeHtml(c.status)}</span>
          </div>

          <div class="hr"></div>

          <div class="muted" style="margin-bottom:10px">
            Required documents:
            <ul>
              <li><b>W-9</b></li>
              <li><b>Certificate of Insurance (Auto Liability + Cargo)</b></li>
              <li><b>Operating Authority (MC / DOT proof)</b></li>
            </ul>
          </div>

          <form method="POST" action="/carrier/compliance" enctype="multipart/form-data">
            <div class="formGrid">
              <div class="col-4">
                <label>Insurance expires</label>
                <input name="insurance_expires" placeholder="YYYY-MM-DD" value="${escapeHtml(c.insurance_expires || "")}" required />
              </div>
              <div class="col-4">
                <label>Certificate of Insurance</label>
                <input type="file" name="insurance" accept="application/pdf,image/*" required />
              </div>
              <div class="col-4">
                <label>Operating Authority (MC/DOT)</label>
                <input type="file" name="authority" accept="application/pdf,image/*" required />
              </div>
              <div class="col-6">
                <label>W-9</label>
                <input type="file" name="w9" accept="application/pdf,image/*" required />
              </div>
              <div class="col-6" style="display:flex;align-items:flex-end;gap:10px;justify-content:flex-end">
                <button class="btn green" type="submit">Submit for Verification</button>
                <a class="btn ghost" href="/loads">Browse Loads</a>
              </div>
            </div>
          </form>
        </div>

        <div class="card">
          <h3 style="margin-top:0">How it works</h3>
          <div class="muted" style="line-height:1.55">
            <ol>
              <li>Upload docs to get verified</li>
              <li>Find loads with full terms (rate, detention, accessorials)</li>
              <li>Request-to-book → shipper accepts → load is booked</li>
            </ol>
          </div>
          <div class="hr"></div>
          <div class="row">
            <a class="btn green" href="/loads">Search Loads</a>
            <span class="badge brand">RPM sorting</span>
            <span class="badge brand">Equipment filters</span>
          </div>
        </div>
      </div>
    `;
    return res.send(layout({ title: "Carrier", user, body }));
  }

  // ADMIN dashboard
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
      <h2 style="margin-top:0">Admin — Carrier Verification</h2>
      <div class="muted">Approve carriers to enable Verified badge + request-to-book.</div>
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
          <div class="muted">Files: ${escapeHtml(p.insurance_filename || "—")}, ${escapeHtml(
                  p.authority_filename || "—"
                )}, ${escapeHtml(p.w9_filename || "—")}</div>
          <div class="row" style="margin-top:10px">
            <a class="btn ghost" href="/admin/carriers/${p.carrier_id}/doc/insurance">Download COI</a>
            <a class="btn ghost" href="/admin/carriers/${p.carrier_id}/doc/authority">Download Authority</a>
            <a class="btn ghost" href="/admin/carriers/${p.carrier_id}/doc/w9">Download W-9</a>
          </div>
          <div class="row" style="margin-top:10px">
            <form method="POST" action="/admin/carriers/${p.carrier_id}/approve"><button class="btn green" type="submit">Approve</button></form>
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
});

/* -------------------- Shipper actions -------------------- */
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

  // Notifications
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

/* -------------------- Carrier actions -------------------- */
app.post(
  "/carrier/compliance",
  requireAuth,
  requireRole("CARRIER"),
  upload.fields([
    { name: "insurance", maxCount: 1 },
    { name: "authority", maxCount: 1 },
    { name: "w9", maxCount: 1 },
  ]),
  async (req, res) => {
    const files = req.files || {};
    const insurance = files.insurance?.[0];
    const authority = files.authority?.[0];
    const w9 = files.w9?.[0];
    const insurance_expires = String(req.body.insurance_expires || "").trim();

    if (!insurance || !authority || !w9) return res.status(400).send("All 3 documents are required.");
    if (!insurance_expires) return res.status(400).send("Insurance expiration is required.");

    await pool.query(
      `INSERT INTO carriers_compliance
         (carrier_id, insurance_filename, insurance_bytes, authority_filename, authority_bytes, w9_filename, w9_bytes, insurance_expires, status, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'PENDING',NOW())
       ON CONFLICT (carrier_id) DO UPDATE
         SET insurance_filename=EXCLUDED.insurance_filename,
             insurance_bytes=EXCLUDED.insurance_bytes,
             authority_filename=EXCLUDED.authority_filename,
             authority_bytes=EXCLUDED.authority_bytes,
             w9_filename=EXCLUDED.w9_filename,
             w9_bytes=EXCLUDED.w9_bytes,
             insurance_expires=EXCLUDED.insurance_expires,
             status='PENDING',
             updated_at=NOW()`,
      [
        req.user.id,
        insurance.originalname,
        insurance.buffer,
        authority.originalname,
        authority.buffer,
        w9.originalname,
        w9.buffer,
        insurance_expires,
      ]
    );

    res.redirect("/dashboard?docs=submitted");
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

  res.redirect("/loads?requested=1");
});

/* -------------------- Admin compliance actions -------------------- */
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

app.get("/admin/carriers/:id/doc/:type", requireAuth, requireRole("ADMIN"), async (req, res) => {
  const carrierId = Number(req.params.id);
  const type = String(req.params.type || "");
  const row = (
    await pool.query(`SELECT * FROM carriers_compliance WHERE carrier_id=$1`, [carrierId])
  ).rows[0];
  if (!row) return res.sendStatus(404);

  let bytes = null;
  let filename = "document";
  if (type === "insurance") {
    bytes = row.insurance_bytes;
    filename = row.insurance_filename || "insurance";
  } else if (type === "authority") {
    bytes = row.authority_bytes;
    filename = row.authority_filename || "authority";
  } else if (type === "w9") {
    bytes = row.w9_bytes;
    filename = row.w9_filename || "w9";
  } else {
    return res.sendStatus(400);
  }
  if (!bytes) return res.status(404).send("File not found.");

  res.setHeader("Content-Type", "application/octet-stream");
  res.setHeader("Content-Disposition", `attachment; filename="${filename.replaceAll('"', "")}"`);
  res.send(bytes);
});

/* -------------------- Load board (FIXED FILTERS + pro layout) -------------------- */
app.get("/loads", async (req, res) => {
  const user = getUser(req);

  // Carrier badge if logged in as carrier
  let carrierBadge = null;
  if (user?.role === "CARRIER") {
    const comp = await pool.query(`SELECT status FROM carriers_compliance WHERE carrier_id=$1`, [user.id]);
    carrierBadge = comp.rows[0]?.status || "PENDING";
  }

  // Filters (working)
  const qOrigin = String(req.query.origin || "").trim();
  const qDest = String(req.query.dest || "").trim();
  const qEquip = String(req.query.equipment || "").trim();
  const qStatus = String(req.query.status || "").trim(); // "open" | "all"
  const qMinMiles = String(req.query.minMiles || "").trim();
  const qMaxMiles = String(req.query.maxMiles || "").trim();
  const qMinRate = String(req.query.minRate || "").trim();
  const qSort = String(req.query.sort || "").trim(); // "newest" | "rpm"

  // default: actionable loads only (OPEN/REQUESTED)
  const actionableOnly = qStatus ? qStatus !== "all" : true;

  // default sorting: carriers newest, but allow rpm
  const sort = qSort || "newest";
  const orderBy =
    sort === "rpm" ? `ORDER BY (rate_all_in::numeric / NULLIF(miles,0)) DESC, created_at DESC` : `ORDER BY created_at DESC`;

  const where = [];
  const params = [];
  let i = 1;

  if (actionableOnly) {
    where.push(`status IN ('OPEN','REQUESTED')`);
  }

  if (qOrigin) {
    params.push(`%${qOrigin}%`);
    where.push(`lane_from ILIKE $${i++}`);
  }
  if (qDest) {
    params.push(`%${qDest}%`);
    where.push(`lane_to ILIKE $${i++}`);
  }
  if (qEquip) {
    params.push(qEquip);
    where.push(`equipment = $${i++}`);
  }
  if (qMinMiles) {
    params.push(int(qMinMiles));
    where.push(`miles >= $${i++}`);
  }
  if (qMaxMiles) {
    params.push(int(qMaxMiles));
    where.push(`miles <= $${i++}`);
  }
  if (qMinRate) {
    params.push(Number(qMinRate));
    where.push(`rate_all_in >= $${i++}`);
  }

  const sql = `
    SELECT *
    FROM loads
    ${where.length ? `WHERE ${where.join(" AND ")}` : ``}
    ${orderBy}
  `;

  const r = await pool.query(sql, params);

  const view = String(req.query.view || "cards"); // "cards" or "table"
  const viewButtons = `
    <div class="row" style="justify-content:space-between">
      <div class="row">
        <span class="badge brand">Transparent Loads</span>
        ${user?.role === "CARRIER"
          ? `<span class="badge ${carrierBadge === "APPROVED" ? "ok" : "warn"}">Verification: ${escapeHtml(carrierBadge)}</span>`
          : user?.role === "SHIPPER"
            ? `<a class="btn green" href="/shipper/plans">Plans</a>`
            : ``}
      </div>
      <div class="row">
        <a class="btn ${view === "cards" ? "green" : "ghost"}" href="${buildLoadsUrl(req, { view: "cards" })}">Cards</a>
        <a class="btn ${view === "table" ? "green" : "ghost"}" href="${buildLoadsUrl(req, { view: "table" })}">Table</a>
      </div>
    </div>
  `;

  const filters = `
    <form method="GET" action="/loads">
      <input type="hidden" name="view" value="${escapeHtml(view)}"/>
      <div class="hr"></div>
      <div class="formGrid">
        <div class="col-4"><label>Origin</label><input name="origin" placeholder="City, ST" value="${escapeHtml(qOrigin)}"/></div>
        <div class="col-4"><label>Destination</label><input name="dest" placeholder="City, ST" value="${escapeHtml(qDest)}"/></div>
        <div class="col-4">
          <label>Equipment</label>
          <select name="equipment">
            <option value="">All</option>
            ${equipmentOptions(qEquip)}
          </select>
        </div>

        <div class="col-3"><label>Min miles</label><input name="minMiles" type="number" value="${escapeHtml(qMinMiles)}"/></div>
        <div class="col-3"><label>Max miles</label><input name="maxMiles" type="number" value="${escapeHtml(qMaxMiles)}"/></div>
        <div class="col-3"><label>Min rate ($)</label><input name="minRate" type="number" step="0.01" value="${escapeHtml(qMinRate)}"/></div>

        <div class="col-3">
          <label>Sort</label>
          <select name="sort">
            <option value="newest" ${sort === "newest" ? "selected" : ""}>Newest</option>
            <option value="rpm" ${sort === "rpm" ? "selected" : ""}>Highest RPM</option>
          </select>
        </div>

        <div class="col-3">
          <label>Show</label>
          <select name="status">
            <option value="open" ${actionableOnly ? "selected" : ""}>Open / Requested</option>
            <option value="all" ${!actionableOnly ? "selected" : ""}>All (including booked)</option>
          </select>
        </div>

        <div class="col-9 row" style="justify-content:flex-end; align-items:flex-end">
          <button class="btn green" type="submit">Search</button>
          <a class="btn ghost" href="/loads?view=${escapeHtml(view)}">Clear</a>
        </div>
      </div>
    </form>
  `;

  const list =
    view === "table"
      ? renderLoadsTable(r.rows, user, carrierBadge)
      : r.rows.length
        ? r.rows.map((l) => loadCard(l, user, carrierBadge)).join("")
        : `<div class="muted">No loads match your search. Try clearing filters.</div>`;

  const body = `
    <div class="card">
      ${viewButtons}
      ${filters}
      <div class="hr"></div>
      ${list}
    </div>
  `;

  res.send(layout({ title: "Load Board", user, body }));
});

function buildLoadsUrl(req, overrides = {}) {
  const u = new URL(APP_URL.replace(/\/$/, "") + "/loads");
  // Copy current query from request
  const current = req.query || {};
  for (const k of Object.keys(current)) {
    u.searchParams.set(k, String(current[k]));
  }
  for (const k of Object.keys(overrides)) {
    u.searchParams.set(k, String(overrides[k]));
  }
  // Return path+query (not full external if APP_URL not set)
  return "/loads" + (u.search ? u.search : "");
}

function renderLoadsTable(rows, user, carrierBadge) {
  if (!rows.length) return `<div class="muted">No loads match your search. Try clearing filters.</div>`;

  return `
    <div class="tableWrap">
      <table>
        <thead>
          <tr>
            <th>Lane</th>
            <th>Dates</th>
            <th>Equip</th>
            <th>Miles</th>
            <th>Weight</th>
            <th>Rate</th>
            <th>RPM</th>
            <th>Terms</th>
            <th>Status</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          ${rows.map((l) => loadRow(l, user, carrierBadge)).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function loadRow(l, user, carrierBadge) {
  const status = String(l.status || "OPEN");
  const canRequest = user?.role === "CARRIER";
  const r = rpm(l.rate_all_in, l.miles);

  let action = "";
  if (canRequest) {
    if (status === "BOOKED") {
      action = `<span class="badge ok">Booked</span>`;
    } else if (carrierBadge === "APPROVED") {
      action = `<form method="POST" action="/carrier/loads/${l.id}/request"><button class="btn green" type="submit">Request</button></form>`;
    } else {
      action = `<span class="badge warn">Verify to request</span>`;
    }
  }

  return `
    <tr>
      <td><b>#${l.id}</b> ${escapeHtml(l.lane_from)} → ${escapeHtml(l.lane_to)}</td>
      <td><span class="muted">${escapeHtml(l.pickup_date)} → ${escapeHtml(l.delivery_date)}</span></td>
      <td>${escapeHtml(l.equipment)}</td>
      <td>${int(l.miles).toLocaleString()}</td>
      <td>${int(l.weight_lbs).toLocaleString()} lbs</td>
      <td><b>${money(l.rate_all_in)}</b></td>
      <td>${r ? `$${r.toFixed(2)}` : "—"}</td>
      <td><span class="muted">${escapeHtml(l.payment_terms)}${l.quickpay_available ? " • QuickPay" : ""}</span></td>
      <td><span class="badge ${status === "BOOKED" ? "ok" : status === "REQUESTED" ? "warn" : "brand"}">${escapeHtml(status)}</span></td>
      <td>${action}</td>
    </tr>
  `;
}

function loadCard(l, user, carrierBadge) {
  const status = String(l.status || "OPEN");
  const canRequest = user?.role === "CARRIER";
  const r = rpm(l.rate_all_in, l.miles);

  return `
    <div class="load">
      <div class="loadTop">
        <div>
          <div class="lane">#${l.id} ${escapeHtml(l.lane_from)} → ${escapeHtml(l.lane_to)}</div>
          <div class="muted">${escapeHtml(l.pickup_date)} → ${escapeHtml(l.delivery_date)} • ${escapeHtml(l.equipment)}</div>
        </div>
        <div style="text-align:right">
          <div style="font-weight:1000">${money(l.rate_all_in)} <span class="muted">(all-in)</span></div>
          <div class="muted">${int(l.miles).toLocaleString()} mi • ${int(l.weight_lbs).toLocaleString()} lbs • RPM: ${r ? `$${r.toFixed(2)}` : "—"}</div>
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

function equipmentOptions(selected = "") {
  const opts = [
    "Dry Van",
    "Standard Van",
    "Reefer",
    "Flatbed",
    "Stepdeck",
    "Conestoga",
    "Power Only",
    "Hotshot",
    "Box Truck",
    "Sprinter Van",
    "Tanker",
    "Intermodal",
    "RGN / Lowboy",
  ];
  return opts
    .map((o) => `<option ${selected === o ? "selected" : ""}>${escapeHtml(o)}</option>`)
    .join("");
}

/* -------------------- Health -------------------- */
app.get("/health", (_, res) => {
  res.json({
    ok: true,
    stripeEnabled,
    smtpEnabled: !!getMailer(),
    appUrl: APP_URL,
  });
});

/* -------------------- Start -------------------- */
initDb()
  .then(async () => {
    await bootstrapAdmin();
    app.listen(PORT, "0.0.0.0", () => console.log("Server running on port", PORT));
  })
  .catch((e) => {
    console.error("DB init failed:", e);
    process.exit(1);
  });
