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

// --- DFX LOGO (SVG) ---
app.get("/logo.svg", (req, res) => {
  res.type("image/svg+xml").send(`
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 420 120">
  <g fill="none" stroke="#000" stroke-width="8">
    <path d="M20 70 C80 20, 200 20, 300 50" />
    <rect x="300" y="45" width="90" height="35" rx="6"/>
    <circle cx="320" cy="85" r="10"/>
    <circle cx="370" cy="85" r="10"/>
  </g>
  <text x="20" y="105" font-size="36" font-family="Arial Black, Arial" fill="#000">DFX</text>
</svg>`);
});


/* --------------------- CONFIG --------------------- */
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;
const BUILD_VERSION = process.env.BUILD_VERSION || "2026-01-01-pro-ui-v2";

const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;
const BOOTSTRAP_ADMIN_EMAIL = String(process.env.BOOTSTRAP_ADMIN_EMAIL || "").trim().toLowerCase();

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY; // sk_...
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET; // whsec_...
const STRIPE_PRICE_STARTER = process.env.STRIPE_PRICE_STARTER;
const STRIPE_PRICE_GROWTH = process.env.STRIPE_PRICE_GROWTH;
const STRIPE_PRICE_ENTERPRISE = process.env.STRIPE_PRICE_ENTERPRISE;

const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = Number(process.env.SMTP_PORT || "587");
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const SMTP_FROM = process.env.SMTP_FROM || "no-reply@dfx-usa.com";

const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || "support@dfx-usa.com";
const LIVE_CHAT_URL = process.env.LIVE_CHAT_URL || "";

/* --------------------- REQUIRED ENV --------------------- */
function bootFail(msg) {
  app.get("*", (_, res) => {
    res.status(500).send(`<h1>Config error</h1><p>${escapeHtml(msg)}</p><p>Build: ${escapeHtml(BUILD_VERSION)}</p>`);
  });
  app.listen(PORT, "0.0.0.0", () => console.log("Boot fail:", msg));
}
if (!DATABASE_URL) return bootFail("Missing DATABASE_URL");
if (!JWT_SECRET) return bootFail("Missing JWT_SECRET");

/* --------------------- MIDDLEWARE --------------------- */
// Stripe webhook MUST be raw body
app.post("/stripe/webhook", express.raw({ type: "application/json" }), stripeWebhookHandler);

// normal parsers
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  next();
});

/* --------------------- DB --------------------- */
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

/* --------------------- UPLOADS --------------------- */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

/* --------------------- STRIPE --------------------- */
const stripeEnabled = !!(
  STRIPE_SECRET_KEY &&
  STRIPE_WEBHOOK_SECRET &&
  STRIPE_PRICE_STARTER &&
  STRIPE_PRICE_GROWTH &&
  STRIPE_PRICE_ENTERPRISE
);
const stripe = stripeEnabled ? new Stripe(STRIPE_SECRET_KEY) : null;

/* --------------------- CONSTANTS --------------------- */
const DISCLAIMER_TEXT =
  "Direct Freight Exchange is a technology platform and is not a broker or carrier. Users are responsible for verifying compliance, insurance, and payment terms.";

const BRAND_PITCH =
  "Cut out the middleman. Book carriers directly. Transparent terms up front — rate, detention, accessorials, appointment type, and payment terms. No broker games.";

const PLANS = {
  STARTER: { label: "Starter", price: 99, limit: 15, bestFor: "New shippers posting a handful of weekly loads." },
  GROWTH: { label: "Growth", price: 199, limit: 30, bestFor: "Teams scaling volume and moving consistent lanes." },
  ENTERPRISE: { label: "Enterprise", price: 399, limit: -1, bestFor: "High-volume shippers who want unlimited posting." },
};

const EQUIPMENT_OPTIONS = [
  "Standard Van",
  "Dry Van",
  "Reefer",
  "Flatbed",
  "Step Deck",
  "Conestoga",
  "RGN",
  "Double Drop",
  "Lowboy",
  "Power Only",
  "Hotshot",
  "Straight Truck",
  "Box Truck",
  "Tanker",
  "Intermodal / Container",
  "Car Hauler",
  "Livestock",
  "Oversize / Permitted",
  "Other",
];

/* --------------------- HELPERS --------------------- */
function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
function safeLower(s) {
  return String(s || "").trim().toLowerCase();
}
function clampStr(s, max = 200) {
  s = String(s ?? "").trim();
  if (s.length > max) return s.slice(0, max);
  return s;
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
function money(n) {
  const x = Number(n);
  if (!Number.isFinite(x)) return "";
  return `$${x.toFixed(2)}`;
}
function rpm(rate, miles) {
  const r = Number(rate), m = Number(miles);
  if (!Number.isFinite(r) || !Number.isFinite(m) || m <= 0) return 0;
  return r / m;
}
function monthKey(d = new Date()) {
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  return `${y}-${m}`;
}
function sha256hex(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}
function randomToken(bytes = 24) {
  return crypto.randomBytes(bytes).toString("hex");
}
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

/* --------------------- AUTH --------------------- */
function signIn(res, user) {
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
  const isProd = process.env.NODE_ENV === "production";
  res.cookie("dfx_token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: isProd, // localhost needs false; Render/production uses true
    path: "/",
    maxAge: 1000 * 60 * 60 * 24 * 7,
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
    // Ensure req.user is populated even if a route accidentally omitted requireAuth
    if (!req.user) {
      const u = getUser(req);
      if (!u) return res.redirect("/login");
      req.user = u;
    }
    if (req.user.role !== role) return res.sendStatus(403);
    next();
  };
}

/* --------------------- EMAIL --------------------- */
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
  await t.sendMail({ from: SMTP_FROM, to, subject, html });
}

/* --------------------- UI ICONS --------------------- */
function icon(name) {
  const common = `fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"`;
  if (name === "home") return `<svg width="18" height="18" viewBox="0 0 24 24" ${common}><path d="M3 10.5 12 3l9 7.5"/><path d="M5 10v11h14V10"/><path d="M9 21v-7h6v7"/></svg>`;
  if (name === "shield") return `<svg width="18" height="18" viewBox="0 0 24 24" ${common}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/></svg>`;
  if (name === "bolt") return `<svg width="18" height="18" viewBox="0 0 24 24" ${common}><path d="M13 2 3 14h9l-1 8 10-12h-9l1-8Z"/></svg>`;
  if (name === "tag") return `<svg width="18" height="18" viewBox="0 0 24 24" ${common}><path d="M20 10V4H14L4 14l6 6 10-10Z"/><path d="M7 17 17 7"/><path d="M15 5h.01"/></svg>`;
  if (name === "truck") return `<svg width="18" height="18" viewBox="0 0 24 24" ${common}><path d="M14 18V6H3v12h11Z"/><path d="M14 10h4l3 3v5h-7v-8Z"/><path d="M7 18a2 2 0 1 0 0 4 2 2 0 0 0 0-4Z"/><path d="M17 18a2 2 0 1 0 0 4 2 2 0 0 0 0-4Z"/></svg>`;
  if (name === "clipboard") return `<svg width="18" height="18" viewBox="0 0 24 24" ${common}><path d="M9 3h6v4H9z"/><path d="M9 5H7a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2"/></svg>`;
  if (name === "search") return `<svg width="18" height="18" viewBox="0 0 24 24" ${common}><circle cx="11" cy="11" r="7"/><path d="M21 21 16.65 16.65"/></svg>`;
  if (name === "spark") return `<svg width="18" height="18" viewBox="0 0 24 24" ${common}><path d="M12 2l1.8 6.2L20 10l-6.2 1.8L12 18l-1.8-6.2L4 10l6.2-1.8L12 2Z"/></svg>`;
  return "";
}

function logoSvg() {
  // Simple, clean inline mark (no external assets)
  return `
    <svg width="22" height="22" viewBox="0 0 24 24" aria-hidden="true">
      <defs>
        <linearGradient id="dfx_g" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stop-color="rgba(34,197,94,1)"/>
          <stop offset="1" stop-color="rgba(163,230,53,1)"/>
        </linearGradient>
      </defs>
      <path d="M12 2 20 6v6c0 5.2-3.7 9.2-8 10-4.3-.8-8-4.8-8-10V6l8-4Z" fill="url(#dfx_g)"/>
      <path d="M8.1 12.2h7.8" stroke="rgba(6,19,11,.9)" stroke-width="2" stroke-linecap="round"/>
      <path d="M10 9.2h4" stroke="rgba(6,19,11,.9)" stroke-width="2" stroke-linecap="round"/>
      <path d="M10 15.2h4" stroke="rgba(6,19,11,.9)" stroke-width="2" stroke-linecap="round"/>
    </svg>`;
}

/* --------------------- UI (Layout) --------------------- */
function layout({ title, user, body, extraHead = "", extraScript = "" }) {
  const helpBtn = LIVE_CHAT_URL
    ? `<a class="helpFab" target="_blank" rel="noopener noreferrer" href="${escapeHtml(LIVE_CHAT_URL)}">Live Help</a>`
    : `<a class="helpFab" href="mailto:${escapeHtml(SUPPORT_EMAIL)}?subject=DFX%20Support">Support</a>`;

  const rolePill = user
    ? `<span class="pill"><span class="dot"></span>${escapeHtml(user.role)}</span>`
    : "";

  const topCta = user
    ? `<a class="btn btnPrimary" href="/dashboard">Dashboard</a><a class="btn btnGhost" href="/logout">Logout</a>`
    : `<a class="btn btnGhost" href="/login">Login</a><a class="btn btnPrimary" href="/signup">Get Started</a>`;

  return `<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${escapeHtml(title)} • Direct Freight Exchange</title>
<meta name="description" content="Cut out the middleman broker. Direct shipper-to-carrier booking with transparent all-in pricing, detention, accessorials, and payment terms."/>
${extraHead}
<style>
:root{
  --bg:#050607;
  --panel: rgba(10,14,13,.78);
  --panel2: rgba(7,9,10,.72);
  --panel3: rgba(5,7,8,.62);
  --line:rgba(255,255,255,.10);
  --line2:rgba(163,230,53,.22);
  --text:#eef7f1;
  --muted:rgba(238,247,241,.70);
  --muted2:rgba(238,247,241,.52);
  --green:#22c55e;
  --lime:#a3e635;
  --shadow:0 22px 70px rgba(0,0,0,.55);
  --radius:18px;
  --radius2:26px;
  --max: 1480px;
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
}

*{box-sizing:border-box}
html,body{height:100%}
body{
  margin:0; color:var(--text);
  font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
  background:
    radial-gradient(1100px 540px at 12% -6%, rgba(34,197,94,.22), transparent 60%),
    radial-gradient(1100px 540px at 92% 0%, rgba(163,230,53,.16), transparent 60%),
    linear-gradient(180deg, rgba(34,197,94,.10), transparent 42%),
    var(--bg);
}

a{color:var(--lime);text-decoration:none}
a:hover{text-decoration:underline}
hr{border:0;height:1px;background:rgba(255,255,255,.10);margin:16px 0}

.wrap{max-width:var(--max);margin:0 auto;padding:22px}
@media(max-width:900px){.wrap{padding:16px}}

.announce{
  border:1px solid rgba(163,230,53,.18);
  background: rgba(6,8,9,.65);
  box-shadow: var(--shadow);
  border-radius:999px;
  padding:10px 14px;
  display:flex;
  gap:10px;
  align-items:center;
  justify-content:space-between;
  margin-bottom:14px;
  backdrop-filter: blur(10px);
}
.announce b{color:rgba(240,255,219,.95)}
.announce .aRow{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.announce .aChip{
  padding:6px 10px;border-radius:999px;border:1px solid rgba(34,197,94,.28);
  background:rgba(34,197,94,.12);color:rgba(219,255,236,.92);font-size:12px
}

.nav{
  position:sticky; top:14px; z-index:40;
  display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;
  padding:14px 16px;border:1px solid var(--line);border-radius:var(--radius2);
  background: linear-gradient(180deg, rgba(12,16,15,.84), rgba(7,9,10,.72));
  backdrop-filter: blur(12px); box-shadow: var(--shadow);
}
@media(max-width:900px){.nav{position:static}}

.brand{display:flex;gap:12px;align-items:center}
.mark{
  width:46px;height:46px;border-radius:18px;border:1px solid rgba(255,255,255,.10);
  background: linear-gradient(135deg, rgba(34,197,94,.98), rgba(163,230,53,.68));
  display:grid;place-items:center; font-weight:1000; color:#06130b;
  box-shadow: 0 22px 60px rgba(34,197,94,.14);
}
.brandTitle{font-weight:1000;letter-spacing:-.2px}
.brandSub{color:var(--muted2);font-size:12px;margin-top:2px}

.navLinks{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.navLinks a{color:var(--text)}
.navLinks a:hover{text-decoration:none}
.linkPill{
  padding:9px 12px;border-radius:999px;border:1px solid rgba(255,255,255,.10);
  background: rgba(6,8,9,.55); color: rgba(238,247,241,.88);
  display:inline-flex;gap:8px;align-items:center; font-size:13px;
}
.linkPill:hover{filter:brightness(1.07)}

.right{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.pill{
  padding:8px 10px;border-radius:999px;border:1px solid rgba(255,255,255,.10);
  background: rgba(6,8,9,.55); color: rgba(238,247,241,.78);
  font-size:12px; display:inline-flex;gap:8px;align-items:center
}
.dot{width:8px;height:8px;border-radius:50%;background:rgba(34,197,94,.95);box-shadow:0 0 0 4px rgba(34,197,94,.15)}

.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:10px;
  padding:10px 14px;border-radius:14px;border:1px solid rgba(255,255,255,.10);
  background: rgba(6,8,9,.55); color: rgba(238,247,241,.92);
  cursor:pointer; transition: transform .08s ease, filter .12s ease;
  font-weight:700;
}
.btn:hover{filter:brightness(1.07);text-decoration:none}
.btn:active{transform:translateY(1px)}
.btnPrimary{
  border:none;
  background: linear-gradient(135deg, rgba(34,197,94,.98), rgba(163,230,53,.70));
  color:#06130b; font-weight:1000;
  box-shadow: 0 22px 60px rgba(34,197,94,.18);
}
.btnGhost{
  border:1px solid rgba(163,230,53,.22);
  background: rgba(6,8,9,.52);
}
.btnDanger{
  border:1px solid rgba(239,68,68,.25);
  background: rgba(239,68,68,.10);
  color: rgba(255,224,224,.95);
}

.section{
  margin-top:16px;
  border:1px solid var(--line);
  border-radius: var(--radius2);
  background: linear-gradient(180deg, rgba(12,16,15,.80), rgba(7,9,10,.66));
  backdrop-filter: blur(12px);
  box-shadow: var(--shadow);
  padding: 22px;
  overflow:hidden;
}
.sectionTight{padding:18px}

.hero{
  margin-top:16px;
  border:1px solid rgba(163,230,53,.14);
  border-radius: var(--radius2);
  background:
    radial-gradient(900px 320px at 18% 0%, rgba(34,197,94,.22), transparent 60%),
    radial-gradient(900px 320px at 92% 0%, rgba(163,230,53,.12), transparent 60%),
    linear-gradient(180deg, rgba(12,16,15,.86), rgba(6,8,9,.66));
  backdrop-filter: blur(12px);
  box-shadow: var(--shadow);
  padding: 30px;
  position:relative;
}
@media(max-width:900px){.hero{padding:22px}}

.heroGrid{
  display:grid;
  grid-template-columns: 1.35fr .65fr;
  gap:18px;
  align-items:start;
}
@media(max-width:980px){.heroGrid{grid-template-columns:1fr}}

.hTitle{
  margin:0;
  font-size:52px;
  line-height:1.03;
  letter-spacing:-1px;
}
@media(max-width:900px){.hTitle{font-size:38px}}
.hLead{
  margin-top:12px;
  color: rgba(238,247,241,.82);
  max-width: 860px;
  line-height:1.55;
  font-size:16px;
}
.badgeRow{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}
.badge{
  display:inline-flex;gap:10px;align-items:center;
  padding:8px 12px;border-radius:999px;border:1px solid rgba(255,255,255,.10);
  background: rgba(6,8,9,.58);
  color: rgba(238,247,241,.80);
  font-size:12px;
}
.badgeOk{
  border-color: rgba(34,197,94,.28);
  background: rgba(34,197,94,.12);
  color: rgba(219,255,236,.92);
}
.badgeWarn{
  border-color: rgba(163,230,53,.22);
  background: rgba(163,230,53,.08);
  color: rgba(240,255,219,.90);
}
.kpiGrid{
  display:grid;
  gap:12px;
}
.kpi{
  border:1px solid rgba(255,255,255,.10);
  background: rgba(6,8,9,.55);
  border-radius: 18px;
  padding:14px;
}
.kpi .num{font-size:26px;font-weight:1000;letter-spacing:-.5px}
.kpi .lab{color:var(--muted2);font-size:12px;margin-top:4px;line-height:1.3}

.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:980px){.grid3,.grid2{grid-template-columns:1fr}}

.feature{
  border:1px solid rgba(255,255,255,.10);
  background: rgba(6,8,9,.55);
  border-radius: 20px;
  padding:16px;
}
.featureTop{display:flex;gap:12px;align-items:center}
.featureIcon{
  width:38px;height:38px;border-radius:14px;
  display:grid;place-items:center;
  border:1px solid rgba(163,230,53,.20);
  background: rgba(34,197,94,.10);
  color: rgba(240,255,219,.95);
}
.featureTitle{font-weight:1000}
.featureText{color:rgba(238,247,241,.74);line-height:1.55;margin-top:8px}

.callout{
  border:1px solid rgba(163,230,53,.18);
  background: rgba(6,8,9,.55);
  border-radius: 22px;
  padding:18px;
}
.callout h3{margin:0}
.callout p{margin:10px 0 0 0;color:rgba(238,247,241,.74);line-height:1.55}

.formGrid{display:grid;gap:10px}
.twoCol{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.threeCol{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}
@media(max-width:900px){.twoCol,.threeCol{grid-template-columns:1fr}}

input,select,textarea{
  width:100%; min-width:0;
  padding:12px 12px;
  border-radius:14px;
  border:1px solid rgba(255,255,255,.10);
  background: rgba(5,7,8,.70);
  color: rgba(238,247,241,.95);
  outline:none;
}
textarea{min-height:100px;resize:vertical}
input:focus,select:focus,textarea:focus{border-color:rgba(34,197,94,.55)}

.small{font-size:12px;color:rgba(238,247,241,.58)}
.muted{color:rgba(238,247,241,.72)}
.mono{font-family: var(--mono); font-variant-numeric: tabular-nums;}
.spread{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:flex-end}
.divider{height:1px;background:rgba(255,255,255,.10);margin:16px 0}

.footer{
  margin-top:16px;
  border:1px solid rgba(255,255,255,.10);
  border-radius: var(--radius2);
  background: rgba(6,8,9,.62);
  backdrop-filter: blur(12px);
  box-shadow: var(--shadow);
  padding:18px;
}
.footerTop{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:center}
.footLinks{display:flex;gap:12px;flex-wrap:wrap}
.footLinks a{color:rgba(238,247,241,.80)}
.footText{margin-top:10px;color:rgba(238,247,241,.60);font-size:12px;line-height:1.45}
.footLegal{margin-top:10px;color:rgba(238,247,241,.45);font-size:12px}

.helpFab{
  position:fixed; right:18px; bottom:18px;
  z-index:999;
  padding:12px 14px;
  border-radius:999px;
  border:1px solid rgba(163,230,53,.25);
  background:rgba(6,8,9,.88);
  color:rgba(238,247,241,.92);
  box-shadow: 0 18px 60px rgba(0,0,0,.55);
  font-weight:900;
}
.helpFab:hover{filter:brightness(1.08);text-decoration:none}

/* Load board */
.boardGrid{display:grid;grid-template-columns: 420px 1fr;gap:16px;margin-top:16px}
@media(max-width:980px){.boardGrid{grid-template-columns:1fr}}
.filterCard{position:sticky;top:96px;align-self:start}
@media(max-width:980px){.filterCard{position:static}}
.loadList{display:grid;gap:12px;margin-top:14px}
.loadCard{
  border:1px solid rgba(255,255,255,.10);
  background: rgba(6,8,9,.55);
  border-radius: 22px;
  padding:16px;
}
.loadTop{display:flex;justify-content:space-between;gap:14px;flex-wrap:wrap}
.lane{font-weight:1000;font-size:16px;letter-spacing:-.2px}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
.chip{
  display:inline-flex;align-items:center;gap:8px;
  padding:7px 10px;border-radius:999px;border:1px solid rgba(255,255,255,.10);
  background: rgba(255,255,255,.04);
  color: rgba(238,247,241,.86);
  font-size:12px;
}
.chipStrong{
  border-color: rgba(34,197,94,.30);
  background: rgba(34,197,94,.12);
  color: rgba(219,255,236,.92);
}
.resultsBar{
  display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:center;
  padding:12px 14px;border-radius:18px;border:1px solid rgba(255,255,255,.10);
  background: rgba(6,8,9,.45);
}
.resultsBar .left{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.resultsBar .right{display:flex;gap:10px;flex-wrap:wrap;align-items:center}

</style>
</head>
<body>
<div class="wrap">

  <div class="announce">
    <div class="aRow">
      <span class="aChip">${icon("spark")} No broker games</span>
      <div class="small"><b>Book direct.</b> All-in rate, detention, accessorials, appointment type & payment terms visible up front.</div>
    </div>
    <div class="aRow">
      <a class="linkPill" href="/features">${icon("bolt")} Features</a>
      <a class="linkPill" href="/how-it-works">${icon("clipboard")} How it works</a>
      <a class="linkPill" href="/contact">${icon("shield")} Support</a>
    </div>
  </div>

  <div class="nav">
    <div class="brand">
      <div class="mark" title="Direct Freight Exchange">${logoSvg()}</div>
      <div>
        <div class="brandTitle">Direct Freight Exchange</div>
        <div class="brandSub">Direct shipper ↔ carrier marketplace • Transparent terms • Faster booking</div>
      </div>
    </div>

    <div class="navLinks">
      <a class="linkPill" href="/">${icon("home")} Home</a>
      <a class="linkPill" href="/loads">${icon("search")} Load Board</a>
      <a class="linkPill" href="/features">${icon("tag")} Pricing & Features</a>
      <a class="linkPill" href="/contracts">${icon("clipboard")} Contracts</a>
      <a class="linkPill" href="/about">${icon("spark")} About</a>
    </div>

    <div class="right">
      ${rolePill}
      ${topCta}
    </div>
  </div>

  ${body}

  <div class="footer">
    <div class="footerTop">
      <div class="brand" style="gap:10px">
        <div class="mark" style="width:42px;height:42px;border-radius:16px" title="Direct Freight Exchange">${logoSvg()}</div>
        <div>
          <div class="brandTitle">Direct Freight Exchange</div>
          <div class="brandSub">Cut out the middleman. Transparent freight, built for speed.</div>
        </div>
      </div>
      <div class="footLinks">
        <a href="/terms">Terms</a>
        <a href="/privacy">Privacy</a>
        <a href="/contact">Contact</a>
        <a href="/contracts">Contracts</a>
        <a href="/health">Status</a>
        <a href="/version">Version</a>
      </div>
    </div>
    <div class="footText">${escapeHtml(DISCLAIMER_TEXT)}</div>
    <div class="footLegal">© 2026 Direct Freight Exchange. All rights reserved. • Build: <span class="mono">${escapeHtml(BUILD_VERSION)}</span></div>
  </div>

</div>

${helpBtn}
${extraScript}
</body>
</html>`;
}

function equipmentSelectHtml(selected) {
  const opts = [`<option value="" ${!selected ? "selected" : ""} disabled>Select equipment</option>`]
    .concat(EQUIPMENT_OPTIONS.map(e => `<option value="${escapeHtml(e)}"${selected === e ? " selected" : ""}>${escapeHtml(e)}</option>`));
  return opts.join("");
}

/* --------------------- DB MIGRATIONS --------------------- */
async function ensureColumn(table, column, sqlType) {
  const safeSqlType = String(sqlType).replace(/'/g, "''");
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='${table}' AND column_name='${column}'
      ) THEN
        EXECUTE 'ALTER TABLE ${table} ADD COLUMN ${column} ${safeSqlType}';
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
      insurance_expires TEXT,
      status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','APPROVED','REJECTED')),
      admin_note TEXT,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS carrier_files (
      id SERIAL PRIMARY KEY,
      carrier_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      kind TEXT NOT NULL CHECK (kind IN ('W9','COI','AUTHORITY')),
      filename TEXT NOT NULL,
      mimetype TEXT NOT NULL,
      bytes BYTEA NOT NULL,
      uploaded_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(carrier_id, kind)
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

    CREATE TABLE IF NOT EXISTS load_files (
      id SERIAL PRIMARY KEY,
      load_id INTEGER NOT NULL REFERENCES loads(id) ON DELETE CASCADE,
      uploaded_by_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      kind TEXT NOT NULL CHECK (kind IN ('BOL')),
      filename TEXT NOT NULL,
      mimetype TEXT NOT NULL,
      bytes BYTEA NOT NULL,
      uploaded_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS password_resets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ
    );
  `);

  await ensureColumn("loads", "status", "TEXT NOT NULL DEFAULT ''OPEN''");
  await ensureColumn("loads", "appointment_type", "TEXT NOT NULL DEFAULT ''FCFS''");
  await ensureColumn("loads", "accessorials", "TEXT NOT NULL DEFAULT ''''");
  await ensureColumn("loads", "special_requirements", "TEXT NOT NULL DEFAULT ''''");
  await ensureColumn("loads", "detention_rate_per_hr", "NUMERIC NOT NULL DEFAULT 0");
  await ensureColumn("loads", "detention_after_hours", "INTEGER NOT NULL DEFAULT 0");

  if (BOOTSTRAP_ADMIN_EMAIL) {
    const r = await pool.query(`SELECT id,role FROM users WHERE lower(email)=lower($1)`, [BOOTSTRAP_ADMIN_EMAIL]);
    if (r.rows[0] && r.rows[0].role !== "ADMIN") {
      await pool.query(`UPDATE users SET role='ADMIN' WHERE id=$1`, [r.rows[0].id]);
      console.log("[BOOTSTRAP_ADMIN] set ADMIN for:", BOOTSTRAP_ADMIN_EMAIL);
    }
  }
}

/* --------------------- BILLING HELPERS --------------------- */
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
      nowM, shipperId
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

/* --------------------- STATIC PAGES --------------------- */
app.get("/version", (_, res) => res.json({ build: BUILD_VERSION, stripeEnabled, smtpEnabled: !!getMailer() }));
app.get("/health", (_, res) => res.json({ ok: true, build: BUILD_VERSION, stripeEnabled, smtpEnabled: !!getMailer() }));

app.get("/about", (req, res) => {
  const user = getUser(req);
  res.send(layout({
    title: "About",
    user,
    body: `
      <div class="section">
        <div class="spread">
          <div>
            <h2 style="margin:0">About DFX</h2>
            <div class="muted" style="margin-top:8px;max-width:920px;line-height:1.6">
              Direct Freight Exchange exists for one simple reason: <b>move freight without the middleman</b>.
              We give shippers and carriers a direct marketplace where the most important details are visible upfront.
            </div>
          </div>
          <div class="badge badgeOk">${icon("spark")} Built for speed</div>
        </div>

        <div class="divider"></div>

        <div class="grid2">
          <div class="callout">
            <h3>Our philosophy</h3>
            <p>
              Freight shouldn’t require chasing updates or negotiating mystery fees.
              DFX is structured to reduce friction: post a load with real terms,
              let verified carriers request it, and generate clean paperwork when booked.
            </p>
          </div>

          <div class="callout">
            <h3>What “no broker games” means</h3>
            <p>
              Shippers see a clear posting workflow.
              Carriers see the full picture: <b>all-in rate</b>, <b>payment terms</b>, <b>detention</b>,
              <b>accessorials</b>, appointment type and requirements — before they request.
            </p>
          </div>
        </div>
      </div>
    `
  }));
});

app.get("/how-it-works", (req, res) => {
  const user = getUser(req);
  res.send(layout({
    title: "How it works",
    user,
    body: `
      <div class="section">
        <h2 style="margin:0">How it works</h2>
        <div class="muted" style="margin-top:8px;line-height:1.6;max-width:960px">
          A direct workflow designed for real freight operations — not endless back-and-forth.
        </div>

        <div class="divider"></div>

        <div class="grid3">
          <div class="feature">
            <div class="featureTop">
              <div class="featureIcon">${icon("clipboard")}</div>
              <div>
                <div class="featureTitle">1) Shipper posts real terms</div>
                <div class="small">All-in rate, miles, weight, equipment, payment terms, detention, accessorials</div>
              </div>
            </div>
            <div class="featureText">
              No hidden details. No “call for rate.” Your posting is what the carrier sees.
            </div>
          </div>

          <div class="feature">
            <div class="featureTop">
              <div class="featureIcon">${icon("shield")}</div>
              <div>
                <div class="featureTitle">2) Verified carriers request</div>
                <div class="small">W-9, COI (Auto + Cargo), Authority</div>
              </div>
            </div>
            <div class="featureText">
              Verification creates trust. Once approved, carriers can request loads.
            </div>
          </div>

          <div class="feature">
            <div class="featureTop">
              <div class="featureIcon">${icon("bolt")}</div>
              <div>
                <div class="featureTitle">3) Book direct + paperwork</div>
                <div class="small">Auto-filled rate confirmations after booking</div>
              </div>
            </div>
            <div class="featureText">
              When accepted, the load is marked booked and both sides have clean terms to execute.
            </div>
          </div>
        </div>
      </div>
    `
  }));
});

app.get("/features", (req, res) => {
  const user = getUser(req);

  const planCards = Object.keys(PLANS).map((k) => {
    const p = PLANS[k];
    const limit = p.limit === -1 ? "Unlimited" : `${p.limit} loads / month`;
    return `
      <div class="feature">
        <div class="featureTop">
          <div class="featureIcon">${icon("tag")}</div>
          <div>
            <div class="featureTitle">${escapeHtml(p.label)}</div>
            <div class="small">${escapeHtml(p.bestFor)}</div>
          </div>
        </div>
        <div class="divider"></div>
        <div class="spread">
          <div>
            <div class="muted">${escapeHtml(limit)}</div>
            <div class="small">Transparent posting workflow • Rate confirmations • Direct carrier requests</div>
          </div>
          <div style="font-weight:1000;font-size:18px">$${p.price}/mo</div>
        </div>
        <div style="margin-top:12px">
          <a class="btn btnPrimary" href="${user?.role === "SHIPPER" ? "/shipper/plans" : "/signup"}">Choose</a>
        </div>
      </div>
    `;
  }).join("");

  res.send(layout({
    title: "Pricing & Features",
    user,
    body: `
      <div class="section">
        <div class="spread">
          <div>
            <h2 style="margin:0">Pricing & Features</h2>
            <div class="muted" style="margin-top:8px;line-height:1.6;max-width:980px">
              Built for real freight operations: direct booking, full transparency, and a carrier verification process
              that helps reduce risk.
            </div>
          </div>
          <div class="badge badgeOk">${icon("spark")} Carrier accounts are free</div>
        </div>

        <div class="divider"></div>

        <div class="grid3">
          <div class="feature">
            <div class="featureTop">
              <div class="featureIcon">${icon("shield")}</div>
              <div>
                <div class="featureTitle">Verification workflow</div>
                <div class="small">W-9 • COI • MC/DOT proof</div>
              </div>
            </div>
            <div class="featureText">Carriers upload once. Admin approval unlocks requesting loads.</div>
          </div>

          <div class="feature">
            <div class="featureTop">
              <div class="featureIcon">${icon("bolt")}</div>
              <div>
                <div class="featureTitle">Fast booking</div>
                <div class="small">Requests → accept → booked</div>
              </div>
            </div>
            <div class="featureText">No endless phone calls. Confirm quickly and execute.</div>
          </div>

          <div class="feature">
            <div class="featureTop">
              <div class="featureIcon">${icon("clipboard")}</div>
              <div>
                <div class="featureTitle">Clean paperwork</div>
                <div class="small">Auto-filled rate confirmations</div>
              </div>
            </div>
            <div class="featureText">Generate a printable confirmation after booking with both sides populated.</div>
          </div>
        </div>

        <div class="divider"></div>

        <h3 style="margin:0">Shipper subscription options</h3>
        <div class="muted" style="margin-top:6px">Pick the level that matches your monthly posting volume.</div>

        <div class="divider"></div>
        <div class="grid3">
          ${planCards}
        </div>
      </div>
    `
  }));
});

app.get("/contact", (req, res) => {
  const user = getUser(req);
  res.send(layout({
    title: "Contact",
    user,
    body: `
      <div class="section">
        <h2 style="margin:0">Support</h2>
        <div class="muted" style="margin-top:8px;line-height:1.6">
          If you need help with onboarding, billing, verification, or bookings — we’re here.
        </div>

        <div class="divider"></div>

        <div class="grid2">
          <div class="callout">
            <h3>Email support</h3>
            <p>
              <a href="mailto:${escapeHtml(SUPPORT_EMAIL)}">${escapeHtml(SUPPORT_EMAIL)}</a>
              <br/><span class="small">Response times may vary by volume.</span>
            </p>
          </div>

          <div class="callout">
            <h3>Live assistance</h3>
            <p>
              ${LIVE_CHAT_URL
                ? `Open live chat: <a target="_blank" rel="noopener noreferrer" href="${escapeHtml(LIVE_CHAT_URL)}">${escapeHtml(LIVE_CHAT_URL)}</a>`
                : `Live chat is not configured yet. Add <span class="mono">LIVE_CHAT_URL</span> in Render when you’re ready.`
              }
            </p>
          </div>
        </div>
      </div>
    `
  }));
});

app.get("/terms", (req, res) => {
  const user = getUser(req);
  res.send(layout({
    title: "Terms",
    user,
    body: `
      <div class="section">
        <h2 style="margin:0">Terms</h2>
        <div class="muted" style="margin-top:10px;line-height:1.6;max-width:980px">
          ${escapeHtml(DISCLAIMER_TEXT)}
        </div>
        <div class="divider"></div>
        <div class="grid2">
          <div class="callout">
            <h3>Transparency</h3>
            <p>
              Loads should be posted with clear and accurate details: rate, equipment, dates,
              payment terms, detention and accessorials.
            </p>
          </div>
          <div class="callout">
            <h3>Verification</h3>
            <p>
              Carrier verification is designed to reduce risk. Shippers are still responsible for due diligence.
              Carriers are responsible for maintaining authority and insurance.
            </p>
          </div>
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
      <div class="section">
        <h2 style="margin:0">Privacy Policy</h2>
        <div class="muted" style="margin-top:10px;line-height:1.6;max-width:980px">
          We collect the minimum data needed to operate the marketplace (account email, security tokens,
          load postings and booking activity). Carrier documents are uploaded for verification and stored securely.
        </div>
        <div class="divider"></div>
        <div class="grid2">
          <div class="callout">
            <h3>What we store</h3>
            <p>
              Account information, marketplace activity, and uploaded compliance documents for verification.
            </p>
          </div>
          <div class="callout">
            <h3>Contact</h3>
            <p>
              Privacy requests: <a href="mailto:${escapeHtml(SUPPORT_EMAIL)}">${escapeHtml(SUPPORT_EMAIL)}</a>
            </p>
          </div>
        </div>
      </div>
    `
  }));
});

app.get("/contracts", (req, res) => {
  const user = getUser(req);
  res.send(layout({
    title: "Contracts",
    user,
    body: `
      <div class="section">
        <div class="spread">
          <div>
            <h2 style="margin:0">Pre‑built contracts</h2>
            <div class="muted" style="margin-top:8px;line-height:1.6;max-width:980px">
              Use these templates as a starting point. You should still review with your team and counsel for your specific lanes and customers.
            </div>
          </div>
          <div class="badge badgeOk">${icon("clipboard")} Ready to use</div>
        </div>

        <div class="divider"></div>

        <div class="grid2">
          <div class="feature">
            <div class="featureTitle">Shipper ↔ Carrier Load Agreement (Template)</div>
            <div class="featureText">
              A simple, plain‑language template covering scope, payment terms, accessorials, detention, and claims.
              <div style="margin-top:12px" class="small">Coming soon: downloadable PDF/DOCX built into the app.</div>
            </div>
          </div>

          <div class="feature">
            <div class="featureTitle">Carrier Packet Checklist</div>
            <div class="featureText">
              W‑9 • COI • Authority • banking info • contact roles • safety notes. Use it to standardize onboarding.
              <div style="margin-top:12px" class="small">Tip: carriers upload W‑9/COI/Authority in the dashboard.</div>
            </div>
          </div>

          <div class="feature">
            <div class="featureTitle">Rate Confirmation (Generated on booking)</div>
            <div class="featureText">
              DFX already generates an auto‑filled rate confirmation after a load is booked.
              You can print/save as PDF from the booked load page.
            </div>
          </div>

          <div class="feature">
            <div class="featureTitle">Need a custom template?</div>
            <div class="featureText">
              Email <a href="mailto:${escapeHtml(SUPPORT_EMAIL)}">${escapeHtml(SUPPORT_EMAIL)}</a> and tell us what you want standardized
              (quickpay, fuel, lumper, tarp, appointment policy, etc.).
            </div>
          </div>
        </div>
      </div>
    `
  }));
});

/* --------------------- HOME --------------------- */

app.get("/", (req, res) => {
  const body = `
    <section class="hero" style="text-align:center;padding:60px">
      <img src="/logo.svg" style="width:300px;margin-bottom:30px"/>
      <h1>Book Freight Direct.<br/>No Brokers. No Games.</h1>
      <p>Transparent rates, verified carriers, and paperwork that lives inside DFX.</p>
      <div style="margin-top:20px">
        <a href="/signup">Post a Load (Shippers)</a> |
        <a href="/loads">Find Loads (Carriers)</a>
      </div>
    </section>
  `;
  res.send(layout({ title: "Direct Freight Exchange", body }));
});


/* --------------------- AUTH PAGES --------------------- */
app.get("/signup", (req, res) => {
  const user = getUser(req);
  res.send(layout({
    title: "Create account",
    user,
    body: `
      <div class="section">
        <div class="spread">
          <div>
            <h2 style="margin:0">Create your account</h2>
            <div class="muted" style="margin-top:8px;line-height:1.6;max-width:980px">
              Get access to the marketplace. Carriers are free. Shippers subscribe to post loads.
            </div>
          </div>
          <a class="btn btnGhost" href="/login">Already have an account?</a>
        </div>

        <div class="divider"></div>

        <form method="POST" action="/signup" class="formGrid">
          <div class="twoCol">
            <input name="email" type="email" placeholder="Email" required />
            <input name="password" type="password" placeholder="Password (min 8 chars)" minlength="8" required />
          </div>
          <div class="twoCol">
            <select name="role" required>
              <option value="SHIPPER">Shipper</option>
              <option value="CARRIER">Carrier (free)</option>
            </select>
            <button class="btn btnPrimary" type="submit">Create account</button>
          </div>

          <div class="small">
            By continuing, you agree to the <a href="/terms">Terms</a> and <a href="/privacy">Privacy Policy</a>.
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
    const user = r.rows[0];

    if (role === "SHIPPER") {
      await pool.query(
        `INSERT INTO shippers_billing (shipper_id,status,plan,monthly_limit,usage_month,loads_used)
         VALUES ($1,'INACTIVE',NULL,0,$2,0)
         ON CONFLICT DO NOTHING`,
        [user.id, monthKey()]
      );
    } else {
      await pool.query(
        `INSERT INTO carriers_compliance (carrier_id,status) VALUES ($1,'PENDING') ON CONFLICT DO NOTHING`,
        [user.id]
      );
    }

    if (BOOTSTRAP_ADMIN_EMAIL && email === BOOTSTRAP_ADMIN_EMAIL) {
      await pool.query(`UPDATE users SET role='ADMIN' WHERE id=$1`, [user.id]);
      user.role = "ADMIN";
      console.log("[BOOTSTRAP_ADMIN] set ADMIN for:", email);
    }

    signIn(res, user);
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
      <div class="section">
        <div class="spread">
          <div>
            <h2 style="margin:0">Login</h2>
            <div class="muted" style="margin-top:8px">Access your shipper or carrier dashboard.</div>
          </div>
          <a class="btn btnGhost" href="/signup">Create account</a>
        </div>

        <div class="divider"></div>

        <form method="POST" action="/login" class="formGrid">
          <div class="twoCol">
            <input name="email" type="email" placeholder="Email" required />
            <input name="password" type="password" placeholder="Password" required />
          </div>
          <div style="display:flex;gap:10px;flex-wrap:wrap">
            <button class="btn btnPrimary" type="submit">Login</button>
            <a class="btn btnGhost" href="/forgot">Forgot password</a>
            <a class="btn btnGhost" href="/loads">Browse loads</a>
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

/* --------------------- FORGOT PASSWORD --------------------- */
app.get("/forgot", (req, res) => {
  const user = getUser(req);
  res.send(layout({
    title: "Reset password",
    user,
    body: `
      <div class="section">
        <h2 style="margin:0">Reset your password</h2>
        <div class="muted" style="margin-top:8px">Enter your email. We’ll send a secure reset link.</div>
        <div class="divider"></div>

        <form method="POST" action="/forgot" class="formGrid">
          <div class="twoCol">
            <input name="email" type="email" placeholder="Email" required />
            <button class="btn btnPrimary" type="submit">Send reset link</button>
          </div>
          <div class="small">If SMTP is not configured yet, the server will log that it “would send” the email.</div>
        </form>
      </div>
    `
  }));
});

app.post("/forgot", async (req, res) => {
  const email = safeLower(req.body.email);
  const r = await pool.query(`SELECT id,email FROM users WHERE email=$1`, [email]);
  const u = r.rows[0];

  if (!u) {
    return res.send(layout({
      title: "Check your email",
      user: null,
      body: `<div class="section"><h2 style="margin:0">Check your email</h2><div class="muted" style="margin-top:8px">If an account exists, a reset link was sent.</div></div>`
    }));
  }

  const token = randomToken(24);
  const tokenHash = sha256hex(token);
  const expires = new Date(Date.now() + 1000 * 60 * 30);

  await pool.query(`INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES ($1,$2,$3)`, [
    u.id, tokenHash, expires.toISOString()
  ]);

  const link = `${APP_URL}/reset?token=${encodeURIComponent(token)}&email=${encodeURIComponent(u.email)}`;
  try {
    await sendEmail(u.email, "DFX Password Reset", `
      <p>Use this link to set a new password (valid for 30 minutes):</p>
      <p><a href="${escapeHtml(link)}">${escapeHtml(link)}</a></p>
    `);
  } catch (e) {
    console.error("Reset email failed:", e);
  }

  res.send(layout({
    title: "Check your email",
    user: null,
    body: `<div class="section"><h2 style="margin:0">Check your email</h2><div class="muted" style="margin-top:8px">If an account exists, a reset link was sent.</div></div>`
  }));
});

app.get("/reset", (req, res) => {
  const token = String(req.query.token || "");
  const email = safeLower(req.query.email);
  res.send(layout({
    title: "Set new password",
    user: null,
    body: `
      <div class="section">
        <h2 style="margin:0">Set a new password</h2>
        <div class="divider"></div>
        <form method="POST" action="/reset" class="formGrid">
          <input type="hidden" name="token" value="${escapeHtml(token)}"/>
          <input type="hidden" name="email" value="${escapeHtml(email)}"/>
          <div class="twoCol">
            <input name="password" type="password" minlength="8" placeholder="New password (min 8 chars)" required />
            <button class="btn btnPrimary" type="submit">Update password</button>
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

/* --------------------- DASHBOARD --------------------- */
app.get("/dashboard", requireAuth, async (req, res) => {
  const user = req.user;

  if (user.role === "SHIPPER") {
    const billing = await getAndNormalizeBilling(user.id);
    const gate = postingAllowed(billing);

    const myLoads = await pool.query(`SELECT * FROM loads WHERE shipper_id=$1 ORDER BY created_at DESC`, [user.id]);

    const booked = await pool.query(`
      SELECT l.*, u.email AS carrier_email
      FROM loads l
      LEFT JOIN users u ON u.id = l.booked_carrier_id
      WHERE l.shipper_id=$1 AND l.status='BOOKED'
      ORDER BY l.created_at DESC
    `, [user.id]);

    const requests = await pool.query(`
      SELECT lr.*, l.lane_from, l.lane_to, l.rate_all_in, l.miles, u.email as carrier_email
      FROM load_requests lr
      JOIN loads l ON l.id = lr.load_id
      JOIN users u ON u.id = lr.carrier_id
      WHERE l.shipper_id=$1 AND lr.status='REQUESTED'
      ORDER BY lr.created_at DESC
      LIMIT 200
    `, [user.id]);

    const usageText = billing.monthly_limit === -1
      ? "Unlimited posting"
      : `${billing.loads_used} / ${billing.monthly_limit} used this month`;

    const body = `
      <div class="section">
        <div class="spread">
          <div>
            <h2 style="margin:0">Shipper Dashboard</h2>
            <div class="muted" style="margin-top:8px;line-height:1.6">
              Post loads with real terms, review carrier requests, and generate rate confirmations after booking.
            </div>
          </div>
          <span class="badge ${billing.status === "ACTIVE" ? "badgeOk" : "badgeWarn"}">${icon("tag")} Billing: ${escapeHtml(billing.status)}</span>
        </div>

        <div class="divider"></div>

        <div style="display:flex;gap:10px;flex-wrap:wrap">
          <span class="badge">${icon("spark")} Plan: ${escapeHtml(billing.plan || "None")}</span>
          <span class="badge badgeOk">${icon("clipboard")} ${escapeHtml(usageText)}</span>
          <a class="btn btnPrimary" href="/shipper/plans">Manage plan</a>
          <a class="btn btnGhost" href="/shipper/invoices">Invoices & receipts</a>
        </div>

        <div class="divider"></div>

        <div class="grid2">
          <div class="callout">
            <h3>Post a load</h3>
            <p>
              Your posting is what carriers see. Include accurate terms and requirements to speed up booking.
            </p>

            ${gate.ok ? `
              <form method="POST" action="/shipper/loads" class="formGrid" style="margin-top:12px">
                <div class="threeCol">
                  <input name="lane_from" placeholder="Origin (City, ST)" required />
                  <input name="lane_to" placeholder="Destination (City, ST)" required />
                  <select name="equipment" required>${equipmentSelectHtml("")}</select>

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

                  <input name="accessorials" placeholder="Accessorials (lumper, tarp, etc.)" required />
                  <input name="special_requirements" placeholder="Special requirements / notes" required />
                </div>

                <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:10px">
                  <button class="btn btnPrimary" type="submit">${icon("bolt")} Post load</button>
                  <a class="btn btnGhost" href="/loads">${icon("search")} View load board</a>
                </div>
              </form>
            ` : `
              <div class="badge badgeWarn" style="margin-top:12px">
                ${icon("tag")} Posting blocked: ${escapeHtml(gate.reason)}
              </div>
              <div style="margin-top:12px">
                <a class="btn btnPrimary" href="/shipper/plans">Subscribe / upgrade</a>
              </div>
            `}
          </div>

          <div class="callout">
            <h3>Incoming requests</h3>
            <p>Review requests and book the carrier you want. Booking generates a rate confirmation.</p>
            <div class="divider"></div>

            ${requests.rows.length ? requests.rows.map(r => {
              const rRPM = rpm(r.rate_all_in, r.miles);
              return `
                <div class="loadCard" style="margin-top:10px">
                  <div class="loadTop">
                    <div>
                      <div class="lane">Load #${r.load_id} • ${escapeHtml(r.lane_from)} → ${escapeHtml(r.lane_to)}</div>
                      <div class="muted">Carrier: ${escapeHtml(r.carrier_email)}</div>
                      <div class="chips">
                        <span class="chip chipStrong">All-in: ${money(r.rate_all_in)}</span>
                        <span class="chip mono">RPM: $${(rRPM || 0).toFixed(2)}</span>
                      </div>
                    </div>
                    <div style="display:flex;gap:10px;flex-wrap:wrap">
                      <form method="POST" action="/shipper/requests/${r.id}/accept">
                        <button class="btn btnPrimary" type="submit">Accept & book</button>
                      </form>
                      <form method="POST" action="/shipper/requests/${r.id}/decline">
                        <button class="btn btnGhost" type="submit">Decline</button>
                      </form>
                    </div>
                  </div>
                </div>
              `;
            }).join("") : `<div class="muted">No incoming requests right now.</div>`}
          </div>
        </div>
      </div>

      <div class="section">
        <div class="spread">
          <div>
            <h2 style="margin:0">Booked loads</h2>
            <div class="muted" style="margin-top:8px">Generate auto-filled rate confirmations after booking.</div>
          </div>
        </div>
        <div class="divider"></div>
        ${booked.rows.length ? booked.rows.map(l => `
          <div class="loadCard">
            <div class="loadTop">
              <div>
                <div class="lane">#${l.id} ${escapeHtml(l.lane_from)} → ${escapeHtml(l.lane_to)}</div>
                <div class="muted">${escapeHtml(l.pickup_date)} → ${escapeHtml(l.delivery_date)} • Carrier: ${escapeHtml(l.carrier_email || "—")}</div>
                <div class="chips">
                  <span class="chip chipStrong">${escapeHtml(l.equipment)}</span>
                  <span class="chip mono">${int(l.miles).toLocaleString()} mi</span>
                  <span class="chip mono">${int(l.weight_lbs).toLocaleString()} lbs</span>
                  <span class="chip">Commodity: ${escapeHtml(l.commodity)}</span>
                  <span class="chip">Terms: ${escapeHtml(l.payment_terms)}${l.quickpay_available ? " • QuickPay" : ""}</span>
                </div>
              </div>
              <div style="text-align:right">
                <div style="font-weight:1000;font-size:18px">${money(l.rate_all_in)}</div>
                <div class="small mono">RPM: ${rpm(l.rate_all_in, l.miles) ? `$${rpm(l.rate_all_in, l.miles).toFixed(2)}` : "—"}</div>
                <div style="margin-top:12px">
                  <a class="btn btnPrimary" href="/shipper/loads/${l.id}/rate-confirmation" target="_blank">Open rate confirmation</a>
                </div>
              </div>
            </div>
          </div>
        `).join("") : `<div class="muted">No booked loads yet.</div>`}
      </div>

      <div class="section">
        <div class="spread">
          <div>
            <h2 style="margin:0">Your posted loads</h2>
            <div class="muted" style="margin-top:8px">Everything you’ve posted, newest first.</div>
          </div>
        </div>
        <div class="divider"></div>
        ${myLoads.rows.length ? myLoads.rows.map(l => `
          <div class="loadCard">
            <div class="loadTop">
              <div>
                <div class="lane">#${l.id} ${escapeHtml(l.lane_from)} → ${escapeHtml(l.lane_to)}</div>
                <div class="muted">${escapeHtml(l.pickup_date)} → ${escapeHtml(l.delivery_date)} • Status: ${escapeHtml(l.status)}</div>
                <div class="chips">
                  <span class="chip chipStrong">${escapeHtml(l.equipment)}</span>
                  <span class="chip mono">${int(l.miles).toLocaleString()} mi</span>
                  <span class="chip mono">${int(l.weight_lbs).toLocaleString()} lbs</span>
                  <span class="chip">Commodity: ${escapeHtml(l.commodity)}</span>
                  <span class="chip">Terms: ${escapeHtml(l.payment_terms)}${l.quickpay_available ? " • QuickPay" : ""}</span>
                </div>
              </div>
              <div style="text-align:right">
                <div style="font-weight:1000;font-size:18px">${money(l.rate_all_in)}</div>
                <div class="small mono">RPM: ${rpm(l.rate_all_in, l.miles) ? `$${rpm(l.rate_all_in, l.miles).toFixed(2)}` : "—"}</div>
              </div>
            </div>
          </div>
        `).join("") : `<div class="muted">No loads posted yet.</div>`}
      </div>
    `;

    return res.send(layout({ title: "Dashboard", user, body }));
  }

  if (user.role === "CARRIER") {
    const c = (await pool.query(`SELECT * FROM carriers_compliance WHERE carrier_id=$1`, [user.id])).rows[0] || { status: "PENDING" };
    const hasW9 = (await pool.query(`SELECT 1 FROM carrier_files WHERE carrier_id=$1 AND kind='W9'`, [user.id])).rowCount > 0;
    const hasCOI = (await pool.query(`SELECT 1 FROM carrier_files WHERE carrier_id=$1 AND kind='COI'`, [user.id])).rowCount > 0;
    const hasAUTH = (await pool.query(`SELECT 1 FROM carrier_files WHERE carrier_id=$1 AND kind='AUTHORITY'`, [user.id])).rowCount > 0;

    const canRequest = c.status === "APPROVED";

    const myReqs = await pool.query(`
      SELECT lr.*, l.lane_from, l.lane_to, l.status as load_status
      FROM load_requests lr
      JOIN loads l ON l.id = lr.load_id
      WHERE lr.carrier_id=$1
      ORDER BY lr.created_at DESC
      LIMIT 200
    `, [user.id]);

    const bookedLoads = await pool.query(`
      SELECT * FROM loads
      WHERE booked_carrier_id=$1 AND status='BOOKED'
      ORDER BY created_at DESC
      LIMIT 200
    `, [user.id]);

    const body = `
      <div class="section">
        <div class="spread">
          <div>
            <h2 style="margin:0">Carrier Dashboard</h2>
            <div class="muted" style="margin-top:8px;line-height:1.6;max-width:980px">
              Carriers are free on DFX. Upload verification documents once, get approved, then request loads
              with clear terms — rate, RPM, miles, weight, detention, accessorials, and payment terms.
            </div>
          </div>
          <span class="badge ${c.status === "APPROVED" ? "badgeOk" : "badgeWarn"}">${icon("shield")} Verification: ${escapeHtml(c.status)}</span>
        </div>

        <div class="divider"></div>

        <div style="display:flex;gap:10px;flex-wrap:wrap">
          <span class="badge ${hasW9 ? "badgeOk" : "badgeWarn"}">W-9</span>
          <span class="badge ${hasCOI ? "badgeOk" : "badgeWarn"}">COI (Auto + Cargo)</span>
          <span class="badge ${hasAUTH ? "badgeOk" : "badgeWarn"}">Operating Authority (MC/DOT)</span>
          ${canRequest ? `<span class="badge badgeOk">${icon("bolt")} You can request loads</span>` : `<span class="badge badgeWarn">${icon("tag")} Approval required before requesting</span>`}
        </div>

        <div class="divider"></div>

        <div class="grid2">
          <div class="callout">
            <h3>Submit for verification</h3>
            <p>
              Upload the required documents. Once approved by an admin, you can request loads.
              This creates trust and reduces wasted time.
            </p>
            <form method="POST" action="/carrier/compliance" enctype="multipart/form-data" class="formGrid" style="margin-top:12px">
              <div class="threeCol">
                <input name="insurance_expires" placeholder="Insurance expires (YYYY-MM-DD)" value="${escapeHtml(c.insurance_expires || "")}" required />
                <input type="file" name="w9" accept="application/pdf,image/*" required />
                <input type="file" name="insurance" accept="application/pdf,image/*" required />
                <input type="file" name="authority" accept="application/pdf,image/*" required />
              </div>
              <button class="btn btnPrimary" type="submit">${icon("shield")} Submit documents</button>
              <div class="small">Required files: W-9 • Certificate of Insurance (Auto Liability + Cargo) • Operating Authority (MC/DOT proof)</div>
            </form>
          </div>

          <div class="callout">
            <h3>Find loads</h3>
            <p>
              Use the load board filters to find loads by origin, destination, equipment, miles, weight, and RPM.
              By default, you’ll see actionable loads (open + requested).
            </p>
            <div style="margin-top:12px;display:flex;gap:10px;flex-wrap:wrap">
              <a class="btn btnPrimary" href="/loads">${icon("search")} Go to load board</a>
              <a class="btn btnGhost" href="/how-it-works">${icon("clipboard")} How it works</a>
            </div>
          </div>
        </div>
      </div>

      <div class="section">
        <div class="spread">
          <div>
            <h2 style="margin:0">Booked loads & BOL upload</h2>
            <div class="muted" style="margin-top:8px">Upload Bills of Lading for loads you were booked on. Shippers can keep paperwork clean.</div>
          </div>
        </div>
        <div class="divider"></div>

        ${bookedLoads.rows.length ? bookedLoads.rows.map(l => `
          <div class="loadCard">
            <div class="loadTop">
              <div>
                <div class="lane">#${l.id} ${escapeHtml(l.lane_from)} → ${escapeHtml(l.lane_to)}</div>
                <div class="muted">${escapeHtml(l.pickup_date)} → ${escapeHtml(l.delivery_date)} • ${escapeHtml(l.equipment)} • ${int(l.miles).toLocaleString()} mi</div>
                <div class="chips">
                  <span class="chip chipStrong">All-in: ${money(l.rate_all_in)}</span>
                  <span class="chip">Terms: ${escapeHtml(l.payment_terms)}${l.quickpay_available ? " • QuickPay" : ""}</span>
                </div>
              </div>
              <div style="min-width:280px">
                <form method="POST" action="/carrier/loads/${l.id}/bol" enctype="multipart/form-data" class="formGrid">
                  <input type="file" name="bol" accept="application/pdf,image/*" required />
                  <button class="btn btnPrimary" type="submit">${icon("clipboard")} Upload BOL</button>
                  <div class="small">Accepted: PDF or image. Stored securely.</div>
                </form>
              </div>
            </div>
          </div>
        `).join("") : `<div class="muted">No booked loads yet.</div>`}
      </div>

      <div class="section">
        <div class="spread">
          <div>
            <h2 style="margin:0">Your requests</h2>
            <div class="muted" style="margin-top:8px">Track the loads you requested and their status.</div>
          </div>
        </div>
        <div class="divider"></div>

        ${myReqs.rows.length ? myReqs.rows.map(r => `
          <div class="loadCard">
            <div class="loadTop">
              <div>
                <div class="lane">Load #${r.load_id} ${escapeHtml(r.lane_from)} → ${escapeHtml(r.lane_to)}</div>
                <div class="muted">Request: ${escapeHtml(r.status)} • Load status: ${escapeHtml(r.load_status)}</div>
              </div>
            </div>
          </div>
        `).join("") : `<div class="muted">No requests yet.</div>`}
      </div>
    `;
    return res.send(layout({ title: "Dashboard", user, body }));
  }

  // ADMIN dashboard
  const pending = await pool.query(`
    SELECT cc.*, u.email
    FROM carriers_compliance cc
    JOIN users u ON u.id = cc.carrier_id
    WHERE cc.status='PENDING'
    ORDER BY cc.updated_at DESC
    LIMIT 200
  `);

  const body = `
    <div class="section">
      <div class="spread">
        <div>
          <h2 style="margin:0">Admin • Carrier Verifications</h2>
          <div class="muted" style="margin-top:8px">Approve carriers to enable requests. Review uploaded documents quickly.</div>
        </div>
        <span class="badge badgeOk">${icon("shield")} Admin access</span>
      </div>

      <div class="divider"></div>

      ${pending.rows.length ? pending.rows.map(p => `
        <div class="loadCard">
          <div class="loadTop">
            <div>
              <div class="lane">${escapeHtml(p.email)}</div>
              <div class="muted">Insurance exp: ${escapeHtml(p.insurance_expires || "—")}</div>
              <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px">
                <a class="btn btnGhost" href="/admin/carriers/${p.carrier_id}/file/W9">W-9</a>
                <a class="btn btnGhost" href="/admin/carriers/${p.carrier_id}/file/COI">COI</a>
                <a class="btn btnGhost" href="/admin/carriers/${p.carrier_id}/file/AUTHORITY">Authority</a>
              </div>
            </div>
            <div style="display:flex;gap:10px;flex-wrap:wrap">
              <form method="POST" action="/admin/carriers/${p.carrier_id}/approve"><button class="btn btnPrimary" type="submit">Approve</button></form>
              <form method="POST" action="/admin/carriers/${p.carrier_id}/reject"><button class="btn btnGhost" type="submit">Reject</button></form>
            </div>
          </div>
        </div>
      `).join("") : `<div class="muted">No pending carriers.</div>`}
    </div>
  `;
  return res.send(layout({ title: "Admin", user, body }));
});

/* --------------------- SHIPPER: POST LOAD --------------------- */
app.post("/shipper/loads", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  try {
    const billing = await getAndNormalizeBilling(req.user.id);
    const gate = postingAllowed(billing);
    if (!gate.ok) return res.status(403).send(`Posting blocked: ${gate.reason}`);

    const lane_from = clampStr(req.body.lane_from, 120);
    const lane_to = clampStr(req.body.lane_to, 120);
    const pickup_date = clampStr(req.body.pickup_date, 30);
    const delivery_date = clampStr(req.body.delivery_date, 30);
    const equipment = clampStr(req.body.equipment, 60);
    const commodity = clampStr(req.body.commodity, 90);

    const weight_lbs = int(req.body.weight_lbs);
    const miles = int(req.body.miles);
    const rate_all_in = Number(req.body.rate_all_in);

    const payment_terms = clampStr(req.body.payment_terms, 60);
    const quickpay_available = String(req.body.quickpay_available) === "true";
    const detention_rate_per_hr = Number(req.body.detention_rate_per_hr);
    const detention_after_hours = int(req.body.detention_after_hours);
    const appointment_type = clampStr(req.body.appointment_type, 60);
    const accessorials = clampStr(req.body.accessorials, 140);
    const special_requirements = clampStr(req.body.special_requirements, 220);

    if (!lane_from || !lane_to || !pickup_date || !delivery_date || !equipment || !commodity) return res.status(400).send("Missing required fields.");
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
    res.status(500).send("Post load failed.");
  }
});

/* --------------------- CARRIER: COMPLIANCE UPLOAD (stored in Postgres) --------------------- */
app.post(
  "/carrier/compliance",
  requireAuth,
  requireRole("CARRIER"),
  upload.fields([{ name: "insurance", maxCount: 1 }, { name: "authority", maxCount: 1 }, { name: "w9", maxCount: 1 }]),
  async (req, res) => {
    try {
      const files = req.files || {};
      const coi = files.insurance?.[0];
      const auth = files.authority?.[0];
      const w9 = files.w9?.[0];
      const insurance_expires = clampStr(req.body.insurance_expires, 30);

      if (!coi || !auth || !w9) return res.status(400).send("All 3 documents are required.");
      if (!insurance_expires) return res.status(400).send("Insurance expiration is required.");

      await pool.query(
        `INSERT INTO carriers_compliance (carrier_id, insurance_expires, status, updated_at)
         VALUES ($1,$2,'PENDING',NOW())
         ON CONFLICT (carrier_id) DO UPDATE SET
           insurance_expires=EXCLUDED.insurance_expires,
           status='PENDING',
           updated_at=NOW()`,
        [req.user.id, insurance_expires]
      );

      const upsertFile = async (kind, file) => {
        await pool.query(
          `INSERT INTO carrier_files (carrier_id, kind, filename, mimetype, bytes)
           VALUES ($1,$2,$3,$4,$5)
           ON CONFLICT (carrier_id, kind) DO UPDATE SET
             filename=EXCLUDED.filename,
             mimetype=EXCLUDED.mimetype,
             bytes=EXCLUDED.bytes,
             uploaded_at=NOW()`,
          [req.user.id, kind, file.originalname, file.mimetype || "application/octet-stream", file.buffer]
        );
      };

      await upsertFile("W9", w9);
      await upsertFile("COI", coi);
      await upsertFile("AUTHORITY", auth);

      res.redirect("/dashboard");
    } catch (e) {
      console.error("Compliance upload failed:", e);
      res.status(500).send("Compliance upload failed.");
    }
  }
);

/* --------------------- ADMIN: APPROVE/REJECT + VIEW FILES --------------------- */
app.post("/admin/carriers/:id/approve", requireAuth, requireRole("ADMIN"), async (req, res) => {
  const carrierId = Number(req.params.id);
  await pool.query(`UPDATE carriers_compliance SET status='APPROVED', updated_at=NOW(), admin_note=NULL WHERE carrier_id=$1`, [carrierId]);
  res.redirect("/dashboard");
});
app.post("/admin/carriers/:id/reject", requireAuth, requireRole("ADMIN"), async (req, res) => {
  const carrierId = Number(req.params.id);
  await pool.query(`UPDATE carriers_compliance SET status='REJECTED', updated_at=NOW(), admin_note='Rejected' WHERE carrier_id=$1`, [carrierId]);
  res.redirect("/dashboard");
});
app.get("/admin/carriers/:id/file/:kind", requireAuth, requireRole("ADMIN"), async (req, res) => {
  const carrierId = Number(req.params.id);
  const kind = String(req.params.kind || "").toUpperCase();
  if (!["W9", "COI", "AUTHORITY"].includes(kind)) return res.status(400).send("Invalid file kind.");

  const r = await pool.query(
    `SELECT filename, mimetype, bytes FROM carrier_files WHERE carrier_id=$1 AND kind=$2`,
    [carrierId, kind]
  );
  const f = r.rows[0];
  if (!f) return res.status(404).send("File not found.");
  res.setHeader("Content-Type", f.mimetype || "application/octet-stream");
  res.setHeader("Content-Disposition", `inline; filename="${f.filename.replaceAll('"', "")}"`);
  res.send(f.bytes);
});

/* --------------------- LOAD BOARD (API + PAGE) --------------------- */
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
  else if (["OPEN", "REQUESTED", "BOOKED"].includes(status)) where.push(`status = ${push(status)}`);

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

  return { sql: `SELECT * FROM loads ${whereSql} ${orderBy}`, params };
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
    const r = await pool.query(built.sql, built.params);
    res.json({ ok: true, build: BUILD_VERSION, count: r.rows.length, filters, rows: r.rows });
  } catch (e) {
    console.error("/api/loads failed:", e);
    res.status(500).json({ ok: false, error: "api_failed" });
  }
});

app.get("/loads", async (req, res) => {
  const user = getUser(req);
  let carrierBadge = null;

  if (user?.role === "CARRIER") {
    const comp = await pool.query(`SELECT status FROM carriers_compliance WHERE carrier_id=$1`, [user.id]);
    carrierBadge = comp.rows[0]?.status || "PENDING";
  }

  const statusDefault = user?.role === "CARRIER" ? "ACTIONABLE" : "";

  const body = `
    <div class="section sectionTight">
      <div class="spread">
        <div>
          <h2 style="margin:0">Load Board</h2>
          <div class="muted" style="margin-top:8px;line-height:1.6;max-width:980px">
            Search and filter loads by lane, equipment, miles, weight, rate, and RPM. Transparent terms are visible up front.
            ${user?.role === "CARRIER" ? `Carriers default to actionable loads (open + requested).` : ``}
          </div>
        </div>
        <div class="badge badgeOk">${icon("spark")} ${escapeHtml(BRAND_PITCH)}</div>
      </div>
    </div>

    <div class="boardGrid">
      <div class="section filterCard sectionTight">
        <div class="spread">
          <div>
            <div style="font-weight:1000;font-size:16px">Search & Filters</div>
            <div class="small">Dial in the lane, equipment, and pricing that fits your operation.</div>
          </div>
          <button class="btn btnGhost" id="resetBtn" type="button">Reset</button>
        </div>

        <div class="divider"></div>

        <div class="formGrid">
          <input id="q" placeholder="Search lane or commodity (Houston, Dallas, beef, etc.)" />
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

          <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
            <button class="btn btnPrimary" id="applyBtn" type="button">${icon("search")} Apply</button>
            <span class="badge" id="countBadge">Results: —</span>
          </div>

          ${user?.role === "CARRIER" ? `
            <div class="badge ${carrierBadge === "APPROVED" ? "badgeOk" : "badgeWarn"}">
              ${icon("shield")} Carrier verification: ${escapeHtml(carrierBadge || "PENDING")}
            </div>
          ` : ``}
        </div>
      </div>

      <div class="section">
        <div class="resultsBar">
          <div class="left">
            <span class="badge badgeOk">${icon("tag")} Transparent terms</span>
            <span class="badge">${icon("clipboard")} Detention & accessorials shown</span>
            <span class="badge">${icon("shield")} Verified carriers request</span>
          </div>
          <div class="right">
            <a class="btn btnGhost" href="/how-it-works">${icon("clipboard")} How it works</a>
            <a class="btn btnGhost" href="/features">${icon("tag")} Pricing</a>
          </div>
        </div>

        <div id="loads" class="loadList"></div>
      </div>
    </div>
  `;

  const extraScript = `
  <script>
    const statusDefault = ${JSON.stringify(statusDefault)};
    const userRole = ${JSON.stringify(user?.role || "")};
    const carrierBadge = ${JSON.stringify(carrierBadge || "")};

    const el = (id) => document.getElementById(id);

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
    function chip(t, strong=false){
      return '<span class="chip ' + (strong ? 'chipStrong' : '') + '">' + t + '</span>';
    }

    function renderLoad(l){
      const r = rpm(l.rate_all_in, l.miles);
      const status = String(l.status || "OPEN");
      const rtxt = r ? ("$" + r.toFixed(2)) : "—";
      const canRequest = userRole === "CARRIER";

      let requestHtml = "";
      if(canRequest){
        if(status === "BOOKED"){
          requestHtml = chip("Booked", true);
        } else if (carrierBadge === "APPROVED") {
          requestHtml =
            '<form method="POST" action="/carrier/loads/' + l.id + '/request">' +
              '<button class="btn btnPrimary" type="submit">Request to book</button>' +
            '</form>';
        } else {
          requestHtml = '<span class="badge badgeWarn">Upload docs + get approved to request loads</span>';
        }
      }

      return \`
        <div class="loadCard">
          <div class="loadTop">
            <div>
              <div class="lane">#\${l.id} \${l.lane_from} → \${l.lane_to}</div>
              <div class="muted">\${l.pickup_date} → \${l.delivery_date}</div>
              <div class="chips">
                \${chip(l.equipment, true)}
                \${chip(Number(l.miles).toLocaleString() + " mi")}
                \${chip(Number(l.weight_lbs).toLocaleString() + " lbs")}
                \${chip("Commodity: " + l.commodity)}
                \${chip("Terms: " + l.payment_terms + (l.quickpay_available ? " • QuickPay" : ""))}
                \${chip("Status: " + status)}
              </div>
            </div>

            <div style="text-align:right; min-width: 220px">
              <div style="font-weight:1000;font-size:18px">\${dollars(l.rate_all_in)} <span class="small">(all-in)</span></div>
              <div class="small mono">RPM: \${rtxt}</div>
              <div style="margin-top:12px; display:flex; justify-content:flex-end">
                \${requestHtml}
              </div>
            </div>
          </div>
        </div>
      \`;
    }

    async function loadData(){
      const params = {
        q: el("q").value,
        origin: el("origin").value,
        dest: el("dest").value,
        equipment: el("equipment").value,
        status: el("status").value,
        minMiles: el("minMiles").value,
        maxMiles: el("maxMiles").value,
        minWeight: el("minWeight").value,
        maxWeight: el("maxWeight").value,
        minRate: el("minRate").value,
        maxRate: el("maxRate").value,
        quickpay: el("quickpay").value,
        sort: el("sort").value
      };
      if(!params.status && statusDefault) params.status = statusDefault;

      const res = await fetch("/api/loads?" + qs(params));
      const data = await res.json();

      el("countBadge").textContent = "Results: " + (data.count ?? 0);

      const container = el("loads");
      container.innerHTML = "";

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

    el("applyBtn").addEventListener("click", loadData);
    el("resetBtn").addEventListener("click", () => {
      ["q","origin","dest","minMiles","maxMiles","minWeight","maxWeight","minRate","maxRate"].forEach(id => el(id).value = "");
      el("equipment").value = "";
      el("quickpay").value = "";
      el("sort").value = "newest";
      el("status").value = statusDefault || "";
      loadData();
    });

    loadData();
  </script>
  `;

  res.send(layout({ title: "Load Board", user, body, extraScript }));
});

/* --------------------- CARRIER: REQUEST LOAD --------------------- */
app.post("/carrier/loads/:id/request", requireAuth, requireRole("CARRIER"), async (req, res) => {
  const loadId = Number(req.params.id);

  const comp = await pool.query(`SELECT status FROM carriers_compliance WHERE carrier_id=$1`, [req.user.id]);
  const compStatus = comp.rows[0]?.status || "PENDING";
  if (compStatus !== "APPROVED") return res.status(403).send("Verification approval required before requesting loads.");

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

/* --------------------- SHIPPER: ACCEPT/DECLINE REQUESTS --------------------- */
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
  const shipperEmail = req.user.email;
  try {
    await sendEmail(shipperEmail, `DFX Booking Confirmed • Load #${row.load_id}`, `
      <p><b>Booking confirmed.</b></p>
      <p>Load #${row.load_id}: ${escapeHtml(row.lane_from)} → ${escapeHtml(row.lane_to)}</p>
      <p>Status: BOOKED</p>
    `);
    if (carrierEmail) {
      await sendEmail(carrierEmail, `DFX Request Accepted • Load #${row.load_id}`, `
        <p><b>Your request was accepted.</b></p>
        <p>Load #${row.load_id}: ${escapeHtml(row.lane_from)} → ${escapeHtml(row.lane_to)}</p>
        <p>Status: BOOKED</p>
      `);
    }
  } catch (e) {
    console.error("Email failed:", e);
  }

  res.redirect("/dashboard");
});

app.post("/shipper/requests/:id/decline", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  const requestId = Number(req.params.id);
  const r = await pool.query(`
    SELECT lr.*, l.shipper_id, l.lane_from, l.lane_to, l.id as load_id
    FROM load_requests lr
    JOIN loads l ON l.id = lr.load_id
    WHERE lr.id=$1
  `, [requestId]);

  const row = r.rows[0];
  if (!row || row.shipper_id !== req.user.id) return res.sendStatus(404);

  await pool.query(`UPDATE load_requests SET status='DECLINED' WHERE id=$1`, [requestId]);

  // If no other REQUESTED rows remain for this load and it's not booked, revert load status back to OPEN
  const still = await pool.query(
    `SELECT 1 FROM load_requests WHERE load_id=$1 AND status='REQUESTED' LIMIT 1`,
    [row.load_id]
  );
  if (still.rowCount === 0) {
    await pool.query(
      `UPDATE loads SET status='OPEN' WHERE id=$1 AND status='REQUESTED' AND booked_carrier_id IS NULL`,
      [row.load_id]
    );
  }

  const carrierEmail = (await pool.query(`SELECT email FROM users WHERE id=$1`, [row.carrier_id])).rows[0]?.email;
  try {
    if (carrierEmail) {
      await sendEmail(carrierEmail, `DFX Request Declined • Load #${row.load_id}`, `
        <p><b>Your request was declined.</b></p>
        <p>Load #${row.load_id}: ${escapeHtml(row.lane_from)} → ${escapeHtml(row.lane_to)}</p>
      `);
    }
  } catch (e) {
    console.error("Email failed:", e);
  }

  res.redirect("/dashboard");
});

/* --------------------- RATE CONFIRMATION (AUTO-FILL) --------------------- */
app.get("/shipper/loads/:id/rate-confirmation", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  const loadId = Number(req.params.id);
  const l = (await pool.query(`SELECT * FROM loads WHERE id=$1 AND shipper_id=$2`, [loadId, req.user.id])).rows[0];
  if (!l) return res.status(404).send("Load not found.");
  if (l.status !== "BOOKED") return res.status(400).send("Rate confirmation is available after booking.");

  const carrier = l.booked_carrier_id
    ? (await pool.query(`SELECT email FROM users WHERE id=$1`, [l.booked_carrier_id])).rows[0]
    : null;

  const html = `
<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Rate Confirmation • Load #${l.id}</title>
<style>
  body{font-family: Arial, sans-serif; padding:24px; color:#111; max-width:920px; margin:0 auto}
  h1{margin:0 0 10px 0}
  .box{border:1px solid #ddd; border-radius:10px; padding:14px; margin-top:12px}
  .grid{display:grid; grid-template-columns: 220px 1fr; gap:8px; margin-top:8px}
  .k{color:#555}
  .sig{margin-top:26px; display:grid; grid-template-columns: 1fr 1fr; gap:18px}
  .line{border-bottom:1px solid #111; height:24px}
  .muted{color:#666}
  .print{position:fixed; top:16px; right:16px; padding:10px 12px; border:1px solid #111; border-radius:10px; background:#fff; cursor:pointer}
</style>
</head>
<body>
  <button class="print" onclick="window.print()">Print / Save PDF</button>
  <h1>Rate Confirmation</h1>
  <div class="muted">Load #${l.id} • Generated by Direct Freight Exchange</div>

  <div class="box">
    <b>Parties</b>
    <div class="grid">
      <div class="k">Shipper</div><div>${escapeHtml(req.user.email)}</div>
      <div class="k">Carrier</div><div>${escapeHtml(carrier?.email || "—")}</div>
    </div>
  </div>

  <div class="box">
    <b>Lane & Dates</b>
    <div class="grid">
      <div class="k">Origin</div><div>${escapeHtml(l.lane_from)}</div>
      <div class="k">Destination</div><div>${escapeHtml(l.lane_to)}</div>
      <div class="k">Pickup</div><div>${escapeHtml(l.pickup_date)}</div>
      <div class="k">Delivery</div><div>${escapeHtml(l.delivery_date)}</div>
      <div class="k">Equipment</div><div>${escapeHtml(l.equipment)}</div>
      <div class="k">Commodity</div><div>${escapeHtml(l.commodity)}</div>
      <div class="k">Weight</div><div>${int(l.weight_lbs).toLocaleString()} lbs</div>
      <div class="k">Miles</div><div>${int(l.miles).toLocaleString()} mi</div>
    </div>
  </div>

  <div class="box">
    <b>Rate & Terms</b>
    <div class="grid">
      <div class="k">All-In Rate</div><div><b>${money(l.rate_all_in)}</b></div>
      <div class="k">Payment Terms</div><div>${escapeHtml(l.payment_terms)}${l.quickpay_available ? " • QuickPay Available" : ""}</div>
      <div class="k">Detention</div><div>${money(l.detention_rate_per_hr)}/hr after ${escapeHtml(l.detention_after_hours)} hours</div>
      <div class="k">Accessorials</div><div>${escapeHtml(l.accessorials)}</div>
      <div class="k">Appointment</div><div>${escapeHtml(l.appointment_type)}</div>
      <div class="k">Special Requirements</div><div>${escapeHtml(l.special_requirements)}</div>
    </div>
  </div>

  <div class="box">
    <b>Agreement</b>
    <div class="muted" style="line-height:1.5">
      By signing below, Shipper and Carrier agree to the load terms above, including rate, payment terms, detention, accessorials,
      and requirements. Carrier certifies it has valid authority and insurance for this shipment.
    </div>

    <div class="sig">
      <div>
        <div class="muted">Shipper Authorized Signature</div>
        <div class="line"></div>
        <div class="muted">Name / Title / Date</div>
      </div>
      <div>
        <div class="muted">Carrier Authorized Signature</div>
        <div class="line"></div>
        <div class="muted">Name / Title / Date</div>
      </div>
    </div>
  </div>
</body>
</html>
  `;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(html);
});

/* --------------------- OPTIONAL: BOL UPLOAD FOR BOOKED LOADS --------------------- */
app.post("/carrier/loads/:id/bol", requireAuth, requireRole("CARRIER"), upload.single("bol"), async (req, res) => {
  const loadId = Number(req.params.id);
  const file = req.file;
  if (!file) return res.status(400).send("Missing BOL file.");

  const l = (await pool.query(`SELECT * FROM loads WHERE id=$1`, [loadId])).rows[0];
  if (!l) return res.status(404).send("Load not found.");
  if (l.status !== "BOOKED") return res.status(400).send("BOL upload allowed after booking.");
  if (Number(l.booked_carrier_id) !== Number(req.user.id)) return res.status(403).send("Not your booked load.");

  await pool.query(
    `INSERT INTO load_files (load_id, uploaded_by_user_id, kind, filename, mimetype, bytes)
     VALUES ($1,$2,'BOL',$3,$4,$5)`,
    [loadId, req.user.id, file.originalname, file.mimetype || "application/octet-stream", file.buffer]
  );

  res.redirect("/dashboard");
});

/* --------------------- SHIPPER PLANS + STRIPE --------------------- */
app.get("/shipper/plans", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  const user = req.user;
  const bill = (await pool.query(`SELECT * FROM shippers_billing WHERE shipper_id=$1`, [user.id])).rows[0] || null;

  const nowMonth = monthKey();
  const usageMonth = bill?.usage_month || nowMonth;
  const used = bill?.loads_used ?? 0;
  const limit = bill?.monthly_limit ?? 0;
  const plan = bill?.plan || null;
  const status = bill?.status || "INACTIVE";

  const usageText = (limit === -1) ? `Unlimited` : `${used} / ${limit} used this month`;

  const cards = Object.keys(PLANS).map(p => {
    const pd = PLANS[p];
    const isCurrent = plan === p && status === "ACTIVE";
    const capText = pd.limit === -1 ? "Unlimited loads" : `${pd.limit} loads / month`;
    return `
      <div class="feature">
        <div class="featureTop">
          <div class="featureIcon">${icon("tag")}</div>
          <div>
            <div class="featureTitle">${escapeHtml(pd.label)}</div>
            <div class="small">${escapeHtml(pd.bestFor)}</div>
          </div>
        </div>
        <div class="divider"></div>
        <div class="spread">
          <div>
            <div class="muted">${escapeHtml(capText)}</div>
            <div class="small">Direct booking • Transparent terms • Rate confirmations</div>
          </div>
          <div style="font-weight:1000;font-size:18px">$${pd.price}/mo</div>
        </div>

        <div style="margin-top:12px">
          ${isCurrent
            ? `<span class="badge badgeOk">${icon("spark")} Current plan</span>`
            : `
              <form method="POST" action="/shipper/plan">
                <input type="hidden" name="plan" value="${p}">
                <button class="btn btnPrimary" type="submit">${status === "ACTIVE" ? "Switch now" : "Subscribe"}</button>
              </form>
            `
          }
        </div>
      </div>
    `;
  }).join("");

  const body = `
    <div class="section">
      <div class="spread">
        <div>
          <h2 style="margin:0">Shipper Plans</h2>
          <div class="muted" style="margin-top:8px;line-height:1.6;max-width:980px">
            Subscriptions unlock posting capacity. Choose the plan aligned with your monthly volume.
          </div>
        </div>
        <span class="badge ${status === "ACTIVE" ? "badgeOk" : "badgeWarn"}">${icon("tag")} Status: ${escapeHtml(status)}</span>
      </div>

      <div class="divider"></div>

      <div style="display:flex;gap:10px;flex-wrap:wrap">
        <span class="badge">${icon("spark")} Plan: ${escapeHtml(plan || "None")}</span>
        <span class="badge badgeOk">${icon("clipboard")} Month: ${escapeHtml(usageMonth)}</span>
        <span class="badge badgeOk">${icon("bolt")} Usage: ${escapeHtml(usageText)}</span>
      </div>

      ${!stripeEnabled ? `
        <div class="divider"></div>
        <div class="badge badgeWarn">${icon("tag")} Stripe is not configured yet. Add STRIPE_* env vars in Render.</div>
      ` : `
        <div class="divider"></div>
        <div class="grid3">
          ${cards}
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
  const b = (await pool.query(`SELECT * FROM shippers_billing WHERE shipper_id=$1`, [req.user.id])).rows[0];

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
    plan, planDef.limit, req.user.id
  ]);

  res.redirect("/shipper/plans?switched=1");
});

app.get("/shipper/invoices", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  const user = req.user;
  const bill = (await pool.query(`SELECT * FROM shippers_billing WHERE shipper_id=$1`, [user.id])).rows[0];

  let invoices = [];
  let portalUrl = null;

  if (stripeEnabled && bill?.stripe_customer_id) {
    try {
      const inv = await stripe.invoices.list({ customer: bill.stripe_customer_id, limit: 20 });
      invoices = inv.data || [];

      const portal = await stripe.billingPortal.sessions.create({
        customer: bill.stripe_customer_id,
        return_url: `${APP_URL}/shipper/invoices`,
      });
      portalUrl = portal.url;
    } catch (e) {
      console.error("Stripe invoice list failed:", e);
    }
  }

  const body = `
    <div class="section">
      <div class="spread">
        <div>
          <h2 style="margin:0">Invoices & Receipts</h2>
          <div class="muted" style="margin-top:8px">Download invoices (PDF) and manage billing.</div>
        </div>
        ${portalUrl ? `<a class="btn btnPrimary" target="_blank" rel="noopener noreferrer" href="${escapeHtml(portalUrl)}">Open Billing Portal</a>` : ``}
      </div>

      <div class="divider"></div>

      ${!stripeEnabled ? `<div class="badge badgeWarn">${icon("tag")} Stripe is not configured.</div>` : ``}

      ${invoices.length ? invoices.map(i => `
        <div class="loadCard">
          <div class="loadTop">
            <div>
              <div class="lane">Invoice ${escapeHtml(i.number || i.id)}</div>
              <div class="muted">Status: ${escapeHtml(i.status)} • Total: ${money((i.total || 0) / 100)}</div>
            </div>
            <div style="display:flex;gap:10px;flex-wrap:wrap">
              ${i.hosted_invoice_url ? `<a class="btn btnGhost" target="_blank" rel="noopener noreferrer" href="${escapeHtml(i.hosted_invoice_url)}">Open</a>` : ``}
              ${i.invoice_pdf ? `<a class="btn btnPrimary" target="_blank" rel="noopener noreferrer" href="${escapeHtml(i.invoice_pdf)}">Download PDF</a>` : ``}
            </div>
          </div>
        </div>
      `).join("") : `<div class="muted">No invoices found yet.</div>`}
    </div>
  `;

  res.send(layout({ title: "Invoices", user, body }));
});

/* --------------------- STRIPE WEBHOOK HANDLER --------------------- */
async function stripeWebhookHandler(req, res) {
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
}

/* --------------------- STARTUP --------------------- */
initDb()
  .then(() => app.listen(PORT, "0.0.0.0", () => console.log("Server running on port", PORT, "build", BUILD_VERSION)))
  .catch((e) => { console.error("DB init failed:", e); process.exit(1); });
