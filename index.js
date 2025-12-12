const express = require("express");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const multer = require("multer");
const Stripe = require("stripe");

const app = express();

// Stripe webhook needs raw body only on this route:
app.post("/stripe/webhook", express.raw({ type: "application/json" }));

app.use(express.urlencoded({ extended: true }));
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
  app.get("*", (_, res) => res.send(`<h1>Config error</h1><p>${msg}</p>`));
  app.listen(PORT, "0.0.0.0");
}

const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
});

const PLANS = {
  STARTER: { label: "Starter", price: 99, limit: 15, priceIdEnv: "STRIPE_PRICE_STARTER" },
  GROWTH: { label: "Growth", price: 199, limit: 30, priceIdEnv: "STRIPE_PRICE_GROWTH" },
  ENTERPRISE: { label: "Enterprise", price: 399, limit: -1, priceIdEnv: "STRIPE_PRICE_ENTERPRISE" }, // unlimited
};

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

function layout({ title, user, body }) {
  return `<!doctype html>
<html><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${escapeHtml(title)}</title>
<style>
:root{--bg:#070b14;--line:#233455;--text:#eef2ff;--muted:#b7c2dd;--blue:#60a5fa;--orange:#f59e0b;--ok:#22c55e;--warn:#fbbf24;--shadow:0 18px 60px rgba(0,0,0,.40)}
*{box-sizing:border-box}
body{margin:0;color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;
background:radial-gradient(950px 520px at 14% -8%, rgba(245,158,11,.24), transparent 55%),
radial-gradient(950px 520px at 92% 0%, rgba(96,165,250,.24), transparent 55%), var(--bg)}
.wrap{max-width:1200px;margin:0 auto;padding:22px}
a{color:var(--blue);text-decoration:none} a:hover{text-decoration:underline}
.nav{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:center;
padding:14px 16px;border:1px solid var(--line);border-radius:20px;background:rgba(15,27,51,.72);
backdrop-filter: blur(10px);box-shadow:var(--shadow)}
.brand{display:flex;gap:12px;align-items:center}
.mark{width:46px;height:46px;border-radius:16px;border:1px solid rgba(255,255,255,.10);
background:linear-gradient(135deg, rgba(245,158,11,.95), rgba(96,165,250,.95));display:grid;place-items:center}
.sub{color:var(--muted);font-size:12px}
.right{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.pill{padding:7px 10px;border-radius:999px;border:1px solid var(--line);background:rgba(11,20,38,.85);color:var(--muted);font-size:12px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:10px 14px;border-radius:12px;border:1px solid var(--line);
background:rgba(11,20,38,.86);color:var(--text);cursor:pointer}
.btn.orange{border:none;background:linear-gradient(135deg, rgba(245,158,11,.98), rgba(251,146,60,.82));color:#111827;font-weight:900}
.btn.blue{border:none;background:linear-gradient(135deg, rgba(37,99,235,.98), rgba(96,165,250,.85));color:#0b1020;font-weight:900}
.card{margin-top:16px;border:1px solid var(--line);border-radius:18px;background:rgba(15,27,51,.72);
backdrop-filter: blur(10px);box-shadow:var(--shadow);padding:18px}
.grid{display:grid;gap:16px;grid-template-columns:1.1fr .9fr;margin-top:16px}
@media(max-width:980px){.grid{grid-template-columns:1fr}}
.muted{color:var(--muted)}
.hr{height:1px;background:rgba(35,52,85,.9);margin:14px 0;border:0}
input,select,textarea{width:100%;padding:12px;border-radius:12px;border:1px solid var(--line);background:rgba(11,20,38,.92);color:var(--text);outline:none}
.filters{display:grid;gap:10px;grid-template-columns:1.2fr 1.2fr 1fr 1fr 1fr}
@media(max-width:980px){.filters{grid-template-columns:1fr 1fr}}
.badge{display:inline-flex;gap:8px;align-items:center;padding:6px 10px;border-radius:999px;border:1px solid var(--line);
background:rgba(11,20,38,.86);color:var(--muted);font-size:12px}
.badge.ok{border-color:rgba(34,197,94,.35);background:rgba(34,197,94,.10);color:rgba(220,255,240,.92)}
.badge.warn{border-color:rgba(251,191,36,.35);background:rgba(251,191,36,.10);color:rgba(255,250,220,.92)}
.badge.orange{border-color:rgba(245,158,11,.35);background:rgba(245,158,11,.10);color:rgba(255,243,220,.92)}
.load{margin-top:12px;padding:14px;border-radius:16px;border:1px solid rgba(255,255,255,.08);background:rgba(11,20,38,.78)}
.loadTop{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
.lane{font-weight:900}
.kv{display:grid;grid-template-columns:210px 1fr;gap:6px;margin-top:10px}
@media(max-width:780px){.kv{grid-template-columns:1fr}}
.k{color:var(--muted)}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
</style>
</head>
<body><div class="wrap">
<div class="nav">
  <div class="brand">
    <div class="mark">🚚</div>
    <div>
      <div style="font-weight:900">Direct Freight Exchange</div>
      <div class="sub">Direct shipper ↔ carrier • Full transparency loads • Carriers free</div>
    </div>
  </div>
  <div class="right">
    <a class="btn" href="/">Home</a>
    <a class="btn" href="/loads">Load Board</a>
    ${user
      ? `<span class="pill">${escapeHtml(user.role)}</span><span class="pill">${escapeHtml(user.email)}</span>
         <a class="btn blue" href="/dashboard">Dashboard</a><a class="btn" href="/logout">Logout</a>`
      : `<a class="btn" href="/signup">Sign up</a><a class="btn blue" href="/login">Login</a>`}
  </div>
</div>
${body}
</div></body></html>`;
}

/* ---------- DB ---------- */
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
  `);
}

/* ---------- Stripe helpers ---------- */
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

  // Keep usage month consistent and reset if needed
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

/* ---------- Stripe routes ---------- */
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
      <div class="muted">Posting is available only while your subscription is ACTIVE.</div>
      <div class="hr"></div>

      <div class="row">
        <span class="badge ${status === "ACTIVE" ? "ok" : "warn"}">Status: ${escapeHtml(status)}</span>
        <span class="badge">Plan: ${escapeHtml(plan || "None")}</span>
        <span class="badge">Month: ${escapeHtml(usageMonth)}</span>
        <span class="badge orange">${escapeHtml(usageText)}</span>
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
                      <button class="btn orange" type="submit">${status === "ACTIVE" ? "Switch immediately" : "Subscribe"}</button>
                    </form>
                  `}
              </div>
            `;
          }).join("")}
        </div>

        <div class="hr"></div>
        <div class="muted">
          Immediate switching uses Stripe proration (you may be charged/credited immediately depending on timing).
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

  // If no active subscription, start checkout
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

  // Otherwise: immediate plan switch (prorated)
  const sub = await stripe.subscriptions.retrieve(b.stripe_subscription_id);

  const item = sub.items?.data?.[0];
  if (!item) return res.status(400).send("Subscription item not found.");

  await stripe.subscriptions.update(b.stripe_subscription_id, {
    items: [{ id: item.id, price: targetPriceId }],
    proration_behavior: "create_prorations",
  });

  // DB will update via webhook; but we can optimistically update plan/limit to reflect UI fast
  const planDef = PLANS[plan];
  await pool.query(
    `UPDATE shippers_billing SET plan=$1, monthly_limit=$2, updated_at=NOW() WHERE shipper_id=$3`,
    [plan, planDef.limit, req.user.id]
  );

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
    // On checkout success, mark shipper active + plan
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

    // Keep billing in sync whenever subscription changes
    if (
      event.type === "customer.subscription.created" ||
      event.type === "customer.subscription.updated" ||
      event.type === "customer.subscription.deleted"
    ) {
      const sub = event.data.object;
      const subscriptionId = sub.id;
      const customerId = sub.customer;
      const priceId = sub.items?.data?.[0]?.price?.id;

      // Map by subscription id → shipper
      const row = await pool.query(
        `SELECT shipper_id FROM shippers_billing WHERE stripe_subscription_id=$1`,
        [subscriptionId]
      );
      const shipperId = row.rows[0]?.shipper_id;

      // If we can't find by subscription id (rare), try by customer id
      const shipperId2 = shipperId
        ? shipperId
        : (await pool.query(`SELECT shipper_id FROM shippers_billing WHERE stripe_customer_id=$1`, [customerId])).rows[0]
            ?.shipper_id;

      if (shipperId2) {
        await upsertBillingFromSubscription({
          shipperId: shipperId2,
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

/* ---------- Auth ---------- */
app.get("/signup", (req, res) => {
  const user = getUser(req);
  res.send(layout({
    title: "Sign up",
    user,
    body: `<div class="card">
      <h2 style="margin-top:0">Sign up</h2>
      <form method="POST" action="/signup">
        <div class="filters" style="grid-template-columns:1.2fr 1.2fr 1fr 1fr 1fr">
          <input name="email" type="email" placeholder="Email" required />
          <input name="password" type="password" placeholder="Password (min 8 chars)" minlength="8" required />
          <select name="role" required>
            <option value="SHIPPER">Shipper</option>
            <option value="CARRIER">Carrier (free)</option>
          </select>
          <button class="btn orange" type="submit">Create</button>
          <a class="btn" href="/login">Login</a>
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
      await pool.query(`INSERT INTO carriers_compliance (carrier_id,status) VALUES ($1,'PENDING') ON CONFLICT DO NOTHING`, [r.rows[0].id]);
    }

    signIn(res, r.rows[0]);
    res.redirect("/dashboard");
  } catch (e) {
    if (String(e).includes("duplicate")) return res.status(409).send("Email already exists. Go to /login.");
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
          <button class="btn blue" type="submit">Login</button>
          <a class="btn" href="/signup">Create</a>
          <a class="btn" href="/loads">Load Board</a>
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
  res.send(layout({
    title: "DFX",
    user,
    body: `<div class="card">
      <span class="badge orange">Default: Fully transparent loads</span>
      <h2 style="margin:10px 0 6px 0">Connect carriers directly with shippers — no hidden load details.</h2>
      <div class="muted">All-in rate • terms • detention • accessorials • notes. Carriers are free. Shippers subscribe to post.</div>
      <div class="hr"></div>
      <div class="row">
        <a class="btn orange" href="${user ? "/dashboard" : "/signup"}">${user ? "Dashboard" : "Create account"}</a>
        <a class="btn blue" href="/loads">Browse Load Board</a>
        ${user?.role === "SHIPPER" ? `<a class="btn" href="/shipper/plans">Plans</a>` : ``}
      </div>
    </div>`
  }));
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
    const r2 = await pool.query(`SELECT * FROM shippers_billing WHERE shipper_id=$1`, [shipperId]);
    b = r2.rows[0];
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
  if (!stripeEnabled) {
    // If Stripe not configured, allow posting so you can keep testing
    return { ok: true, reason: null };
  }
  if (billing.status !== "ACTIVE") return { ok: false, reason: "Subscription required (not ACTIVE)." };
  if (billing.monthly_limit === -1) return { ok: true, reason: null }; // unlimited
  if (billing.loads_used >= billing.monthly_limit) return { ok: false, reason: "Monthly posting limit reached." };
  return { ok: true, reason: null };
}

/* ---------- Dashboards ---------- */
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

    res.send(layout({
      title: "Shipper Dashboard",
      user,
      body: `<div class="grid">
        <div class="card">
          <div class="row" style="justify-content:space-between">
            <div>
              <h2 style="margin:0">Shipper Dashboard</h2>
              <div class="muted">Plans: Starter (15) • Growth (30) • Enterprise (Unlimited)</div>
            </div>
            <span class="badge ${billing.status === "ACTIVE" ? "ok" : "warn"}">Billing: ${escapeHtml(billing.status)}</span>
          </div>

          <div class="hr"></div>

          <div class="row">
            <span class="badge">Plan: ${escapeHtml(planLabel)}</span>
            <span class="badge orange">${escapeHtml(limitText)}</span>
            <a class="btn blue" href="/shipper/plans">Manage Plan</a>
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
              <button class="btn orange" type="submit">Post Load</button>
              <a class="btn blue" href="/loads">View Load Board</a>
            </div>
          </form>
          ` : `
            <div class="badge warn">Posting blocked: ${escapeHtml(gate.reason)}</div>
            <div class="row" style="margin-top:10px">
              <a class="btn orange" href="/shipper/plans">Upgrade / Subscribe</a>
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
                  <form method="POST" action="/shipper/requests/${r.request_id}/accept"><button class="btn orange" type="submit">Accept</button></form>
                  <form method="POST" action="/shipper/requests/${r.request_id}/decline"><button class="btn" type="submit">Decline</button></form>
                </div>` : ``}
            </div>
          `).join("") : `<div class="muted">No requests yet.</div>`}
        </div>
      </div>

      <div class="card">
        <h3 style="margin-top:0">Your Loads</h3>
        <div class="hr"></div>
        ${myLoads.rows.length ? myLoads.rows.map(l => loadCard(l, user)).join("") : `<div class="muted">No loads yet.</div>`}
      </div>`
    }));
    return;
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
      LIMIT 200
    `, [user.id]);

    const loads = await pool.query(`SELECT * FROM loads ORDER BY created_at DESC LIMIT 200`);

    res.send(layout({
      title: "Carrier Dashboard",
      user,
      body: `<div class="grid">
        <div class="card">
          <div class="row" style="justify-content:space-between">
            <div>
              <h2 style="margin:0">Carrier Dashboard</h2>
              <div class="muted">Upload compliance docs to earn Verified badge.</div>
            </div>
            <span class="badge ${c.status === "APPROVED" ? "ok" : "warn"}">Compliance: ${escapeHtml(c.status)}</span>
          </div>

          <div class="hr"></div>

          <form method="POST" action="/carrier/compliance" enctype="multipart/form-data">
            <div class="filters" style="grid-template-columns:1.2fr 1.2fr 1fr 1fr 1fr">
              <input name="insurance_expires" placeholder="Insurance expires (YYYY-MM-DD)" value="${escapeHtml(c.insurance_expires || "")}" required />
              <input type="file" name="insurance" accept="application/pdf,image/*" required />
              <input type="file" name="authority" accept="application/pdf,image/*" required />
              <input type="file" name="w9" accept="application/pdf,image/*" required />
              <button class="btn orange" type="submit">Upload Docs</button>
            </div>
            <div class="muted" style="margin-top:10px">Next upgrade: store docs safely on S3 (recommended for production).</div>
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
        <h3 style="margin-top:0">Load Board</h3>
        <div class="muted">Request a load → shipper accepts/declines → booked.</div>
        <div class="hr"></div>
        ${loads.rows.length ? loads.rows.map(l => loadCard(l, user, c.status)).join("") : `<div class="muted">No loads yet.</div>`}
      </div>`
    }));
    return;
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

  res.send(layout({
    title: "Admin",
    user,
    body: `<div class="card">
      <h2 style="margin-top:0">Admin — Compliance Approvals</h2>
      <div class="muted">Approve carriers to display Verified badge + enable booking requests.</div>
      <div class="hr"></div>
      ${pending.rows.length ? pending.rows.map(p => `
        <div class="load">
          <div class="row" style="justify-content:space-between">
            <div><b>${escapeHtml(p.email)}</b> • Insurance exp: ${escapeHtml(p.insurance_expires || "—")}</div>
            <span class="badge warn">PENDING</span>
          </div>
          <div class="muted">Files: ${escapeHtml(p.insurance_filename||"—")}, ${escapeHtml(p.authority_filename||"—")}, ${escapeHtml(p.w9_filename||"—")}</div>
          <div class="row" style="margin-top:10px">
            <form method="POST" action="/admin/carriers/${p.carrier_id}/approve"><button class="btn orange" type="submit">Approve</button></form>
            <form method="POST" action="/admin/carriers/${p.carrier_id}/reject"><button class="btn" type="submit">Reject</button></form>
          </div>
        </div>
      `).join("") : `<div class="muted">No pending carriers.</div>`}
    </div>`
  }));
});

/* ---------- Shipper actions ---------- */
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

  // Increment usage only if not unlimited
  if (billing.monthly_limit !== -1) {
    await pool.query(
      `UPDATE shippers_billing SET loads_used = loads_used + 1, updated_at=NOW() WHERE shipper_id=$1`,
      [req.user.id]
    );
  }

  res.redirect("/dashboard");
});

app.post("/shipper/requests/:id/accept", requireAuth, requireRole("SHIPPER"), async (req, res) => {
  const requestId = Number(req.params.id);
  const r = await pool.query(`
    SELECT lr.*, l.shipper_id, l.status as load_status
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

/* ---------- Carrier actions ---------- */
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

/* ---------- Admin compliance ---------- */
app.post("/admin/carriers/:id/approve", requireAuth, requireRole("ADMIN"), async (req, res) => {
  const carrierId = Number(req.params.id);
  await pool.query(`UPDATE carriers_compliance SET status='APPROVED', updated_at=NOW(), admin_note=NULL WHERE carrier_id=$1`, [carrierId]);
  res.redirect("/dashboard");
});
app.post("/admin/carriers/:id/reject", requireAuth, requireRole("ADMIN"), async (req, res) => {
  const carrierId = Number(req.params.id);
  await pool.query(`UPDATE carriers_compliance SET status='REJECTED', updated_at=NOW(), admin_note='Rejected', updated_at=NOW() WHERE carrier_id=$1`, [carrierId]);
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

  res.send(layout({
    title: "Load Board",
    user,
    body: `<div class="card">
      <div class="row" style="justify-content:space-between">
        <div>
          <h2 style="margin:0">Load Board</h2>
          <div class="muted">Transparent loads: rate + terms + detention + accessorials shown.</div>
        </div>
        ${user?.role === "CARRIER"
          ? `<span class="badge ${carrierBadge === "APPROVED" ? "ok" : "warn"}">Carrier status: ${escapeHtml(carrierBadge)}</span>`
          : user?.role === "SHIPPER"
            ? `<a class="btn blue" href="/shipper/plans">Plans</a>`
            : ``}
      </div>
      <div class="hr"></div>
      ${r.rows.length ? r.rows.map(l => loadCard(l, user, carrierBadge)).join("") : `<div class="muted">No loads posted yet.</div>`}
    </div>`
  }));
});

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
          <div style="margin-top:6px"><span class="badge ${status==="BOOKED"?"ok":status==="REQUESTED"?"warn":"orange"}">${escapeHtml(status)}</span></div>
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
              ? `<form method="POST" action="/carrier/loads/${l.id}/request"><button class="btn orange" type="submit">Request to Book</button></form>`
              : `<span class="badge warn">Upload docs + get approved to request loads</span>`
          }
        </div>
      ` : ``}
    </div>
  `;
}

/* ---------- Health ---------- */
app.get("/health", (_, res) => res.json({ ok: true, stripeEnabled }));

initDb()
  .then(() => app.listen(PORT, "0.0.0.0", () => console.log("Server running on port", PORT)))
  .catch((e) => { console.error("DB init failed:", e); process.exit(1); });
