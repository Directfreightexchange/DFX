const express = require("express");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;

if (!DATABASE_URL) {
  app.get("*", (_, res) => res.send("<h1>Missing DATABASE_URL</h1>"));
  app.listen(PORT, "0.0.0.0");
  return;
}
if (!JWT_SECRET) {
  app.get("*", (_, res) => res.send("<h1>Missing JWT_SECRET</h1><p>Add JWT_SECRET in Render → Environment.</p>"));
  app.listen(PORT, "0.0.0.0");
  return;
}

const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#039;");
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

function layout({ title, user, body }) {
  const rolePill = user ? `<span class="pill"><span class="dot"></span>${escapeHtml(user.role)}</span>` : "";
  const userPill = user ? `<span class="pill mono">${escapeHtml(user.email)}</span>` : "";

  return `<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${escapeHtml(title)}</title>
<style>
  :root{
    --bg:#070b14;
    --panel:#0b1426;
    --card:#0f1b33;
    --line:#233455;
    --text:#eef2ff;
    --muted:#b7c2dd;

    --blue:#60a5fa;
    --blue2:#2563eb;
    --orange:#f59e0b;
    --orange2:#fb923c;

    --ok:#22c55e;
    --warn:#fbbf24;

    --shadow: 0 18px 60px rgba(0,0,0,.40);
    --radius: 18px;
  }
  *{box-sizing:border-box}
  body{
    margin:0;
    color:var(--text);
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
    background:
      radial-gradient(950px 520px at 14% -8%, rgba(245,158,11,.24), transparent 55%),
      radial-gradient(950px 520px at 92% 0%, rgba(96,165,250,.24), transparent 55%),
      linear-gradient(180deg, rgba(37,99,235,.10), transparent 45%),
      var(--bg);
  }
  a{color:var(--blue);text-decoration:none}
  a:hover{text-decoration:underline}
  .wrap{max-width:1200px;margin:0 auto;padding:22px}

  .nav{
    display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;
    padding:14px 16px;border:1px solid var(--line);border-radius:20px;
    background:rgba(15,27,51,.72);backdrop-filter: blur(10px);
    box-shadow: var(--shadow);
    position:sticky;top:14px;z-index:20;
  }
  .brand{display:flex;align-items:center;gap:12px}
  .mark{
    width:46px;height:46px;border-radius:16px;
    border:1px solid rgba(255,255,255,.10);
    background: linear-gradient(135deg, rgba(245,158,11,.95), rgba(96,165,250,.95));
    display:grid;place-items:center;
  }
  .brand h1{font-size:16px;margin:0;letter-spacing:.2px}
  .sub{font-size:12px;color:var(--muted);margin-top:2px}
  .right{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
  .pill{
    padding:7px 10px;border-radius:999px;border:1px solid var(--line);
    background:rgba(11,20,38,.85);
    color:var(--muted);font-size:12px;display:inline-flex;gap:8px;align-items:center;
  }
  .dot{width:8px;height:8px;border-radius:999px;background:linear-gradient(135deg,var(--orange),var(--blue))}
  .mono{font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;}
  .btn{
    display:inline-flex;align-items:center;justify-content:center;gap:8px;
    padding:10px 14px;border-radius:12px;border:1px solid var(--line);
    background:rgba(11,20,38,.86);color:var(--text);cursor:pointer;
    transition: transform .08s ease, filter .12s ease;
  }
  .btn:hover{filter:brightness(1.06)}
  .btn:active{transform:translateY(1px)}
  .btn.orange{
    border:none;
    background: linear-gradient(135deg, rgba(245,158,11,.98), rgba(251,146,60,.82));
    color:#111827;font-weight:900;
    box-shadow: 0 18px 55px rgba(245,158,11,.18);
  }
  .btn.blue{
    border:none;
    background: linear-gradient(135deg, rgba(37,99,235,.98), rgba(96,165,250,.85));
    color:#0b1020;font-weight:900;
    box-shadow: 0 18px 55px rgba(96,165,250,.15);
  }

  .hero{
    margin-top:16px;
    border:1px solid var(--line);
    border-radius: var(--radius);
    background: linear-gradient(180deg, rgba(15,27,51,.78), rgba(11,20,38,.72));
    backdrop-filter: blur(10px);
    box-shadow: var(--shadow);
    padding:20px;
    overflow:hidden;
    position:relative;
  }
  .hero:before{
    content:"";
    position:absolute; inset:-2px;
    background:
      radial-gradient(520px 240px at 14% 0%, rgba(245,158,11,.22), transparent 60%),
      radial-gradient(520px 240px at 92% 0%, rgba(96,165,250,.22), transparent 60%);
    pointer-events:none;
  }
  .heroInner{position:relative}
  .title{
    font-size:44px;line-height:1.03;margin:0 0 10px 0;letter-spacing:-.4px;
  }
  .muted{color:var(--muted)}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
  .grid{display:grid;gap:16px;grid-template-columns: 1.15fr .85fr; margin-top:16px}
  @media (max-width:980px){ .grid{grid-template-columns:1fr} .nav{position:static} .title{font-size:38px} }

  .card{
    border:1px solid var(--line);
    border-radius: var(--radius);
    background:rgba(15,27,51,.72);
    backdrop-filter: blur(10px);
    box-shadow: var(--shadow);
    padding:18px;
  }
  .card.soft{background:rgba(11,20,38,.76)}
  .hr{height:1px;background:rgba(35,52,85,.9);margin:14px 0;border:0}

  .kpis{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
  .kpi{min-width:160px;padding:10px 12px;border-radius:14px;border:1px solid var(--line);background:rgba(11,20,38,.86);font-size:12px}
  .kpi b{display:block;font-size:14px;color:var(--text)}

  /* Load board + filters */
  .filters{
    display:grid; gap:10px;
    grid-template-columns: 1.2fr 1.2fr 1fr 1fr 1fr;
  }
  @media (max-width:980px){ .filters{grid-template-columns:1fr 1fr} }
  input,select,textarea{
    width:100%; padding:12px 12px; border-radius:12px; border:1px solid var(--line);
    background:rgba(11,20,38,.92); color:var(--text); outline:none;
  }
  textarea{min-height:86px;resize:vertical}
  input:focus,select:focus,textarea:focus{border-color:rgba(245,158,11,.55)}
  .small{font-size:12px}
  .badge{
    display:inline-flex;gap:8px;align-items:center;
    padding:6px 10px;border-radius:999px;border:1px solid var(--line);
    background:rgba(11,20,38,.86); color:var(--muted); font-size:12px;
  }
  .badge.ok{border-color:rgba(34,197,94,.35); background:rgba(34,197,94,.10); color:rgba(220,255,240,.92)}
  .badge.warn{border-color:rgba(251,191,36,.35); background:rgba(251,191,36,.10); color:rgba(255,250,220,.92)}
  .badge.blue{border-color:rgba(96,165,250,.35); background:rgba(96,165,250,.10); color:rgba(220,235,255,.92)}
  .badge.orange{border-color:rgba(245,158,11,.35); background:rgba(245,158,11,.10); color:rgba(255,243,220,.92)}

  .load{
    margin-top:12px;
    padding:14px;
    border-radius:16px;
    border:1px solid rgba(255,255,255,.08);
    background:rgba(11,20,38,.78);
  }
  .loadTop{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:flex-start}
  .lane{font-size:16px;font-weight:900}
  .price{font-size:18px;font-weight:1000}
  .kv{display:grid;grid-template-columns: 210px 1fr;gap:6px;margin-top:10px}
  @media (max-width:780px){ .kv{grid-template-columns:1fr} }
  .k{color:var(--muted)}
  .pillStatus{
    padding:6px 10px;border-radius:999px;border:1px solid var(--line);
    background:rgba(11,20,38,.86); color:var(--muted); font-size:12px;
  }
  .pillStatus.open{border-color:rgba(96,165,250,.35);background:rgba(96,165,250,.10);color:rgba(220,235,255,.92)}
  .pillStatus.booked{border-color:rgba(34,197,94,.35);background:rgba(34,197,94,.10);color:rgba(220,255,240,.92)}
  .pillStatus.requested{border-color:rgba(251,191,36,.35);background:rgba(251,191,36,.10);color:rgba(255,250,220,.92)}
</style>
</head>
<body>
<div class="wrap">
  <div class="nav">
    <div class="brand">
      <div class="mark" aria-hidden="true">🚚</div>
      <div>
        <h1>Direct Freight Exchange</h1>
        <div class="sub">Direct shipper ↔ carrier • Transparent loads • Orange + Blue</div>
      </div>
    </div>
    <div class="right">
      ${rolePill}${userPill}
      <a class="btn" href="/">Home</a>
      <a class="btn" href="/loads">Load Board</a>
      ${user ? `<a class="btn blue" href="/dashboard">Dashboard</a><a class="btn" href="/logout">Logout</a>`
             : `<a class="btn" href="/signup">Sign up</a><a class="btn blue" href="/login">Login</a>`}
    </div>
  </div>
  ${body}
</div>
</body>
</html>`;
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

      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

/* ---------------- Routes ---------------- */

app.get("/", (req, res) => {
  const user = getUser(req);

  const body = `
    <div class="hero">
      <div class="heroInner">
        <div class="badge orange">Full transparency by default</div>
        <h2 class="title">Connect truckers directly with shippers — no hidden load details.</h2>
        <div class="muted">
          Every load shows: <b>all-in rate</b>, miles, weight, equipment, pickup/delivery, <b>payment terms</b>,
          <b>detention</b>, appointment type, accessorials, and notes. No “call for rate.”
        </div>

        <div class="kpis">
          <div class="kpi"><b>Direct marketplace</b><span class="muted">Shipper ↔ Carrier workflow</span></div>
          <div class="kpi"><b>Transparent load cards</b><span class="muted">Rate + terms up front</span></div>
          <div class="kpi"><b>Compliance-first</b><span class="muted">Insurance • Authority • W-9 (next)</span></div>
        </div>

        <div class="row" style="margin-top:14px">
          <a class="btn orange" href="${user ? "/dashboard" : "/signup"}">${user ? "Go to Dashboard" : "Create account"}</a>
          <a class="btn blue" href="/loads">Browse Load Board</a>
          ${user ? "" : `<a class="btn" href="/login">Login</a>`}
        </div>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <h3 style="margin-top:0">For Shippers</h3>
        <div class="muted">
          Post loads with full details so carriers can commit fast.
          (Next: Stripe subscription to post + invoices/receipts.)
        </div>
        <div class="hr"></div>
        <div class="row">
          <span class="badge ok">✅ Transparent rate</span>
          <span class="badge ok">✅ Terms & QuickPay</span>
          <span class="badge ok">✅ Detention policy</span>
          <span class="badge ok">✅ Accessorials</span>
        </div>
      </div>

      <div class="card soft">
        <h3 style="margin-top:0">For Carriers</h3>
        <div class="muted">
          See the full picture up front: equipment, dates, miles, pay, and requirements.
          (Next: compliance uploads + verified badge.)
        </div>
        <div class="hr"></div>
        <div class="row">
          <span class="badge blue">🟦 No games</span>
          <span class="badge orange">🟧 No “call for rate”</span>
          <span class="badge warn">⏱ Detention clearly stated</span>
        </div>
      </div>
    </div>
  `;

  res.send(layout({ title: "DFX", user, body }));
});

app.get("/signup", (req, res) => {
  const user = getUser(req);
  const body = `
    <div class="card">
      <h2 style="margin-top:0">Create an account</h2>
      <div class="muted small">Choose Shipper or Carrier. Admin comes later.</div>
      <div class="hr"></div>
      <form method="POST" action="/signup">
        <div class="filters" style="grid-template-columns: 1.2fr 1.2fr 1fr 1fr 1fr;">
          <input name="email" type="email" placeholder="Email" required />
          <input name="password" type="password" placeholder="Password (min 8 chars)" minlength="8" required />
          <select name="role" required>
            <option value="SHIPPER">Shipper</option>
            <option value="CARRIER">Carrier</option>
          </select>
          <button class="btn orange" type="submit">Create account</button>
          <a class="btn" href="/login">Login</a>
        </div>
      </form>
    </div>
  `;
  res.send(layout({ title: "Sign up", user, body }));
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
  const body = `
    <div class="card">
      <h2 style="margin-top:0">Login</h2>
      <div class="muted small">You’ll stay logged in for 7 days.</div>
      <div class="hr"></div>
      <form method="POST" action="/login">
        <div class="filters" style="grid-template-columns: 1.2fr 1.2fr 1fr 1fr 1fr;">
          <input name="email" type="email" placeholder="Email" required />
          <input name="password" type="password" placeholder="Password" required />
          <button class="btn blue" type="submit">Login</button>
          <a class="btn" href="/signup">Create account</a>
          <a class="btn" href="/loads">Load Board</a>
        </div>
      </form>
    </div>
  `;
  res.send(layout({ title: "Login", user, body }));
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

app.get("/logout", (req, res) => {
  res.clearCookie("dfx_token");
  res.redirect("/");
});

app.get("/dashboard", requireAuth, async (req, res) => {
  const user = req.user;

  if (user.role === "SHIPPER") {
    const loads = await pool.query(
      `SELECT * FROM loads WHERE shipper_id=$1 ORDER BY created_at DESC`,
      [user.id]
    );

    const body = `
      <div class="grid">
        <div class="card">
          <div class="row" style="justify-content:space-between">
            <div>
              <h2 style="margin:0">Shipper Dashboard</h2>
              <div class="muted small">Post loads with full transparency (default fields included).</div>
            </div>
            <span class="badge warn">Stripe subscription (next)</span>
          </div>
          <div class="hr"></div>

          <form method="POST" action="/shipper/loads">
            <div class="filters">
              <input name="lane_from" placeholder="From (City, ST)" required />
              <input name="lane_to" placeholder="To (City, ST)" required />
              <input name="pickup_date" placeholder="Pickup date (YYYY-MM-DD)" required />
              <input name="delivery_date" placeholder="Delivery date (YYYY-MM-DD)" required />
              <select name="equipment" required>
                <option>Dry Van</option>
                <option>Reefer</option>
                <option>Flatbed</option>
                <option>Power Only</option>
                <option>Stepdeck</option>
              </select>

              <input name="weight_lbs" type="number" placeholder="Weight (lbs)" value="42000" required />
              <input name="miles" type="number" placeholder="Miles" value="800" required />
              <input name="commodity" placeholder="Commodity" value="General Freight" required />
              <input name="rate_all_in" type="number" step="0.01" placeholder="All-in rate ($)" value="2500" required />
              <select name="payment_terms" required>
                <option value="NET 30">NET 30 (default)</option>
                <option value="NET 15">NET 15</option>
                <option value="NET 45">NET 45</option>
                <option value="QuickPay">QuickPay</option>
              </select>

              <select name="quickpay_available" required>
                <option value="false">QuickPay Available? No (default)</option>
                <option value="true">QuickPay Available? Yes</option>
              </select>

              <input name="detention_rate_per_hr" type="number" step="0.01" placeholder="Detention $/hr" value="75" required />
              <input name="detention_after_hours" type="number" placeholder="Detention after (hours)" value="2" required />
              <select name="appointment_type" required>
                <option value="FCFS">Appointment: FCFS (default)</option>
                <option value="Appt Required">Appointment: Appt Required</option>
              </select>
              <input name="accessorials" placeholder="Accessorials (e.g., lumper, tarp, stop-off)" value="None" required />
              <input name="special_requirements" placeholder="Notes (PPE, gate code, trailer size, etc.)" value="None" required />
            </div>

            <div class="row" style="margin-top:12px">
              <button class="btn orange" type="submit">Post Load</button>
              <a class="btn blue" href="/loads">View Load Board</a>
              <span class="badge ok">Transparency checklist enforced</span>
            </div>
          </form>
        </div>

        <div class="card soft">
          <div class="row" style="justify-content:space-between">
            <h3 style="margin:0">Your Loads</h3>
            <span class="badge blue">${loads.rows.length} total</span>
          </div>
          <div class="hr"></div>
          ${loads.rows.length ? loads.rows.map(l => loadCard(l)).join("") : `<div class="muted">No loads yet.</div>`}
        </div>
      </div>
    `;

    return res.send(layout({ title: "Shipper Dashboard", user, body }));
  }

  if (user.role === "CARRIER") {
    const loads = await pool.query(`SELECT * FROM loads ORDER BY created_at DESC LIMIT 100`);
    const body = `
      <div class="card">
        <div class="row" style="justify-content:space-between">
          <div>
            <h2 style="margin:0">Carrier Dashboard</h2>
            <div class="muted small">Browse fully transparent loads. (Request-to-book is next.)</div>
          </div>
          <span class="badge warn">Compliance badge (next)</span>
        </div>
        <div class="hr"></div>
        <div class="row">
          <a class="btn blue" href="/loads">Open Load Board</a>
          <span class="badge ok">Rate + terms visible</span>
          <span class="badge ok">Detention visible</span>
          <span class="badge ok">Accessorials visible</span>
        </div>
      </div>

      <div class="card soft" style="margin-top:16px">
        <div class="row" style="justify-content:space-between">
          <h3 style="margin:0">Latest Loads</h3>
          <span class="badge blue">${loads.rows.length} shown</span>
        </div>
        <div class="hr"></div>
        ${loads.rows.length ? loads.rows.map(l => loadCard(l, true)).join("") : `<div class="muted">No loads posted yet.</div>`}
      </div>
    `;
    return res.send(layout({ title: "Carrier Dashboard", user, body }));
  }

  return res.send(layout({
    title: "Admin",
    user,
    body: `<div class="card"><h2 style="margin-top:0">Admin</h2><div class="muted">Next: approve/reject carrier compliance docs + enforce badges.</div></div>`
  }));
});

app.post("/shipper/loads", requireAuth, async (req, res) => {
  if (req.user.role !== "SHIPPER") return res.sendStatus(403);

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

  if (!lane_from || !lane_to || !pickup_date || !delivery_date || !equipment || !commodity) {
    return res.status(400).send("Missing required fields.");
  }
  if (![weight_lbs, miles, detention_after_hours].every(n => Number.isFinite(n) && n > 0)) {
    return res.status(400).send("Numeric fields invalid.");
  }
  if (![rate_all_in, detention_rate_per_hr].every(n => Number.isFinite(n) && n >= 0)) {
    return res.status(400).send("Rate/detention invalid.");
  }

  await pool.query(
    `INSERT INTO loads
      (shipper_id,lane_from,lane_to,pickup_date,delivery_date,equipment,weight_lbs,commodity,miles,
       rate_all_in,payment_terms,quickpay_available,detention_rate_per_hr,detention_after_hours,
       appointment_type,accessorials,special_requirements,status)
     VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8,$9,
       $10,$11,$12,$13,$14,$15,$16,$17,'OPEN')`,
    [
      req.user.id, lane_from, lane_to, pickup_date, delivery_date, equipment, weight_lbs, commodity, miles,
      rate_all_in, payment_terms, quickpay_available, detention_rate_per_hr, detention_after_hours,
      appointment_type, accessorials, special_requirements
    ]
  );

  res.redirect("/dashboard");
});

app.get("/loads", async (req, res) => {
  const user = getUser(req);

  // Filters (query params)
  const q = String(req.query.q || "").trim().toLowerCase();
  const equipment = String(req.query.equipment || "").trim();
  const minRate = Number(req.query.minRate);
  const maxMiles = Number(req.query.maxMiles);
  const sort = String(req.query.sort || "new").trim(); // new | rate | rpm

  // Get loads (limit)
  const r = await pool.query(`SELECT * FROM loads ORDER BY created_at DESC LIMIT 200`);
  let loads = r.rows;

  // Apply filters in memory (simple + reliable for now)
  if (q) {
    loads = loads.filter(l =>
      `${l.lane_from} ${l.lane_to} ${l.commodity}`.toLowerCase().includes(q)
    );
  }
  if (equipment) {
    loads = loads.filter(l => String(l.equipment) === equipment);
  }
  if (Number.isFinite(minRate)) {
    loads = loads.filter(l => Number(l.rate_all_in) >= minRate);
  }
  if (Number.isFinite(maxMiles)) {
    loads = loads.filter(l => Number(l.miles) <= maxMiles);
  }

  // Sorting
  if (sort === "rate") {
    loads.sort((a, b) => Number(b.rate_all_in) - Number(a.rate_all_in));
  } else if (sort === "rpm") {
    loads.sort((a, b) => (Number(b.rate_all_in) / Math.max(1, Number(b.miles))) - (Number(a.rate_all_in) / Math.max(1, Number(a.miles))));
  } // "new" stays as-is

  const uniqueEquip = Array.from(new Set(r.rows.map(x => x.equipment))).filter(Boolean).sort();

  const body = `
    <div class="card">
      <div class="row" style="justify-content:space-between">
        <div>
          <h2 style="margin:0">Load Board</h2>
          <div class="muted small">Full transparency: rate + terms + detention + accessorials on every load.</div>
        </div>
        <span class="badge ok">${loads.length} matches</span>
      </div>
      <div class="hr"></div>

      <form method="GET" action="/loads">
        <div class="filters">
          <input name="q" placeholder="Search lane/commodity (e.g., Chicago, Dallas, steel)" value="${escapeHtml(req.query.q || "")}" />
          <select name="equipment">
            <option value="">All equipment</option>
            ${uniqueEquip.map(e => `<option ${e === equipment ? "selected" : ""}>${escapeHtml(e)}</option>`).join("")}
          </select>
          <input name="minRate" type="number" step="0.01" placeholder="Min all-in rate ($)" value="${escapeHtml(req.query.minRate || "")}" />
          <input name="maxMiles" type="number" placeholder="Max miles" value="${escapeHtml(req.query.maxMiles || "")}" />
          <select name="sort">
            <option value="new" ${sort === "new" ? "selected" : ""}>Sort: Newest</option>
            <option value="rate" ${sort === "rate" ? "selected" : ""}>Sort: Highest rate</option>
            <option value="rpm" ${sort === "rpm" ? "selected" : ""}>Sort: Best $/mile</option>
          </select>
        </div>
        <div class="row" style="margin-top:12px">
          <button class="btn blue" type="submit">Apply Filters</button>
          <a class="btn" href="/loads">Clear</a>
          ${user ? `<a class="btn orange" href="/dashboard">Dashboard</a>` : `<a class="btn orange" href="/signup">Create account</a>`}
          <span class="badge orange">No “call for rate”</span>
        </div>
      </form>
    </div>

    <div class="card soft" style="margin-top:16px">
      <div class="row" style="justify-content:space-between">
        <h3 style="margin:0">Loads</h3>
        <span class="badge blue">Showing up to 200</span>
      </div>
      <div class="hr"></div>
      ${loads.length ? loads.map(l => loadCard(l, user?.role === "CARRIER")).join("") : `<div class="muted">No loads match your filters.</div>`}
    </div>
  `;

  res.send(layout({ title: "Load Board", user, body }));
});

/* UI helper: load card */
function loadCard(l, showCarrierHint = false) {
  const rpm = Number(l.rate_all_in) / Math.max(1, Number(l.miles));
  const status = String(l.status || "OPEN");
  const statusClass = status === "BOOKED" ? "booked" : status === "REQUESTED" ? "requested" : "open";

  const transparencyBadges = `
    <span class="badge ok">Rate: ${money(l.rate_all_in)} all-in</span>
    <span class="badge ok">Terms: ${escapeHtml(l.payment_terms)}${l.quickpay_available ? " • QuickPay" : ""}</span>
    <span class="badge ok">Detention: ${money(l.detention_rate_per_hr)}/hr after ${escapeHtml(l.detention_after_hours)}h</span>
    <span class="badge ok">Accessorials: ${escapeHtml(l.accessorials)}</span>
  `;

  return `
    <div class="load">
      <div class="loadTop">
        <div>
          <div class="lane">#${l.id} ${escapeHtml(l.lane_from)} → ${escapeHtml(l.lane_to)}</div>
          <div class="muted small">${escapeHtml(l.pickup_date)} → ${escapeHtml(l.delivery_date)} • ${escapeHtml(l.equipment)}</div>
        </div>
        <div style="text-align:right">
          <div class="price">${money(l.rate_all_in)} <span class="muted small">(all-in)</span></div>
          <div class="muted small">${int(l.miles).toLocaleString()} mi • <b>${money(rpm)}</b>/mi</div>
          <div style="margin-top:6px"><span class="pillStatus ${statusClass}">${escapeHtml(status)}</span></div>
        </div>
      </div>

      <div class="row" style="margin-top:10px">${transparencyBadges}</div>

      <div class="kv">
        <div class="k">Weight / Commodity</div><div>${int(l.weight_lbs).toLocaleString()} lbs • ${escapeHtml(l.commodity)}</div>
        <div class="k">Appointment</div><div>${escapeHtml(l.appointment_type)}</div>
        <div class="k">Notes</div><div>${escapeHtml(l.special_requirements)}</div>
      </div>

      ${showCarrierHint ? `
        <div class="row" style="margin-top:12px">
          <button class="btn orange" disabled title="Next feature">Request to Book (next)</button>
          <span class="badge warn">Direct booking workflow is next</span>
        </div>` : ``}
    </div>
  `;
}

/* Health */
app.get("/health", (_, res) => res.json({ ok: true }));

initDb()
  .then(() => app.listen(PORT, "0.0.0.0", () => console.log("Server running on port", PORT)))
  .catch((e) => { console.error("DB init failed:", e); process.exit(1); });
