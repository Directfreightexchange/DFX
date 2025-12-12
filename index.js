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
  app.get("*", (req, res) => res.send("<h1>Missing DATABASE_URL</h1>"));
  app.listen(PORT, "0.0.0.0");
  return;
}
if (!JWT_SECRET) {
  app.get("*", (req, res) => res.send("<h1>Missing JWT_SECRET</h1><p>Add JWT_SECRET in Render → Environment.</p>"));
  app.listen(PORT, "0.0.0.0");
  return;
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

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

function layout(title, user, body) {
  return `<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${escapeHtml(title)}</title>
<style>
  :root{
    --bg:#070b14; --card:#0e1a2f; --card2:#0a1426; --line:#233455;
    --text:#eef2ff; --muted:#b7c2dd;
    --blue:#60a5fa; --blue2:#2563eb; --orange:#f59e0b; --orange2:#fb923c;
    --shadow: 0 18px 50px rgba(0,0,0,.38);
  }
  *{box-sizing:border-box}
  body{margin:0;color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;
    background:
      radial-gradient(900px 520px at 15% -10%, rgba(245,158,11,.22), transparent 55%),
      radial-gradient(900px 520px at 90% 0%, rgba(96,165,250,.22), transparent 55%),
      var(--bg);
  }
  a{color:var(--blue);text-decoration:none}
  a:hover{text-decoration:underline}
  .wrap{max-width:1180px;margin:0 auto;padding:22px}
  .nav{
    display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;
    padding:14px 16px;border:1px solid var(--line);border-radius:18px;
    background:rgba(14,26,47,.72);backdrop-filter: blur(10px);box-shadow: var(--shadow);
  }
  .brand{display:flex;align-items:center;gap:12px}
  .mark{width:44px;height:44px;border-radius:14px;border:1px solid rgba(255,255,255,.10);
    background: linear-gradient(135deg, rgba(245,158,11,.95), rgba(96,165,250,.95));
    display:grid;place-items:center;
  }
  .brand h1{font-size:16px;margin:0}
  .sub{font-size:12px;color:var(--muted);margin-top:2px}
  .right{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
  .pill{padding:7px 10px;border-radius:999px;border:1px solid var(--line);background:rgba(10,20,38,.80);color:var(--muted);font-size:12px}
  .btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:10px 14px;border-radius:12px;
    border:1px solid var(--line);background:rgba(10,20,38,.85);color:var(--text);cursor:pointer}
  .btn.primary{border:none;background: linear-gradient(135deg, rgba(245,158,11,.98), rgba(251,146,60,.82));color:#111827;font-weight:800}
  .btn.blue{border:none;background: linear-gradient(135deg, rgba(37,99,235,.98), rgba(96,165,250,.85));color:#0b1020;font-weight:800}
  .grid{display:grid;gap:16px;grid-template-columns:1.1fr .9fr;margin-top:16px}
  @media (max-width:980px){.grid{grid-template-columns:1fr}}
  .card{border:1px solid var(--line);border-radius:18px;background:rgba(14,26,47,.72);backdrop-filter: blur(10px);padding:18px;box-shadow: var(--shadow)}
  .card.soft{background:rgba(10,20,38,.76)}
  .muted{color:var(--muted)}
  .hr{height:1px;background:rgba(35,52,85,.9);margin:14px 0;border:0}
  input,select,textarea{
    width:100%; padding:12px 12px;border-radius:12px;border:1px solid var(--line);
    background:rgba(10,20,38,.92);color:var(--text);outline:none;
  }
  textarea{min-height:86px;resize:vertical}
  .formGrid{display:grid;gap:10px;grid-template-columns:1fr 1fr}
  @media (max-width:780px){.formGrid{grid-template-columns:1fr}}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
  .load{padding:14px;border-radius:16px;border:1px solid rgba(255,255,255,.08);background:rgba(10,20,38,.75);margin-top:10px}
  .load h3{margin:0 0 8px 0}
  .kv{display:grid;grid-template-columns:200px 1fr;gap:6px;max-width:900px}
  @media (max-width:780px){.kv{grid-template-columns:1fr}}
  .k{color:var(--muted)}
</style>
</head>
<body>
<div class="wrap">
  <div class="nav">
    <div class="brand">
      <div class="mark" aria-hidden="true">🚚</div>
      <div>
        <h1>Direct Freight Exchange</h1>
        <div class="sub">Orange + Blue • Direct shipper ↔ carrier • Fully transparent loads</div>
      </div>
    </div>
    <div class="right">
      <a class="btn" href="/">Home</a>
      ${user ? `<span class="pill">${escapeHtml(user.role)}</span><span class="pill">${escapeHtml(user.email)}</span><a class="btn" href="/dashboard">Dashboard</a><a class="btn" href="/logout">Logout</a>`
             : `<a class="btn" href="/signup">Sign up</a><a class="btn blue" href="/login">Login</a>`}
    </div>
  </div>
  ${body}
</div>
</body>
</html>`;
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

      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

app.get("/", (req, res) => {
  const user = getUser(req);
  const body = `
    <div class="grid">
      <div class="card">
        <h2 style="margin:0 0 10px 0; font-size:38px; line-height:1.05">Direct shipper ↔ carrier matching with full load transparency.</h2>
        <div class="muted">
          Every load shows the details upfront: <b>all-in rate, miles, weight, equipment, pickup/delivery, payment terms, detention, accessorials</b>.
        </div>
        <div class="hr"></div>
        <div class="row">
          <a class="btn primary" href="/signup">Create account</a>
          <a class="btn blue" href="/login">Login</a>
          <a class="btn" href="/loads">View Load Board</a>
          ${user ? `<a class="btn" href="/dashboard">Go to Dashboard</a>` : ``}
        </div>
      </div>

      <div class="card soft">
        <h3 style="margin-top:0">Transparent default fields</h3>
        <div class="muted">
          Rate (all-in), Payment terms (NET 30 default), QuickPay flag, Detention ($/hr + after X hrs),
          Appointment type (FCFS / Appt), Accessorials, Special requirements.
        </div>
      </div>
    </div>
  `;
  res.send(layout("DFX", user, body));
});

app.get("/signup", (req, res) => {
  const user = getUser(req);
  const body = `
    <div class="card">
      <h2 style="margin-top:0">Sign up</h2>
      <form method="POST" action="/signup">
        <div class="formGrid">
          <input name="email" type="email" placeholder="Email" required />
          <input name="password" type="password" placeholder="Password (min 8 chars)" required minlength="8" />
          <select name="role" required>
            <option value="SHIPPER">Shipper</option>
            <option value="CARRIER">Carrier</option>
          </select>
          <button class="btn primary" type="submit">Create account</button>
        </div>
      </form>
    </div>
  `;
  res.send(layout("Sign up", user, body));
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
      <form method="POST" action="/login">
        <div class="formGrid">
          <input name="email" type="email" placeholder="Email" required />
          <input name="password" type="password" placeholder="Password" required />
          <button class="btn blue" type="submit">Login</button>
          <a class="btn" href="/signup">Create account</a>
        </div>
      </form>
    </div>
  `;
  res.send(layout("Login", user, body));
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
      "SELECT id,lane_from,lane_to,pickup_date,delivery_date,rate_all_in,miles,equipment,weight_lbs,commodity,payment_terms,quickpay_available,detention_rate_per_hr,detention_after_hours,appointment_type,accessorials,special_requirements,created_at FROM loads WHERE shipper_id=$1 ORDER BY created_at DESC",
      [user.id]
    );

    const body = `
      <div class="grid">
        <div class="card">
          <h2 style="margin-top:0">Shipper Dashboard</h2>
          <div class="muted">Post a fully transparent load (default settings included).</div>
          <div class="hr"></div>

          <form method="POST" action="/shipper/loads">
            <div class="formGrid">
              <input name="lane_from" placeholder="From (City, ST)" required />
              <input name="lane_to" placeholder="To (City, ST)" required />
              <input name="pickup_date" placeholder="Pickup date (e.g., 2025-12-15)" required />
              <input name="delivery_date" placeholder="Delivery date (e.g., 2025-12-16)" required />
              <input name="equipment" placeholder="Equipment (e.g., Dry Van / Reefer / Flatbed)" required />
              <input name="commodity" placeholder="Commodity (e.g., General Freight)" value="General Freight" required />
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
                <option value="false">QuickPay Available? No (default)</option>
                <option value="true">QuickPay Available? Yes</option>
              </select>

              <input name="detention_rate_per_hr" type="number" step="0.01" placeholder="Detention $/hr" value="75" required />
              <input name="detention_after_hours" type="number" placeholder="Detention after (hours)" value="2" required />

              <select name="appointment_type" required>
                <option value="FCFS">Appointment: FCFS (default)</option>
                <option value="Appt Required">Appointment: Appt Required</option>
              </select>

              <input name="accessorials" placeholder="Accessorials (e.g., lumper, stop-off, hazmat, tarp)" value="None" required />
              <textarea name="special_requirements" placeholder="Special requirements / notes (gate codes, PPE, trailer size, etc.)">None</textarea>
            </div>

            <div class="row" style="margin-top:12px">
              <button class="btn primary" type="submit">Post Transparent Load</button>
              <a class="btn" href="/loads">View Load Board</a>
            </div>
          </form>
        </div>

        <div class="card soft">
          <h3 style="margin-top:0">Your posted loads</h3>
          ${loads.rows.length ? loads.rows.map(l => `
            <div class="load">
              <h3>#${l.id} ${escapeHtml(l.lane_from)} → ${escapeHtml(l.lane_to)}</h3>
              <div class="kv">
                <div class="k">Pickup / Delivery</div><div>${escapeHtml(l.pickup_date)} → ${escapeHtml(l.delivery_date)}</div>
                <div class="k">Equipment</div><div>${escapeHtml(l.equipment)}</div>
                <div class="k">Weight / Commodity</div><div>${Number(l.weight_lbs).toLocaleString()} lbs • ${escapeHtml(l.commodity)}</div>
                <div class="k">Miles / Rate</div><div>${Number(l.miles).toLocaleString()} • <b>${money(l.rate_all_in)}</b> (all-in)</div>
                <div class="k">Payment terms</div><div>${escapeHtml(l.payment_terms)} • QuickPay: ${l.quickpay_available ? "Yes" : "No"}</div>
                <div class="k">Detention</div><div>${money(l.detention_rate_per_hr)}/hr after ${escapeHtml(l.detention_after_hours)} hrs</div>
                <div class="k">Appointment</div><div>${escapeHtml(l.appointment_type)}</div>
                <div class="k">Accessorials</div><div>${escapeHtml(l.accessorials)}</div>
                <div class="k">Notes</div><div>${escapeHtml(l.special_requirements)}</div>
              </div>
            </div>
          `).join("") : `<div class="muted">No loads yet.</div>`}
        </div>
      </div>
    `;
    return res.send(layout("Shipper Dashboard", user, body));
  }

  if (user.role === "CARRIER") {
    const loads = await pool.query(
      "SELECT id,lane_from,lane_to,pickup_date,delivery_date,rate_all_in,miles,equipment,weight_lbs,commodity,payment_terms,quickpay_available,detention_rate_per_hr,detention_after_hours,appointment_type,accessorials,special_requirements,created_at FROM loads ORDER BY created_at DESC LIMIT 50"
    );

    const body = `
      <div class="card">
        <h2 style="margin-top:0">Carrier Dashboard</h2>
        <div class="muted">Full transparency load board (no hidden details).</div>
        <div class="hr"></div>
        <div class="row">
          <a class="btn blue" href="/loads">Open Load Board</a>
        </div>
      </div>

      <div class="card soft" style="margin-top:16px">
        <h3 style="margin-top:0">Latest loads</h3>
        ${loads.rows.length ? loads.rows.map(l => `
          <div class="load">
            <h3>#${l.id} ${escapeHtml(l.lane_from)} → ${escapeHtml(l.lane_to)}</h3>
            <div class="kv">
              <div class="k">Pickup / Delivery</div><div>${escapeHtml(l.pickup_date)} → ${escapeHtml(l.delivery_date)}</div>
              <div class="k">Equipment</div><div>${escapeHtml(l.equipment)}</div>
              <div class="k">Weight / Commodity</div><div>${Number(l.weight_lbs).toLocaleString()} lbs • ${escapeHtml(l.commodity)}</div>
              <div class="k">Miles / Rate</div><div>${Number(l.miles).toLocaleString()} • <b>${money(l.rate_all_in)}</b> (all-in)</div>
              <div class="k">Payment terms</div><div>${escapeHtml(l.payment_terms)} • QuickPay: ${l.quickpay_available ? "Yes" : "No"}</div>
              <div class="k">Detention</div><div>${money(l.detention_rate_per_hr)}/hr after ${escapeHtml(l.detention_after_hours)} hrs</div>
              <div class="k">Appointment</div><div>${escapeHtml(l.appointment_type)}</div>
              <div class="k">Accessorials</div><div>${escapeHtml(l.accessorials)}</div>
              <div class="k">Notes</div><div>${escapeHtml(l.special_requirements)}</div>
            </div>
            <div class="row" style="margin-top:12px">
              <button class="btn primary" disabled title="Next feature">Request to Book (next)</button>
              <span class="pill">Direct shipper ↔ carrier booking is next</span>
            </div>
          </div>
        `).join("") : `<div class="muted">No loads posted yet.</div>`}
      </div>
    `;
    return res.send(layout("Carrier Dashboard", user, body));
  }

  // ADMIN placeholder
  return res.send(layout("Admin", user, `<div class="card"><h2>Admin</h2><div class="muted">Next: document approvals + compliance enforcement.</div></div>`));
});

app.post("/shipper/loads", requireAuth, async (req, res) => {
  if (req.user.role !== "SHIPPER") return res.sendStatus(403);

  const lane_from = String(req.body.lane_from || "").trim();
  const lane_to = String(req.body.lane_to || "").trim();
  const pickup_date = String(req.body.pickup_date || "").trim();
  const delivery_date = String(req.body.delivery_date || "").trim();
  const equipment = String(req.body.equipment || "").trim();
  const commodity = String(req.body.commodity || "").trim();
  const weight_lbs = Number(req.body.weight_lbs);
  const miles = Number(req.body.miles);

  const rate_all_in = Number(req.body.rate_all_in);
  const payment_terms = String(req.body.payment_terms || "NET 30").trim();
  const quickpay_available = String(req.body.quickpay_available || "false") === "true";

  const detention_rate_per_hr = Number(req.body.detention_rate_per_hr);
  const detention_after_hours = Number(req.body.detention_after_hours);

  const appointment_type = String(req.body.appointment_type || "FCFS").trim();
  const accessorials = String(req.body.accessorials || "None").trim();
  const special_requirements = String(req.body.special_requirements || "None").trim();

  if (!lane_from || !lane_to || !pickup_date || !delivery_date || !equipment || !commodity) return res.status(400).send("Missing required fields.");
  if (![weight_lbs, miles, rate_all_in, detention_rate_per_hr, detention_after_hours].every(n => Number.isFinite(n))) return res.status(400).send("Numeric fields invalid.");

  await pool.query(
    `INSERT INTO loads
      (shipper_id,lane_from,lane_to,pickup_date,delivery_date,equipment,weight_lbs,commodity,miles,
       rate_all_in,payment_terms,quickpay_available,detention_rate_per_hr,detention_after_hours,
       appointment_type,accessorials,special_requirements)
     VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8,$9,
       $10,$11,$12,$13,$14,$15,$16,$17)`,
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
  const loads = await pool.query(
    "SELECT id,lane_from,lane_to,pickup_date,delivery_date,rate_all_in,miles,equipment,weight_lbs,commodity,payment_terms,quickpay_available,detention_rate_per_hr,detention_after_hours,appointment_type,accessorials,special_requirements,created_at FROM loads ORDER BY created_at DESC LIMIT 100"
  );

  const body = `
    <div class="card">
      <h2 style="margin-top:0">Load Board (Fully Transparent)</h2>
      <div class="muted">Every load shows rate + terms + detention + accessorials. No hidden details.</div>
      <div class="hr"></div>
      ${loads.rows.length ? loads.rows.map(l => `
        <div class="load">
          <h3>#${l.id} ${escapeHtml(l.lane_from)} → ${escapeHtml(l.lane_to)}</h3>
          <div class="kv">
            <div class="k">Pickup / Delivery</div><div>${escapeHtml(l.pickup_date)} → ${escapeHtml(l.delivery_date)}</div>
            <div class="k">Equipment</div><div>${escapeHtml(l.equipment)}</div>
            <div class="k">Weight / Commodity</div><div>${Number(l.weight_lbs).toLocaleString()} lbs • ${escapeHtml(l.commodity)}</div>
            <div class="k">Miles / Rate</div><div>${Number(l.miles).toLocaleString()} • <b>${money(l.rate_all_in)}</b> (all-in)</div>
            <div class="k">Payment terms</div><div>${escapeHtml(l.payment_terms)} • QuickPay: ${l.quickpay_available ? "Yes" : "No"}</div>
            <div class="k">Detention</div><div>${money(l.detention_rate_per_hr)}/hr after ${escapeHtml(l.detention_after_hours)} hrs</div>
            <div class="k">Appointment</div><div>${escapeHtml(l.appointment_type)}</div>
            <div class="k">Accessorials</div><div>${escapeHtml(l.accessorials)}</div>
            <div class="k">Notes</div><div>${escapeHtml(l.special_requirements)}</div>
          </div>
        </div>
      `).join("") : `<div class="muted">No loads posted yet.</div>`}
    </div>
  `;
  res.send(layout("Load Board", user, body));
});

initDb()
  .then(() => app.listen(PORT, "0.0.0.0", () => console.log("Server running on port", PORT)))
  .catch((e) => { console.error("DB init failed:", e); process.exit(1); });
