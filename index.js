const express = require("express");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  app.get("*", (req, res) => {
    res.send(`
      <h1>Setup Needed</h1>
      <p>Your app is running, but <b>DATABASE_URL</b> is not set in Render.</p>
      <p>Render → Web Service → Environment → add DATABASE_URL (Internal Database URL from your Render Postgres).</p>
    `);
  });
  app.listen(PORT, "0.0.0.0", () => console.log("Running without DB on port", PORT));
  return;
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('SHIPPER','CARRIER','ADMIN')),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function layout({ title, body }) {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <style>
    :root{
      --bg:#070b14;
      --card:#0e1a2f;
      --card2:#0a1426;
      --line:#233455;
      --text:#eef2ff;
      --muted:#b7c2dd;

      /* Brand: Blue + Orange */
      --blue:#60a5fa;
      --blue2:#2563eb;
      --orange:#f59e0b;
      --orange2:#fb923c;

      --shadow: 0 18px 50px rgba(0,0,0,.38);
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      color:var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
      background:
        radial-gradient(900px 520px at 15% -10%, rgba(245,158,11,.22), transparent 55%),
        radial-gradient(900px 520px at 90% 0%, rgba(96,165,250,.22), transparent 55%),
        linear-gradient(180deg, rgba(37,99,235,.12), transparent 45%),
        var(--bg);
    }
    a{color:var(--blue); text-decoration:none}
    a:hover{text-decoration:underline}
    .wrap{max-width:1120px; margin:0 auto; padding:22px}
    .nav{
      display:flex; align-items:center; justify-content:space-between; gap:14px;
      padding:14px 16px;
      border:1px solid var(--line);
      border-radius:18px;
      background:rgba(14,26,47,.72);
      backdrop-filter: blur(10px);
      position:sticky; top:14px; z-index:20;
      box-shadow: var(--shadow);
    }
    .brand{display:flex; align-items:center; gap:12px}
    .mark{
      width:44px;height:44px;border-radius:14px;
      border:1px solid rgba(255,255,255,.10);
      background: linear-gradient(135deg, rgba(245,158,11,.95), rgba(96,165,250,.95));
      display:grid; place-items:center;
      box-shadow: 0 18px 55px rgba(245,158,11,.12);
    }
    .brand h1{font-size:16px;margin:0;letter-spacing:.2px}
    .sub{font-size:12px;color:var(--muted); margin-top:2px}
    .right{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
    .pill{
      padding:7px 10px;border-radius:999px;
      border:1px solid var(--line);
      background:rgba(10,20,38,.80);
      color:var(--muted);
      font-size:12px;
      display:inline-flex; gap:8px; align-items:center;
    }
    .btn{
      display:inline-flex;align-items:center;justify-content:center;gap:8px;
      padding:10px 14px;border-radius:12px;
      border:1px solid var(--line);
      background:rgba(10,20,38,.85);
      color:var(--text);
      cursor:pointer;
      transition: transform .08s ease, border-color .12s ease;
    }
    .btn:hover{border-color:rgba(96,165,250,.55)}
    .btn:active{transform: translateY(1px)}
    .btn.primary{
      border:none;
      background: linear-gradient(135deg, rgba(245,158,11,.98), rgba(251,146,60,.82));
      color:#111827;
      box-shadow: 0 18px 55px rgba(245,158,11,.18);
      font-weight:800;
    }
    .btn.blue{
      border:none;
      background: linear-gradient(135deg, rgba(37,99,235,.98), rgba(96,165,250,.85));
      color:#0b1020;
      box-shadow: 0 18px 55px rgba(96,165,250,.14);
      font-weight:800;
    }
    .grid{display:grid;gap:16px;grid-template-columns:1.35fr .65fr;margin-top:16px}
    @media (max-width:900px){ .grid{grid-template-columns:1fr} .nav{position:static} }
    .card{
      border:1px solid var(--line);
      border-radius:18px;
      background:rgba(14,26,47,.72);
      backdrop-filter: blur(10px);
      padding:18px;
      box-shadow: var(--shadow);
    }
    .card.soft{background:rgba(10,20,38,.76)}
    .heroTitle{
      font-size:40px; line-height:1.05; margin:0 0 10px 0;
      letter-spacing:-.35px;
    }
    .muted{color:var(--muted)}
    .hr{height:1px;background:rgba(35,52,85,.9);margin:14px 0;border:0}
    .kpis{display:flex; gap:10px; flex-wrap:wrap; margin-top:12px}
    .kpi{
      padding:10px 12px; border-radius:14px;
      border:1px solid var(--line);
      background:rgba(10,20,38,.85);
      font-size:12px; min-width: 150px;
    }
    .kpi b{display:block;font-size:14px;color:var(--text)}
    .two{display:grid; gap:12px; grid-template-columns:1fr 1fr}
    @media (max-width:700px){ .two{grid-template-columns:1fr} }
    .roleCard{
      padding:14px;border-radius:16px;
      border:1px solid rgba(255,255,255,.08);
      background: linear-gradient(180deg, rgba(10,20,38,.78), rgba(10,20,38,.58));
    }
    .roleTitle{display:flex;align-items:center;justify-content:space-between;gap:10px}
    .tag{
      font-size:12px; padding:6px 10px; border-radius:999px;
      border:1px solid rgba(245,158,11,.30);
      background: rgba(245,158,11,.10);
      color: rgba(255,243,220,.95);
    }
    .tagBlue{
      border:1px solid rgba(96,165,250,.30);
      background: rgba(96,165,250,.10);
      color: rgba(220,235,255,.95);
    }
    .tiny{font-size:12px}
    input,select{
      width:min(520px,100%);
      padding:12px 12px;border-radius:12px;
      border:1px solid var(--line);
      background:rgba(10,20,38,.92);
      color:var(--text);
      outline:none;
    }
    input:focus,select:focus{border-color:rgba(245,158,11,.55)}
    .formGrid{display:grid;gap:10px;grid-template-columns:1fr 1fr}
    @media (max-width:700px){ .formGrid{grid-template-columns:1fr} }
    .footer{margin:22px 0 8px 0;color:var(--muted);font-size:12px}

    .icon{width:20px;height:20px;display:block}
    .callouts{display:grid;gap:12px;margin-top:14px}
    .callout{
      padding:12px 12px;border-radius:16px;border:1px solid var(--line);
      background:rgba(10,20,38,.75);
    }
    .check{color:var(--orange); font-weight:900}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="nav">
      <div class="brand">
        <div class="mark" aria-hidden="true">
          <svg class="icon" viewBox="0 0 24 24" fill="none">
            <path d="M3 7h11v10H3V7Z" stroke="rgba(17,24,39,.9)" stroke-width="2"/>
            <path d="M14 10h4l3 3v4h-7v-7Z" stroke="rgba(17,24,39,.9)" stroke-width="2"/>
            <path d="M7 19a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3Z" fill="rgba(17,24,39,.9)"/>
            <path d="M18 19a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3Z" fill="rgba(17,24,39,.9)"/>
          </svg>
        </div>
        <div>
          <h1>Direct Freight Exchange</h1>
          <div class="sub">Direct shipper ↔ carrier connections • Transparent loads • Compliance-first</div>
        </div>
      </div>
      <div class="right">
        <span class="pill">🟧🟦 Live</span>
        <a class="btn" href="/">Home</a>
        <a class="btn" href="/signup">Sign up</a>
        <a class="btn blue" href="/login">Login</a>
      </div>
    </div>

    ${body}

    <div class="footer">
      Next we’ll add: staying logged in + role dashboards → Stripe subscriptions (shippers) → carrier document uploads → admin review → compliance badge enforcement.
    </div>
  </div>
</body>
</html>`;
}

app.get("/", (req, res) => {
  const body = `
    <div class="grid">
      <div class="card">
        <h2 class="heroTitle">Connect shippers and truckers—directly.</h2>
        <div class="muted">
          No hidden details. No “call for rate.” Post loads with full transparency so carriers can say <b>yes</b> faster—and move freight with confidence.
        </div>

        <div class="kpis">
          <div class="kpi"><b>Direct connections</b><span class="muted">Shipper ↔ carrier chat/workflow next</span></div>
          <div class="kpi"><b>Transparent loads</b><span class="muted">Rate • miles • weight • terms</span></div>
          <div class="kpi"><b>Verified carriers</b><span class="muted">Insurance • authority • W-9</span></div>
        </div>

        <div class="callouts">
          <div class="callout">
            <div><span class="check">✓</span> Post loads with: <span class="muted">lane, pickup/delivery, equipment, weight, commodity, miles, rate, payment terms, detention/accessorials</span></div>
          </div>
          <div class="callout">
            <div><span class="check">✓</span> Carriers earn a badge by uploading U.S. documents: <span class="muted">insurance + authority + W-9</span></div>
          </div>
        </div>

        <div class="hr"></div>

        <div class="two">
          <div class="roleCard">
            <div class="roleTitle">
              <b>Shippers</b>
              <span class="tag">Subscribe • Post • Track</span>
            </div>
            <div class="muted tiny" style="margin-top:8px">
              Post transparent loads, get direct carrier interest, manage invoices/receipts.
            </div>
          </div>
          <div class="roleCard">
            <div class="roleTitle">
              <b>Carriers</b>
              <span class="tag tagBlue">Verify • Book • Get paid</span>
            </div>
            <div class="muted tiny" style="margin-top:8px">
              See the details up front, verify compliance once, and book freight faster.
            </div>
          </div>
        </div>

        <div style="margin-top:14px; display:flex; gap:10px; flex-wrap:wrap">
          <a class="btn primary" href="/signup">Get started</a>
          <a class="btn" href="/login">Log in</a>
        </div>
      </div>

      <div class="card soft">
        <h3 style="margin-top:0">What works today</h3>
        <ul class="muted" style="margin:10px 0 0 18px; padding:0">
          <li>Orange/blue brand homepage</li>
          <li>Signup stored in Postgres</li>
          <li>Role selection (Shipper/Carrier)</li>
        </ul>
        <div class="hr"></div>
        <h3 style="margin-top:0">What we add next</h3>
        <ul class="muted" style="margin:10px 0 0 18px; padding:0">
          <li>Stay logged in (sessions)</li>
          <li>Role dashboards</li>
          <li>Stripe subscription + receipts</li>
          <li>Transparent load posting form</li>
        </ul>
      </div>
    </div>
  `;
  res.send(layout({ title: "DFX", body }));
});

app.get("/signup", (req, res) => {
  const body = `
    <div class="grid">
      <div class="card">
        <h2 style="margin-top:0">Create your account</h2>
        <div class="muted">Choose your role. (Admin will be added later.)</div>

        <form method="POST" action="/signup" style="margin-top:14px">
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

        <div class="tiny muted" style="margin-top:10px">
          Next: shippers subscribe to post loads. carriers upload compliance docs for verification.
        </div>
      </div>

      <div class="card soft">
        <h3 style="margin-top:0">Transparency promise</h3>
        <div class="muted tiny">
          Loads will show <b>rate + terms</b> up front. No hidden accessorials. Clear pickup/delivery requirements.
        </div>
      </div>
    </div>
  `;
  res.send(layout({ title: "Sign up", body }));
});

app.post("/signup", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const role = String(req.body.role || "SHIPPER").toUpperCase();

    if (!email || password.length < 8) return res.status(400).send("Password must be at least 8 characters.");
    if (!["SHIPPER", "CARRIER"].includes(role)) return res.status(400).send("Invalid role.");

    const hash = await bcrypt.hash(password, 12);
    await pool.query(
      "INSERT INTO users (email, password_hash, role) VALUES ($1,$2,$3)",
      [email, hash, role]
    );

    res.redirect("/login");
  } catch (e) {
    if (String(e).includes("duplicate")) return res.status(409).send("That email is already registered. Go to /login.");
    console.error(e);
    res.status(500).send("Signup failed.");
  }
});

app.get("/login", (req, res) => {
  const body = `
    <div class="grid">
      <div class="card">
        <h2 style="margin-top:0">Login</h2>
        <div class="muted">For now this verifies your account exists (next we’ll keep you logged in).</div>

        <form method="POST" action="/login" style="margin-top:14px">
          <div class="formGrid">
            <input name="email" type="email" placeholder="Email" required />
            <input name="password" type="password" placeholder="Password" required />
            <button class="btn blue" type="submit">Login</button>
            <a class="btn" href="/signup">Create account</a>
          </div>
        </form>
      </div>

      <div class="card soft">
        <h3 style="margin-top:0">After login (next)</h3>
        <ul class="muted" style="margin:10px 0 0 18px; padding:0">
          <li>Shipper dashboard: subscribe + post transparent loads</li>
          <li>Carrier dashboard: upload docs + get verified</li>
          <li>Admin: approve docs + badge enforcement</li>
        </ul>
      </div>
    </div>
  `;
  res.send(layout({ title: "Login", body }));
});

app.post("/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const r = await pool.query("SELECT password_hash, role FROM users WHERE email=$1", [email]);
    if (!r.rows[0]) return res.status(401).send("No account found. Go to /signup.");

    const ok = await bcrypt.compare(password, r.rows[0].password_hash);
    if (!ok) return res.status(401).send("Wrong password.");

    res.send(layout({
      title: "Logged in",
      body: `
        <div class="card">
          <h2 style="margin-top:0">Login successful ✅</h2>
          <div class="muted">Role: <b>${escapeHtml(r.rows[0].role)}</b></div>
          <div class="muted tiny" style="margin-top:10px">
            Next: I’ll add real sessions so you stay logged in + dashboards for transparent loads & compliance.
          </div>
          <div style="margin-top:14px; display:flex; gap:10px; flex-wrap:wrap">
            <a class="btn primary" href="/">Back to Home</a>
            <a class="btn" href="/signup">Create another account</a>
          </div>
        </div>
      `
    }));
  } catch (e) {
    console.error(e);
    res.status(500).send("Login failed.");
  }
});

initDb()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => console.log("Server running on port", PORT));
  })
  .catch((e) => {
    console.error("DB init failed:", e);
    process.exit(1);
  });
