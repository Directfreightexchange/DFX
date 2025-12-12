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
      --bg:#0a0f18;
      --card:#101a2b;
      --card2:#0c1422;
      --line:#26344f;
      --text:#eef2ff;
      --muted:#b2bdd8;
      --accent:#f59e0b;       /* freight orange */
      --accent2:#60a5fa;      /* steel blue */
      --good:#22c55e;
      --warn:#fbbf24;
      --shadow: 0 18px 50px rgba(0,0,0,.35);
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      color:var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
      background:
        linear-gradient(180deg, rgba(96,165,250,.10), transparent 55%),
        radial-gradient(1000px 600px at 18% -10%, rgba(245,158,11,.18), transparent 55%),
        radial-gradient(1000px 600px at 92% 0%, rgba(96,165,250,.16), transparent 55%),
        var(--bg);
    }
    a{color:var(--accent2); text-decoration:none}
    a:hover{text-decoration:underline}
    .wrap{max-width:1100px; margin:0 auto; padding:22px}
    .nav{
      display:flex; align-items:center; justify-content:space-between; gap:14px;
      padding:14px 16px;
      border:1px solid var(--line);
      border-radius:18px;
      background:rgba(16,26,43,.72);
      backdrop-filter: blur(8px);
      position:sticky; top:14px; z-index:20;
      box-shadow: var(--shadow);
    }
    .brand{display:flex; align-items:center; gap:12px}
    .mark{
      width:42px;height:42px;border-radius:14px;
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
      background:rgba(12,20,34,.80);
      color:var(--muted);
      font-size:12px;
      display:inline-flex; gap:8px; align-items:center;
    }
    .btn{
      display:inline-flex;align-items:center;justify-content:center;gap:8px;
      padding:10px 14px;border-radius:12px;
      border:1px solid var(--line);
      background:rgba(12,20,34,.85);
      color:var(--text);
      cursor:pointer;
      transition: transform .08s ease, border-color .12s ease;
    }
    .btn:hover{border-color:rgba(96,165,250,.55)}
    .btn:active{transform: translateY(1px)}
    .btn.primary{
      border:none;
      background: linear-gradient(135deg, rgba(245,158,11,.98), rgba(245,158,11,.78));
      color:#111827;
      box-shadow: 0 18px 55px rgba(245,158,11,.18);
      font-weight:700;
    }
    .grid{display:grid;gap:16px;grid-template-columns:1.35fr .65fr;margin-top:16px}
    @media (max-width:900px){ .grid{grid-template-columns:1fr} .nav{position:static} }
    .card{
      border:1px solid var(--line);
      border-radius:18px;
      background:rgba(16,26,43,.72);
      backdrop-filter: blur(8px);
      padding:18px;
      box-shadow: var(--shadow);
    }
    .card.soft{background:rgba(12,20,34,.76)}
    .heroTitle{font-size:38px;line-height:1.05;margin:0 0 10px 0;letter-spacing:-.3px}
    .muted{color:var(--muted)}
    .hr{height:1px;background:rgba(38,52,79,.8);margin:14px 0;border:0}
    .kpis{display:flex; gap:10px; flex-wrap:wrap; margin-top:12px}
    .kpi{
      padding:10px 12px; border-radius:14px;
      border:1px solid var(--line);
      background:rgba(12,20,34,.85);
      font-size:12px; min-width: 140px;
    }
    .kpi b{display:block;font-size:14px;color:var(--text)}
    .two{display:grid; gap:12px; grid-template-columns:1fr 1fr}
    @media (max-width:700px){ .two{grid-template-columns:1fr} }
    .roleCard{
      padding:14px;border-radius:16px;
      border:1px solid rgba(255,255,255,.08);
      background: linear-gradient(180deg, rgba(12,20,34,.75), rgba(12,20,34,.55));
    }
    .roleTitle{display:flex;align-items:center;justify-content:space-between;gap:10px}
    .tag{
      font-size:12px; padding:6px 10px; border-radius:999px;
      border:1px solid rgba(245,158,11,.25);
      background: rgba(245,158,11,.10);
      color: rgba(255,243,220,.95);
    }
    .tiny{font-size:12px}
    input,select{
      width:min(520px,100%);
      padding:12px 12px;border-radius:12px;
      border:1px solid var(--line);
      background:rgba(12,20,34,.92);
      color:var(--text);
      outline:none;
    }
    input:focus,select:focus{border-color:rgba(245,158,11,.55)}
    .formGrid{display:grid;gap:10px;grid-template-columns:1fr 1fr}
    @media (max-width:700px){ .formGrid{grid-template-columns:1fr} }
    .footer{margin:22px 0 8px 0;color:var(--muted);font-size:12px}
    .icon{width:20px;height:20px;display:block}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="nav">
      <div class="brand">
        <div class="mark" aria-hidden="true">
          <!-- Simple truck icon -->
          <svg class="icon" viewBox="0 0 24 24" fill="none">
            <path d="M3 7h11v10H3V7Z" stroke="rgba(17,24,39,.9)" stroke-width="2"/>
            <path d="M14 10h4l3 3v4h-7v-7Z" stroke="rgba(17,24,39,.9)" stroke-width="2"/>
            <path d="M7 19a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3Z" fill="rgba(17,24,39,.9)"/>
            <path d="M18 19a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3Z" fill="rgba(17,24,39,.9)"/>
          </svg>
        </div>
        <div>
          <h1>Direct Freight Exchange</h1>
          <div class="sub">Professional marketplace • Compliance-first • Built for U.S. freight</div>
        </div>
      </div>
      <div class="right">
        <span class="pill">✅ Live</span>
        <a class="btn" href="/">Home</a>
        <a class="btn" href="/signup">Sign up</a>
        <a class="btn primary" href="/login">Login</a>
      </div>
    </div>

    ${body}

    <div class="footer">
      Next we’ll add: role dashboards → Stripe subscriptions (shippers) → carrier document uploads → admin review → compliance badge enforcement.
    </div>
  </div>
</body>
</html>`;
}

app.get("/", (req, res) => {
  const body = `
    <div class="grid">
      <div class="card">
        <h2 class="heroTitle">Book freight with verified carriers.</h2>
        <div class="muted">
          A clean, compliance-first exchange: shippers subscribe to post loads, carriers upload required U.S. documents, and admins approve before booking.
        </div>

        <div class="kpis">
          <div class="kpi"><b>Compliance-ready</b><span class="muted">Insurance • Authority • W-9</span></div>
          <div class="kpi"><b>Subscription-based</b><span class="muted">Stripe billing</span></div>
          <div class="kpi"><b>Fast onboarding</b><span class="muted">Role dashboards</span></div>
        </div>

        <div class="hr"></div>

        <div class="two">
          <div class="roleCard">
            <div class="roleTitle">
              <b>For Shippers</b>
              <span class="tag">Subscribe & post loads</span>
            </div>
            <div class="muted tiny" style="margin-top:8px">
              Post loads after subscription. Manage invoices/receipts. Build a carrier network.
            </div>
          </div>
          <div class="roleCard">
            <div class="roleTitle">
              <b>For Carriers</b>
              <span class="tag">Upload & get verified</span>
            </div>
            <div class="muted tiny" style="margin-top:8px">
              Upload proof of insurance, proof of authority (MC/FF), and W-9. Earn a compliance badge.
            </div>
          </div>
        </div>

        <div class="row" style="margin-top:14px; display:flex; gap:10px; flex-wrap:wrap">
          <a class="btn primary" href="/signup">Get started</a>
          <a class="btn" href="/login">Log in</a>
        </div>
      </div>

      <div class="card soft">
        <h3 style="margin-top:0">What works today</h3>
        <ul class="muted" style="margin:10px 0 0 18px; padding:0">
          <li>Clean homepage</li>
          <li>Signup stored in Postgres</li>
          <li>Role selection (Shipper/Carrier)</li>
        </ul>
        <div class="hr"></div>
        <div class="muted tiny">
          Next upgrade: keep users logged in (sessions/JWT) + role-based dashboards.
        </div>
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
        <div class="muted">Choose Shipper or Carrier. (Admin will be added later.)</div>

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
          Carriers will upload documents next (insurance/authority/W-9). Shippers will subscribe next (Stripe).
        </div>
      </div>

      <div class="card soft">
        <h3 style="margin-top:0">Required carrier docs (next)</h3>
        <ul class="muted" style="margin:10px 0 0 18px; padding:0">
          <li>Proof of Insurance (with expiry)</li>
          <li>Proof of Authority (MC/FF)</li>
          <li>W-9</li>
        </ul>
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
            <button class="btn primary" type="submit">Login</button>
            <a class="btn" href="/signup">Create account</a>
          </div>
        </form>
      </div>

      <div class="card soft">
        <h3 style="margin-top:0">After login (next)</h3>
        <ul class="muted" style="margin:10px 0 0 18px; padding:0">
          <li>Role dashboard</li>
          <li>Shipper subscription (Stripe)</li>
          <li>Carrier compliance uploads</li>
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
          <div style="margin-top:12px" class="muted tiny">
            Next: I’ll add real sessions so you stay logged in + dashboards for Shipper/Carrier/Admin.
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
