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
  ssl: { rejectUnauthorized: false }
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

function layout({ title, body }) {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <style>
    :root{
      --bg:#070b16;
      --card:#0f1830;
      --card2:#0b1326;
      --line:#24345e;
      --text:#e9edf7;
      --muted:#a8b3d1;
      --accent:#6ea8ff;
      --accent2:#7c5cff;
      --good:#2dd4bf;
      --warn:#fbbf24;
    }
    *{box-sizing:border-box}
    body{
      margin:0; color:var(--text); background:
        radial-gradient(900px 500px at 20% 10%, rgba(124,92,255,.22), transparent 55%),
        radial-gradient(900px 500px at 80% 0%, rgba(110,168,255,.22), transparent 55%),
        var(--bg);
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
    }
    a{color:var(--accent); text-decoration:none}
    a:hover{text-decoration:underline}
    .wrap{max-width:1050px; margin:0 auto; padding:22px}
    .nav{
      display:flex; align-items:center; justify-content:space-between; gap:14px;
      padding:14px 16px; border:1px solid var(--line); border-radius:18px;
      background:rgba(15,24,48,.75); backdrop-filter: blur(8px);
      position:sticky; top:14px; z-index:20;
    }
    .brand{display:flex; align-items:center; gap:12px}
    .logo{
      width:38px;height:38px;border-radius:14px;
      background: linear-gradient(135deg, var(--accent2), var(--accent));
      box-shadow: 0 12px 40px rgba(110,168,255,.18);
    }
    .brand h1{font-size:16px;margin:0;letter-spacing:.2px}
    .brand .sub{font-size:12px;color:var(--muted); margin-top:2px}
    .nav .right{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
    .pill{
      padding:7px 10px; border-radius:999px;
      border:1px solid var(--line);
      background:rgba(11,19,38,.75);
      color:var(--muted); font-size:12px;
    }
    .btn{
      display:inline-flex; align-items:center; justify-content:center;
      padding:10px 14px; border-radius:12px;
      border:1px solid var(--line);
      background:rgba(11,19,38,.75);
      color:var(--text);
      cursor:pointer;
    }
    .btn:hover{border-color:rgba(110,168,255,.55)}
    .btn.primary{
      border:none;
      background: linear-gradient(135deg, var(--accent2), var(--accent));
      box-shadow: 0 12px 40px rgba(124,92,255,.18);
    }
    .grid{display:grid; gap:16px; grid-template-columns: 1.35fr .65fr; margin-top:16px}
    @media (max-width:900px){ .grid{grid-template-columns:1fr} .nav{position:static} }
    .card{
      border:1px solid var(--line); border-radius:18px;
      background:rgba(15,24,48,.75); backdrop-filter: blur(8px);
      padding:18px;
    }
    .heroTitle{font-size:34px; line-height:1.1; margin:0 0 10px 0}
    .muted{color:var(--muted)}
    .kpis{display:flex; gap:10px; flex-wrap:wrap; margin-top:12px}
    .kpi{padding:10px 12px; border-radius:14px; border:1px solid var(--line); background:rgba(11,19,38,.75); font-size:12px}
    .kpi b{display:block; font-size:14px; color:var(--text)}
    .row{display:flex; gap:10px; flex-wrap:wrap; align-items:center}
    input, select{
      width: min(460px, 100%);
      padding:12px 12px; border-radius:12px;
      border:1px solid var(--line);
      background:rgba(11,19,38,.9);
      color:var(--text);
      outline:none;
    }
    input:focus, select:focus{border-color:rgba(110,168,255,.6)}
    .formGrid{display:grid; gap:10px; grid-template-columns: 1fr 1fr}
    @media (max-width:700px){ .formGrid{grid-template-columns:1fr} }
    .tiny{font-size:12px}
    .badgeGood{color:var(--good)}
    .badgeWarn{color:var(--warn)}
    .footer{margin:22px 0 8px 0; color:var(--muted); font-size:12px}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="nav">
      <div class="brand">
        <div class="logo"></div>
        <div>
          <h1>Direct Freight Exchange</h1>
          <div class="sub">Shippers • Carriers • Compliance • Subscriptions</div>
        </div>
      </div>
      <div class="right">
        <span class="pill">Live on Render</span>
        <a class="btn" href="/">Home</a>
        <a class="btn" href="/signup">Sign up</a>
        <a class="btn primary" href="/login">Login</a>
      </div>
    </div>

    ${body}

    <div class="footer">
      Next features: Stripe subscriptions → carrier document uploads (S3) → admin review → compliance badge enforcement.
    </div>
  </div>
</body>
</html>`;
}

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

app.get("/", (req, res) => {
  const body = `
    <div class="grid">
      <div class="card">
        <h2 class="heroTitle">Move freight with verified carriers — fast.</h2>
        <div class="muted">
          This is your production foundation. Next we’ll plug in Stripe subscriptions for shippers and compliance uploads for carriers.
        </div>
        <div class="kpis">
          <div class="kpi"><b>✅ Live</b><span class="muted">Hosting works</span></div>
          <div class="kpi"><b class="badgeGood">🗄️ DB Ready</b><span class="muted">Postgres connected</span></div>
          <div class="kpi"><b class="badgeWarn">💳 Next</b><span class="muted">Stripe subscriptions</span></div>
        </div>
        <div class="row" style="margin-top:14px">
          <a class="btn primary" href="/signup">Create an account</a>
          <a class="btn" href="/login">Log in</a>
        </div>
      </div>

      <div class="card" style="background:rgba(11,19,38,.75)">
        <h3 style="margin-top:0">What you can do now</h3>
        <ul class="muted" style="margin:10px 0 0 18px; padding:0">
          <li>Create Shipper or Carrier account</li>
          <li>Store users in database</li>
          <li>Proves the “real app” setup works</li>
        </ul>
        <hr/>
        <div class="tiny muted">
          Once this looks right, I’ll add your full dashboards + Stripe + compliance uploads.
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
        <div class="muted">Choose your role. You can add Admin later.</div>
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
          Tip: Use a real email/password—you’ll reuse these when we add Stripe + dashboards.
        </div>
      </div>

      <div class="card" style="background:rgba(11,19,38,.75)">
        <h3 style="margin-top:0">Next</h3>
        <div class="muted">
          Shippers will subscribe before posting loads. Carriers will upload insurance/authority/W-9.
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
        <div class="muted">For now this just confirms your account exists in the database.</div>
        <form method="POST" action="/login" style="margin-top:14px">
          <div class="formGrid">
            <input name="email" type="email" placeholder="Email" required />
            <input name="password" type="password" placeholder="Password" required />
            <button class="btn primary" type="submit">Login</button>
            <a class="btn" href="/signup">Need an account?</a>
          </div>
        </form>
      </div>

      <div class="card" style="background:rgba(11,19,38,.75)">
        <h3 style="margin-top:0">What’s next after login</h3>
        <ul class="muted" style="margin:10px 0 0 18px; padding:0">
          <li>Role-based dashboards</li>
          <li>Stripe subscription + billing portal</li>
          <li>Carrier compliance uploads + admin review</li>
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
          <div class="row" style="margin-top:14px">
            <a class="btn primary" href="/">Back to home</a>
            <a class="btn" href="/signup">Create another account</a>
          </div>
          <div class="tiny muted" style="margin-top:10px">
            Next: I’ll add real dashboards + sessions so you stay logged in.
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
