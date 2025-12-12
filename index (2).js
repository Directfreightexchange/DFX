const express = require("express");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;

function mustEnv(name, val) {
  if (!val) {
    console.error(`Missing ${name} environment variable`);
  }
}
mustEnv("DATABASE_URL", DATABASE_URL);
mustEnv("JWT_SECRET", JWT_SECRET);

// Render Postgres commonly requires SSL; this works for Render and many managed DBs.
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL ? { rejectUnauthorized: false } : undefined,
});

async function initDb() {
  // Minimal production foundation: users + carrier docs + loads
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('SHIPPER','CARRIER','ADMIN')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS carrier_docs (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      doc_type TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS loads (
      id SERIAL PRIMARY KEY,
      shipper_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

function layout(title, body, user) {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;margin:0;background:#0b0f19;color:#e9edf5}
    .wrap{max-width:920px;margin:0 auto;padding:24px}
    .card{background:#111a2e;border:1px solid #223155;border-radius:14px;padding:18px;margin:14px 0}
    a{color:#7bb0ff}
    input,select,button{padding:10px;border-radius:10px;border:1px solid #2a3a66;background:#0b1223;color:#e9edf5}
    button{cursor:pointer}
    .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
    .pill{display:inline-block;padding:6px 10px;border-radius:999px;background:#172443;border:1px solid #2a3a66}
    .muted{opacity:.75}
    .top{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
    h1,h2,h3{margin:0 0 10px 0}
    hr{border:0;border-top:1px solid #223155;margin:14px 0}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div>
        <div style="font-size:22px;font-weight:700">Direct Freight Exchange</div>
        <div class="muted">Accounts + roles + dashboards (DB-backed)</div>
      </div>
      <div class="row">
        ${user ? `<span class="pill">${user.role}</span><span class="pill">${user.email}</span><a href="/logout">Logout</a>`
               : `<a href="/login">Login</a> · <a href="/signup">Sign up</a>`}
      </div>
    </div>
    ${body}
  </div>
</body>
</html>`;
}

function getUserFromReq(req) {
  try {
    const token = req.cookies?.dfx_token;
    if (!token) return null;
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function requireAuth(req, res, next) {
  const user = getUserFromReq(req);
  if (!user) return res.redirect("/login");
  req.user = user;
  next();
}

app.get("/", (req, res) => {
  const user = getUserFromReq(req);
  const body = `
    <div class="card">
      <h2>Website is LIVE ✅</h2>
      <div class="muted">Now with real accounts and role-based dashboards.</div>
      <hr/>
      <div class="row">
        <a href="/signup">Create account</a>
        <a href="/login">Login</a>
        ${user ? `<a href="/dashboard">Go to dashboard</a>` : ``}
      </div>
    </div>
    <div class="card">
      <h3>Next steps (after this works)</h3>
      <div class="muted">Stripe subscriptions → S3 document uploads → Admin review → Compliance badge/score</div>
    </div>
  `;
  res.send(layout("DFX", body, user));
});

app.get("/signup", (req, res) => {
  const user = getUserFromReq(req);
  const body = `
    <div class="card">
      <h2>Sign up</h2>
      <form method="POST" action="/signup">
        <div class="row">
          <input name="email" type="email" placeholder="Email" required />
          <input name="password" type="password" placeholder="Password (min 8 chars)" required minlength="8" />
          <select name="role" required>
            <option value="SHIPPER">Shipper</option>
            <option value="CARRIER">Carrier</option>
          </select>
          <button type="submit">Create account</button>
        </div>
        <div class="muted" style="margin-top:10px">Admin is created later (safely) after you’re stable.</div>
      </form>
    </div>
  `;
  res.send(layout("Sign up", body, user));
});

app.post("/signup", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const role = String(req.body.role || "SHIPPER").toUpperCase();

    if (!email || password.length < 8) return res.status(400).send("Invalid signup.");
    if (!["SHIPPER", "CARRIER"].includes(role)) return res.status(400).send("Invalid role.");

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      "INSERT INTO users (email, password_hash, role) VALUES ($1,$2,$3) RETURNING id,email,role",
      [email, hash, role]
    );

    const u = result.rows[0];
    const token = jwt.sign({ id: u.id, email: u.email, role: u.role }, JWT_SECRET, { expiresIn: "7d" });
    res.cookie("dfx_token", token, { httpOnly: true, sameSite: "lax", secure: true });
    res.redirect("/dashboard");
  } catch (e) {
    if (String(e).includes("duplicate")) return res.status(409).send("Email already exists. Go back and login.");
    console.error(e);
    res.status(500).send("Signup failed.");
  }
});

app.get("/login", (req, res) => {
  const user = getUserFromReq(req);
  const body = `
    <div class="card">
      <h2>Login</h2>
      <form method="POST" action="/login">
        <div class="row">
          <input name="email" type="email" placeholder="Email" required />
          <input name="password" type="password" placeholder="Password" required />
          <button type="submit">Login</button>
        </div>
      </form>
    </div>
  `;
  res.send(layout("Login", body, user));
});

app.post("/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const r = await pool.query("SELECT id,email,password_hash,role FROM users WHERE email=$1", [email]);
    const u = r.rows[0];
    if (!u) return res.status(401).send("Invalid credentials.");

    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).send("Invalid credentials.");

    const token = jwt.sign({ id: u.id, email: u.email, role: u.role }, JWT_SECRET, { expiresIn: "7d" });
    res.cookie("dfx_token", token, { httpOnly: true, sameSite: "lax", secure: true });
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

  let body = `<div class="card"><h2>Dashboard</h2><div class="muted">Role-based view</div></div>`;

  if (user.role === "SHIPPER") {
    const loads = await pool.query(
      "SELECT id,title,created_at FROM loads WHERE shipper_id=$1 ORDER BY created_at DESC",
      [user.id]
    );

    body += `
      <div class="card">
        <h3>Shipper dashboard</h3>
        <div class="muted">Next we’ll add Stripe subscription (required to post loads).</div>
      </div>

      <div class="card">
        <h3>Post a load</h3>
        <form method="POST" action="/shipper/loads">
          <div class="row">
            <input name="title" placeholder="Example: Chicago → Dallas, 40k lbs" required />
            <button type="submit">Create</button>
          </div>
        </form>
      </div>

      <div class="card">
        <h3>Your loads</h3>
        ${loads.rows.length
          ? loads.rows.map(l => `<div class="pill">#${l.id} ${escapeHtml(l.title)}</div>`).join(" ")
          : `<div class="muted">No loads yet.</div>`}
      </div>
    `;
  }

  if (user.role === "CARRIER") {
    const docs = await pool.query(
      "SELECT doc_type,status,created_at FROM carrier_docs WHERE user_id=$1 ORDER BY created_at DESC",
      [user.id]
    );

    const approved = docs.rows.filter(d => d.status === "approved").length;
    const score = Math.min(100, Math.round((approved / 3) * 100));
    const badge = score === 100 ? "Verified" : score >= 50 ? "In Review" : "Incomplete";

    body += `
      <div class="card">
        <h3>Carrier dashboard</h3>
        <div class="row">
          <span class="pill">Compliance score: ${score}/100</span>
          <span class="pill">Badge: ${badge}</span>
        </div>
        <div class="muted" style="margin-top:10px">
          Next we’ll add real uploads to S3 + admin approve/reject.
        </div>
      </div>

      <div class="card">
        <h3>Submit compliance doc (placeholder)</h3>
        <form method="POST" action="/carrier/docs">
          <div class="row">
            <select name="doc_type" required>
              <option value="INSURANCE">Proof of Insurance</option>
              <option value="AUTHORITY">Proof of Authority</option>
              <option value="W9">W‑9</option>
            </select>
            <button type="submit">Submit</button>
          </div>
        </form>
        <div class="muted" style="margin-top:10px">
          (For now this just records submission. Next step is uploading PDFs/images.)
        </div>
      </div>

      <div class="card">
        <h3>Your documents</h3>
        ${docs.rows.length
          ? docs.rows.map(d => `<div class="pill">${escapeHtml(d.doc_type)}: ${escapeHtml(d.status)}</div>`).join(" ")
          : `<div class="muted">No documents yet.</div>`}
      </div>
    `;
  }

  if (user.role === "ADMIN") {
    body += `
      <div class="card">
        <h3>Admin dashboard</h3>
        <div class="muted">Next step: add the review queue (approve/reject) + carrier compliance enforcement.</div>
      </div>
    `;
  }

  res.send(layout("Dashboard", body, user));
});

app.post("/shipper/loads", requireAuth, async (req, res) => {
  if (req.user.role !== "SHIPPER") return res.sendStatus(403);
  const title = String(req.body.title || "").trim();
  if (!title) return res.status(400).send("Missing title.");
  await pool.query("INSERT INTO loads (shipper_id, title) VALUES ($1,$2)", [req.user.id, title]);
  res.redirect("/dashboard");
});

app.post("/carrier/docs", requireAuth, async (req, res) => {
  if (req.user.role !== "CARRIER") return res.sendStatus(403);
  const docType = String(req.body.doc_type || "").trim().toUpperCase();
  if (!["INSURANCE", "AUTHORITY", "W9"].includes(docType)) return res.status(400).send("Invalid doc type.");
  await pool.query("INSERT INTO carrier_docs (user_id, doc_type) VALUES ($1,$2)", [req.user.id, docType]);
  res.redirect("/dashboard");
});

app.get("/health", (req, res) => res.json({ ok: true }));

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

initDb()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => console.log("Server running on port", PORT));
  })
  .catch((e) => {
    console.error("DB init failed:", e);
    process.exit(1);
  });
