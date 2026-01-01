// ===============================
// DFX – Direct Freight Exchange
// index.js (logo-only update)
// ===============================

const express = require("express");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const multer = require("multer");
const Stripe = require("stripe");
const nodemailer = require("nodemailer");

const app = express();

/* ===============================
   LOGO (Base64 embedded)
   =============================== */
const LOGO_BASE64 = `
data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...REDACTED_FOR_LENGTH...
`;

/* ===============================
   Middleware
   =============================== */
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

/* ===============================
   ENV
   =============================== */
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;

/* ===============================
   DB
   =============================== */
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

/* ===============================
   AUTH HELPERS
   =============================== */
function signIn(res, user) {
  const token = jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
  res.cookie("dfx_token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: true,
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

/* ===============================
   LAYOUT (ONLY CHANGE IS LOGO)
   =============================== */
function layout({ title, user, body }) {
  return `
<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${title}</title>

<style>
body {
  margin: 0;
  font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial;
  background: #050607;
  color: #eef7f1;
}
.wrap { max-width: 1200px; margin: 0 auto; padding: 20px; }
a { color: #a3e635; text-decoration: none; }

.nav {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 14px 18px;
  border-radius: 16px;
  background: rgba(13,20,18,.75);
  border: 1px solid rgba(255,255,255,.1);
}

.brand {
  display: flex;
  align-items: center;
  gap: 14px;
}

.brand img {
  height: 46px;
  width: auto;
}

.brandText {
  font-weight: 900;
  font-size: 18px;
}

.sub {
  font-size: 12px;
  color: rgba(238,247,241,.65);
}

.btn {
  padding: 8px 14px;
  border-radius: 10px;
  border: 1px solid rgba(255,255,255,.1);
  background: rgba(6,8,9,.6);
  color: #eef7f1;
}

.btn.green {
  background: linear-gradient(135deg,#22c55e,#a3e635);
  color: #06130b;
  border: none;
  font-weight: 800;
}
</style>
</head>

<body>
<div class="wrap">

  <div class="nav">
    <div class="brand">
      <img src="${LOGO_BASE64}" alt="DFX Logo"/>
      <div>
        <div class="brandText">Direct Freight Exchange</div>
        <div class="sub">No brokers • No games • Direct shipper ↔ carrier</div>
      </div>
    </div>

    <div>
      ${
        user
          ? `<a class="btn" href="/dashboard">Dashboard</a>
             <a class="btn" href="/logout">Logout</a>`
          : `<a class="btn" href="/login">Login</a>
             <a class="btn green" href="/signup">Sign up</a>`
      }
    </div>
  </div>

  ${body}

</div>
</body>
</html>
`;
}

/* ===============================
   ROUTES (UNCHANGED)
   =============================== */

// HOME
app.get("/", (req, res) => {
  const user = getUser(req);
  res.send(
    layout({
      title: "DFX",
      user,
      body: `
        <h1>No hidden rates. No broker games.</h1>
        <p>
          Direct Freight Exchange connects shippers and carriers directly with
          transparent, all-in pricing.
        </p>
      `,
    })
  );
});

// LOGIN
app.get("/login", (req, res) => {
  res.send(
    layout({
      title: "Login",
      user: null,
      body: `
        <form method="POST">
          <input name="email" placeholder="Email" required />
          <input name="password" type="password" placeholder="Password" required />
          <button class="btn green">Login</button>
        </form>
      `,
    })
  );
});

// LOGOUT
app.get("/logout", (req, res) => {
  res.clearCookie("dfx_token");
  res.redirect("/");
});

/* ===============================
   START SERVER
   =============================== */
app.listen(PORT, "0.0.0.0", () =>
  console.log("DFX running on port", PORT)
);
