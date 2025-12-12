const express = require("express");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL ? { rejectUnauthorized: false } : undefined
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

app.get("/", (req, res) => {
  res.send("<h1>Direct Freight Exchange</h1><p>Website is LIVE ✅</p><a href='/signup'>Sign up</a>");
});

app.get("/signup", (req, res) => {
  res.send(`
    <h2>Sign up</h2>
    <form method="POST">
      <input name="email" placeholder="Email" required /><br/><br/>
      <input name="password" type="password" placeholder="Password" required /><br/><br/>
      <select name="role">
        <option value="SHIPPER">Shipper</option>
        <option value="CARRIER">Carrier</option>
      </select><br/><br/>
      <button>Create account</button>
    </form>
  `);
});

app.post("/signup", async (req, res) => {
  const { email, password, role } = req.body;
  const hash = await bcrypt.hash(password, 10);
  await pool.query(
    "INSERT INTO users (email, password_hash, role) VALUES ($1,$2,$3)",
    [email.toLowerCase(), hash, role]
  );
  res.redirect("/");
});

initDb().then(() => {
  app.listen(PORT, "0.0.0.0", () => {
    console.log("Server running on port", PORT);
  });
});
