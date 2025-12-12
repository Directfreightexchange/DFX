const express = require("express");
const app = express();

const PORT = process.env.PORT || 3000;

app.get("/", (req, res) => {
  res.send(`
    <h1>Direct Freight Exchange</h1>
    <p>Your website is LIVE.</p>
    <p>If you see this page, deployment works.</p>
  `);
});

app.listen(PORT, "0.0.0.0", () => {
  console.log("Server running on port", PORT);
});
