const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");

const app = express();
const port = 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Database connection configuration
const dbConfig = {
  host: "localhost",
  user: "cs51703_kgadmin",
  password: "Vasya11091109",
  database: "cs51703_kgadmin",
};

// Test endpoint
app.get("/api/message", (req, res) => {
  res.json({ message: "Привет от бэкенда Ala-Too!" });
});

// Admin login endpoint
app.post("/api/admin/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    // Create database connection
    const connection = await mysql.createConnection(dbConfig);

    // Query to find user by email and check if role is admin
    const [rows] = await connection.execute(
      "SELECT * FROM users1 WHERE email = ? AND role = 'admin'",
      [email]
    );

    if (rows.length === 0) {
      await connection.end();
      return res.status(401).json({ error: "Invalid email or not an admin" });
    }

    const user = rows[0];

    // Compare provided password with hashed password in database
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      await connection.end();
      return res.status(401).json({ error: "Invalid password" });
    }

    // Close connection
    await connection.end();

    // Return success response with user details (excluding password)
    res.json({
      message: "Login successful",
      user: {
        id: user.id,
        first_name: user.first_name,
        last_name: user.last_name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Сервер запущен на http://localhost:${port}`);
});