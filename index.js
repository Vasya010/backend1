const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const { S3Client, PutObjectCommand, DeleteObjectCommand } = require("@aws-sdk/client-s3");
const path = require("path");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 5000;
const publicDomain = process.env.PUBLIC_DOMAIN || "https://vasya010-backend1-10db.twc1.net";
const jwtSecret = process.env.JWT_SECRET || "your_jwt_secret_123";

// Valid roles for validation
const VALID_ROLES = ['USER', 'ADMIN', 'SUPER_ADMIN', 'REALTOR'];

// S3 Configuration
const s3Client = new S3Client({
  region: process.env.S3_REGION || "ru-1",
  endpoint: process.env.S3_ENDPOINT || "https://s3.twcstorage.ru",
  credentials: {
    accessKeyId: process.env.S3_ACCESS_KEY || "GIMZKRMOGP4F0MOTLVCE",
    secretAccessKey: process.env.S3_SECRET_KEY || "WvhFfIzzCkITUrXfD8JfoDne7LmBhnNzDuDBj89I",
  },
  forcePathStyle: true,
});

const bucketName = process.env.S3_BUCKET || "a2c31109-3cf2c97b-aca1-42b0-a822-3e0ade279447";

// Middleware
app.use(cors());
app.use(express.json());

// Global Error Handler
app.use((err, req, res, next) => {
  console.error("Global error:", err.stack);
  res.status(500).json({ error: `Internal server error: ${err.message}` });
});

// Multer Configuration
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|pdf|doc|docx/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    if (extname && mimetype) {
      console.log(`File ${file.originalname} accepted for upload`);
      return cb(null, true);
    }
    console.error(`File ${file.originalname} rejected: invalid type`);
    cb(new Error("Only images (jpeg, jpg, png) and documents (pdf, doc, docx) are allowed"));
  },
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
});

// MySQL Connection Pool
const dbConfig = {
  host: process.env.DB_HOST || "vh452.timeweb.ru",
  user: process.env.DB_USER || "cs51703_kgadmin",
  password: process.env.DB_PASSWORD || "Vasya11091109",
  database: process.env.DB_NAME || "cs51703_kgadmin",
  port: process.env.DB_PORT || 3306,
  connectionLimit: 10,
};
const pool = mysql.createPool(dbConfig);

// JWT Authentication Middleware
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    console.error("Authentication error: Token missing");
    return res.status(401).json({ error: "Token missing" });
  }
  try {
    const decoded = jwt.verify(token, jwtSecret);
    const connection = await pool.getConnection();
    const [users] = await connection.execute(
      "SELECT id, role, first_name, last_name FROM users1 WHERE id = ? AND token = ?",
      [decoded.id, token]
    );
    connection.release();

    if (users.length === 0) {
      console.error("Authentication error: Invalid token for user ID:", decoded.id);
      return res.status(401).json({ error: "Invalid token" });
    }

    req.user = { ...decoded, first_name: users[0].first_name, last_name: users[0].last_name };
    next();
  } catch (error) {
    console.error("Authentication error:", error.message);
    res.status(401).json({ error: "Invalid token" });
  }
};

// Database Connection Test and Setup
async function testDatabaseConnection() {
  let connection;
  try {
    connection = await pool.getConnection();
    console.log("Database connection established successfully!");

    // Create users1 table
    const [tables] = await connection.execute("SHOW TABLES LIKE 'users1'");
    if (tables.length === 0) {
      console.log("Creating users1 table...");
      await connection.execute(`
        CREATE TABLE users1 (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          first_name VARCHAR(255) NOT NULL,
          last_name VARCHAR(255) NOT NULL,
          role VARCHAR(50) NOT NULL,
          email VARCHAR(255) NOT NULL UNIQUE,
          phone VARCHAR(255) NOT NULL,
          profile_picture VARCHAR(255) DEFAULT NULL,
          password VARCHAR(255) NOT NULL,
          token TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci
      `);
    }

    // Create properties table
    const [propTables] = await connection.execute("SHOW TABLES LIKE 'properties'");
    if (propTables.length === 0) {
      console.log("Creating properties table...");
      await connection.execute(`
        CREATE TABLE properties (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          type_id VARCHAR(255) DEFAULT NULL,
          \`condition\` VARCHAR(255) DEFAULT NULL,
          series VARCHAR(255) DEFAULT NULL,
          zhk_id VARCHAR(255) DEFAULT NULL,
          document_id INT NOT NULL DEFAULT 0,
          owner_name VARCHAR(255) DEFAULT NULL,
          curator_id INT UNSIGNED DEFAULT NULL,
          price DECIMAL(15,2) NOT NULL,
          unit VARCHAR(50) DEFAULT NULL,
          rukprice DECIMAL(15,2) NOT NULL,
          mkv DECIMAL(10,2) NOT NULL,
          room VARCHAR(10) DEFAULT NULL,
          phone VARCHAR(50) DEFAULT NULL,
          district_id VARCHAR(255) DEFAULT NULL,
          subdistrict_id VARCHAR(255) DEFAULT NULL,
          address TEXT NOT NULL,
          notes TEXT DEFAULT NULL,
          description TEXT DEFAULT NULL,
          latitude DECIMAL(10,6) DEFAULT NULL,
          longitude DECIMAL(10,6) DEFAULT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          photos TEXT DEFAULT NULL,
          document VARCHAR(255) DEFAULT NULL,
          status VARCHAR(50) DEFAULT NULL,
          owner_id INT DEFAULT NULL,
          etaj INT NOT NULL,
          etajnost INT NOT NULL,
          FOREIGN KEY (curator_id) REFERENCES users1(id) ON DELETE SET NULL
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
      `);
    }

    // Create jk table
    const [jkTables] = await connection.execute("SHOW TABLES LIKE 'jk'");
    if (jkTables.length === 0) {
      console.log("Creating jk table...");
      await connection.execute(`
        CREATE TABLE jk (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          description TEXT DEFAULT NULL,
          address VARCHAR(255) DEFAULT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci
      `);
    }

    // Create districts table
    const [districtTables] = await connection.execute("SHOW TABLES LIKE 'districts'");
    if (districtTables.length === 0) {
      console.log("Creating districts table...");
      await connection.execute(`
        CREATE TABLE districts (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci
      `);
    }

    // Create subdistricts table
    const [subdistrictTables] = await connection.execute("SHOW TABLES LIKE 'subdistricts'");
    if (subdistrictTables.length === 0) {
      console.log("Creating subdistricts table...");
      await connection.execute(`
        CREATE TABLE subdistricts (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          district_id INT UNSIGNED NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (district_id) REFERENCES districts(id) ON DELETE CASCADE
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci
      `);
    }

    // Setup admin user
    const adminEmail = process.env.ADMIN_EMAIL || "admin@example.com";
    const adminPassword = process.env.ADMIN_PASSWORD || "admin123";
    const hashedPassword = await bcrypt.hash(adminPassword, 10);
    const [existingAdmin] = await connection.execute("SELECT id FROM users1 WHERE email = ?", [adminEmail]);

    if (existingAdmin.length === 0) {
      console.log("Creating admin user...");
      const token = jwt.sign({ id: 1, role: "SUPER_ADMIN" }, jwtSecret, { expiresIn: "30d" });
      await connection.execute(
        "INSERT INTO users1 (first_name, last_name, email, phone, role, password, token) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ["Admin", "User", adminEmail, "123456789", "SUPER_ADMIN", hashedPassword, token]
      );
    } else {
      console.log("Updating admin user...");
      const token = jwt.sign({ id: existingAdmin[0].id, role: "SUPER_ADMIN" }, jwtSecret, { expiresIn: "30d" });
      await connection.execute("UPDATE users1 SET password = ?, token = ? WHERE email = ?", [hashedPassword, token, adminEmail]);
    }

    console.log("Admin login details:", { email: adminEmail, password: adminPassword, role: "SUPER_ADMIN" });
  } catch (error) {
    console.error("Database setup error:", error.message);
    if (error.code === "ECONNREFUSED") {
      console.error("MySQL server not running or incorrect host/port.");
    }
  } finally {
    if (connection) connection.release();
  }
}

testDatabaseConnection();

// Test Endpoint
app.get("/api/message", (req, res) => {
  res.json({ message: "Hello from Ala-Too backend!" });
});

// Admin Login Endpoint
app.post("/api/admin/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    console.error("Login error: Missing email or password");
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, first_name, last_name, email, phone, role, password, profile_picture AS photoUrl FROM users1 WHERE email = ?",
      [email]
    );

    if (rows.length === 0) {
      connection.release();
      return res.status(401).json({ error: "Invalid email or user not found" });
    }

    const user = rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      connection.release();
      return res.status(401).json({ error: "Invalid password" });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, jwtSecret, { expiresIn: "30d" });
    await connection.execute("UPDATE users1 SET token = ? WHERE id = ?", [token, user.id]);

    const userResponse = {
      id: user.id,
      first_name: user.first_name,
      last_name: user.last_name,
      email: user.email,
      phone: user.phone,
      role: user.role,
      photoUrl: user.photoUrl ? `https://s3.twcstorage.ru/${bucketName}/${user.photoUrl}` : null,
      name: `${user.first_name} ${user.last_name}`.trim(),
      token,
    };

    connection.release();
    res.json({ message: "Authorization successful", user: userResponse, token });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({ error: `Internal server error: ${error.message}` });
  }
});

// Logout Endpoint
app.post("/api/logout", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    await connection.execute("UPDATE users1 SET token = NULL WHERE id = ?", [req.user.id]);
    connection.release();
    res.json({ message: "Logout successful" });
  } catch (error) {
    console.error("Logout error:", error.message);
    res.status(500).json({ error: `Internal server error: ${error.message}` });
  }
});

// Get All Users (Protected, SUPER_ADMIN only)
app.get("/api/users", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Access denied: SUPER_ADMIN role required" });
  }

  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, first_name, last_name, email, phone, role, profile_picture AS photoUrl FROM users1"
    );
    connection.release();

    res.json(
      rows.map((user) => ({
        ...user,
        name: `${user.first_name} ${user.last_name}`.trim(),
        photoUrl: user.photoUrl ? `https://s3.twcstorage.ru/${bucketName}/${user.photoUrl}` : null,
      }))
    );
  } catch (error) {
    console.error("Error retrieving users:", error.message);
    res.status(500).json({ error: `Internal server error: ${error.message}` });
  }
});

// Create New User (Protected, SUPER_ADMIN only)
app.post("/api/users", authenticate, upload.single("photo"), async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Access denied: SUPER_ADMIN role required" });
  }

  const { email, name, phone, role, password } = req.body;
  const photo = req.file;

  if (!email || !name || !phone || !role || !password) {
    return res.status(400).json({ error: "All fields (email, name, phone, role, password) are required" });
  }

  // Validate role
  if (!VALID_ROLES.includes(role)) {
    return res.status(400).json({ error: `Invalid role. Must be one of: ${VALID_ROLES.join(', ')}` });
  }

  const [first_name, last_name = ""] = name.split(" ");
  const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
  const profile_picture = photo ? `${uniqueSuffix}${path.extname(photo.originalname)}` : null;

  try {
    const connection = await pool.getConnection();
    const [existingUser] = await connection.execute("SELECT id FROM users1 WHERE email = ?", [email]);
    if (existingUser.length > 0) {
      connection.release();
      return res.status(400).json({ error: "User with this email already exists" });
    }

    if (photo) {
      await s3Client.send(new PutObjectCommand({
        Bucket: bucketName,
        Key: profile_picture,
        Body: photo.buffer,
        ContentType: photo.mimetype,
      }));
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await connection.execute(
      "INSERT INTO users1 (first_name, last_name, email, phone, role, password, profile_picture) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [first_name, last_name, email, phone, role, hashedPassword, profile_picture]
    );

    const userId = result.insertId;
    const token = jwt.sign({ id: userId, role }, jwtSecret, { expiresIn: "30d" });
    await connection.execute("UPDATE users1 SET token = ? WHERE id = ?", [token, userId]);

    const newUser = {
      id: userId,
      first_name,
      last_name,
      email,
      phone,
      role,
      photoUrl: profile_picture ? `https://s3.twcstorage.ru/${bucketName}/${profile_picture}` : null,
      name: `${first_name} ${last_name}`.trim(),
      token,
    };

    connection.release();
    res.json(newUser);
  } catch (error) {
    console.error("Error creating user:", error.message);
    res.status(500).json({ error: `Internal server error: ${error.message}` });
  }
});

// Update User (Protected, SUPER_ADMIN only)
app.put("/api/users/:id", authenticate, upload.single("photo"), async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Access denied: SUPER_ADMIN role required" });
  }

  const { id } = req.params;
  const { email, name, phone, role } = req.body;
  const photo = req.file;

  if (!email || !name || !phone || !role) {
    return res.status(400).json({ error: "All fields (email, name, phone, role) are required" });
  }

  // Validate role
  if (!VALID_ROLES.includes(role)) {
    return res.status(400).json({ error: `Invalid role. Must be one of: ${VALID_ROLES.join(', ')}` });
  }

  const [first_name, last_name = ""] = name.split(" ");
  const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
  let profile_picture = null;

  try {
    const connection = await pool.getConnection();
    const [existingUsers] = await connection.execute("SELECT profile_picture FROM users1 WHERE id = ?", [id]);
    if (existingUsers.length === 0) {
      connection.release();
      return res.status(404).json({ error: "User not found" });
    }

    const [emailCheck] = await connection.execute("SELECT id FROM users1 WHERE email = ? AND id != ?", [email, id]);
    if (emailCheck.length > 0) {
      connection.release();
      return res.status(400).json({ error: "User with this email already exists" });
    }

    profile_picture = existingUsers[0].profile_picture;
    if (photo) {
      profile_picture = `${uniqueSuffix}${path.extname(photo.originalname)}`;
      await s3Client.send(new PutObjectCommand({
        Bucket: bucketName,
        Key: profile_picture,
        Body: photo.buffer,
        ContentType: photo.mimetype,
      }));

      if (existingUsers[0].profile_picture) {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: existingUsers[0].profile_picture }));
      }
    }

    await connection.execute(
      "UPDATE users1 SET first_name = ?, last_name = ?, email = ?, phone = ?, role = ?, profile_picture = ? WHERE id = ?",
      [first_name, last_name, email, phone, role, profile_picture, id]
    );

    const updatedUser = {
      id: parseInt(id),
      first_name,
      last_name,
      email,
      phone,
      role,
      photoUrl: profile_picture ? `https://s3.twcstorage.ru/${bucketName}/${profile_picture}` : null,
      name: `${first_name} ${last_name}`.trim(),
    };

    connection.release();
    res.json(updatedUser);
  } catch (error) {
    console.error("Error updating user:", error.message);
    res.status(500).json({ error: `Internal server error: ${error.message}` });
  }
});

// Delete User (Protected, SUPER_ADMIN only)
app.delete("/api/users/:id", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Access denied: SUPER_ADMIN role required" });
  }

  const { id } = req.params;

  try {
    const connection = await pool.getConnection();
    const [users] = await connection.execute("SELECT profile_picture FROM users1 WHERE id = ?", [id]);
    if (users.length === 0) {
      connection.release();
      return res.status(404).json({ error: "User not found" });
    }

    if (users[0].profile_picture) {
      await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: users[0].profile_picture }));
    }

    await connection.execute("DELETE FROM users1 WHERE id = ?", [id]);
    connection.release();
    res.json({ message: "User successfully deleted" });
  } catch (error) {
    console.error("Error deleting user:", error.message);
    res.status(500).json({ error: `Internal server error: ${error.message}` });
  }
});

// Get All JK (Protected)
app.get("/api/jk", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute("SELECT id, name FROM jk");
    connection.release();
    res.json(rows);
  } catch (error) {
    console.error("Error retrieving JK:", error.message);
    res.status(500).json({ error: `Internal server error: ${error.message}` });
  }
});

// Get All Districts (Protected)
app.get("/api/districts", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute("SELECT id, name FROM districts");
    connection.release();
    res.json(rows);
  } catch (error) {
    console.error("Error retrieving districts:", error.message);
    res.status(500).json({ error: `Internal server error: ${error.message}` });
  }
});

// Get Subdistricts by District ID (Protected)
app.get("/api/subdistricts", authenticate, async (req, res) => {
  const { district_id } = req.query;
  if (!district_id) {
    return res.status(400).json({ error: "district_id is required" });
  }

  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, name FROM subdistricts WHERE district_id = ?",
      [district_id]
    );
    connection.release();
    res.json(rows);
  } catch (error) {
    console.error("Error retrieving subdistricts:", error.message);
    res.status(500).json({ error: `Internal server error: ${error.message}` });
  }
});

// Create New Property (Protected, SUPER_ADMIN or REALTOR)
app.post("/api/properties", authenticate, upload.fields([
  { name: "photos", maxCount: 10 },
  { name: "document", maxCount: 1 },
]), async (req, res) => {
  if (!["SUPER_ADMIN", "REALTOR"].includes(req.user.role)) {
    return res.status(403).json({ error: "Access denied: SUPER_ADMIN or REALTOR role required" });
  }

  const { type_id, condition, series, zhk_id, owner_name, curator_id, price, unit, rukprice, mkv, room, phone, district_id, subdistrict_id, address, notes, description, status, owner_id, etaj, etajnost } = req.body;
  const photos = req.files["photos"] ? req.files["photos"].map(file => ({
    filename: `${Date.now()}-${Math.round(Math.random() * 1e9)}${path.extname(file.originalname)}`,
    buffer: file.buffer,
    mimetype: file.mimetype,
  })) : [];
  const document = req.files["document"] ? {
    filename: `${Date.now()}-${Math.round(Math.random() * 1e9)}${path.extname(req.files["document"][0].originalname)}`,
    buffer: req.files["document"][0].buffer,
    mimetype: req.files["document"][0].mimetype,
  } : null;

  if (!type_id || !price || !rukprice || !mkv || !address || !etaj || !etajnost) {
    return res.status(400).json({ error: "All required fields (type_id, price, rukprice, mkv, address, etaj, etajnost) must be provided" });
  }

  if (isNaN(parseFloat(price)) || isNaN(parseFloat(rukprice)) || isNaN(parseFloat(mkv)) || isNaN(parseInt(etaj)) || isNaN(parseInt(etajnost))) {
    return res.status(400).json({ error: "Fields price, rukprice, mkv, etaj, etajnost must be numeric" });
  }

  let finalCuratorId = curator_id || (req.user.role === "REALTOR" ? req.user.id : null);
  if (req.user.role === "REALTOR" && curator_id && curator_id != req.user.id) {
    return res.status(403).json({ error: "Realtor can only assign themselves as curator" });
  }

  try {
    const connection = await pool.getConnection();

    // Validate zhk_id
    if (zhk_id) {
      const [jkCheck] = await connection.execute("SELECT id FROM jk WHERE id = ?", [zhk_id]);
      if (jkCheck.length === 0) {
        connection.release();
        return res.status(400).json({ error: "Invalid JK ID" });
      }
    }

    // Validate district_id
    if (district_id) {
      const [districtCheck] = await connection.execute("SELECT id FROM districts WHERE id = ?", [district_id]);
      if (districtCheck.length === 0) {
        connection.release();
        return res.status(400).json({ error: "Invalid district ID" });
      }
    }

    // Validate subdistrict_id
    if (subdistrict_id) {
      const [subdistrictCheck] = await connection.execute("SELECT id FROM subdistricts WHERE id = ? AND district_id = ?", [subdistrict_id, district_id || null]);
      if (subdistrictCheck.length === 0) {
        connection.release();
        return res.status(400).json({ error: "Invalid subdistrict ID or subdistrict does not belong to the selected district" });
      }
    }

    // Validate curator_id
    let curatorName = null;
    if (finalCuratorId) {
      const [curatorCheck] = await connection.execute(
        "SELECT id, CONCAT(first_name, ' ', last_name) AS curator_name FROM users1 WHERE id = ?",
        [finalCuratorId]
      );
      if (curatorCheck.length === 0) {
        connection.release();
        return res.status(400).json({ error: "Invalid curator ID" });
      }
      curatorName = curatorCheck[0].curator_name;
    }

    // Upload files to S3
    for (const photo of photos) {
      await s3Client.send(new PutObjectCommand({
        Bucket: bucketName,
        Key: photo.filename,
        Body: photo.buffer,
        ContentType: photo.mimetype,
      }));
    }

    if (document) {
      await s3Client.send(new PutObjectCommand({
        Bucket: bucketName,
        Key: document.filename,
        Body: document.buffer,
        ContentType: document.mimetype,
      }));
    }

    const photosJson = JSON.stringify(photos.map(img => img.filename));
    const [result] = await connection.execute(
      `INSERT INTO properties (
        type_id, \`condition\`, series, zhk_id, document_id, owner_name, curator_id, price, unit, rukprice, mkv, room, phone, 
        district_id, subdistrict_id, address, notes, description, photos, document, status, owner_id, etaj, etajnost
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        type_id || null,
        condition || null,
        series || null,
        zhk_id || null,
        0,
        owner_name || null,
        finalCuratorId,
        price,
        unit || null,
        rukprice,
        mkv,
        room || null,
        phone || null,
        district_id || null,
        subdistrict_id || null,
        address,
        notes || null,
        description || null,
        photosJson,
        document ? document.filename : null,
        status || null,
        owner_id || null,
        etaj,
        etajnost,
      ]
    );

    const newProperty = {
      id: result.insertId,
      type_id,
      condition,
      series,
      zhk_id,
      document_id: 0,
      owner_name,
      curator_id: finalCuratorId,
      curator_name: curatorName || null,
      price,
      unit,
      rukprice,
      mkv,
      room,
      phone,
      district_id,
      subdistrict_id,
      address,
      notes,
      description,
      status,
      owner_id,
      etaj,
      etajnost,
      photos: photos.map(img => `https://s3.twcstorage.ru/${bucketName}/${img.filename}`),
      document: document ? `https://s3.twcstorage.ru/${bucketName}/${document.filename}` : null,
      date: new Date().toLocaleDateString("ru-RU"),
      time: new Date().toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" }),
    };

    connection.release();
    res.json(newProperty);
  } catch (error) {
    console.error("Error creating property:", error.message);
    res.status(500).json({ error: `Internal server error: ${error.message}` });
  }
});

// Update Property (Protected, SUPER_ADMIN or REALTOR)
app.put("/api/properties/:id", authenticate, upload.fields([
  { name: "photos", maxCount: 10 },
  { name: "document", maxCount: 1 },
]), async (req, res) => {
  if (!["SUPER_ADMIN", "REALTOR"].includes(req.user.role)) {
    return res.status(403).json({ error: "Access denied: SUPER_ADMIN or REALTOR role required" });
  }

  const { id } = req.params;
  const { type_id, condition, series, zhk_id, owner_name, curator_id, price, unit, rukprice, mkv, room, phone, district_id, subdistrict_id, address, notes, description, status, owner_id, etaj, etajnost, existingPhotos } = req.body;
  const photos = req.files["photos"] ? req.files["photos"].map(file => ({
    filename: `${Date.now()}-${Math.round(Math.random() * 1e9)}${path.extname(file.originalname)}`,
    buffer: file.buffer,
    mimetype: file.mimetype,
  })) : [];
  const document = req.files["document"] ? {
    filename: `${Date.now()}-${Math.round(Math.random() * 1e9)}${path.extname(req.files["document"][0].originalname)}`,
    buffer: req.files["document"][0].buffer,
    mimetype: req.files["document"][0].mimetype,
  } : null;

  if (!type_id || !price || !rukprice || !mkv || !address || !etaj || !etajnost) {
    return res.status(400).json({ error: "All required fields (type_id, price, rukprice, mkv, address, etaj, etajnost) must be provided" });
  }

  if (isNaN(parseFloat(price)) || isNaN(parseFloat(rukprice)) || isNaN(parseFloat(mkv)) || isNaN(parseInt(etaj)) || isNaN(parseInt(etajnost))) {
    return res.status(400).json({ error: "Fields price, rukprice, mkv, etaj, etajnost must be numeric" });
  }

  let finalCuratorId = curator_id || (req.user.role === "REALTOR" ? req.user.id : null);
  if (req.user.role === "REALTOR" && curator_id && curator_id != req.user.id) {
    return res.status(403).json({ error: "Realtor can only assign themselves as curator" });
  }

  try {
    const connection = await pool.getConnection();
    const [existingProperties] = await connection.execute("SELECT photos, document, curator_id FROM properties WHERE id = ?", [id]);
    if (existingProperties.length === 0) {
      connection.release();
      return res.status(404).json({ error: "Property not found" });
    }

    const existingProperty = existingProperties[0];
    if (req.user.role === "REALTOR" && existingProperty.curator_id && existingProperty.curator_id != req.user.id) {
      connection.release();
      return res.status(403).json({ error: "You do not have permission to edit this property" });
    }

    // Validate zhk_id
    if (zhk_id) {
      const [jkCheck] = await connection.execute("SELECT id FROM jk WHERE id = ?", [zhk_id]);
      if (jkCheck.length === 0) {
        connection.release();
        return res.status(400).json({ error: "Invalid JK ID" });
      }
    }

    // Validate district_id
    if (district_id) {
      const [districtCheck] = await connection.execute("SELECT id FROM districts WHERE id = ?", [district_id]);
      if (districtCheck.length === 0) {
        connection.release();
        return res.status(400).json({ error: "Invalid district ID" });
      }
    }

    // Validate subdistrict_id
    if (subdistrict_id) {
      const [subdistrictCheck] = await connection.execute("SELECT id FROM subdistricts WHERE id = ? AND district_id = ?", [subdistrict_id, district_id || null]);
      if (subdistrictCheck.length === 0) {
        connection.release();
        return res.status(400).json({ error: "Invalid subdistrict ID or subdistrict does not belong to the selected district" });
      }
    }

    // Validate curator_id
    let curatorName = null;
    if (finalCuratorId) {
      const [curatorCheck] = await connection.execute(
        "SELECT id, CONCAT(first_name, ' ', last_name) AS curator_name FROM users1 WHERE id = ?",
        [finalCuratorId]
      );
      if (curatorCheck.length === 0) {
        connection.release();
        return res.status(400).json({ error: "Invalid curator ID" });
      }
      curatorName = curatorCheck[0].curator_name;
    }

    // Handle photos
    let photoFiles = [];
    if (existingProperty.photos) {
      try {
        photoFiles = JSON.parse(existingProperty.photos) || [];
      } catch (error) {
        console.warn(`Error parsing photos for ID: ${id}, falling back to split:`, existingProperty.photos);
        photoFiles = existingProperty.photos.split(",").filter(p => p.trim());
      }
    }

    let existingPhotosList = [];
    if (existingPhotos) {
      try {
        existingPhotosList = JSON.parse(existingPhotos) || [];
      } catch (error) {
        console.warn(`Error parsing existingPhotos for ID: ${id}:`, existingPhotos);
        existingPhotosList = [];
      }
    }

    // Upload new photos
    for (const photo of photos) {
      await s3Client.send(new PutObjectCommand({
        Bucket: bucketName,
        Key: photo.filename,
        Body: photo.buffer,
        ContentType: photo.mimetype,
      }));
    }

    // Delete old photos not in existingPhotosList
    const photosToDelete = photoFiles.filter(p => !existingPhotosList.includes(p));
    for (const oldPhoto of photosToDelete) {
      try {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: oldPhoto }));
      } catch (error) {
        console.warn(`Failed to delete old photo from S3: ${oldPhoto}`);
      }
    }

    // Combine photos
    const newPhotos = [...existingPhotosList, ...photos.map(img => img.filename)];
    const photosJson = newPhotos.length > 0 ? JSON.stringify(newPhotos) : null;

    // Handle document
    let newDocument = existingProperty.document;
    if (document) {
      await s3Client.send(new PutObjectCommand({
        Bucket: bucketName,
        Key: document.filename,
        Body: document.buffer,
        ContentType: document.mimetype,
      }));
      if (existingProperty.document) {
        try {
          await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: existingProperty.document }));
        } catch (error) {
          console.warn(`Failed to delete old document from S3: ${existingProperty.document}`);
        }
      }
      newDocument = document.filename;
    }

    await connection.execute(
      `UPDATE properties SET
        type_id = ?, \`condition\` = ?, series = ?, zhk_id = ?, document_id = ?, owner_name = ?, curator_id = ?, price = ?, unit = ?, rukprice = ?, mkv = ?, room = ?, phone = ?,
        district_id = ?, subdistrict_id = ?, address = ?, notes = ?, description = ?, photos = ?, document = ?, status = ?, owner_id = ?, etaj = ?, etajnost = ?
        WHERE id = ?`,
      [
        type_id || null,
        condition || null,
        series || null,
        zhk_id || null,
        0,
        owner_name || null,
        finalCuratorId,
        price,
        unit || null,
        rukprice,
        mkv,
        room || null,
        phone || null,
        district_id || null,
        subdistrict_id || null,
        address,
        notes || null,
        description || null,
        photosJson,
        newDocument,
        status || null,
        owner_id || null,
        etaj,
        etajnost,
        id,
      ]
    );

    const updatedProperty = {
      id: parseInt(id),
      type_id,
      condition,
      series,
      zhk_id,
      document_id: 0,
      owner_name,
      curator_id: finalCuratorId,
      curator_name: curatorName || null,
      price,
      unit,
      rukprice,
      mkv,
      room,
      phone,
      district_id,
      subdistrict_id,
      address,
      notes,
      description,
      status,
      owner_id,
      etaj,
      etajnost,
      photos: newPhotos.map(img => `https://s3.twcstorage.ru/${bucketName}/${img}`),
      document: newDocument ? `https://s3.twcstorage.ru/${bucketName}/${newDocument}` : null,
      date: new Date().toLocaleDateString("ru-RU"),
      time: new Date().toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" }),
    };

    connection.release();
    res.json(updatedProperty);
  } catch (error) {
    console.error("Error updating property:", error.message);
    res.status(500).json({ error: `Internal server error: ${error.message}` });
  }
});

// Delete Property (Protected, SUPER_ADMIN or REALTOR)
app.delete("/api/properties/:id", authenticate, async (req, res) => {
  if (!["SUPER_ADMIN", "REALTOR"].includes(req.user.role)) {
    return res.status(403).json({ error: "Access denied: SUPER_ADMIN or REALTOR role required" });
  }

  const { id } = req.params;

  try {
    const connection = await pool.getConnection();
    const [properties] = await connection.execute("SELECT photos, document, curator_id FROM properties WHERE id = ?", [id]);
    if (properties.length === 0) {
      connection.release();
      return res.status(404).json({ error: "Property not found" });
    }

    const existingProperty = properties[0];
    if (req.user.role === "REALTOR" && existingProperty.curator_id && existingProperty.curator_id != req.user.id) {
      connection.release();
      return res.status(403).json({ error: "You do not have permission to delete this property" });
    }

    let photoFiles = [];
    if (existingProperty.photos) {
      try {
        photoFiles = JSON.parse(existingProperty.photos) || [];
      } catch (error) {
        console.warn(`Error parsing photos for ID: ${id}:`, existingProperty.photos);
        photoFiles = existingProperty.photos.split(",").filter(p => p.trim());
      }
      for (const img of photoFiles) {
        try {
          await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: img }));
        } catch (error) {
          console.warn(`Failed to delete image from S3: ${img}`);
        }
      }
    }

    if (existingProperty.document) {
      try {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: existingProperty.document }));
      } catch (error) {
        console.warn(`Failed to delete document from S3: ${existingProperty.document}`);
      }
    }

    await connection.execute("DELETE FROM properties WHERE id = ?", [id]);
    connection.release();
    res.json({ message: "Property successfully deleted" });
  } catch (error) {
    console.error("Error deleting property:", error.message);
    res.status(500).json({ error: `Internal server error: ${error.message}` });
  }
});

// Get All Properties (Protected)
app.get("/api/properties", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      `SELECT p.*, CONCAT(u.first_name, ' ', u.last_name) AS curator_name
       FROM properties p
       LEFT JOIN users1 u ON p.curator_id = u.id`
    );

    const properties = rows.map(row => {
      let parsedPhotos = [];
      if (row.photos) {
        try {
          parsedPhotos = JSON.parse(row.photos) || [];
        } catch (error) {
          console.warn(`Error parsing photos for ID: ${row.id}:`, row.photos);
          parsedPhotos = row.photos.split(",").filter(p => p.trim());
        }
      }

      return {
        ...row,
        photos: parsedPhotos.map(img => `https://s3.twcstorage.ru/${bucketName}/${img}`),
        document: row.document ? `https://s3.twcstorage.ru/${bucketName}/${row.document}` : null,
        date: new Date(row.created_at).toLocaleDateString("ru-RU"),
        time: new Date(row.created_at).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" }),
        curator_name: row.curator_name || null,
      };
    });

    connection.release();
    res.json(properties);
  } catch (error) {
    console.error("Error retrieving properties:", error.message);
    res.status(500).json({ error: `Internal server error: ${error.message}` });
  }
});

// Get All Listings for AdminDashboard (Protected)
app.get("/api/listings", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, type_id, price, rukprice, mkv, status, address, created_at FROM properties"
    );

    const listings = rows.map(row => ({
      id: row.id,
      date: new Date(row.created_at).toLocaleDateString("ru-RU"),
      time: new Date(row.created_at).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" }),
      area: row.mkv,
      district: row.address,
      price: row.price,
      status: row.status,
    }));

    connection.release();
    res.json(listings);
  } catch (error) {
    console.error("Error retrieving listings:", error.message);
    res.status(500).json({ error: `Internal server error: ${error.message}` });
  }
});

// Get All Districts and Subdistricts
app.get("/api/raions", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [districts] = await connection.execute("SELECT id, name, NULL AS parentRaionId FROM districts");
    const [subdistricts] = await connection.execute("SELECT id, name, district_id AS parentRaionId FROM subdistricts");
    
    const raions = [
      ...districts.map(row => ({ id: row.id, name: row.name, parentRaionId: null, isRaion: true })),
      ...subdistricts.map(row => ({ id: row.id, name: row.name, parentRaionId: row.parentRaionId, isRaion: false })),
    ];

    connection.release();
    res.json(raions);
  } catch (error) {
    console.error("Error retrieving districts and subdistricts:", error.message);
    res.status(500).json({ error: `Internal server error: ${error.message}` });
  }
});

// Redirect Properties (Protected, SUPER_ADMIN only)
app.patch("/api/properties/redirect", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Access denied: SUPER_ADMIN role required" });
  }

  const { propertyIds, curator_id } = req.body;

  if (!Array.isArray(propertyIds) || !curator_id) {
    return res.status(400).json({ error: "propertyIds must be an array, curator_id is required" });
  }

  try {
    const connection = await pool.getConnection();
    const [curatorCheck] = await connection.execute(
      "SELECT id, CONCAT(first_name, ' ', last_name) AS curator_name FROM users1 WHERE id = ?",
      [curator_id]
    );
    if (curatorCheck.length === 0) {
      connection.release();
      return res.status(400).json({ error: "Invalid curator ID" });
    }

    const [existingProperties] = await connection.execute(
      "SELECT id FROM properties WHERE id IN (?)",
      [propertyIds]
    );
    if (existingProperties.length !== propertyIds.length) {
      connection.release();
      return res.status(404).json({ error: "Some properties not found" });
    }

    const [result] = await connection.execute(
      "UPDATE properties SET curator_id = ? WHERE id IN (?)",
      [curator_id, propertyIds]
    );

    connection.release();
    res.json({ message: "Properties successfully redirected", affectedRows: result.affectedRows });
  } catch (error) {
    console.error("Error redirecting properties:", error.message);
    res.status(500).json({ error: `Internal server error: ${error.message}` });
  }
});

// Start Server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
  console.log(`Public access: ${publicDomain}:${port}`);
});