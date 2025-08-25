const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const { S3Client, PutObjectCommand, DeleteObjectCommand } = require("@aws-sdk/client-s3");
const path = require("path");
require("dotenv").config(); // Add dotenv for environment variables

const app = express();
const port = process.env.PORT || 5000;
const publicDomain = process.env.PUBLIC_DOMAIN || "https://vasya010-backend1-10db.twc1.net";
const jwtSecret = process.env.JWT_SECRET || "your_jwt_secret_123";

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

// Global error handler
app.use((err, req, res, next) => {
  console.error("Global error:", err.message);
  res.status(500).json({ error: `Internal server error: ${err.message}` });
});

// Multer configuration
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
  limits: {
    fileSize: 5 * 1024 * 1024, // Limit file size to 5MB
  },
});

// MySQL connection pool
const dbConfig = {
  host: process.env.DB_HOST || "vh452.timeweb.ru",
  user: process.env.DB_USER || "cs51703_kgadmin",
  password: process.env.DB_PASSWORD || "Vasya11091109",
  database: process.env.DB_NAME || "cs51703_kgadmin",
  port: process.env.DB_PORT || 3306,
  connectionLimit: 10,
};
const pool = mysql.createPool(dbConfig);

// JWT authentication middleware
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    console.error("Authentication error: Token missing");
    return res.status(401).json({ error: "Token missing" });
  }
  try {
    const decoded = jwt.verify(token, jwtSecret);
    console.log("Token verified:", decoded);

    const connection = await pool.getConnection();
    const [users] = await connection.execute("SELECT id, role FROM users1 WHERE id = ? AND token = ?", [decoded.id, token]);
    connection.release();

    if (users.length === 0) {
      console.error("Authentication error: Token not found in database");
      return res.status(401).json({ error: "Invalid token" });
    }

    req.user = decoded;
    next();
  } catch (error) {
    console.error("Authentication error:", error.message);
    res.status(401).json({ error: "Invalid token" });
  }
};

// Database connection test and admin setup
async function testDatabaseConnection() {
  try {
    const connection = await pool.getConnection();
    console.log("Database connection established successfully!");

    // Create users1 table if it doesn't exist
    const [tables] = await connection.execute("SHOW TABLES LIKE 'users1'");
    if (tables.length === 0) {
      console.log("Table users1 does not exist, creating...");
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
          token TEXT DEFAULT NULL
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci
      `);
    } else {
      const [columns] = await connection.execute("SHOW COLUMNS FROM users1 LIKE 'token'");
      if (columns.length === 0) {
        console.log("Column token does not exist, adding...");
        await connection.execute("ALTER TABLE users1 ADD token TEXT DEFAULT NULL");
      }
      const [indexes] = await connection.execute("SHOW INDEX FROM users1 WHERE Column_name = 'email' AND Non_unique = 0");
      if (indexes.length === 0) {
        console.log("Unique index for email does not exist, adding...");
        await connection.execute("ALTER TABLE users1 ADD UNIQUE (email)");
      }
    }

    // Create properties table if it doesn't exist
    const [propTables] = await connection.execute("SHOW TABLES LIKE 'properties'");
    if (propTables.length === 0) {
      console.log("Table properties does not exist, creating...");
      await connection.execute(`
        CREATE TABLE properties (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          type_id VARCHAR(255) DEFAULT NULL,
          \`condition\` VARCHAR(255) DEFAULT NULL,
          series VARCHAR(255) DEFAULT NULL,
          zhk_id VARCHAR(255) DEFAULT NULL,
          document_id INT NOT NULL,
          owner_name VARCHAR(255) DEFAULT NULL,
          curator_ids TEXT DEFAULT NULL,
          price TEXT NOT NULL,
          unit VARCHAR(50) DEFAULT NULL,
          rukprice VARCHAR(50) NOT NULL,
          mkv VARCHAR(12) NOT NULL,
          room VARCHAR(10) DEFAULT NULL,
          phone VARCHAR(50) DEFAULT NULL,
          district_id VARCHAR(255) DEFAULT NULL,
          subdistrict_id VARCHAR(255) DEFAULT NULL,
          address TEXT DEFAULT NULL,
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
          etaj VARCHAR(255) NOT NULL,
          etajnost VARCHAR(255) NOT NULL
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
      `);
    }

    const adminEmail = process.env.ADMIN_EMAIL || "admin@example.com";
    const adminPassword = process.env.ADMIN_PASSWORD || "admin123";
    const hashedPassword = await bcrypt.hash(adminPassword, 10);
    console.log("Hashed admin password:", hashedPassword);

    const [existingAdmin] = await connection.execute("SELECT id FROM users1 WHERE email = ?", [adminEmail]);

    if (existingAdmin.length === 0) {
      console.log("Admin does not exist, creating...");
      const token = jwt.sign({ id: 1, role: "SUPER_ADMIN" }, jwtSecret, { expiresIn: "30d" });
      await connection.execute(
        "INSERT INTO users1 (first_name, last_name, email, phone, role, password, token) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ["Admin", "User", adminEmail, "123456789", "SUPER_ADMIN", hashedPassword, token]
      );
    } else {
      console.log("Admin exists, updating password and token...");
      const token = jwt.sign({ id: existingAdmin[0].id, role: "SUPER_ADMIN" }, jwtSecret, { expiresIn: "30d" });
      await connection.execute("UPDATE users1 SET password = ?, token = ? WHERE email = ?", [hashedPassword, token, adminEmail]);
    }

    console.log("Admin login details:");
    console.log(`Email: ${adminEmail}`);
    console.log(`Password: ${adminPassword}`);
    console.log("Role: SUPER_ADMIN");

    const [rows] = await connection.execute("SELECT 1 AS test");
    if (rows.length > 0) {
      console.log("Database is functioning correctly!");
      const [tablesList] = await connection.execute("SHOW TABLES");
      console.log("Tables in database:", tablesList.map((t) => t[`Tables_in_${dbConfig.database}`]));
    }
    connection.release();
  } catch (error) {
    console.error("Database connection error:", error.message);
    if (error.code === "ECONNREFUSED") {
      console.error("MySQL server not running or incorrect host/port.");
    }
  }
}

testDatabaseConnection();

// Test endpoint
app.get("/api/message", (req, res) => {
  res.json({ message: "Hello from Ala-Too backend!" });
});

// Admin login endpoint
app.post("/api/admin/login", async (req, res) => {
  const { email, password } = req.body;
  console.log("Login attempt:", { email });

  if (!email || !password) {
    console.error("Error: Email or password missing");
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, first_name, last_name, email, phone, role, password, profile_picture AS photoUrl, token FROM users1 WHERE email = ?",
      [email]
    );
    console.log("Database query result:", rows.length > 0 ? "User found" : "User not found");

    if (rows.length === 0) {
      connection.release();
      return res.status(401).json({ error: "Invalid email or user not found" });
    }

    const user = rows[0];
    if (!user.password) {
      console.error("Error: User password not set");
      connection.release();
      return res.status(500).json({ error: "User password not set" });
    }

    console.log("Hashed password from DB:", user.password);
    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log("Password comparison result:", isPasswordValid);

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

    console.log("Login successful, token generated and saved");
    connection.release();
    res.json({ message: "Authorization successful", user: userResponse, token });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({ error: `Internal server error: ${error.message}` });
  }
});

// Logout endpoint
app.post("/api/logout", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    await connection.execute("UPDATE users1 SET token = NULL WHERE id = ?", [req.user.id]);
    connection.release();
    console.log("Logout successful, token invalidated for user ID:", req.user.id);
    res.json({ message: "Logout successful" });
  } catch (error) {
    console.error("Logout error:", error.message);
    res.status(500).json({ error: `Internal server error: ${error.message}` });
  }
});

// Get all users (protected)
app.get("/api/users", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, first_name, last_name, email, phone, role, profile_picture AS photoUrl FROM users1"
    );
    console.log("Users retrieved from DB:", rows.length);
    connection.release();
    res.json(
      rows.map((user) => ({
        ...user,
        name: `${user.first_name} ${user.last_name}`,
        photoUrl: user.photoUrl ? `https://s3.twcstorage.ru/${bucketName}/${user.photoUrl}` : null,
      }))
    );
  } catch (error) {
    console.error("Error retrieving users:", error.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Create new user (protected, SUPER_ADMIN only)
app.post("/api/users", authenticate, upload.single("photo"), async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Access denied: Not SUPER_ADMIN");
    return res.status(403).json({ error: "Access denied: SUPER_ADMIN role required" });
  }

  const { email, name, phone, role, password } = req.body;
  const photo = req.file;

  console.log("Input data for user creation:", { email, name, phone, role, hasPhoto: !!photo });

  if (!email || !name || !phone || !role || !password) {
    console.error("Error: Not all fields provided", { email, name, phone, role, password });
    return res.status(400).json({ error: "All fields, including password, are required" });
  }

  if (typeof password !== "string") {
    console.error("Error: Password must be a string", { password, type: typeof password });
    return res.status(400).json({ error: "Password must be a string" });
  }

  const [first_name, last_name = ""] = name.split(" ");
  const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
  const profile_picture = photo ? `${uniqueSuffix}${path.extname(photo.originalname)}` : null;

  try {
    const connection = await pool.getConnection();

    const [existingUser] = await connection.execute("SELECT id FROM users1 WHERE email = ?", [email]);
    if (existingUser.length > 0) {
      connection.release();
      console.error("Error: Email already exists", { email });
      return res.status(400).json({ error: "User with this email already exists" });
    }

    if (photo) {
      const uploadParams = {
        Bucket: bucketName,
        Key: profile_picture,
        Body: photo.buffer,
        ContentType: photo.mimetype,
      };
      await s3Client.send(new PutObjectCommand(uploadParams));
      console.log(`Photo uploaded to S3: ${profile_picture}`);
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    console.log("Hashed password for new user:", hashedPassword);

    const [result] = await connection.execute(
      "INSERT INTO users1 (first_name, last_name, email, phone, role, password, profile_picture) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [first_name, last_name, email, phone, role, hashedPassword, profile_picture]
    );
    const userId = result.insertId;
    const token = jwt.sign({ id: userId, role }, jwtSecret, { expiresIn: "30d" });
    await connection.execute("UPDATE users1 SET token = ? WHERE id = ?", [token, userId]);
    console.log("New user created, ID:", userId, "Token saved:", token);

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

// Update user (protected, SUPER_ADMIN only)
app.put("/api/users/:id", authenticate, upload.single("photo"), async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Access denied: Not SUPER_ADMIN");
    return res.status(403).json({ error: "Access denied: SUPER_ADMIN role required" });
  }

  const { id } = req.params;
  const { email, name, phone, role } = req.body;
  const photo = req.file;

  console.log("Input data for user update:", { id, email, name, phone, role, hasPhoto: !!photo });

  if (!email || !name || !phone || !role) {
    console.error("Error: Not all fields provided");
    return res.status(400).json({ error: "All fields are required" });
  }

  const [first_name, last_name = ""] = name.split(" ");
  const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
  let profile_picture = null;

  try {
    const connection = await pool.getConnection();
    const [existingUsers] = await connection.execute("SELECT profile_picture FROM users1 WHERE id = ?", [id]);
    if (existingUsers.length === 0) {
      connection.release();
      console.error("User not found by ID:", id);
      return res.status(404).json({ error: "User not found" });
    }

    const [emailCheck] = await connection.execute("SELECT id FROM users1 WHERE email = ? AND id != ?", [email, id]);
    if (emailCheck.length > 0) {
      connection.release();
      console.error("Error: Email already exists", { email });
      return res.status(400).json({ error: "User with this email already exists" });
    }

    const existingPhoto = existingUsers[0].profile_picture;
    profile_picture = existingPhoto;

    if (photo) {
      profile_picture = `${uniqueSuffix}${path.extname(photo.originalname)}`;
      const uploadParams = {
        Bucket: bucketName,
        Key: profile_picture,
        Body: photo.buffer,
        ContentType: photo.mimetype,
      };
      await s3Client.send(new PutObjectCommand(uploadParams));
      console.log(`New photo uploaded to S3: ${profile_picture}`);

      if (existingPhoto) {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: existingPhoto }));
        console.log(`Old photo deleted from S3: ${existingPhoto}`);
      }
    }

    const [result] = await connection.execute(
      "UPDATE users1 SET first_name = ?, last_name = ?, email = ?, phone = ?, role = ?, profile_picture = ? WHERE id = ?",
      [first_name, last_name, email, phone, role, profile_picture, id]
    );

    if (result.affectedRows === 0) {
      connection.release();
      return res.status(404).json({ error: "User not found" });
    }
    console.log("User updated, ID:", id);

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

// Delete user (protected, SUPER_ADMIN only)
app.delete("/api/users/:id", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Access denied: Not SUPER_ADMIN");
    return res.status(403).json({ error: "Access denied: SUPER_ADMIN role required" });
  }

  const { id } = req.params;

  try {
    const connection = await pool.getConnection();
    const [users] = await connection.execute("SELECT profile_picture FROM users1 WHERE id = ?", [id]);
    if (users.length === 0) {
      connection.release();
      console.error("User not found by ID:", id);
      return res.status(404).json({ error: "User not found" });
    }

    const profile_picture = users[0].profile_picture;
    if (profile_picture) {
      await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: profile_picture }));
      console.log(`Photo deleted from S3: ${profile_picture}`);
    }

    const [result] = await connection.execute("DELETE FROM users1 WHERE id = ?", [id]);
    if (result.affectedRows === 0) {
      connection.release();
      return res.status(404).json({ error: "User not found" });
    }
    console.log("User deleted, ID:", id);

    connection.release();
    res.json({ message: "User successfully deleted" });
  } catch (error) {
    console.error("Error deleting user:", error.message);
    res.status(500).json({ error: `Internal server error: ${error.message}` });
  }
});

// Create new property (protected, SUPER_ADMIN or REALTOR)
app.post("/api/properties", authenticate, upload.fields([
  { name: "photos", maxCount: 10 },
  { name: "document", maxCount: 1 },
]), async (req, res) => {
  if (!["SUPER_ADMIN", "REALTOR"].includes(req.user.role)) {
    console.error("Access denied: Not SUPER_ADMIN or REALTOR");
    return res.status(403).json({ error: "Access denied: SUPER_ADMIN or REALTOR role required" });
  }

  const { type_id, condition, series, zhk_id, owner_name, curator_ids, price, unit, rukprice, mkv, room, phone, district_id, subdistrict_id, address, notes, description, status, owner_id, etaj, etajnost } = req.body;
  const photos = req.files["photos"] ? req.files["photos"].map((file) => ({
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
    console.error("Error: Not all required fields provided", { type_id, price, rukprice, mkv, address, etaj, etajnost });
    return res.status(400).json({ error: "All required fields (type_id, price, rukprice, mkv, address, etaj, etajnost) must be provided" });
  }

  if (isNaN(parseFloat(price)) || isNaN(parseFloat(rukprice)) || isNaN(parseFloat(mkv)) || isNaN(parseInt(etaj)) || isNaN(parseInt(etajnost))) {
    console.error("Error: Numeric fields are invalid", { price, rukprice, mkv, etaj, etajnost });
    return res.status(400).json({ error: "Fields price, rukprice, mkv, etaj, etajnost must be numeric" });
  }

  let finalCuratorIds = curator_ids || (req.user.role === "REALTOR" ? req.user.id.toString() : null);
  if (req.user.role === "REALTOR" && curator_ids && curator_ids !== req.user.id.toString()) {
    console.error("Error: REALTOR can only set themselves as curator", { curator_ids, userId: req.user.id });
    return res.status(403).json({ error: "REALTOR can only set themselves as curator" });
  }

  try {
    for (const photo of photos) {
      const uploadParams = {
        Bucket: bucketName,
        Key: photo.filename,
        Body: photo.buffer,
        ContentType: photo.mimetype,
      };
      await s3Client.send(new PutObjectCommand(uploadParams));
      console.log(`Image uploaded to S3: ${photo.filename}`);
    }

    if (document) {
      const uploadParams = {
        Bucket: bucketName,
        Key: document.filename,
        Body: document.buffer,
        ContentType: document.mimetype,
      };
      await s3Client.send(new PutObjectCommand(uploadParams));
      console.log(`Document uploaded to S3: ${document.filename}`);
    }

    const connection = await pool.getConnection();
    const photosJson = JSON.stringify(photos.map(img => img.filename));

    const [result] = await connection.execute(
      `INSERT INTO properties (
        type_id, \`condition\`, series, zhk_id, document_id, owner_name, curator_ids, price, unit, rukprice, mkv, room, phone, 
        district_id, subdistrict_id, address, notes, description, latitude, longitude, photos, document, status, owner_id, etaj, etajnost
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        type_id || null,
        condition || null,
        series || null,
        zhk_id || null,
        0,
        owner_name || null,
        finalCuratorIds,
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
        null,
        null,
        photosJson,
        document ? document.filename : null,
        status || null,
        owner_id || null,
        etaj,
        etajnost,
      ]
    );
    console.log("New property created, ID:", result.insertId);

    const newProperty = {
      id: result.insertId,
      type_id,
      condition,
      series,
      zhk_id,
      document_id: 0,
      owner_name,
      curator_ids: finalCuratorIds,
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
      photos: photos.map((img) => `https://s3.twcstorage.ru/${bucketName}/${img.filename}`),
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

// Update property (protected, SUPER_ADMIN or REALTOR)
app.put("/api/properties/:id", authenticate, upload.fields([
  { name: "photos", maxCount: 10 },
  { name: "document", maxCount: 1 },
]), async (req, res) => {
  if (!["SUPER_ADMIN", "REALTOR"].includes(req.user.role)) {
    console.error("Access denied: Not SUPER_ADMIN or REALTOR");
    return res.status(403).json({ error: "Access denied: SUPER_ADMIN or REALTOR role required" });
  }

  const { id } = req.params;
  const { type_id, condition, series, zhk_id, owner_name, curator_ids, price, unit, rukprice, mkv, room, phone, district_id, subdistrict_id, address, notes, description, status, owner_id, etaj, etajnost, existingPhotos } = req.body;
  const photos = req.files["photos"] ? req.files["photos"].map((file) => ({
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
    console.error("Error: Not all required fields provided", { type_id, price, rukprice, mkv, address, etaj, etajnost });
    return res.status(400).json({ error: "All required fields (type_id, price, rukprice, mkv, address, etaj, etajnost) must be provided" });
  }

  if (isNaN(parseFloat(price)) || isNaN(parseFloat(rukprice)) || isNaN(parseFloat(mkv)) || isNaN(parseInt(etaj)) || isNaN(parseInt(etajnost))) {
    console.error("Error: Numeric fields are invalid", { price, rukprice, mkv, etaj, etajnost });
    return res.status(400).json({ error: "Fields price, rukprice, mkv, etaj, etajnost must be numeric" });
  }

  let finalCuratorIds = curator_ids || (req.user.role === "REALTOR" ? req.user.id.toString() : null);
  if (req.user.role === "REALTOR" && curator_ids && curator_ids !== req.user.id.toString()) {
    console.error("Error: REALTOR can only set themselves as curator", { curator_ids, userId: req.user.id });
    return res.status(403).json({ error: "REALTOR can only set themselves as curator" });
  }

  try {
    const connection = await pool.getConnection();
    const [existingProperties] = await connection.execute("SELECT photos, document, curator_ids FROM properties WHERE id = ?", [id]);
    if (existingProperties.length === 0) {
      connection.release();
      console.error("Property not found by ID:", id);
      return res.status(404).json({ error: "Property not found" });
    }

    const existingProperty = existingProperties[0];
    if (req.user.role === "REALTOR" && existingProperty.curator_ids !== req.user.id.toString()) {
      connection.release();
      console.error("Error: REALTOR is not the curator of this property", { id, curator_ids: existingProperty.curator_ids, userId: req.user.id });
      return res.status(403).json({ error: "You do not have permission to edit this property" });
    }

    let photoFiles = [];
    if (existingProperty.photos) {
      try {
        photoFiles = JSON.parse(existingProperty.photos);
        if (!Array.isArray(photoFiles)) {
          console.warn(`Photos field is not an array for ID: ${id}, data: ${existingProperty.photos}`);
          photoFiles = existingProperty.photos.split(",").filter(p => p.trim());
        }
      } catch (error) {
        console.warn(`Error parsing photos for ID: ${id}, Error: ${error.message}, Data: ${existingProperty.photos}`);
        photoFiles = existingProperty.photos.split(",").filter(p => p.trim());
      }
    }

    // Parse existingPhotos from request
    let existingPhotosList = [];
    if (existingPhotos) {
      try {
        existingPhotosList = JSON.parse(existingPhotos);
        if (!Array.isArray(existingPhotosList)) {
          console.warn(`existingPhotos is not an array for ID: ${id}, data: ${existingPhotos}`);
          existingPhotosList = [];
        }
      } catch (error) {
        console.warn(`Error parsing existingPhotos for ID: ${id}, Error: ${error.message}, Data: ${existingPhotos}`);
        existingPhotosList = [];
      }
    }

    // Upload new photos to S3
    for (const photo of photos) {
      const uploadParams = {
        Bucket: bucketName,
        Key: photo.filename,
        Body: photo.buffer,
        ContentType: photo.mimetype,
      };
      await s3Client.send(new PutObjectCommand(uploadParams));
      console.log(`New image uploaded to S3: ${photo.filename}`);
    }

    // Delete photos that are not in existingPhotosList
    const photosToDelete = photoFiles.filter(p => !existingPhotosList.includes(p));
    for (const oldPhoto of photosToDelete) {
      try {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: oldPhoto }));
        console.log(`Old image deleted from S3: ${oldPhoto}`);
      } catch (error) {
        console.warn(`Failed to delete old image from S3: ${oldPhoto}, Error: ${error.message}`);
      }
    }

    // Combine existing and new photos
    const newPhotos = [...existingPhotosList, ...photos.map(img => img.filename)];
    const photosJson = newPhotos.length > 0 ? JSON.stringify(newPhotos) : null;

    // Handle document update
    let newDocument = existingProperty.document;
    if (document) {
      const uploadParams = {
        Bucket: bucketName,
        Key: document.filename,
        Body: document.buffer,
        ContentType: document.mimetype,
      };
      await s3Client.send(new PutObjectCommand(uploadParams));
      console.log(`New document uploaded to S3: ${document.filename}`);

      if (existingProperty.document) {
        try {
          await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: existingProperty.document }));
          console.log(`Old document deleted from S3: ${existingProperty.document}`);
        } catch (error) {
          console.warn(`Failed to delete old document from S3: ${existingProperty.document}, Error: ${error.message}`);
        }
      }
      newDocument = document.filename;
    }

    const [result] = await connection.execute(
      `UPDATE properties SET
        type_id = ?, \`condition\` = ?, series = ?, zhk_id = ?, document_id = ?, owner_name = ?, curator_ids = ?, price = ?, unit = ?, rukprice = ?, mkv = ?, room = ?, phone = ?,
        district_id = ?, subdistrict_id = ?, address = ?, notes = ?, description = ?, photos = ?, document = ?, status = ?, owner_id = ?, etaj = ?, etajnost = ?
        WHERE id = ?`,
      [
        type_id || null,
        condition || null,
        series || null,
        zhk_id || null,
        0,
        owner_name || null,
        finalCuratorIds,
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

    if (result.affectedRows === 0) {
      connection.release();
      return res.status(404).json({ error: "Property not found" });
    }
    console.log("Property updated, ID:", id);

    const updatedProperty = {
      id: parseInt(id),
      type_id,
      condition,
      series,
      zhk_id,
      document_id: 0,
      owner_name,
      curator_ids: finalCuratorIds,
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
      photos: newPhotos.map((img) => `https://s3.twcstorage.ru/${bucketName}/${img}`),
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

// Delete property (protected, SUPER_ADMIN or REALTOR)
app.delete("/api/properties/:id", authenticate, async (req, res) => {
  if (!["SUPER_ADMIN", "REALTOR"].includes(req.user.role)) {
    console.error("Access denied: Not SUPER_ADMIN or REALTOR");
    return res.status(403).json({ error: "Access denied: SUPER_ADMIN or REALTOR role required" });
  }

  const { id } = req.params;

  try {
    const connection = await pool.getConnection();
    const [properties] = await connection.execute("SELECT photos, document, curator_ids FROM properties WHERE id = ?", [id]);
    if (properties.length === 0) {
      connection.release();
      console.error("Property not found by ID:", id);
      return res.status(404).json({ error: "Property not found" });
    }

    const existingProperty = properties[0];
    if (req.user.role === "REALTOR" && existingProperty.curator_ids !== req.user.id.toString()) {
      connection.release();
      console.error("Error: REALTOR is not the curator of this property", { id, curator_ids: existingProperty.curator_ids, userId: req.user.id });
      return res.status(403).json({ error: "You do not have permission to delete this property" });
    }

    let photoFiles = [];
    if (existingProperty.photos) {
      try {
        photoFiles = JSON.parse(existingProperty.photos);
        if (!Array.isArray(photoFiles)) {
          console.warn(`Photos field is not an array for ID: ${id}, data: ${existingProperty.photos}`);
          photoFiles = existingProperty.photos.split(",").filter(p => p.trim());
        }
      } catch (error) {
        console.warn(`Error parsing photos for ID: ${id}, Error: ${error.message}, Data: ${existingProperty.photos}`);
        photoFiles = existingProperty.photos.split(",").filter(p => p.trim());
      }
      for (const img of photoFiles) {
        try {
          await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: img }));
          console.log(`Image deleted from S3: ${img}`);
        } catch (error) {
          console.warn(`Failed to delete image from S3: ${img}, Error: ${error.message}`);
        }
      }
    }
    if (existingProperty.document) {
      try {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: existingProperty.document }));
        console.log(`Document deleted from S3: ${existingProperty.document}`);
      } catch (error) {
        console.warn(`Failed to delete document from S3: ${existingProperty.document}, Error: ${error.message}`);
      }
    }

    const [result] = await connection.execute("DELETE FROM properties WHERE id = ?", [id]);
    if (result.affectedRows === 0) {
      connection.release();
      return res.status(404).json({ error: "Property not found" });
    }
    console.log("Property deleted, ID:", id);

    connection.release();
    res.json({ message: "Property successfully deleted" });
  } catch (error) {
    console.error("Error deleting property:", error.message);
    res.status(500).json({ error: `Internal server error: ${error.message}` });
  }
});

// Get all properties (protected)
app.get("/api/properties", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      `SELECT id, type_id, \`condition\`, series, zhk_id, document_id, owner_name, curator_ids, price, unit, rukprice, mkv, room, phone, 
       district_id, subdistrict_id, address, notes, description, latitude, longitude, created_at, photos, document, status, owner_id, etaj, etajnost 
       FROM properties`
    );
    console.log("Properties retrieved from DB:", rows.length);

    const properties = rows.map((row) => {
      let parsedPhotos = [];
      if (row.photos) {
        try {
          parsedPhotos = JSON.parse(row.photos);
          if (!Array.isArray(parsedPhotos)) {
            console.warn(`Photos field is not an array for ID: ${row.id}, data: ${row.photos}`);
            parsedPhotos = row.photos.split(",").filter(p => p.trim());
          }
        } catch (error) {
          console.warn(`Error parsing photos for ID: ${row.id}, Error: ${error.message}, Data: ${row.photos}`);
          parsedPhotos = row.photos.split(",").filter(p => p.trim());
        }
      }

      return {
        ...row,
        photos: parsedPhotos.map((img) => `https://s3.twcstorage.ru/${bucketName}/${img}`),
        document: row.document ? `https://s3.twcstorage.ru/${bucketName}/${row.document}` : null,
        date: new Date(row.created_at).toLocaleDateString("ru-RU"),
        time: new Date(row.created_at).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" }),
      };
    });

    connection.release();
    res.json(properties);
  } catch (error) {
    console.error("Error retrieving properties:", error.message);
    res.status(500).json({ error: `Internal server error: ${error.message}` });
  }
});

// Get all listings for AdminDashboard (protected)
app.get("/api/listings", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, type_id, price, rukprice, mkv, status, address, created_at FROM properties"
    );
    console.log("Listings retrieved from properties:", rows.length);

    const listings = rows.map((row) => ({
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

// Start server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
  console.log(`Public access: ${publicDomain}:${port}`);
});