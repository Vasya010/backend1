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




app.use(cors({
  origin: (origin, callback) => {
    callback(null, origin || "*");
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
}));


// JSON Middleware
app.use(express.json());

// Global Error Handler
app.use((err, req, res, next) => {
  console.error("Global error:", {
    message: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method
  });
  res.status(500).json({ error: `Внутренняя ошибка сервера: ${err.message}` });
});

// Multer Configuration
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    // List of common image MIME types
    const allowedImageTypes = [
      'image/jpeg',          // .jpg, .jpeg
      'image/png',           // .png
      'image/gif',           // .gif
      'image/bmp',           // .bmp
      'image/tiff',          // .tiff, .tif
      'image/webp',          // .webp
      'image/heic',          // .heic (iPhone HEIF format)
      'image/heif',          // .heif
      'image/svg+xml',       // .svg
      'image/x-icon',        // .ico
      'image/vnd.microsoft.icon', // .ico (alternate MIME type)
      'image/jp2',           // .jp2 (JPEG 2000)
      'image/avif'           // .avif
    ];

    if (allowedImageTypes.includes(file.mimetype)) {
      console.log(`File ${file.originalname} accepted for upload`);
      cb(null, true);
    } else {
      console.error(`File ${file.originalname} rejected: Invalid MIME type ${file.mimetype}`);
      cb(new Error('Недопустимый формат файла. Разрешены только изображения (JPEG, PNG, GIF, BMP, TIFF, WebP, HEIC, HEIF, SVG, ICO, JP2, AVIF).'), false);
    }

  },
  limits: { fileSize: 100 * 1024 * 1024 }, // Лимит 100 МБ
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


app.use('/images', express.static(path.join(__dirname, 'public/images')));

// JWT Authentication Middleware
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    console.error("Authentication error: Token missing");
    return res.status(401).json({ error: "Токен отсутствует" });
  }
  try {
    const decoded = jwt.verify(token, jwtSecret);
    const connection = await pool.getConnection();
    const [users] = await connection.execute(
      "SELECT id, role, first_name, last_name, balance, email, phone, created_at FROM users1 WHERE id = ? AND token = ?",
      [decoded.id, token]
    );
    connection.release();

    if (users.length === 0) {
      console.error("Authentication error: Invalid token for user ID:", decoded.id);
      return res.status(401).json({ error: "Недействительный токен" });
    }

    const [promotionOrderTables] = await connection.execute("SHOW TABLES LIKE 'promotion_orders'");
    if (promotionOrderTables.length === 0) {
      console.log("Creating promotion_orders table...");
      await connection.execute(`
        CREATE TABLE promotion_orders (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          user_id INT UNSIGNED NOT NULL,
          property_id VARCHAR(255) NOT NULL,
          property_title VARCHAR(255) NOT NULL,
          duration VARCHAR(100) NOT NULL,
          placement VARCHAR(100) NOT NULL,
          amount DECIMAL(12,2) NOT NULL,
          payment_method VARCHAR(100) NOT NULL,
          status VARCHAR(50) DEFAULT 'processing',
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users1(id) ON DELETE CASCADE
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
      `);
    }

    req.user = {
      ...decoded,
      first_name: users[0].first_name,
      last_name: users[0].last_name,
      balance: users[0].balance,
      email: users[0].email,
      phone: users[0].phone,
      created_at: users[0].created_at,
    };
    next();
  } catch (error) {
    console.error("Authentication error:", {
      message: error.message,
      stack: error.stack
    });
    res.status(401).json({ error: "Недействительный токен" });
  }
};

const buildUserResponse = (user) => ({
  id: user.id,
  first_name: user.first_name,
  last_name: user.last_name,
  email: user.email,
  phone: user.phone,
  role: user.role,
  balance: user.balance !== undefined && user.balance !== null ? Number(user.balance) : 0,
  name: `${user.first_name} ${user.last_name}`.trim(),
  photoUrl: user.photoUrl || null,
  created_at: user.created_at
    ? new Date(user.created_at).toISOString()
    : null,
});

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
          balance DECIMAL(12,2) NOT NULL DEFAULT 0,
          token TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci
      `);
    } else {
      const [balanceColumns] = await connection.execute(
        "SHOW COLUMNS FROM users1 LIKE 'balance'"
      );
      if (balanceColumns.length === 0) {
        console.log("Adding balance column to users1 table...");
        await connection.execute(
          "ALTER TABLE users1 ADD COLUMN balance DECIMAL(12,2) NOT NULL DEFAULT 0"
        );
      }

      const [createdAtColumns] = await connection.execute(
        "SHOW COLUMNS FROM users1 LIKE 'created_at'"
      );
      if (createdAtColumns.length === 0) {
        console.log("Adding created_at column to users1 table...");
        await connection.execute(
          "ALTER TABLE users1 ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        );
      }
    }

    // Create properties table
    const [propTables] = await connection.execute("SHOW TABLES LIKE 'properties'");
    if (propTables.length === 0) {
      console.log("Creating properties table...");
      await connection.execute(`
        CREATE TABLE properties (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          type_id VARCHAR(255) DEFAULT NULL,
          repair VARCHAR(255) DEFAULT NULL,
          series VARCHAR(255) DEFAULT NULL,
          zhk_id VARCHAR(255) DEFAULT NULL,
          document_id INT NOT NULL DEFAULT 0,
          owner_name VARCHAR(255) DEFAULT NULL,
          owner_phone VARCHAR(50) DEFAULT NULL,
          curator_id INT UNSIGNED DEFAULT NULL,
          price DECIMAL(15,2) NOT NULL,
          unit VARCHAR(50) DEFAULT NULL,
          rukprice DECIMAL(15,2) NOT NULL,
          mkv DECIMAL(10,2) NOT NULL,
          rooms VARCHAR(10) DEFAULT NULL,
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
    } else {
      // Check and add owner_phone column if not exists
      const [ownerPhoneColumns] = await connection.execute(
        "SHOW COLUMNS FROM properties LIKE 'owner_phone'"
      );
      if (ownerPhoneColumns.length === 0) {
        console.log("Adding owner_phone column to properties table...");
        await connection.execute(
          "ALTER TABLE properties ADD COLUMN owner_phone VARCHAR(50) DEFAULT NULL"
        );
      }

      const [conditionColumns] = await connection.execute(
        "SHOW COLUMNS FROM properties LIKE 'condition'"
      );
      if (conditionColumns.length > 0) {
        console.log("Renaming column 'condition' to 'repair'...");
        await connection.execute("ALTER TABLE properties CHANGE COLUMN `condition` `repair` VARCHAR(255) DEFAULT NULL");
      }

      const [roomColumns] = await connection.execute(
        "SHOW COLUMNS FROM properties LIKE 'room'"
      );
      if (roomColumns.length > 0) {
        console.log("Renaming column 'room' to 'rooms'...");
        await connection.execute("ALTER TABLE properties CHANGE COLUMN `room` `rooms` VARCHAR(10) DEFAULT NULL");
      }
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
    console.error("Database setup error:", {
      message: error.message,
      code: error.code,
      sqlMessage: error.sqlMessage,
      stack: error.stack
    });
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

app.post("/public/auth/register", async (req, res) => {
  const { name, email, password, phone } = req.body || {};

  if (!name || !email || !password) {
    return res.status(400).json({ error: "Имя, email и пароль обязательны" });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: "Пароль должен быть не менее 6 символов" });
  }

  const [firstNameRaw, ...restName] = name.trim().split(/\s+/);
  const first_name = firstNameRaw || "User";
  const last_name = restName.join(" ");
  const normalizedPhone = phone && phone.trim() ? phone.trim() : "Не указан";
    const initialBalance = Number(process.env.INITIAL_USER_BALANCE ?? 0);

  let connection;
  try {
    connection = await pool.getConnection();
    const [existingUser] = await connection.execute("SELECT id FROM users1 WHERE email = ?", [email]);
    if (existingUser.length > 0) {
      return res.status(409).json({ error: "Пользователь с таким email уже существует" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await connection.execute(
      "INSERT INTO users1 (first_name, last_name, email, phone, role, password, balance) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [first_name, last_name, email, normalizedPhone, "USER", hashedPassword, initialBalance]
    );

    const userId = result.insertId;
    const [[createdRow]] = await connection.execute(
      "SELECT created_at FROM users1 WHERE id = ?",
      [userId]
    );
    const token = jwt.sign({ id: userId, role: "USER" }, jwtSecret, { expiresIn: "30d" });
    await connection.execute("UPDATE users1 SET token = ? WHERE id = ?", [token, userId]);

    const user = buildUserResponse({
      id: userId,
      first_name,
      last_name,
      email,
      phone: normalizedPhone,
      role: "USER",
      balance: initialBalance,
      created_at: createdRow?.created_at || new Date(),
    });

    res.status(201).json({
      message: "Регистрация успешна",
      token,
      user,
    });
  } catch (error) {
    console.error("Registration error:", {
      message: error.message,
      stack: error.stack,
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

app.post("/public/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: "Email и пароль обязательны" });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, first_name, last_name, email, phone, role, password, balance, profile_picture AS photoUrl, created_at FROM users1 WHERE email = ?",
      [email]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: "Недействительный email или пользователь не найден" });
    }

    const userRecord = rows[0];
    const isPasswordValid = await bcrypt.compare(password, userRecord.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Недействительный пароль" });
    }

    const token = jwt.sign({ id: userRecord.id, role: userRecord.role }, jwtSecret, { expiresIn: "30d" });
    await connection.execute("UPDATE users1 SET token = ? WHERE id = ?", [token, userRecord.id]);

    const user = buildUserResponse(userRecord);
    res.json({ message: "Авторизация успешна", token, user });
  } catch (error) {
    console.error("Public login error:", {
      message: error.message,
      stack: error.stack,
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

app.post("/public/auth/logout", authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    await connection.execute("UPDATE users1 SET token = NULL WHERE id = ?", [req.user.id]);
    res.json({ message: "Выход выполнен" });
  } catch (error) {
    console.error("Public logout error:", {
      message: error.message,
      stack: error.stack,
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

app.get("/public/auth/profile", authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, first_name, last_name, email, phone, role, balance, profile_picture AS photoUrl FROM users1 WHERE id = ?",
      [req.user.id]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    const user = buildUserResponse(rows[0]);
    res.json({ user });
  } catch (error) {
    console.error("Profile fetch error:", {
      message: error.message,
      stack: error.stack,
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

app.post("/public/payments", authenticate, async (req, res) => {
  const {
    propertyId,
    propertyTitle,
    amount,
    duration,
    placement,
    paymentMethod = "QR",
  } = req.body || {};

  if (!propertyId || !propertyTitle || !amount || !duration || !placement) {
    return res.status(400).json({ error: "propertyId, propertyTitle, amount, duration и placement обязательны" });
  }

  const normalizedAmount = parseFloat(amount);
  if (isNaN(normalizedAmount) || normalizedAmount <= 0) {
    return res.status(400).json({ error: "Сумма должна быть положительным числом" });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();

    const [userRows] = await connection.execute(
      "SELECT balance FROM users1 WHERE id = ? FOR UPDATE",
      [req.user.id]
    );
    if (userRows.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    const currentBalance = parseFloat(userRows[0].balance || 0);
    if (currentBalance < normalizedAmount) {
      await connection.rollback();
      return res.status(400).json({ error: "Недостаточно средств на балансе" });
    }

    const newBalance = currentBalance - normalizedAmount;
    await connection.execute(
      "UPDATE users1 SET balance = ? WHERE id = ?",
      [newBalance, req.user.id]
    );

    const [result] = await connection.execute(
      `INSERT INTO promotion_orders
        (user_id, property_id, property_title, duration, placement, amount, payment_method, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.user.id,
        propertyId,
        propertyTitle,
        duration,
        placement,
        normalizedAmount,
        paymentMethod,
        "processing",
      ]
    );

    await connection.commit();

    res.status(201).json({
      message: "Оплата успешно зарегистрирована",
      order: {
        id: result.insertId,
        property_id: propertyId,
        property_title: propertyTitle,
        duration,
        placement,
        amount: normalizedAmount,
        payment_method: paymentMethod,
        status: "processing",
      },
      balance: newBalance,
    });
  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch (rollbackError) {
        console.error("Rollback error after payment failure:", rollbackError.message);
      }
    }
    console.error("Payment creation error:", {
      message: error.message,
      stack: error.stack,
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

app.get("/public/payments", authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute(
      `SELECT id, property_id, property_title, duration, placement, amount, payment_method, status, created_at
       FROM promotion_orders
       WHERE user_id = ?
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    res.json(rows);
  } catch (error) {
    console.error("Fetch payments error:", {
      message: error.message,
      stack: error.stack,
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Admin Login Endpoint
app.post("/api/admin/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    console.error("Login error: Missing email or password");
    return res.status(400).json({ error: "Email и пароль обязательны" });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, first_name, last_name, email, phone, role, password, profile_picture AS photoUrl FROM users1 WHERE email = ?",
      [email]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: "Недействительный email или пользователь не найден" });
    }

    const user = rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Недействительный пароль" });
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

    res.json({ message: "Авторизация успешна", user: userResponse, token });
  } catch (error) {
    console.error("Login error:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Logout Endpoint
app.post("/api/logout", authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    await connection.execute("UPDATE users1 SET token = NULL WHERE id = ?", [req.user.id]);
    res.json({ message: "Выход успешен" });
  } catch (error) {
    console.error("Logout error:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Get All Users (Protected, SUPER_ADMIN only)
app.get("/api/users", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Доступ запрещён: требуется роль SUPER_ADMIN" });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, first_name, last_name, email, phone, role, profile_picture AS photoUrl FROM users1"
    );

    res.json(
      rows.map((user) => ({
        ...user,
        name: `${user.first_name} ${user.last_name}`.trim(),
        photoUrl: user.photoUrl ? `https://s3.twcstorage.ru/${bucketName}/${user.photoUrl}` : null,
      }))
    );
  } catch (error) {
    console.error("Error retrieving users:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Create New User (Protected, SUPER_ADMIN only)
app.post("/api/users", authenticate, upload.single("photo"), async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Доступ запрещён: требуется роль SUPER_ADMIN" });
  }

  const { email, name, phone, role, password } = req.body;
  const photo = req.file;

  if (!email || !name || !phone || !role || !password) {
    return res.status(400).json({ error: "Все поля (email, name, phone, role, password) обязательны" });
  }

  if (!VALID_ROLES.includes(role)) {
    return res.status(400).json({ error: `Недействительная роль. Должна быть одной из: ${VALID_ROLES.join(', ')}` });
  }

  const [first_name, last_name = ""] = name.split(" ");
  const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
  const profile_picture = photo ? `${uniqueSuffix}${path.extname(photo.originalname)}` : null;

  let connection;
  try {
    connection = await pool.getConnection();
    const [existingUser] = await connection.execute("SELECT id FROM users1 WHERE email = ?", [email]);
    if (existingUser.length > 0) {
      return res.status(400).json({ error: "Пользователь с таким email уже существует" });
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

    res.json(newUser);
  } catch (error) {
    console.error("Error creating user:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Update User (Protected, SUPER_ADMIN only)
app.put("/api/users/:id", authenticate, upload.single("photo"), async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Доступ запрещён: требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;
  const { email, name, phone, role } = req.body;
  const photo = req.file;

  if (!email || !name || !phone || !role) {
    return res.status(400).json({ error: "Все поля (email, name, phone, role) обязательны" });
  }

  if (!VALID_ROLES.includes(role)) {
    return res.status(400).json({ error: `Недействительная роль. Должна быть одной из: ${VALID_ROLES.join(', ')}` });
  }

  const [first_name, last_name = ""] = name.split(" ");
  const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
  let profile_picture = null;

  let connection;
  try {
    connection = await pool.getConnection();
    const [existingUsers] = await connection.execute("SELECT profile_picture FROM users1 WHERE id = ?", [id]);
    if (existingUsers.length === 0) {
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    const [emailCheck] = await connection.execute("SELECT id FROM users1 WHERE email = ? AND id != ?", [email, id]);
    if (emailCheck.length > 0) {
      return res.status(400).json({ error: "Пользователь с таким email уже существует" });
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
        try {
          await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: existingUsers[0].profile_picture }));
        } catch (error) {
          console.warn(`Failed to delete old profile picture from S3: ${existingUsers[0].profile_picture}`);
        }
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

    res.json(updatedUser);
  } catch (error) {
    console.error("Error updating user:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Delete User (Protected, SUPER_ADMIN only)
app.delete("/api/users/:id", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Доступ запрещён: требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;

  let connection;
  try {
    connection = await pool.getConnection();
    const [users] = await connection.execute("SELECT profile_picture FROM users1 WHERE id = ?", [id]);
    if (users.length === 0) {
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    if (users[0].profile_picture) {
      try {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: users[0].profile_picture }));
      } catch (error) {
        console.warn(`Failed to delete profile picture from S3: ${users[0].profile_picture}`);
      }
    }

    await connection.execute("DELETE FROM users1 WHERE id = ?", [id]);
    res.json({ message: "Пользователь успешно удалён" });
  } catch (error) {
    console.error("Error deleting user:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Get All JK (Protected)
app.get("/api/jk", authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute("SELECT id, name, description, address FROM jk");
    res.json(rows);
  } catch (error) {
    console.error("Error retrieving JK:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Create JK (Protected, SUPER_ADMIN only)
app.post("/api/jk", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Доступ запрещён: требуется роль SUPER_ADMIN" });
  }

  const { name, description, address } = req.body;
  if (!name) {
    return res.status(400).json({ error: "Название обязательно" });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    const [existingJk] = await connection.execute("SELECT id FROM jk WHERE name = ?", [name]);
    if (existingJk.length > 0) {
      return res.status(400).json({ error: "ЖК с таким названием уже существует" });
    }

    const [result] = await connection.execute(
      "INSERT INTO jk (name, description, address) VALUES (?, ?, ?)",
      [name, description || null, address || null]
    );

    res.json({ id: result.insertId, name, description, address });
  } catch (error) {
    console.error("Error creating JK:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Update JK (Protected, SUPER_ADMIN only)
app.put("/api/jk/:id", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Доступ запрещён: требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;
  const { name, description, address } = req.body;
  if (!name) {
    return res.status(400).json({ error: "Название обязательно" });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    const [existingJk] = await connection.execute("SELECT id FROM jk WHERE id = ?", [id]);
    if (existingJk.length === 0) {
      return res.status(404).json({ error: "ЖК не найден" });
    }

    const [nameCheck] = await connection.execute("SELECT id FROM jk WHERE name = ? AND id != ?", [name, id]);
    if (nameCheck.length > 0) {
      return res.status(400).json({ error: "ЖК с таким названием уже существует" });
    }

    await connection.execute(
      "UPDATE jk SET name = ?, description = ?, address = ? WHERE id = ?",
      [name, description || null, address || null, id]
    );

    res.json({ id: parseInt(id), name, description, address });
  } catch (error) {
    console.error("Error updating JK:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Delete JK (Protected, SUPER_ADMIN only)
app.delete("/api/jk/:id", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Доступ запрещён: требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;

  let connection;
  try {
    connection = await pool.getConnection();
    const [existingJk] = await connection.execute("SELECT id FROM jk WHERE id = ?", [id]);
    if (existingJk.length === 0) {
      return res.status(404).json({ error: "ЖК не найден" });
    }

    const [linkedProperties] = await connection.execute("SELECT id FROM properties WHERE zhk_id = ?", [id]);
    if (linkedProperties.length > 0) {
      return res.status(400).json({ error: "Нельзя удалить ЖК, связанный с объектами недвижимости" });
    }

    await connection.execute("DELETE FROM jk WHERE id = ?", [id]);
    res.json({ message: "ЖК успешно удалён" });
  } catch (error) {
    console.error("Error deleting JK:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Get All Districts (Protected)
app.get("/api/districts", authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute("SELECT id, name FROM districts");
    res.json(rows);
  } catch (error) {
    console.error("Error retrieving districts:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Публичный эндпоинт для получения списка районов
app.get("/public/districts", async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute("SELECT id, name FROM districts");
    res.json(rows);
  } catch (error) {
    console.error("Ошибка при получении районов:", {
      message: error.message,
      stack: error.stack,
    });
    res.status(500).json({ error: "Внутренняя ошибка сервера" });
  } finally {
    if (connection) connection.release();
  }
});
// Get Subdistricts by District ID (Protected)
app.get("/api/subdistricts", authenticate, async (req, res) => {
  const { district_id } = req.query;
  if (!district_id) {
    return res.status(400).json({ error: "district_id обязателен" });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, name FROM subdistricts WHERE district_id = ?",
      [district_id]
    );
    res.json(rows);
  } catch (error) {
    console.error("Error retrieving subdistricts:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Get All Districts and Subdistricts
app.get("/api/raions", authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    const [districts] = await connection.execute("SELECT id, name, NULL AS parentRaionId FROM districts");
    const [subdistricts] = await connection.execute("SELECT id, name, district_id AS parentRaionId FROM subdistricts");

    const raions = [
      ...districts.map(row => ({ id: row.id, name: row.name, parentRaionId: null, isRaion: true })),
      ...subdistricts.map(row => ({ id: row.id, name: row.name, parentRaionId: row.parentRaionId, isRaion: false })),
    ];

    res.json(raions);
  } catch (error) {
    console.error("Error retrieving districts and subdistricts:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Create District (Protected, SUPER_ADMIN only)
app.post("/api/raions", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Доступ запрещён: требуется роль SUPER_ADMIN" });
  }

  const { name } = req.body;
  if (!name) {
    return res.status(400).json({ error: "Название обязательно" });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    const [existingDistrict] = await connection.execute("SELECT id FROM districts WHERE name = ?", [name]);
    if (existingDistrict.length > 0) {
      return res.status(400).json({ error: "Район с таким названием уже существует" });
    }

    const [result] = await connection.execute(
      "INSERT INTO districts (name) VALUES (?)",
      [name]
    );

    res.json({ id: result.insertId, name, parentRaionId: null, isRaion: true });
  } catch (error) {
    console.error("Ошибка при создании района:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Update District (Protected, SUPER_ADMIN only)
app.put("/api/raions/:id", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Доступ запрещён: требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;
  const { name } = req.body;
  if (!name) {
    return res.status(400).json({ error: "Название обязательно" });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    const [existingDistrict] = await connection.execute("SELECT id FROM districts WHERE id = ?", [id]);
    if (existingDistrict.length === 0) {
      return res.status(404).json({ error: "Район не найден" });
    }

    const [nameCheck] = await connection.execute("SELECT id FROM districts WHERE name = ? AND id != ?", [name, id]);
    if (nameCheck.length > 0) {
      return res.status(400).json({ error: "Район с таким названием уже существует" });
    }

    await connection.execute("UPDATE districts SET name = ? WHERE id = ?", [name, id]);
    res.json({ id: parseInt(id), name, parentRaionId: null, isRaion: true });
  } catch (error) {
    console.error("Ошибка при обновлении района:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Delete District (Protected, SUPER_ADMIN only)
app.delete("/api/raions/:id", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Доступ запрещён: требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;

  let connection;
  try {
    connection = await pool.getConnection();
    const [existingDistrict] = await connection.execute("SELECT id FROM districts WHERE id = ?", [id]);
    if (existingDistrict.length === 0) {
      return res.status(404).json({ error: "Район не найден" });
    }

    const [linkedProperties] = await connection.execute("SELECT id FROM properties WHERE district_id = ?", [id]);
    if (linkedProperties.length > 0) {
      return res.status(400).json({ error: "Нельзя удалить район, связанный с объектами недвижимости" });
    }

    await connection.execute("DELETE FROM districts WHERE id = ?", [id]);
    res.json({ message: "Район успешно удалён" });
  } catch (error) {
    console.error("Ошибка при удалении района:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Create Subdistrict (Protected, SUPER_ADMIN only)
app.post("/api/subraions", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Доступ запрещён: требуется роль SUPER_ADMIN" });
  }

  const { name, parentRaionId } = req.body;
  if (!name || !parentRaionId) {
    return res.status(400).json({ error: "Название и ID родительского района обязательны" });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    const [districtCheck] = await connection.execute("SELECT id FROM districts WHERE id = ?", [parentRaionId]);
    if (districtCheck.length === 0) {
      return res.status(400).json({ error: "Недействительный ID родительского района" });
    }

    const [existingSubdistrict] = await connection.execute(
      "SELECT id FROM subdistricts WHERE name = ? AND district_id = ?",
      [name, parentRaionId]
    );
    if (existingSubdistrict.length > 0) {
      return res.status(400).json({ error: "Микрорайон с таким названием уже существует в этом районе" });
    }

    const [result] = await connection.execute(
      "INSERT INTO subdistricts (name, district_id) VALUES (?, ?)",
      [name, parentRaionId]
    );

    res.json({ id: result.insertId, name, parentRaionId, isRaion: false });
  } catch (error) {
    console.error("Ошибка при создании микрорайона:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Update Subdistrict (Protected, SUPER_ADMIN only)
app.put("/api/subraions/:id", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Доступ запрещён: требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;
  const { name, parentRaionId } = req.body;
  if (!name || !parentRaionId) {
    return res.status(400).json({ error: "Название и ID родительского района обязательны" });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    const [subdistrictCheck] = await connection.execute("SELECT id FROM subdistricts WHERE id = ?", [id]);
    if (subdistrictCheck.length === 0) {
      return res.status(404).json({ error: "Микрорайон не найден" });
    }

    const [districtCheck] = await connection.execute("SELECT id FROM districts WHERE id = ?", [parentRaionId]);
    if (districtCheck.length === 0) {
      return res.status(400).json({ error: "Недействительный ID родительского района" });
    }

    const [nameCheck] = await connection.execute(
      "SELECT id FROM subdistricts WHERE name = ? AND district_id = ? AND id != ?",
      [name, parentRaionId, id]
    );
    if (nameCheck.length > 0) {
      return res.status(400).json({ error: "Микрорайон с таким названием уже существует в этом районе" });
    }

    await connection.execute(
      "UPDATE subdistricts SET name = ?, district_id = ? WHERE id = ?",
      [name, parentRaionId, id]
    );

    res.json({ id: parseInt(id), name, parentRaionId, isRaion: false });
  } catch (error) {
    console.error("Ошибка при обновлении микрорайона:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Delete Subdistrict (Protected, SUPER_ADMIN only)
app.delete("/api/subraions/:id", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Доступ запрещён: требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;

  let connection;
  try {
    connection = await pool.getConnection();
    const [subdistrictCheck] = await connection.execute("SELECT id FROM subdistricts WHERE id = ?", [id]);
    if (subdistrictCheck.length === 0) {
      return res.status(404).json({ error: "Микрорайон не найден" });
    }

    const [linkedProperties] = await connection.execute("SELECT id FROM properties WHERE subdistrict_id = ?", [id]);
    if (linkedProperties.length > 0) {
      return res.status(400).json({ error: "Нельзя удалить микрорайон, связанный с объектами недвижимости" });
    }

    await connection.execute("DELETE FROM subdistricts WHERE id = ?", [id]);
    res.json({ message: "Микрорайон успешно удалён" });
  } catch (error) {
    console.error("Ошибка при удалении микрорайона:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Create New Property (Protected, SUPER_ADMIN or REALTOR)
app.post("/api/properties", authenticate, upload.fields([
  { name: "photos", maxCount: 10 },
  { name: "document", maxCount: 1 },
]), async (req, res) => {
  if (!["SUPER_ADMIN", "REALTOR"].includes(req.user.role)) {
    return res.status(403).json({ error: "Доступ запрещён: требуется роль SUPER_ADMIN или REALTOR" });
  }

  const {
    type_id,
    repair,
    series,
    zhk_id,
    owner_name,
    owner_phone,
    curator_id,
    price,
    unit,
    rukprice,
    mkv,
    rooms,
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
  } = req.body;

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
    return res.status(400).json({ error: "Все обязательные поля (type_id, price, rukprice, mkv, address, etaj, etajnost) должны быть заполнены" });
  }

  if (isNaN(parseFloat(price)) || isNaN(parseFloat(rukprice)) || isNaN(parseFloat(mkv)) || isNaN(parseInt(etaj)) || isNaN(parseInt(etajnost))) {
    return res.status(400).json({ error: "Поля price, rukprice, mkv, etaj, etajnost должны быть числами" });
  }

  if (type_id === "Квартира" && repair && !["ПСО", "С отделкой"].includes(repair)) {
    return res.status(400).json({ error: "Недействительное значение ремонта. Должно быть: ПСО, С отделкой" });
  }

  if (type_id === "Квартира" && series && ![
    "105 серия", "106 серия", "Индивидуалка", "Элитка", "103 серия", "106 серия улучшенная",
    "107 серия", "108 серия", "Малосемейка", "Общежитие и Гостиничного типа", "Сталинка", "Хрущевка"
  ].includes(series)) {
    return res.status(400).json({ error: "Недействительная серия. Должна быть одной из: 105 серия, 106 серия, Индивидуалка, Элитка, 103 серия, 106 серия улучшенная, 107 серия, 108 серия, Малосемейка, Общежитие и Гостиничного типа, Сталинка, Хрущевка" });
  }

  if (type_id === "Квартира" && rooms && !["1", "2", "3", "4", "5+"].includes(rooms)) {
    return res.status(400).json({ error: "Недействительное количество комнат. Должно быть: 1, 2, 3, 4, 5+" });
  }

  let finalCuratorId;
  if (curator_id) {
    if (isNaN(parseInt(curator_id))) {
      return res.status(400).json({ error: "curator_id должен быть числом" });
    }
    finalCuratorId = parseInt(curator_id);
  } else {
    finalCuratorId = req.user.role === "REALTOR" ? req.user.id : null;
  }

  if (req.user.role === "REALTOR" && finalCuratorId && finalCuratorId !== req.user.id) {
    return res.status(403).json({ error: "Риелтор может назначить только себя куратором" });
  }

  let connection;
  try {
    connection = await pool.getConnection();

    if (zhk_id) {
      const [jkCheck] = await connection.execute("SELECT id FROM jk WHERE id = ?", [zhk_id]);
      if (jkCheck.length === 0) {
        return res.status(400).json({ error: "Недействительный ID ЖК" });
      }
    }

    if (district_id) {
      const [districtCheck] = await connection.execute("SELECT id FROM districts WHERE id = ?", [district_id]);
      if (districtCheck.length === 0) {
        return res.status(400).json({ error: "Недействительный ID района" });
      }
    }

    if (subdistrict_id) {
      const [subdistrictCheck] = await connection.execute(
        "SELECT id FROM subdistricts WHERE id = ? AND district_id = ?",
        [subdistrict_id, district_id || null]
      );
      if (subdistrictCheck.length === 0) {
        return res.status(400).json({ error: "Недействительный ID микрорайона или микрорайон не принадлежит указанному району" });
      }
    }

    let curatorName = null;
    if (finalCuratorId) {
      const [curatorCheck] = await connection.execute(
        "SELECT id, CONCAT(first_name, ' ', last_name) AS curator_name FROM users1 WHERE id = ?",
        [finalCuratorId]
      );
      if (curatorCheck.length === 0) {
        return res.status(400).json({ error: "Недействительный ID куратора" });
      }
      curatorName = curatorCheck[0].curator_name;
    }

    for (const photo of photos) {
      try {
        await s3Client.send(new PutObjectCommand({
          Bucket: bucketName,
          Key: photo.filename,
          Body: photo.buffer,
          ContentType: photo.mimetype,
        }));
      } catch (error) {
        console.error(`Failed to upload photo to S3: ${photo.filename}`, error.message);
        throw new Error(`Не удалось загрузить фото: ${photo.filename}`);
      }
    }

    if (document) {
      try {
        await s3Client.send(new PutObjectCommand({
          Bucket: bucketName,
          Key: document.filename,
          Body: document.buffer,
          ContentType: document.mimetype,
        }));
      } catch (error) {
        console.error(`Failed to upload document to S3: ${document.filename}`, error.message);
        throw new Error(`Не удалось загрузить документ: ${document.filename}`);
      }
    }

    const photosJson = photos.length > 0 ? JSON.stringify(photos.map(img => img.filename)) : null;
    const [result] = await connection.execute(
      `INSERT INTO properties (
        type_id, repair, series, zhk_id, document_id, owner_name, owner_phone, curator_id, price, unit, rukprice, mkv, rooms, phone, 
        district_id, subdistrict_id, address, notes, description, photos, document, status, owner_id, etaj, etajnost
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        type_id || null,
        repair || null,
        series || null,
        zhk_id || null,
        0,
        owner_name || null,
        owner_phone || null,
        finalCuratorId,
        price,
        unit || null,
        rukprice,
        mkv,
        rooms || null,
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
      repair,
      series,
      zhk_id,
      document_id: 0,
      owner_name,
      owner_phone,
      curator_id: finalCuratorId,
      curator_name: curatorName || null,
      price,
      unit,
      rukprice,
      mkv,
      rooms,
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

    res.json(newProperty);
  } catch (error) {
    console.error("Error creating property:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Update Property (Protected, SUPER_ADMIN or REALTOR)
app.put("/api/properties/:id", authenticate, upload.fields([
  { name: "photos", maxCount: 10 },
  { name: "document", maxCount: 1 },
]), async (req, res) => {
  if (!["SUPER_ADMIN", "REALTOR"].includes(req.user.role)) {
    return res.status(403).json({ error: "Доступ запрещён: требуется роль SUPER_ADMIN или REALTOR" });
  }

  const { id } = req.params;
  const {
    type_id,
    repair,
    series,
    zhk_id,
    owner_name,
    owner_phone,
    curator_id,
    price,
    unit,
    rukprice,
    mkv,
    rooms,
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
    existingPhotos,
  } = req.body;

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
    return res.status(400).json({ error: "Все обязательные поля (type_id, price, rukprice, mkv, address, etaj, etajnost) должны быть заполнены" });
  }

  if (isNaN(parseFloat(price)) || isNaN(parseFloat(rukprice)) || isNaN(parseFloat(mkv)) || isNaN(parseInt(etaj)) || isNaN(parseInt(etajnost))) {
    return res.status(400).json({ error: "Поля price, rukprice, mkv, etaj, etajnost должны быть числами" });
  }

  if (type_id === "Квартира" && repair && !["ПСО", "С отделкой"].includes(repair)) {
    return res.status(400).json({ error: "Недействительное значение ремонта. Должно быть: ПСО, С отделкой" });
  }

  if (type_id === "Квартира" && series && ![
    "105 серия", "106 серия", "Индивидуалка", "Элитка", "103 серия", "106 серия улучшенная",
    "107 серия", "108 серия", "Малосемейка", "Общежитие и Гостиничного типа", "Сталинка", "Хрущевка"
  ].includes(series)) {
    return res.status(400).json({ error: "Недействительная серия. Должна быть одной из: 105 серия, 106 серия, Индивидуалка, Элитка, 103 серия, 106 серия улучшенная, 107 серия, 108 серия, Малосемейка, Общежитие и Гостиничного типа, Сталинка, Хрущевка" });
  }

  if (type_id === "Квартира" && rooms && !["1", "2", "3", "4", "5+"].includes(rooms)) {
    return res.status(400).json({ error: "Недействительное количество комнат. Должно быть: 1, 2, 3, 4, 5+" });
  }

  let finalCuratorId;
  if (curator_id) {
    if (isNaN(parseInt(curator_id))) {
      return res.status(400).json({ error: "curator_id должен быть числом" });
    }
    finalCuratorId = parseInt(curator_id);
  } else {
    finalCuratorId = req.user.role === "REALTOR" ? req.user.id : null;
  }

  if (req.user.role === "REALTOR" && finalCuratorId && finalCuratorId !== req.user.id) {
    return res.status(403).json({ error: "Риелтор может назначить только себя куратором" });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    const [existingProperties] = await connection.execute(
      "SELECT photos, document, curator_id, owner_phone FROM properties WHERE id = ?",
      [id]
    );
    if (existingProperties.length === 0) {
      return res.status(404).json({ error: "Объект недвижимости не найден" });
    }

    const existingProperty = existingProperties[0];
    if (req.user.role === "REALTOR" && existingProperty.curator_id && existingProperty.curator_id !== req.user.id) {
      return res.status(403).json({ error: "У вас нет прав для редактирования этого объекта" });
    }

    if (zhk_id) {
      const [jkCheck] = await connection.execute("SELECT id FROM jk WHERE id = ?", [zhk_id]);
      if (jkCheck.length === 0) {
        return res.status(400).json({ error: "Недействительный ID ЖК" });
      }
    }

    if (district_id) {
      const [districtCheck] = await connection.execute("SELECT id FROM districts WHERE id = ?", [district_id]);
      if (districtCheck.length === 0) {
        return res.status(400).json({ error: "Недействительный ID района" });
      }
    }

    if (subdistrict_id) {
      const [subdistrictCheck] = await connection.execute(
        "SELECT id FROM subdistricts WHERE id = ? AND district_id = ?",
        [subdistrict_id, district_id || null]
      );
      if (subdistrictCheck.length === 0) {
        return res.status(400).json({ error: "Недействительный ID микрорайона или микрорайон не принадлежит указанному району" });
      }
    }

    let curatorName = null;
    if (finalCuratorId) {
      const [curatorCheck] = await connection.execute(
        "SELECT id, CONCAT(first_name, ' ', last_name) AS curator_name FROM users1 WHERE id = ?",
        [finalCuratorId]
      );
      if (curatorCheck.length === 0) {
        return res.status(400).json({ error: "Недействительный ID куратора" });
      }
      curatorName = curatorCheck[0].curator_name;
    }

    let photoFiles = [];
    if (existingProperty.photos) {
      try {
        photoFiles = JSON.parse(existingProperty.photos) || [];
      } catch (error) {
        console.warn(`Error parsing photos for ID: ${id}:`, error.message);
        photoFiles = [];
      }
    }

    let existingPhotosList = [];
    if (existingPhotos) {
      try {
        existingPhotosList = JSON.parse(existingPhotos) || [];
        if (!Array.isArray(existingPhotosList) || !existingPhotosList.every(p => typeof p === "string" && p.trim() && photoFiles.includes(p))) {
          return res.status(400).json({ error: "Недействительный формат existingPhotos: должен быть массивом имен файлов фотографий" });
        }
      } catch (error) {
        console.error(`Error parsing existingPhotos for ID: ${id}:`, error.message);
        return res.status(400).json({ error: "Недействительный формат existingPhotos" });
      }
    } else {
      existingPhotosList = photoFiles;
    }

    for (const photo of photos) {
      try {
        await s3Client.send(new PutObjectCommand({
          Bucket: bucketName,
          Key: photo.filename,
          Body: photo.buffer,
          ContentType: photo.mimetype,
        }));
      } catch (error) {
        console.error(`Failed to upload photo to S3: ${photo.filename}`, error.message);
        throw new Error(`Не удалось загрузить фото: ${photo.filename}`);
      }
    }

    const photosToDelete = photoFiles.filter(p => !existingPhotosList.includes(p));
    for (const oldPhoto of photosToDelete) {
      try {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: oldPhoto }));
      } catch (error) {
        console.warn(`Failed to delete old photo from S3: ${oldPhoto}`, error.message);
      }
    }

    const newPhotos = [...existingPhotosList, ...photos.map(img => img.filename)];
    const photosJson = newPhotos.length > 0 ? JSON.stringify(newPhotos) : null;

    let newDocument = existingProperty.document;
    if (document) {
      try {
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
            console.warn(`Failed to delete old document from S3: ${existingProperty.document}`, error.message);
          }
        }
        newDocument = document.filename;
      } catch (error) {
        console.error(`Failed to upload document to S3: ${document.filename}`, error.message);
        throw new Error(`Не удалось загрузить документ: ${document.filename}`);
      }
    }

    await connection.execute(
      `UPDATE properties SET
        type_id = ?, repair = ?, series = ?, zhk_id = ?, document_id = ?, owner_name = ?, owner_phone = ?, curator_id = ?, price = ?, unit = ?, rukprice = ?, mkv = ?, rooms = ?, phone = ?,
        district_id = ?, subdistrict_id = ?, address = ?, notes = ?, description = ?, photos = ?, document = ?, status = ?, owner_id = ?, etaj = ?, etajnost = ?
        WHERE id = ?`,
      [
        type_id || null,
        repair || null,
        series || null,
        zhk_id || null,
        0,
        owner_name || null,
        owner_phone || null,
        finalCuratorId,
        price,
        unit || null,
        rukprice,
        mkv,
        rooms || null,
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
      repair,
      series,
      zhk_id,
      document_id: 0,
      owner_name,
      owner_phone,
      curator_id: finalCuratorId,
      curator_name: curatorName || null,
      price,
      unit,
      rukprice,
      mkv,
      rooms,
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

    res.json(updatedProperty);
  } catch (error) {
    console.error("Error updating property:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Delete Property (Protected, SUPER_ADMIN or REALTOR)
app.delete("/api/properties/:id", authenticate, async (req, res) => {
  if (!["SUPER_ADMIN", "REALTOR"].includes(req.user.role)) {
    return res.status(403).json({ error: "Доступ запрещён: требуется роль SUPER_ADMIN или REALTOR" });
  }

  const { id } = req.params;

  let connection;
  try {
    connection = await pool.getConnection();
    const [properties] = await connection.execute(
      "SELECT photos, document, curator_id FROM properties WHERE id = ?",
      [id]
    );
    if (properties.length === 0) {
      return res.status(404).json({ error: "Объект недвижимости не найден" });
    }

    const existingProperty = properties[0];
    if (req.user.role === "REALTOR" && existingProperty.curator_id && existingProperty.curator_id !== req.user.id) {
      return res.status(403).json({ error: "У вас нет прав для удаления этого объекта" });
    }

    let photoFiles = [];
    if (existingProperty.photos) {
      try {
        photoFiles = JSON.parse(existingProperty.photos) || [];
      } catch (error) {
        console.warn(`Error parsing photos for ID: ${id}:`, error.message);
        photoFiles = [];
      }
      for (const img of photoFiles) {
        try {
          await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: img }));
        } catch (error) {
          console.warn(`Failed to delete image from S3: ${img}`, error.message);
        }
      }
    }

    if (existingProperty.document) {
      try {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: existingProperty.document }));
      } catch (error) {
        console.warn(`Failed to delete document from S3: ${existingProperty.document}`, error.message);
      }
    }

    await connection.execute("DELETE FROM properties WHERE id = ?", [id]);
    res.json({ message: "Объект недвижимости успешно удалён" });
  } catch (error) {
    console.error("Error deleting property:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Get All Properties (Protected)
app.get("/api/properties", authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
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
          console.warn(`Error parsing photos for ID: ${row.id}:`, error.message);
          parsedPhotos = [];
        }
      }

      return {
        ...row,
        repair: row.repair || null,
        rooms: row.rooms || null,
        owner_phone: row.owner_phone || null,
        photos: parsedPhotos.map(img => `https://s3.twcstorage.ru/${bucketName}/${img}`),
        document: row.document ? `https://s3.twcstorage.ru/${bucketName}/${row.document}` : null,
        date: new Date(row.created_at).toLocaleDateString("ru-RU"),
        time: new Date(row.created_at).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" }),
        curator_name: row.curator_name || null,
      };
    });

    res.json(properties);
  } catch (error) {
    console.error("Error retrieving properties:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Get All Listings for AdminDashboard (Protected)
app.get("/api/listings", authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
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

    res.json(listings);
  } catch (error) {
    console.error("Error retrieving listings:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});



app.get("/public/properties/:id", async (req, res) => {
  const { id } = req.params;

  if (!id || isNaN(parseInt(id))) {
    console.warn("Invalid property ID:", id);
    return res.status(400).json({ error: "ID объекта должен быть числом" });
  }

  let connection;
  try {
    console.log(`Запрос на /public/properties/${id} от:`, req.get('origin'));
    connection = await pool.getConnection();

    const [rows] = await connection.execute(
      `SELECT 
          p.id,
          p.type_id,
          p.repair,
          p.series,
          p.zhk_id,
          p.price,
          p.mkv,
          p.rooms,
          p.district_id,
          p.subdistrict_id,
          p.address,
          p.description,
          p.notes,
          p.status,
          p.etaj,
          p.etajnost,
          p.photos,
          p.document,
          p.owner_name,
          p.owner_phone,
          p.curator_id,
          p.phone,
          p.owner_id,
          p.latitude,
          p.longitude,
          CONCAT(u.first_name, ' ', u.last_name) AS curator_name,
          u.phone AS curator_phone
        FROM properties p
        LEFT JOIN users1 u ON p.curator_id = u.id
        WHERE p.id = ?`,
      [parseInt(id)]
    );

    if (rows.length === 0) {
      console.warn(`Объект с ID ${id} не найден`);
      return res.status(404).json({ error: "Объект недвижимости не найден" });
    }

    const row = rows[0];
    let parsedPhotos = [];
    try {
      parsedPhotos = row.photos ? JSON.parse(row.photos) : [];
    } catch (error) {
      console.warn(`Ошибка парсинга photos для ID ${id}:`, error.message);
      parsedPhotos = [];
    }

      const finalContactPhone = row.curator_phone || row.owner_phone || row.phone || null;
    const contactPhone = row.curator_phone || row.owner_phone || row.phone || null;

    const property = {
      id: row.id,
      type_id: row.type_id || null,
      repair: row.repair || null,
      series: row.series || null,
      zhk_id: row.zhk_id || null,
      price: row.price || null,
      mkv: row.mkv || null,
      rooms: row.rooms || null,
      district_id: row.district_id || null,
      subdistrict_id: row.subdistrict_id || null,
      address: row.address || null,
      description: row.description || null,
      notes: row.notes || null,
      status: row.status || null,
      etaj: row.etaj || null,
      etajnost: row.etajnost || null,
      photos: parsedPhotos.map(img => `https://s3.twcstorage.ru/${bucketName}/${img}`),
      document: row.document ? `https://s3.twcstorage.ru/${bucketName}/${row.document}` : null,
      owner_name: row.owner_name || null,
      owner_phone: row.owner_phone || null,
      curator_id: row.curator_id || null,
      curator_name: row.curator_name || null,
      curator_phone: row.curator_phone || null,
      contact_phone: contactPhone,
      phone: row.phone || null,
      owner_id: row.owner_id || null,
      latitude: row.latitude || null,
      longitude: row.longitude || null,
      date: new Date(row.created_at).toLocaleDateString("ru-RU"),
      time: new Date(row.created_at).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" })
    };

    res.status(200).json(property);
  } catch (error) {
    console.error(`Ошибка при получении объекта с ID ${id}:`, {
      message: error.message,
      stack: error.stack,
      origin: req.get('origin')
    });
    res.status(500).json({ error: `Ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});


// Public endpoint for AI-related properties
app.get("/aipublic/properties", async (req, res) => {
  const {
    bid,
    titles,
    ftype,
    fjk,
    fseria,
    fsost,
    room,
    frayon,
    fsubrayon,
    fprice,
    fpriceto,
    mkv,
    fetaj,
    page = 1,
    limit = 30,
  } = req.query;

  let connection;
  let query = `SELECT id, type_id, repair, series, zhk_id, price, mkv, rooms, district_id, subdistrict_id,
                      address, description, status, etaj, etajnost, photos
               FROM properties WHERE 1=1`;
  let params = [];

  try {
    connection = await pool.getConnection();
    if (!connection) {
      throw new Error("Не удалось установить соединение с базой данных");
    }

    // Check if properties table exists
    const [tables] = await connection.execute("SHOW TABLES LIKE 'properties'");
    if (!tables.length) {
      console.warn("Таблица properties не найдена");
      return res.status(200).json([]);
    }

    // Filters
    if (bid && !isNaN(parseInt(bid))) {
      query += ` AND id = ?`;
      params.push(parseInt(bid));
    } else if (bid) {
      return res.status(400).json({ error: "Недействительный параметр bid: должен быть числом" });
    }

    if (titles && typeof titles === "string" && titles.trim()) {
      query += ` AND (address LIKE ? OR description LIKE ?)`;
      params.push(`%${titles.trim()}%`, `%${titles.trim()}%`);
    }

    if (ftype && ftype !== "all" && typeof ftype === "string") {
      query += ` AND type_id = ?`;
      params.push(ftype);
    }

    if (fjk && fjk !== "all" && typeof fjk === "string") {
      query += ` AND zhk_id = ?`;
      params.push(fjk);
    }

    if (fseria && fseria !== "all" && typeof fseria === "string") {
      query += ` AND series = ?`;
      params.push(fseria);
    }

    if (fsost && fsost !== "all") {
      if (fsost === "3") {
        query += ` AND repair IS NULL`;
      } else if (fsost === "1") {
        query += ` AND repair = ?`;
        params.push("ПСО");
      } else if (fsost === "2") {
        query += ` AND repair = ?`;
        params.push("С отделкой");
      }
    }

    if (room && typeof room === "string" && room !== "") {
      query += ` AND rooms = ?`;
      params.push(room);
    }

    if (frayon && frayon !== "all" && typeof frayon === "string") {
      query += ` AND district_id = ?`;
      params.push(frayon);
    }

    if (fsubrayon && fsubrayon !== "all" && typeof fsubrayon === "string") {
      query += ` AND subdistrict_id = ?`;
      params.push(fsubrayon);
    }

    if (fprice && !isNaN(parseFloat(fprice))) {
      query += ` AND price >= ?`;
      params.push(parseFloat(fprice));
    }

    if (fpriceto && !isNaN(parseFloat(fpriceto))) {
      query += ` AND price <= ?`;
      params.push(parseFloat(fpriceto));
    }

    if (mkv && !isNaN(parseFloat(mkv))) {
      query += ` AND mkv >= ?`;
      params.push(parseFloat(mkv));
    }

    if (fetaj && fetaj !== "all") {
      if (fetaj === "4") {
        query += ` AND etaj >= ?`;
        params.push(4);
      } else if (!isNaN(parseInt(fetaj))) {
        query += ` AND etaj = ?`;
        params.push(parseInt(fetaj));
      }
    }

    // Pagination
    const parsedPage = parseInt(page);
    const parsedLimit = parseInt(limit);
    if (isNaN(parsedPage) || parsedPage < 1) {
      return res.status(400).json({ error: "Недействительный параметр page: должен быть числом >= 1" });
    }
    if (isNaN(parsedLimit) || parsedLimit < 1) {
      return res.status(400).json({ error: "Недействительный параметр limit: должен быть числом >= 1" });
    }
    const offset = (parsedPage - 1) * parsedLimit;
    query += ` LIMIT ${parsedLimit} OFFSET ${offset}`;

    console.log("SQL запрос:", query);
    console.log("Параметры:", params);

    const [rows] = await connection.execute(query, params);

    const properties = rows.map(row => {
      let parsedPhotos = [];
      try {
        parsedPhotos = row.photos ? JSON.parse(row.photos) : [];
      } catch (error) {
        console.warn(`Ошибка парсинга photos для ID ${row.id}:`, error.message);
        parsedPhotos = [];
      }
      return {
        id: row.id,
        type_id: row.type_id || null,
        repair: row.repair || null,
        series: row.series || null,
        zhk_id: row.zhk_id || null,
        price: row.price || null,
        mkv: row.mkv || null,
        rooms: row.rooms || null,
        district_id: row.district_id || null,
        subdistrict_id: row.subdistrict_id || null,
        address: row.address || null,
        description: row.description || null,
        status: row.status || null,
        etaj: row.etaj || null,
        etajnost: row.etajnost || null,
        photos: parsedPhotos.map(img => `https://s3.twcstorage.ru/${bucketName}/${img}`),
      };
    });

    res.status(200).json(properties);
  } catch (error) {
    console.error("Ошибка при получении недвижимости:", {
      message: error.message,
      stack: error.stack,
      query: req.query,
      sqlQuery: query,
      sqlParams: params,
    });
    res.status(500).json({ error: `Ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

app.get("/public/properties/curator-phone", async (req, res) => {
  const { curator_id } = req.query;

  if (!curator_id || isNaN(parseInt(curator_id))) {
    console.warn("Invalid curator_id:", curator_id);
    return res.status(400).json({ error: "curator_id обязателен и должен быть числом" });
  }

  let connection;
  try {
    console.log("Запрос на /public/properties/curator-phone от:", req.get('origin'), "с curator_id:", curator_id);
    connection = await pool.getConnection();

    const [users] = await connection.execute(
      "SELECT phone FROM users1 WHERE id = ?",
      [parseInt(curator_id)]
    );

    if (users.length === 0) {
      console.warn("Куратор с ID", curator_id, "не найден");
      return res.status(404).json({ error: "Куратор не найден" });
    }

    const phone = users[0].phone;
    console.log("Номер телефона куратора:", phone);
    res.status(200).json({ phone });
  } catch (error) {
    console.error("Ошибка при получении номера телефона куратора:", {
      message: error.message,
      stack: error.stack,
      origin: req.get('origin'),
      curator_id
    });
    res.status(500).json({ error: `Ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});





// Эндпоинты для поставщиков
app.get('/api/suppliers', authenticate, async (req, res) => {
  try {
    const [suppliers] = await pool.query('SELECT * FROM suppliers');
    res.json(suppliers);
  } catch (err) {
    console.error('Ошибка получения поставщиков:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/suppliers', authenticate, upload.array('documents'), async (req, res) => {
  const { name, contact, status, serviceType, address } = req.body;
  if (!name || !contact || !serviceType) {
    return res.status(400).json({ error: 'Название, контакт и тип услуг обязательны' });
  }
  try {
    const documents = req.files ? await Promise.all(req.files.map(async (file) => {
      const params = {
        Bucket: process.env.AWS_S3_BUCKET,
        Key: `suppliers/${Date.now()}_${file.originalname}`,
        Body: file.buffer,
        ContentType: file.mimetype,
      };
      const { Location } = await s3.upload(params).promise();
      return Location;
    })) : [];
    const [result] = await pool.query(
      'INSERT INTO suppliers (name, contact, status, service_type, address, documents) VALUES (?, ?, ?, ?, ?, ?)',
      [name, contact, status || 'Активен', serviceType, address || null, JSON.stringify(documents)]
    );
    res.json({ id: result.insertId, name, contact, status: status || 'Активен', service_type: serviceType, address, documents });
  } catch (err) {
    console.error('Ошибка создания поставщика:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.put('/api/suppliers/:id', authenticate, upload.array('documents'), async (req, res) => {
  const { id } = req.params;
  const { name, contact, status, serviceType, address, existingDocuments } = req.body;
  if (!name || !contact || !serviceType) {
    return res.status(400).json({ error: 'Название, контакт и тип услуг обязательны' });
  }
  try {
    const [existing] = await pool.query('SELECT documents FROM suppliers WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ error: 'Поставщик не найден' });
    let documents = existingDocuments ? JSON.parse(existingDocuments) : existing[0].documents || [];
    if (req.files) {
      const newDocuments = await Promise.all(req.files.map(async (file) => {
        const params = {
          Bucket: process.env.AWS_S3_BUCKET,
          Key: `suppliers/${Date.now()}_${file.originalname}`,
          Body: file.buffer,
          ContentType: file.mimetype,
        };
        const { Location } = await s3.upload(params).promise();
        return Location;
      }));
      documents = [...documents, ...newDocuments];
    }
    await pool.query(
      'UPDATE suppliers SET name = ?, contact = ?, status = ?, service_type = ?, address = ?, documents = ? WHERE id = ?',
      [name, contact, status, serviceType, address || null, JSON.stringify(documents), id]
    );
    res.json({ id, name, contact, status, service_type: serviceType, address, documents });
  } catch (err) {
    console.error('Ошибка обновления поставщика:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.delete('/api/suppliers/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    const [existing] = await pool.query('SELECT documents FROM suppliers WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ error: 'Поставщик не найден' });
    if (existing[0].documents) {
      const documents = JSON.parse(existing[0].documents);
      await Promise.all(documents.map(async (doc) => {
        const key = doc.split('/').pop();
        await s3.deleteObject({ Bucket: process.env.AWS_S3_BUCKET, Key: `suppliers/${key}` }).promise();
      }));
    }
    await pool.query('DELETE FROM suppliers WHERE id = ?', [id]);
    res.json({ message: 'Поставщик удалён' });
  } catch (err) {
    console.error('Ошибка удаления поставщика:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Эндпоинты для продаж
app.get('/api/sales', authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    const [tables] = await connection.query('SHOW TABLES LIKE "sales"');
    if (!tables.length) throw new Error('Таблица sales не найдена');
    const [suppliersTable] = await connection.query('SHOW TABLES LIKE "suppliers"');
    if (!suppliersTable.length) throw new Error('Таблица suppliers не найдена');
    const [propertiesTable] = await connection.query('SHOW TABLES LIKE "properties"');
    if (!propertiesTable.length) throw new Error('Таблица properties не найдена');

    const [sales] = await connection.query(`
      SELECT s.*, sup.name AS supplier_name, p.address AS property_address
      FROM sales s
      JOIN suppliers sup ON s.supplier_id = sup.id
      JOIN properties p ON s.property_id = p.id
    `);
    res.json(sales);
  } catch (err) {
    console.error('Ошибка получения продаж:', {
      message: err.message,
      stack: err.stack,
      sqlMessage: err.sqlMessage,
      sqlState: err.sqlState,
    });
    res.status(500).json({ error: 'Ошибка сервера', details: err.message });
  } finally {
    if (connection) connection.release();
  }
});

// app.js
app.get('/api/news', authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    const [tables] = await connection.execute("SHOW TABLES LIKE 'news'");
    if (!tables.length) {
      console.warn("Таблица news не найдена");
      return res.status(200).json([]);
    }
    const [news] = await connection.execute('SELECT id, title, content, published_at FROM news ORDER BY published_at DESC');
    res.json(news);
  } catch (err) {
    console.error('Ошибка получения новостей:', {
      message: err.message,
      stack: err.stack,
      sqlMessage: err.sqlMessage,
      sqlState: err.sqlState,
    });
    res.status(500).json({ error: 'Ошибка сервера', details: err.message });
  } finally {
    if (connection) connection.release();
  }
});

app.post('/api/sales', authenticate, upload.array('documents'), async (req, res) => {
  const { supplier_id, property_id, amount, date, status } = req.body;
  if (!supplier_id || !property_id || !amount || !date) {
    return res.status(400).json({ error: 'Все поля обязательны' });
  }
  try {
    const documents = req.files ? await Promise.all(req.files.map(async (file) => {
      const params = {
        Bucket: process.env.AWS_S3_BUCKET,
        Key: `sales/${Date.now()}_${file.originalname}`,
        Body: file.buffer,
        ContentType: file.mimetype,
      };
      const { Location } = await s3.upload(params).promise();
      return Location;
    })) : [];
    const [result] = await pool.query(
      'INSERT INTO sales (supplier_id, property_id, amount, date, status, documents) VALUES (?, ?, ?, ?, ?, ?)',
      [supplier_id, property_id, amount, date, status || 'В обработке', JSON.stringify(documents)]
    );
    const [sale] = await pool.query(`
      SELECT s.*, sup.name AS supplier_name, p.title AS property_title
      FROM sales s
      JOIN suppliers sup ON s.supplier_id = sup.id
      JOIN properties p ON s.property_id = p.id
      WHERE s.id = ?
    `, [result.insertId]);
    res.json(sale[0]);
  } catch (err) {
    console.error('Ошибка создания продажи:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.put('/api/sales/:id', authenticate, upload.array('documents'), async (req, res) => {
  const { id } = req.params;
  const { supplier_id, property_id, amount, date, status, existingDocuments } = req.body;
  if (!supplier_id || !property_id || !amount || !date) {
    return res.status(400).json({ error: 'Все поля обязательны' });
  }
  try {
    const [existing] = await pool.query('SELECT documents FROM sales WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ error: 'Продажа не найдена' });
    let documents = existingDocuments ? JSON.parse(existingDocuments) : existing[0].documents || [];
    if (req.files) {
      const newDocuments = await Promise.all(req.files.map(async (file) => {
        const params = {
          Bucket: process.env.AWS_S3_BUCKET,
          Key: `sales/${Date.now()}_${file.originalname}`,
          Body: file.buffer,
          ContentType: file.mimetype,
        };
        const { Location } = await s3.upload(params).promise();
        return Location;
      }));
      documents = [...documents, ...newDocuments];
    }
    await pool.query(
      'UPDATE sales SET supplier_id = ?, property_id = ?, amount = ?, date = ?, status = ?, documents = ? WHERE id = ?',
      [supplier_id, property_id, amount, date, status, JSON.stringify(documents), id]
    );
    const [sale] = await pool.query(`
      SELECT s.*, sup.name AS supplier_name, p.title AS property_title
      FROM sales s
      JOIN suppliers sup ON s.supplier_id = sup.id
      JOIN properties p ON s.property_id = p.id
      WHERE s.id = ?
    `, [id]);
    res.json(sale[0]);
  } catch (err) {
    console.error('Ошибка обновления продажи:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.delete('/api/sales/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    const [existing] = await pool.query('SELECT documents FROM sales WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ error: 'Продажа не найдена' });
    if (existing[0].documents) {
      const documents = JSON.parse(existing[0].documents);
      await Promise.all(documents.map(async (doc) => {
        const key = doc.split('/').pop();
        await s3.deleteObject({ Bucket: process.env.AWS_S3_BUCKET, Key: `sales/${key}` }).promise();
      }));
    }
    await pool.query('DELETE FROM sales WHERE id = ?', [id]);
    res.json({ message: 'Продажа удалена' });
  } catch (err) {
    console.error('Ошибка удаления продажи:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Эндпоинты для клиентов
app.get('/api/clients', authenticate, async (req, res) => {
  try {
    const [clients] = await pool.query('SELECT * FROM clients');
    res.json(clients);
  } catch (err) {
    console.error('Ошибка получения клиентов:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Эндпоинты для сообщений
// GET messages endpoint (public)
app.get('/api/messages/:clientId', async (req, res) => {
  const { clientId } = req.params;
  if (!Number.isInteger(Number(clientId)) || Number(clientId) < 0) {
    return res.status(400).json({ error: 'clientId должен быть положительным целым числом' });
  }
  try {
    const [messages] = await pool.query('SELECT * FROM messages WHERE client_id = ? ORDER BY timestamp ASC', [clientId]);
    res.json(messages);
  } catch (err) {
    console.error('Ошибка получения сообщений:', {
      message: err.message,
      sql: err.sql,
      code: err.code,
      errno: err.errno
    });
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});
// POST messages endpoint (public)
app.post('/api/messages', async (req, res) => {
  console.log('Получен POST запрос /api/messages:', req.body);

  let { client_id, message, sender } = req.body;

  // Валидация входных данных
  if (typeof message !== 'string' || !message.trim()) {
    return res.status(400).json({ error: 'Сообщение должно быть непустой строкой' });
  }
  if (!sender || (sender !== 'client' && sender !== 'agent')) {
    return res.status(400).json({ error: 'Отправитель должен быть "client" или "agent"' });
  }

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    // Если client_id не предоставлен, создаём нового клиента
    if (!client_id) {
      const [clientResult] = await connection.query('INSERT INTO clients (created_at) VALUES (NOW())');
      client_id = clientResult.insertId;
      console.log('Сгенерирован новый client_id:', client_id);
    } else {
      // Проверяем, существует ли client_id
      const [client] = await connection.query('SELECT id FROM clients WHERE id = ?', [client_id]);
      if (!client.length) {
        await connection.rollback();
        return res.status(400).json({ error: 'Указанный client_id не существует' });
      }
    }

    // Проверка client_id на корректность (UNSIGNED INT)
    if (!Number.isInteger(Number(client_id)) || client_id < 0 || client_id > 4294967295) {
      await connection.rollback();
      return res.status(400).json({ error: 'client_id должен быть положительным целым числом (UNSIGNED INT)' });
    }

    // Вставка сообщения
    const [result] = await connection.query(
      'INSERT INTO messages (client_id, message, sender, is_read, timestamp) VALUES (?, ?, ?, ?, NOW())',
      [client_id, message, sender, sender === 'agent' ? 1 : 0]
    );
    console.log('Сообщение сохранено, ID:', result.insertId);

    // Получение сохранённого сообщения
    const [newMessage] = await connection.query('SELECT * FROM messages WHERE id = ?', [result.insertId]);
    if (!newMessage[0]) {
      throw new Error('Не удалось получить новое сообщение');
    }

    // Вставка автоответа
    const autoReply = {
      client_id,
      message: 'Ваше сообщение получено! Мы ответим в ближайшее время.',
      sender: 'agent',
      is_read: 1
    };
    await connection.query(
      'INSERT INTO messages (client_id, message, sender, is_read, timestamp) VALUES (?, ?, ?, ?, NOW())',
      [autoReply.client_id, autoReply.message, autoReply.sender, autoReply.is_read]
    );
    console.log('Автоответ успешно отправлен');

    await connection.commit();
    res.json({
      message: newMessage[0],
      clientId: client_id
    });
  } catch (err) {
    await connection.rollback();
    console.error('Ошибка отправки сообщения:', {
      message: err.message,
      sql: err.sql,
      code: err.code,
      errno: err.errno,
      stack: err.stack
    });
    res.status(500).json({ error: 'Ошибка сервера при обработке сообщения' });
  } finally {
    connection.release();
  }
});

// Эндпоинты для задач
app.get('/api/tasks', authenticate, async (req, res) => {
  try {
    const [tasks] = await pool.query('SELECT * FROM tasks');
    res.json(tasks);
  } catch (err) {
    console.error('Ошибка получения задач:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/tasks', authenticate, async (req, res) => {
  const { title, description, due_date, assigned_to, status } = req.body;
  if (!title || !due_date || !assigned_to) {
    return res.status(400).json({ error: 'Название, дата выполнения и ответственный обязательны' });
  }
  try {
    const [result] = await pool.query(
      'INSERT INTO tasks (title, description, due_date, assigned_to, status) VALUES (?, ?, ?, ?, ?)',
      [title, description || null, due_date, assigned_to, status || 'Открыта']
    );
    const [newTask] = await pool.query('SELECT * FROM tasks WHERE id = ?', [result.insertId]);
    res.json(newTask[0]);
  } catch (err) {
    console.error('Ошибка создания задачи:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.put('/api/tasks/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { title, description, due_date, assigned_to, status } = req.body;
  if (!title || !due_date || !assigned_to) {
    return res.status(400).json({ error: 'Название, дата выполнения и ответственный обязательны' });
  }
  try {
    const [existing] = await pool.query('SELECT * FROM tasks WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ error: 'Задача не найдена' });
    await pool.query(
      'UPDATE tasks SET title = ?, description = ?, due_date = ?, assigned_to = ?, status = ? WHERE id = ?',
      [title, description || null, due_date, assigned_to, status, id]
    );
    const [updatedTask] = await pool.query('SELECT * FROM tasks WHERE id = ?', [id]);
    res.json(updatedTask[0]);
  } catch (err) {
    console.error('Ошибка обновления задачи:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.delete('/api/tasks/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    const [existing] = await pool.query('SELECT * FROM tasks WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ error: 'Задача не найдена' });
    await pool.query('DELETE FROM tasks WHERE id = ?', [id]);
    res.json({ message: 'Задача удалена' });
  } catch (err) {
    console.error('Ошибка удаления задачи:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});



// Публичный эндпоинт для получения списка ЖК
// Public endpoint for JK (zhk)
app.get("/public/jk", async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute("SELECT id, name FROM jk");
    res.json(rows);
  } catch (error) {
    console.error("Error fetching JK:", error);
    res.status(500).json({ error: "Internal server error" });
  } finally {
    if (connection) connection.release();
  }
});

// Public endpoint for JK (zhk)
app.get("/public/jk", async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute("SELECT id, name FROM jk");
    res.json(rows);
  } catch (error) {
    console.error("Error fetching JK:", error);
    res.status(500).json({ error: "Internal server error" });
  } finally {
    if (connection) connection.release();
  }
});

// Public endpoint for subdistricts
app.get("/public/subdistricts", async (req, res) => {
  const { district_id } = req.query;
  if (!district_id) {
    return res.status(400).json({ error: "district_id is required" });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, name FROM subdistricts WHERE district_id = ?",
      [district_id]
    );
    res.json(rows);
  } catch (error) {
    console.error("Error fetching subdistricts:", error);
    res.status(500).json({ error: "Internal server error" });
  } finally {
    if (connection) connection.release();
  }
});


// Endpoint для типов недвижимости
app.get("/public/properties/types", async (req, res) => {
  let connection;
  try {
    console.log("Запрос на /public/properties/types от:", req.get('origin'));
    connection = await pool.getConnection();
    const [tables] = await connection.execute("SHOW TABLES LIKE 'properties'");
    if (!tables.length) {
      console.warn("Таблица properties не найдена");
      return res.status(200).json([]);
    }

    const [rows] = await connection.execute(
      "SELECT DISTINCT type_id FROM properties WHERE type_id IS NOT NULL"
    );
    if (!rows.length) {
      console.warn("Типы недвижимости не найдены в базе данных");
      return res.status(200).json([]);
    }
    const types = rows.map(row => row.type_id);
    console.log("Полученные типы недвижимости:", types);
    res.status(200).json(types);
  } catch (error) {
    console.error("Ошибка при получении типов недвижимости:", {
      message: error.message,
      stack: error.stack,
      origin: req.get('origin')
    });
    res.status(500).json({ error: `Ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Endpoint для списка недвижимости
app.get("/public/properties", async (req, res) => {
  const {
    bid,
    titles,
    ftype,
    fjk,
    fseria,
    fsost,
    room,
    frayon,
    fsubrayon,
    fprice,
    fpriceto,
    mkv,
    fetaj,
    page = 1,
    limit = 30,
  } = req.query;

  let connection;
  let query = `SELECT 
                 p.id,
                 p.type_id,
                 p.repair,
                 p.series,
                 p.zhk_id,
                 p.price,
                 p.mkv,
                 p.rooms,
                 p.district_id,
                 p.subdistrict_id,
                 p.address,
                 p.description,
                 p.status,
                 p.etaj,
                 p.etajnost,
                 p.photos,
                 p.owner_phone,
                 p.owner_name,
                 p.curator_id,
                 CONCAT(u.first_name, ' ', u.last_name) AS curator_name,
                 u.phone AS curator_phone
               FROM properties p
               LEFT JOIN users1 u ON p.curator_id = u.id
               WHERE 1=1`;
  let params = [];

  try {
    connection = await pool.getConnection();

    if (!connection) {
      throw new Error("Не удалось установить соединение с базой данных");
    }

    // Проверка существования таблицы
    const [tables] = await connection.execute("SHOW TABLES LIKE 'properties'");
    if (!tables.length) {
      console.warn("Таблица properties не найдена");
      return res.status(200).json([]);
    }

    // Фильтры
    if (bid && !isNaN(parseInt(bid))) {
      query += ` AND p.id = ?`;
      params.push(parseInt(bid));
    } else if (bid) {
      return res.status(400).json({ error: "Недействительный параметр bid: должен быть числом" });
    }

    if (titles && typeof titles === "string" && titles.trim()) {
      query += ` AND (address = ? OR description = ?)`;
      params.push(titles.trim(), titles.trim());
    }

    if (ftype && ftype !== "all" && typeof ftype === "string") {
      query += ` AND p.type_id = ?`;
      params.push(ftype);
    }

    if (fjk && fjk !== "all" && typeof fjk === "string") {
      query += ` AND p.zhk_id = ?`;
      params.push(fjk);
    }

    if (fseria && fseria !== "all" && typeof fseria === "string") {
      query += ` AND p.series = ?`;
      params.push(fseria);
    }

    if (fsost && fsost !== "all") {
      if (fsost === "3") {
        query += ` AND p.repair IS NULL`;
      } else if (fsost === "1") {
        query += ` AND p.repair = ?`;
        params.push("ПСО");
      } else if (fsost === "2") {
        query += ` AND p.repair = ?`;
        params.push("С отделкой");
      }
    }

    if (room && typeof room === "string" && room !== "") {
      query += ` AND p.rooms = ?`;
      params.push(room);
    }

    if (frayon && frayon !== "all" && typeof frayon === "string") {
      query += ` AND p.district_id = ?`;
      params.push(frayon);
    }

    if (fsubrayon && fsubrayon !== "all" && typeof fsubrayon === "string") {
      query += ` AND p.subdistrict_id = ?`;
      params.push(fsubrayon);
    }

    if (fprice && !isNaN(parseFloat(fprice))) {
      query += ` AND p.price >= ?`;
      params.push(parseFloat(fprice));
    }

    if (fpriceto && !isNaN(parseFloat(fpriceto))) {
      query += ` AND p.price <= ?`;
      params.push(parseFloat(fpriceto));
    }

    if (mkv && !isNaN(parseFloat(mkv))) {
      query += ` AND p.mkv >= ?`;
      params.push(parseFloat(mkv));
    }

    if (fetaj && fetaj !== "all") {
      if (fetaj === "4") {
        query += ` AND p.etaj >= ?`;
        params.push(4);
      } else if (!isNaN(parseInt(fetaj))) {
        query += ` AND p.etaj = ?`;
        params.push(parseInt(fetaj));
      }
    }

    // Пагинация (LIMIT/OFFSET без ?)
    const parsedPage = parseInt(page);
    const parsedLimit = parseInt(limit);
    if (isNaN(parsedPage) || parsedPage < 1) {
      return res.status(400).json({ error: "Недействительный параметр page: должен быть числом >= 1" });
    }
    if (isNaN(parsedLimit) || parsedLimit < 1) {
      return res.status(400).json({ error: "Недействительный параметр limit: должен быть числом >= 1" });
    }
    const offset = (parsedPage - 1) * parsedLimit;

    query += ` LIMIT ${parsedLimit} OFFSET ${offset}`;

    console.log("SQL запрос:", query);
    console.log("Параметры:", params);

    const [rows] = await connection.execute(query, params);

    const properties = rows.map(row => {
  let parsedPhotos = [];
  try {
    parsedPhotos = row.photos ? JSON.parse(row.photos) : [];
  } catch (error) {
    console.warn(`Ошибка парсинга photos для ID ${row.id}:`, error.message);
    parsedPhotos = [];
  }

      const contactPhone = row.owner_phone || row.curator_phone || null;

      return {
        id: row.id,
        type_id: row.type_id || null,
        repair: row.repair || null,
        series: row.series || null,
        zhk_id: row.zhk_id || null,
        price: row.price || null,
        mkv: row.mkv || null,
        rooms: row.rooms || null,
        district_id: row.district_id || null,
        subdistrict_id: row.subdistrict_id || null,
        address: row.address || null,
        description: row.description || null,
        status: row.status || null,
        etaj: row.etaj || null,
        etajnost: row.etajnost || null,
        owner_phone: row.owner_phone || null,
        owner_name: row.owner_name || null,
        curator_id: row.curator_id,
        curator_name: row.curator_name || null,
        curator_phone: row.curator_phone || null,
        contact_phone: finalContactPhone,
        photos: parsedPhotos.map(
          img => `https://s3.twcstorage.ru/${bucketName}/${img}`
        )
      };
});


    res.status(200).json(properties);
  } catch (error) {
    console.error("Ошибка при получении недвижимости:", {
      message: error.message,
      stack: error.stack,
      query: req.query,
      sqlQuery: query,
      sqlParams: params
    });
    res.status(500).json({ error: `Ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Redirect Properties (Protected, SUPER_ADMIN only)444
app.patch("/api/properties/redirect", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Доступ запрещён: требуется роль SUPER_ADMIN" });
  }

  const { propertyIds, curator_id } = req.body;

  if (!Array.isArray(propertyIds) || !curator_id) {
    return res.status(400).json({ error: "propertyIds должен быть массивом, curator_id обязателен" });
  }

  if (isNaN(parseInt(curator_id))) {
    return res.status(400).json({ error: "curator_id должен быть числом" });
  }
  const finalCuratorId = parseInt(curator_id);

  let connection;
  try {
    connection = await pool.getConnection();
    const [curatorCheck] = await connection.execute(
      "SELECT id, CONCAT(first_name, ' ', last_name) AS curator_name FROM users1 WHERE id = ?",
      [finalCuratorId]
    );
    if (curatorCheck.length === 0) {
      return res.status(400).json({ error: "Недействительный ID куратора" });
    }

    const [existingProperties] = await connection.execute(
      "SELECT id FROM properties WHERE id IN (?)",
      [propertyIds]
    );
    if (existingProperties.length !== propertyIds.length) {
      return res.status(404).json({ error: "Некоторые объекты недвижимости не найдены" });
    }

    const [result] = await connection.execute(
      "UPDATE properties SET curator_id = ? WHERE id IN (?)",
      [finalCuratorId, propertyIds]
    );

    res.json({ message: "Объекты недвижимости успешно перенаправлены", affectedRows: result.affectedRows });
  } catch (error) {
    console.error("Error redirecting properties:", {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Start Server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
  console.log(`Public access: ${publicDomain}:${port}`);
});