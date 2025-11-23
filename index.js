const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const { S3Client, PutObjectCommand, DeleteObjectCommand } = require("@aws-sdk/client-s3");
const path = require("path");
const QRCode = require("qrcode");
const { v4: uuidv4 } = require("uuid");
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

// Список разрешенных расширений изображений
const allowedImageExtensions = [
  '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif',
  '.webp', '.heic', '.heif', '.svg', '.ico', '.jp2', '.avif'
];

// Функция проверки расширения файла
const hasImageExtension = (filename) => {
  if (!filename) return false;
  const ext = path.extname(filename).toLowerCase();
  return allowedImageExtensions.includes(ext);
};

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

    // Проверяем MIME тип
    if (allowedImageTypes.includes(file.mimetype)) {
      console.log(`File ${file.originalname} accepted for upload (MIME: ${file.mimetype})`);
      cb(null, true);
      return;
    }

    // Если MIME тип application/octet-stream или не указан, проверяем расширение файла
    if (file.mimetype === 'application/octet-stream' || !file.mimetype) {
      if (hasImageExtension(file.originalname)) {
        const fileExtension = path.extname(file.originalname).toLowerCase();
        console.log(`File ${file.originalname} accepted for upload (by extension: ${fileExtension}, MIME: ${file.mimetype})`);
        cb(null, true);
        return;
      }
    }

    // Файл отклонен
    console.error(`File ${file.originalname} rejected: Invalid MIME type ${file.mimetype} and extension check failed`);
    cb(new Error('Недопустимый формат файла. Разрешены только изображения (JPEG, PNG, GIF, BMP, TIFF, WebP, HEIC, HEIF, SVG, ICO, JP2, AVIF).'), false);
  },
  limits: { fileSize: 100 * 1024 * 1024 }, // Лимит 100 МБ
});

const MAX_USER_PROPERTY_PHOTOS = 3;

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

const isAdminUser = (user) => {
  const role = user?.role ? user.role.toUpperCase() : "";
  return role === "ADMIN" || role === "SUPER_ADMIN";
};

const bootstrapBusinessTables = async () => {
  let connection;
  try {
    connection = await pool.getConnection();
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS crm_leads (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        owner_id INT UNSIGNED NOT NULL,
        name VARCHAR(255) NOT NULL,
        phone VARCHAR(50),
        email VARCHAR(255),
        budget VARCHAR(255),
        status VARCHAR(50) DEFAULT 'new',
        stage VARCHAR(50) DEFAULT 'lead',
        priority VARCHAR(50) DEFAULT 'medium',
        tags JSON DEFAULT NULL,
        next_action_at DATETIME NULL,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_owner_stage (owner_id, stage),
        FOREIGN KEY (owner_id) REFERENCES users1(id) ON DELETE CASCADE
      ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);
    
    // Add email column if it doesn't exist
    const [emailColumn] = await connection.execute("SHOW COLUMNS FROM crm_leads LIKE 'email'");
    if (emailColumn.length === 0) {
      await connection.execute("ALTER TABLE crm_leads ADD COLUMN email VARCHAR(255) NULL AFTER phone");
    }

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS crm_tasks (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        owner_id INT UNSIGNED NOT NULL,
        lead_id INT UNSIGNED NULL,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        type VARCHAR(50) DEFAULT 'call',
        status VARCHAR(50) DEFAULT 'pending',
        priority VARCHAR(50) DEFAULT 'normal',
        due_at DATETIME NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_owner_status (owner_id, status),
        FOREIGN KEY (owner_id) REFERENCES users1(id) ON DELETE CASCADE,
        FOREIGN KEY (lead_id) REFERENCES crm_leads(id) ON DELETE SET NULL
      ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);
    
    // Add description column if it doesn't exist
    const [descColumn] = await connection.execute("SHOW COLUMNS FROM crm_tasks LIKE 'description'");
    if (descColumn.length === 0) {
      await connection.execute("ALTER TABLE crm_tasks ADD COLUMN description TEXT NULL AFTER title");
    }

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS notifications (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        user_id INT UNSIGNED NOT NULL,
        title VARCHAR(255) NOT NULL,
        body TEXT,
        type VARCHAR(50) DEFAULT 'info',
        is_read TINYINT(1) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        read_at DATETIME NULL,
        INDEX idx_user_read (user_id, is_read),
        FOREIGN KEY (user_id) REFERENCES users1(id) ON DELETE CASCADE
      ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);
  } catch (error) {
    console.error("Error bootstrapping CRM/notification tables:", error.message);
  } finally {
    if (connection) connection.release();
  }
};

bootstrapBusinessTables().catch((err) =>
  console.error("Failed to initialize business tables:", err.message)
);

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
          photos TEXT DEFAULT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users1(id) ON DELETE CASCADE
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
      `);
    } else {
      // Check if photos column exists, if not add it
      const [columns] = await connection.execute("SHOW COLUMNS FROM promotion_orders LIKE 'photos'");
      if (columns.length === 0) {
        console.log("Adding photos column to promotion_orders table...");
        await connection.execute(`
          ALTER TABLE promotion_orders 
          ADD COLUMN photos TEXT DEFAULT NULL
        `);
      }
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

      const [titleColumns] = await connection.execute(
        "SHOW COLUMNS FROM properties LIKE 'title'"
      );
      if (titleColumns.length === 0) {
        console.log("Adding title column to properties table...");
        await connection.execute(
          "ALTER TABLE properties ADD COLUMN title VARCHAR(255) DEFAULT NULL AFTER owner_phone"
        );
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

    // Create chats table
    const [chatTables] = await connection.execute("SHOW TABLES LIKE 'chats'");
    if (chatTables.length === 0) {
      console.log("Creating chats table...");
      await connection.execute(`
        CREATE TABLE chats (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          property_id INT UNSIGNED NOT NULL,
          participant1_id INT UNSIGNED NOT NULL,
          participant2_id INT UNSIGNED NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          FOREIGN KEY (participant1_id) REFERENCES users1(id) ON DELETE CASCADE,
          FOREIGN KEY (participant2_id) REFERENCES users1(id) ON DELETE CASCADE,
          FOREIGN KEY (property_id) REFERENCES properties(id) ON DELETE CASCADE,
          UNIQUE KEY unique_chat (property_id, participant1_id, participant2_id)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci
      `);
    }

    // Create messages table
    const [messageTables] = await connection.execute("SHOW TABLES LIKE 'messages'");
    if (messageTables.length === 0) {
      console.log("Creating messages table...");
      await connection.execute(`
        CREATE TABLE messages (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          chat_id INT UNSIGNED NOT NULL,
          sender_id INT UNSIGNED NOT NULL,
          content TEXT NOT NULL,
          type VARCHAR(20) NOT NULL DEFAULT 'text',
          sticker_id VARCHAR(255) DEFAULT NULL,
          image_url VARCHAR(500) DEFAULT NULL,
          is_read TINYINT(1) NOT NULL DEFAULT 0,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
          FOREIGN KEY (sender_id) REFERENCES users1(id) ON DELETE CASCADE,
          INDEX idx_chat_created (chat_id, created_at DESC),
          INDEX idx_sender (sender_id)
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
    const initialBalance = Number(process.env.INITIAL_USER_BALANCE ?? 500);

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

app.post("/public/payments", authenticate, upload.array("photos", 10), async (req, res) => {
  const {
    propertyId,
    propertyTitle,
    amount,
    duration,
    placement,
    paymentMethod = "QR",
    photoUrls: photoUrlsRaw,
  } = req.body || {};

  if (!propertyId || !propertyTitle || !amount || !duration || !placement) {
    return res.status(400).json({ error: "propertyId, propertyTitle, amount, duration и placement обязательны" });
  }

  const normalizedAmount = parseFloat(amount);
  if (isNaN(normalizedAmount) || normalizedAmount <= 0) {
    return res.status(400).json({ error: "Сумма должна быть положительным числом" });
  }

  // Обрабатываем photoUrls - может быть массивом или строкой JSON
  let photoUrls = [];
  if (photoUrlsRaw) {
    try {
      if (typeof photoUrlsRaw === 'string') {
        // Если это строка, пытаемся распарсить как JSON
        photoUrls = JSON.parse(photoUrlsRaw);
      } else if (Array.isArray(photoUrlsRaw)) {
        // Если это уже массив, используем как есть
        photoUrls = photoUrlsRaw;
      }
      // Убеждаемся, что это массив
      if (!Array.isArray(photoUrls)) {
        photoUrls = [];
      }
    } catch (parseError) {
      console.warn(`Error parsing photoUrls:`, parseError.message);
      photoUrls = [];
    }
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

    // Получаем фотографии объявления из базы данных
    let propertyPhotos = [];
    try {
      const [propertyRows] = await connection.execute(
        "SELECT photos FROM properties WHERE id = ?",
        [propertyId]
      );
      if (propertyRows.length > 0 && propertyRows[0].photos) {
        try {
          propertyPhotos = JSON.parse(propertyRows[0].photos) || [];
        } catch (parseError) {
          console.warn(`Error parsing property photos for ID ${propertyId}:`, parseError.message);
          propertyPhotos = [];
        }
      }
    } catch (propertyError) {
      console.warn(`Error fetching property photos for ID ${propertyId}:`, propertyError.message);
    }

    // Обрабатываем фотографии из запроса (URLs)
    let photoUrlsFromRequest = [];
    if (photoUrls && Array.isArray(photoUrls) && photoUrls.length > 0) {
      // Извлекаем ключи из URL (если это S3 URLs)
      photoUrlsFromRequest = photoUrls.map(url => {
        if (typeof url === 'string' && url.includes(bucketName)) {
          // Извлекаем ключ из URL вида https://s3.twcstorage.ru/bucketName/key
          const parts = url.split(`/${bucketName}/`);
          if (parts.length > 1) {
            return parts[1];
          }
        }
        return null;
      }).filter(key => key !== null);
    }

    // Обрабатываем загруженные фотографии (если есть)
    const uploadedPhotoKeys = [];
    if (req.files && req.files.length > 0) {
      for (const photo of req.files) {
        try {
          const key = `${Date.now()}-${Math.round(Math.random() * 1e9)}${path.extname(photo.originalname)}`;
          await s3Client.send(new PutObjectCommand({
            Bucket: bucketName,
            Key: key,
            Body: photo.buffer,
            ContentType: photo.mimetype,
          }));
          uploadedPhotoKeys.push(key);
        } catch (error) {
          console.error(`Failed to upload photo to S3: ${photo.originalname}`, error.message);
          // Продолжаем даже если одна фотография не загрузилась
        }
      }
    }

    // Объединяем фотографии: сначала загруженные файлы, потом URLs из запроса, потом из объявления
    const allPhotos = [...uploadedPhotoKeys, ...photoUrlsFromRequest, ...propertyPhotos];
    // Удаляем дубликаты
    const uniquePhotos = [...new Set(allPhotos)];
    const photosJson = uniquePhotos.length > 0 ? JSON.stringify(uniquePhotos) : null;

    const newBalance = currentBalance - normalizedAmount;
    await connection.execute(
      "UPDATE users1 SET balance = ? WHERE id = ?",
      [newBalance, req.user.id]
    );

    const [result] = await connection.execute(
      `INSERT INTO promotion_orders
        (user_id, property_id, property_title, duration, placement, amount, payment_method, status, photos)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.user.id,
        propertyId,
        propertyTitle,
        duration,
        placement,
        normalizedAmount,
        paymentMethod,
        "processing",
        photosJson,
      ]
    );

    await connection.commit();

    // Формируем полные URL для фотографий
    const photoUrlsResponse = uniquePhotos.map(img => `https://s3.twcstorage.ru/${bucketName}/${img}`);

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
        photos: photoUrlsResponse,
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
      `SELECT id, property_id, property_title, duration, placement, amount, payment_method, status, photos, created_at
       FROM promotion_orders
       WHERE user_id = ?
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    // Обрабатываем фотографии для каждого заказа
    const ordersWithPhotos = rows.map(row => {
      let parsedPhotos = [];
      if (row.photos) {
        try {
          parsedPhotos = JSON.parse(row.photos) || [];
        } catch (error) {
          console.warn(`Error parsing photos for order ID ${row.id}:`, error.message);
          parsedPhotos = [];
        }
      }
      return {
        ...row,
        photos: parsedPhotos.map(img => `https://s3.twcstorage.ru/${bucketName}/${img}`),
      };
    });

    res.json(ordersWithPhotos);
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

// Admin payments overview
app.get("/api/payments", authenticate, async (req, res) => {
  if (!["SUPER_ADMIN", "ADMIN"].includes(req.user.role)) {
    return res.status(403).json({ error: "Доступ запрещён: требуется роль ADMIN или SUPER_ADMIN" });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute(
      `SELECT po.*, u.first_name, u.last_name, u.email, u.phone
       FROM promotion_orders po
       LEFT JOIN users1 u ON u.id = po.user_id
       ORDER BY po.created_at DESC`
    );

    const payments = rows.map((row) => {
      let parsedPhotos = [];
      if (row.photos) {
        try {
          parsedPhotos = JSON.parse(row.photos) || [];
        } catch (error) {
          console.warn(`Error parsing photos for order ID ${row.id}:`, error.message);
          parsedPhotos = [];
        }
      }
      return {
        id: row.id,
        user_id: row.user_id,
        user_name: `${row.first_name || ""} ${row.last_name || ""}`.trim(),
        user_email: row.email,
        user_phone: row.phone,
        property_id: row.property_id,
        property_title: row.property_title,
        duration: row.duration,
        placement: row.placement,
        amount: Number(row.amount),
        payment_method: row.payment_method,
        status: row.status,
        photos: parsedPhotos.map(img => `https://s3.twcstorage.ru/${bucketName}/${img}`),
        created_at: row.created_at,
        updated_at: row.updated_at,
      };
    });

    res.json(payments);
  } catch (error) {
    console.error("Admin payments fetch error:", {
      message: error.message,
      stack: error.stack,
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

app.patch("/api/payments/:id", authenticate, async (req, res) => {
  if (!["SUPER_ADMIN", "ADMIN"].includes(req.user.role)) {
    return res.status(403).json({ error: "Доступ запрещён: требуется роль ADMIN или SUPER_ADMIN" });
  }

  const { id } = req.params;
  const { status } = req.body || {};
  const allowedStatuses = ["processing", "active", "completed", "rejected"];
  if (!status || !allowedStatuses.includes(status)) {
    return res.status(400).json({ error: "Некорректный статус" });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    const [orders] = await connection.execute("SELECT id FROM promotion_orders WHERE id = ?", [id]);
    if (orders.length === 0) {
      return res.status(404).json({ error: "Заявка не найдена" });
    }

    await connection.execute(
      "UPDATE promotion_orders SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
      [status, id]
    );

    res.json({ message: "Статус обновлён" });
  } catch (error) {
    console.error("Admin payment status update error:", {
      message: error.message,
      stack: error.stack,
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

app.patch("/public/payments/:id", authenticate, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body || {};

  const allowedStatuses = ["processing", "active", "completed", "rejected"];
  if (!status || !allowedStatuses.includes(status)) {
    return res.status(400).json({ error: "Некорректный статус" });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    const [orders] = await connection.execute(
      "SELECT user_id FROM promotion_orders WHERE id = ?",
      [id]
    );
    if (orders.length === 0) {
      return res.status(404).json({ error: "Заявка не найдена" });
    }
    if (orders[0].user_id !== req.user.id) {
      return res.status(403).json({ error: "Нет прав на изменение этой заявки" });
    }

    await connection.execute(
      "UPDATE promotion_orders SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
      [status, id]
    );

    res.json({ message: "Статус обновлён" });
  } catch (error) {
    console.error("Ошибка при обновлении статуса заявки:", {
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
    title,
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
        type_id, repair, series, zhk_id, document_id, owner_name, owner_phone, title, curator_id, price, unit, rukprice, mkv, rooms, phone, 
        district_id, subdistrict_id, address, notes, description, photos, document, status, owner_id, etaj, etajnost
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        type_id || null,
        repair || null,
        series || null,
        zhk_id || null,
        0,
        owner_name || null,
        owner_phone || null,
        title || null,
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
      title: title || null,
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

// Public endpoint for users to submit their property for review
app.patch("/public/user/properties/:id/submit", authenticate, async (req, res) => {
  const { id } = req.params;

  if (!id || isNaN(parseInt(id))) {
    return res.status(400).json({ error: "ID объекта должен быть числом" });
  }

  let connection;
  try {
    connection = await pool.getConnection();

    // Проверяем, что объявление существует и принадлежит пользователю
    const [properties] = await connection.execute(
      "SELECT id, owner_id, status, title FROM properties WHERE id = ?",
      [parseInt(id)]
    );

    if (properties.length === 0) {
      return res.status(404).json({ error: "Объявление не найдено" });
    }

    const property = properties[0];

    // Проверяем, что объявление принадлежит текущему пользователю
    if (property.owner_id !== req.user.id) {
      return res.status(403).json({ error: "У вас нет прав на отправку этого объявления на проверку" });
    }

    // Проверяем, что объявление еще не опубликовано
    if (property.status === "Актуально" || property.status === "active") {
      return res.status(400).json({ error: "Объявление уже опубликовано" });
    }

    // Обновляем статус на pending_review
    await connection.execute(
      "UPDATE properties SET status = 'pending_review', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
      [parseInt(id)]
    );

    res.json({
      id: parseInt(id),
      status: "pending_review",
      message: "Объявление отправлено на модерацию",
      title: property.title,
    });
  } catch (error) {
    console.error("Error submitting property for review:", {
      message: error.message,
      stack: error.stack,
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Public endpoint for regular users to create listings
app.post("/public/user/properties", authenticate, upload.array("photos", MAX_USER_PROPERTY_PHOTOS), async (req, res) => {
  console.log("=== Creating property from user ===");
  console.log("Request body:", req.body);
  console.log("Files received:", req.files?.length || 0);
  console.log("User ID:", req.user?.id);
  
  const {
    category,
    deal_type,
    title,
    description,
    price,
    area,
    rooms,
    location,
    phone,
  } = req.body || {};

  const cleanCategory = category?.trim();
  const cleanDealType = deal_type?.trim();
  const cleanTitle = title?.trim();
  const cleanDescription = description?.trim();
  const cleanRooms = rooms?.trim();
  const cleanLocation = location?.trim();
  const cleanPhone = phone?.trim();
  
  console.log("Cleaned data:", {
    category: cleanCategory,
    deal_type: cleanDealType,
    title: cleanTitle,
    price,
    area,
    rooms: cleanRooms,
    location: cleanLocation,
    phone: cleanPhone,
  });

  if (!cleanCategory || !cleanDealType || !cleanTitle || !cleanDescription || !price || !area || !cleanRooms || !cleanLocation || !cleanPhone) {
    return res.status(400).json({ error: "Заполните обязательные поля: категория, тип сделки, название, описание, цена, площадь, комнаты, адрес и телефон." });
  }

  const parsedPrice = parseFloat(price.toString().replace(/\s|,/g, ""));
  const parsedArea = parseFloat(area.toString().replace(/\s|,/g, ""));
  if (isNaN(parsedPrice) || isNaN(parsedArea)) {
    return res.status(400).json({ error: "Цена и площадь должны быть числом." });
  }

  const uploadedPhotos = req.files || [];
  if (!uploadedPhotos.length) {
    return res.status(400).json({ error: "Добавьте хотя бы одно фото." });
  }
  if (uploadedPhotos.length > MAX_USER_PROPERTY_PHOTOS) {
    return res.status(400).json({ error: `Можно загрузить максимум ${MAX_USER_PROPERTY_PHOTOS} фото.` });
  }

  let connection;
  try {
    connection = await pool.getConnection();

    const filenames = [];
    for (const photo of uploadedPhotos) {
      const key = `${Date.now()}-${Math.round(Math.random() * 1e9)}${path.extname(photo.originalname)}`;
      console.log(`Uploading photo: ${photo.originalname} -> ${key} (${photo.size} bytes, ${photo.mimetype})`);
      try {
        await s3Client.send(new PutObjectCommand({
          Bucket: bucketName,
          Key: key,
          Body: photo.buffer,
          ContentType: photo.mimetype,
        }));
        filenames.push(key);
        console.log(`Photo uploaded successfully: ${key}`);
      } catch (s3Error) {
        console.error(`Failed to upload photo ${photo.originalname}:`, s3Error);
        throw new Error(`Не удалось загрузить фото: ${photo.originalname}`);
      }
    }

    const ownerName = `${req.user.first_name || ""} ${req.user.last_name || ""}`.trim() || null;
    const contactPhone = cleanPhone;

    const insertValues = [
      cleanTitle,
      cleanCategory,
      ownerName,
      contactPhone,
      parsedPrice,
      parsedArea,
      cleanRooms,
      contactPhone,
      cleanLocation,
      cleanDescription,
      JSON.stringify(filenames),
      req.user.id,
      cleanDealType,
      1,
      1,
      "Создано пользователем через приложение",
    ];
    
    console.log("Inserting property with values:", {
      title: cleanTitle,
      type_id: cleanCategory,
      owner_name: ownerName,
      owner_phone: contactPhone,
      price: parsedPrice,
      area: parsedArea,
      rooms: cleanRooms,
      phone: contactPhone,
      address: cleanLocation,
      description: cleanDescription,
      deal_type: cleanDealType,
      photos_count: filenames.length,
      owner_id: req.user.id,
    });
    
    const [result] = await connection.execute(
      `INSERT INTO properties (
        title, type_id, owner_name, owner_phone, price, mkv, rooms, phone, address, description, photos, status, owner_id, unit, etaj, etajnost, notes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_review', ?, ?, ?, ?, ?)`,
      insertValues
    );

    console.log("Property created successfully with ID:", result.insertId);
    
    // Проверяем, что данные действительно сохранились
    const [savedProperty] = await connection.execute(
      "SELECT id, title, type_id, price, mkv, rooms, address, description, photos, status FROM properties WHERE id = ?",
      [result.insertId]
    );
    console.log("Verified saved property:", savedProperty[0]);

    res.status(201).json({
      id: result.insertId,
      status: "pending_review",
      message: "Объявление отправлено на модерацию",
      photos: filenames.map((img) => `https://s3.twcstorage.ru/${bucketName}/${img}`),
    });
  } catch (error) {
    console.error("Error creating public property:", error);
    res.status(500).json({ error: `Не удалось сохранить объявление: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Get user's own properties (authenticated)
app.get("/public/user/properties", authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    
    const [rows] = await connection.execute(
      `SELECT id, title, type_id, price, mkv, rooms, address, description, status, photos, 
              owner_name, owner_phone, phone, unit, created_at, updated_at
       FROM properties 
       WHERE owner_id = ?
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    console.log(`Fetching properties for user ${req.user.id}, found ${rows.length} properties`);

    const properties = rows.map(row => {
      let parsedPhotos = [];
      if (row.photos) {
        try {
          parsedPhotos = JSON.parse(row.photos) || [];
        } catch (error) {
          console.warn(`Error parsing photos for property ID ${row.id}:`, error.message);
          parsedPhotos = [];
        }
      }

      // Маппим unit (deal_type) в понятное значение
      let dealType = 'Продажа';
      if (row.unit) {
        const unitLower = row.unit.toString().toLowerCase();
        if (unitLower.includes('аренд') || unitLower === 'rent') {
          dealType = 'Аренда';
        }
      }

      const property = {
        id: row.id,
        title: row.title || null,
        category: row.type_id || null,
        price: row.price ? parseFloat(row.price) : null,
        area: row.mkv ? parseFloat(row.mkv) : null,
        rooms: row.rooms || null,
        location: row.address || null,
        phone: row.owner_phone || row.phone || null,
        description: row.description || null,
        status: row.status || null, // Возвращаем статус как есть из базы данных
        deal_type: dealType,
        photos: parsedPhotos.map(img => `https://s3.twcstorage.ru/${bucketName}/${img}`),
        createdAt: row.created_at ? new Date(row.created_at).toISOString() : null,
        updatedAt: row.updated_at ? new Date(row.updated_at).toISOString() : null,
      };

      console.log(`Property ID ${row.id}: status="${row.status}", title="${row.title}"`);
      return property;
    });

    console.log(`Returning ${properties.length} properties to user`);
    res.json(properties);
  } catch (error) {
    console.error("Error fetching user properties:", {
      message: error.message,
      stack: error.stack,
    });
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Delete user's own property (authenticated)
app.delete("/public/user/properties/:id", authenticate, async (req, res) => {
  const { id } = req.params;

  if (!id || isNaN(parseInt(id))) {
    return res.status(400).json({ error: "ID объекта должен быть числом" });
  }

  let connection;
  try {
    connection = await pool.getConnection();

    // Проверяем, что объявление существует и принадлежит пользователю
    const [properties] = await connection.execute(
      "SELECT id, owner_id, photos, document FROM properties WHERE id = ?",
      [parseInt(id)]
    );

    if (properties.length === 0) {
      return res.status(404).json({ error: "Объявление не найдено" });
    }

    const property = properties[0];

    // Проверяем, что объявление принадлежит текущему пользователю
    if (property.owner_id !== req.user.id) {
      return res.status(403).json({ error: "У вас нет прав на удаление этого объявления" });
    }

    // Удаляем фотографии из S3
    let photoFiles = [];
    if (property.photos) {
      try {
        photoFiles = JSON.parse(property.photos) || [];
      } catch (error) {
        console.warn(`Error parsing photos for property ID ${id}:`, error.message);
        photoFiles = [];
      }
    }

    // Удаляем фотографии из S3
    for (const photoKey of photoFiles) {
      try {
        await s3Client.send(new DeleteObjectCommand({
          Bucket: bucketName,
          Key: photoKey,
        }));
        console.log(`Deleted photo from S3: ${photoKey}`);
      } catch (error) {
        console.error(`Error deleting photo ${photoKey} from S3:`, error.message);
        // Продолжаем удаление даже если фото не удалось удалить из S3
      }
    }

    // Удаляем документ из S3, если есть
    if (property.document) {
      try {
        await s3Client.send(new DeleteObjectCommand({
          Bucket: bucketName,
          Key: property.document,
        }));
        console.log(`Deleted document from S3: ${property.document}`);
      } catch (error) {
        console.error(`Error deleting document ${property.document} from S3:`, error.message);
        // Продолжаем удаление даже если документ не удалось удалить из S3
      }
    }

    // Удаляем объявление из базы данных
    await connection.execute(
      "DELETE FROM properties WHERE id = ?",
      [parseInt(id)]
    );

    console.log(`Property ID ${id} deleted by user ${req.user.id}`);

    res.json({
      message: "Объявление успешно удалено",
      id: parseInt(id),
    });
  } catch (error) {
    console.error("Error deleting user property:", {
      message: error.message,
      stack: error.stack,
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
    title,
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

  // Логируем входящие данные для отладки
  console.log("=== Property Update Request ===");
  console.log("Property ID:", id);
  console.log("User:", req.user?.email, "Role:", req.user?.role);
  console.log("Body fields:", {
    type_id,
    price,
    rukprice,
    mkv,
    address,
    etaj,
    etajnost,
    rooms,
    repair,
    series,
    status,
  });

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

  // Проверяем обязательные поля (учитываем пустые строки как отсутствие)
  const missingFields = [];
  if (!type_id || type_id.trim() === '') missingFields.push('type_id');
  if (!price || price === '' || price === null || price === undefined) missingFields.push('price');
  if (!rukprice || rukprice === '' || rukprice === null || rukprice === undefined) missingFields.push('rukprice');
  if (!mkv || mkv === '' || mkv === null || mkv === undefined) missingFields.push('mkv');
  if (!address || address.trim() === '') missingFields.push('address');
  if (!etaj || etaj === '' || etaj === null || etaj === undefined) missingFields.push('etaj');
  if (!etajnost || etajnost === '' || etajnost === null || etajnost === undefined) missingFields.push('etajnost');
  
  if (missingFields.length > 0) {
    console.error("Missing required fields:", missingFields);
    return res.status(400).json({ error: `Все обязательные поля (type_id, price, rukprice, mkv, address, etaj, etajnost) должны быть заполнены. Отсутствуют: ${missingFields.join(', ')}` });
  }

  if (isNaN(parseFloat(price)) || isNaN(parseFloat(rukprice)) || isNaN(parseFloat(mkv)) || isNaN(parseInt(etaj)) || isNaN(parseInt(etajnost))) {
    console.error("Invalid numeric values:", { price, rukprice, mkv, etaj, etajnost });
    return res.status(400).json({ error: "Поля price, rukprice, mkv, etaj, etajnost должны быть числами" });
  }

  // Валидация опциональных полей только если они указаны и не пустые
  if (type_id === "Квартира" && repair && typeof repair === 'string' && repair.trim() !== '' && !["ПСО", "С отделкой"].includes(repair.trim())) {
    console.error("Invalid repair value:", repair);
    return res.status(400).json({ error: "Недействительное значение ремонта. Должно быть: ПСО, С отделкой" });
  }

  if (type_id === "Квартира" && series && typeof series === 'string' && series.trim() !== '' && ![
    "105 серия", "106 серия", "Индивидуалка", "Элитка", "103 серия", "106 серия улучшенная",
    "107 серия", "108 серия", "Малосемейка", "Общежитие и Гостиничного типа", "Сталинка", "Хрущевка"
  ].includes(series.trim())) {
    console.error("Invalid series value:", series);
    return res.status(400).json({ error: "Недействительная серия. Должна быть одной из: 105 серия, 106 серия, Индивидуалка, Элитка, 103 серия, 106 серия улучшенная, 107 серия, 108 серия, Малосемейка, Общежитие и Гостиничного типа, Сталинка, Хрущевка" });
  }

  // rooms проверяем только если указано и не пустое
  if (type_id === "Квартира" && rooms && (typeof rooms === 'string' ? rooms.trim() !== '' : rooms) && !["1", "2", "3", "4", "5+"].includes(String(rooms).trim())) {
    console.error("Invalid rooms value:", rooms, "type:", typeof rooms);
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
        type_id = ?, repair = ?, series = ?, zhk_id = ?, document_id = ?, owner_name = ?, owner_phone = ?, title = ?, curator_id = ?, price = ?, unit = ?, rukprice = ?, mkv = ?, rooms = ?, phone = ?,
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
        title || null,
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
      title: title || null,
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
      "SELECT id, title, type_id, price, rukprice, mkv, status, address, created_at FROM properties"
    );

    const listings = rows.map(row => ({
      id: row.id,
      title: row.title || null,
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
      `SELECT id, type_id, repair, series, zhk_id, price, mkv, rooms, district_id, subdistrict_id, 
              address, description, notes, status, etaj, etajnost, photos, document, owner_name, 
              owner_phone, title, curator_id, phone, owner_id, latitude, longitude, created_at
       FROM properties WHERE id = ?`,
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

    const finalContactPhone = row.owner_phone || row.phone || null;

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
      title: row.title || null,
      curator_id: row.curator_id || null,
      contact_phone: finalContactPhone,
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
               FROM properties 
               WHERE 1=1
               AND (status IS NULL OR status != 'pending_review')`;
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
                 id,
                 type_id,
                 repair,
                 series,
                 zhk_id,
                 price,
                 mkv,
                 rooms,
                 district_id,
                 subdistrict_id,
                 address,
                 description,
                 status,
                 etaj,
                 etajnost,
                 photos,
                 owner_phone,
                 owner_name,
                 title,
                 curator_id,
                 phone
               FROM properties
               WHERE 1=1
               AND (status IS NULL OR status != 'pending_review')`;
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
      query += ` AND id = ?`;
      params.push(parseInt(bid));
    } else if (bid) {
      return res.status(400).json({ error: "Недействительный параметр bid: должен быть числом" });
    }

    if (titles && typeof titles === "string" && titles.trim()) {
      query += ` AND (address = ? OR description = ?)`;
      params.push(titles.trim(), titles.trim());
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

      const finalContactPhone = row.owner_phone || row.phone || null;

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
        title: row.title || null,
        curator_id: row.curator_id || null,
        contact_phone: finalContactPhone,
        photos: parsedPhotos.map(
          img => `https://s3.twcstorage.ru/${bucketName}/${img}`
        )
      };
});

// CRM Dashboard
app.get("/api/crm/dashboard", authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    
    // Ensure CRM tables exist
    try {
      await connection.execute(`
        CREATE TABLE IF NOT EXISTS crm_leads (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          owner_id INT UNSIGNED NOT NULL,
          name VARCHAR(255) NOT NULL,
          phone VARCHAR(50),
          email VARCHAR(255),
          budget VARCHAR(255),
          status VARCHAR(50) DEFAULT 'new',
          stage VARCHAR(50) DEFAULT 'lead',
          priority VARCHAR(50) DEFAULT 'medium',
          tags JSON DEFAULT NULL,
          next_action_at DATETIME NULL,
          notes TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          INDEX idx_owner_stage (owner_id, stage),
          FOREIGN KEY (owner_id) REFERENCES users1(id) ON DELETE CASCADE
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
      `);
      
      await connection.execute(`
        CREATE TABLE IF NOT EXISTS crm_tasks (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          owner_id INT UNSIGNED NOT NULL,
          lead_id INT UNSIGNED NULL,
          title VARCHAR(255) NOT NULL,
          description TEXT,
          type VARCHAR(50) DEFAULT 'call',
          status VARCHAR(50) DEFAULT 'pending',
          priority VARCHAR(50) DEFAULT 'normal',
          due_at DATETIME NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          INDEX idx_owner_status (owner_id, status),
          FOREIGN KEY (owner_id) REFERENCES users1(id) ON DELETE CASCADE,
          FOREIGN KEY (lead_id) REFERENCES crm_leads(id) ON DELETE SET NULL
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
      `);
    } catch (tableError) {
      console.log("CRM tables check:", tableError.message);
    }
    
    const userId = req.user.id;

    const [funnelRows] = await connection.execute(
      "SELECT stage, COUNT(*) as count FROM crm_leads WHERE owner_id = ? GROUP BY stage",
      [userId]
    );

    const [hotRows] = await connection.execute(
      "SELECT COUNT(*) as total FROM crm_leads WHERE owner_id = ? AND priority = 'high'",
      [userId]
    );

    const [taskRows] = await connection.execute(
      "SELECT id, title, type, status, priority, due_at FROM crm_tasks WHERE owner_id = ? AND DATE(due_at) = CURDATE() ORDER BY due_at ASC LIMIT 10",
      [userId]
    );

    const [pendingTasks] = await connection.execute(
      "SELECT status, COUNT(*) as count FROM crm_tasks WHERE owner_id = ? GROUP BY status",
      [userId]
    );

    const totalLeads = funnelRows.reduce((sum, row) => sum + row.count, 0);
    const activeDeals = funnelRows.find((row) => row.stage === "deal")?.count || 0;
    const newLeads = funnelRows.find((row) => row.stage === "lead")?.count || 0;

    res.json({
      totals: {
        totalLeads,
        activeDeals,
        hotLeads: hotRows[0]?.total || 0,
        newLeads,
        pendingTasks: pendingTasks.find((row) => row.status === "pending")?.count || 0,
      },
      funnel: funnelRows.map((row) => ({
        stage: row.stage,
        count: row.count,
      })),
      tasksToday: taskRows.map((task) => ({
        id: task.id,
        title: task.title,
        type: task.type,
        status: task.status,
        priority: task.priority,
        dueAt: task.due_at,
      })),
    });
  } catch (error) {
    console.error("Error fetching CRM dashboard:", error.message);
    res.status(500).json({ error: `Не удалось получить данные CRM: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// CRM Leads
app.get("/api/crm/leads", authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute(
      `SELECT id, name, phone, budget, status, stage, priority, next_action_at, notes, created_at
       FROM crm_leads
       WHERE owner_id = ?
       ORDER BY created_at DESC
       LIMIT 100`,
      [req.user.id]
    );
    res.json(rows);
  } catch (error) {
    console.error("Error fetching CRM leads:", error.message);
    res.status(500).json({ error: `Не удалось получить список лидов: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

app.post("/api/crm/leads", authenticate, async (req, res) => {
  const { name, phone, email, budget, status = "new", stage = "lead", priority = "medium", nextActionAt, notes } = req.body || {};
  if (!name || !name.trim()) {
    return res.status(400).json({ error: "Имя лида обязательно" });
  }
  let connection;
  try {
    connection = await pool.getConnection();
    const [result] = await connection.execute(
      `INSERT INTO crm_leads (owner_id, name, phone, email, budget, status, stage, priority, next_action_at, notes)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.user.id,
        name.trim(),
        phone?.trim() || null,
        email?.trim() || null,
        budget?.trim() || null,
        status,
        stage,
        priority,
        nextActionAt || null,
        notes || null,
      ]
    );
    const [leadRows] = await connection.execute(
      "SELECT * FROM crm_leads WHERE id = ?",
      [result.insertId]
    );
    res.status(201).json(leadRows[0]);
  } catch (error) {
    console.error("Error creating CRM lead:", error.message);
    res.status(500).json({ error: `Не удалось создать лид: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

app.patch("/api/crm/leads/:id", authenticate, async (req, res) => {
  const { id } = req.params;
  const { status, stage, priority, notes, nextActionAt } = req.body || {};
  if (!id || isNaN(parseInt(id))) {
    return res.status(400).json({ error: "Некорректный идентификатор лида" });
  }
  let connection;
  try {
    connection = await pool.getConnection();
    const [leads] = await connection.execute(
      "SELECT owner_id FROM crm_leads WHERE id = ?",
      [parseInt(id)]
    );
    if (leads.length === 0) {
      return res.status(404).json({ error: "Лид не найден" });
    }
    if (leads[0].owner_id !== req.user.id) {
      return res.status(403).json({ error: "Нет доступа к этому лиду" });
    }

    await connection.execute(
      `UPDATE crm_leads
       SET status = COALESCE(?, status),
           stage = COALESCE(?, stage),
           priority = COALESCE(?, priority),
           notes = COALESCE(?, notes),
           next_action_at = COALESCE(?, next_action_at)
       WHERE id = ?`,
      [status, stage, priority, notes, nextActionAt, parseInt(id)]
    );

    const [leadRows] = await connection.execute("SELECT * FROM crm_leads WHERE id = ?", [parseInt(id)]);
    res.json(leadRows[0]);
  } catch (error) {
    console.error("Error updating CRM lead:", error.message);
    res.status(500).json({ error: `Не удалось обновить лид: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// CRM Tasks
app.get("/api/crm/tasks", authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    
    // Ensure CRM tasks table exists
    try {
      await connection.execute(`
        CREATE TABLE IF NOT EXISTS crm_tasks (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          owner_id INT UNSIGNED NOT NULL,
          lead_id INT UNSIGNED NULL,
          title VARCHAR(255) NOT NULL,
          description TEXT,
          type VARCHAR(50) DEFAULT 'call',
          status VARCHAR(50) DEFAULT 'pending',
          priority VARCHAR(50) DEFAULT 'normal',
          due_at DATETIME NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          INDEX idx_owner_status (owner_id, status),
          FOREIGN KEY (owner_id) REFERENCES users1(id) ON DELETE CASCADE,
          FOREIGN KEY (lead_id) REFERENCES crm_leads(id) ON DELETE SET NULL
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
      `);
    } catch (tableError) {
      console.log("CRM tasks table check:", tableError.message);
    }
    
    const [rows] = await connection.execute(
      `SELECT id, title, type, status, priority, due_at, lead_id
       FROM crm_tasks
       WHERE owner_id = ?
       ORDER BY due_at ASC
       LIMIT 100`,
      [req.user.id]
    );
    res.json(rows);
  } catch (error) {
    console.error("Error fetching CRM tasks:", error.message);
    res.status(500).json({ error: `Не удалось получить задачи: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

app.post("/api/crm/tasks", authenticate, async (req, res) => {
  const { title, description, type = "call", priority = "normal", dueAt, leadId } = req.body || {};
  if (!title || !title.trim()) {
    return res.status(400).json({ error: "Название задачи обязательно" });
  }
  let connection;
  try {
    connection = await pool.getConnection();
    
    // Ensure CRM tasks table exists
    try {
      await connection.execute(`
        CREATE TABLE IF NOT EXISTS crm_tasks (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          owner_id INT UNSIGNED NOT NULL,
          lead_id INT UNSIGNED NULL,
          title VARCHAR(255) NOT NULL,
          description TEXT,
          type VARCHAR(50) DEFAULT 'call',
          status VARCHAR(50) DEFAULT 'pending',
          priority VARCHAR(50) DEFAULT 'normal',
          due_at DATETIME NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          INDEX idx_owner_status (owner_id, status),
          FOREIGN KEY (owner_id) REFERENCES users1(id) ON DELETE CASCADE,
          FOREIGN KEY (lead_id) REFERENCES crm_leads(id) ON DELETE SET NULL
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
      `);
    } catch (tableError) {
      console.log("CRM tasks table check:", tableError.message);
    }
    
    const [result] = await connection.execute(
      `INSERT INTO crm_tasks (owner_id, lead_id, title, description, type, priority, due_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        req.user.id,
        leadId || null,
        title.trim(),
        description?.trim() || null,
        type,
        priority,
        dueAt || null,
      ]
    );
    const [taskRows] = await connection.execute("SELECT * FROM crm_tasks WHERE id = ?", [result.insertId]);
    res.status(201).json(taskRows[0]);
  } catch (error) {
    console.error("Error creating CRM task:", error.message);
    res.status(500).json({ error: `Не удалось создать задачу: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

app.patch("/api/crm/tasks/:id/status", authenticate, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body || {};
  if (!id || isNaN(parseInt(id)) || !status) {
    return res.status(400).json({ error: "Некорректные данные для обновления задачи" });
  }
  let connection;
  try {
    connection = await pool.getConnection();
    const [tasks] = await connection.execute(
      "SELECT owner_id FROM crm_tasks WHERE id = ?",
      [parseInt(id)]
    );
    if (tasks.length === 0) {
      return res.status(404).json({ error: "Задача не найдена" });
    }
    if (tasks[0].owner_id !== req.user.id) {
      return res.status(403).json({ error: "Нет доступа к этой задаче" });
    }
    await connection.execute(
      "UPDATE crm_tasks SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
      [status, parseInt(id)]
    );
    res.json({ message: "Статус задачи обновлён" });
  } catch (error) {
    console.error("Error updating CRM task:", error.message);
    res.status(500).json({ error: `Не удалось обновить задачу: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Notifications
app.get("/api/notifications", authenticate, async (req, res) => {
  let connection;
  // Ensure limit is a safe integer (max 200 for notifications)
  const limit = Math.min(Math.max(parseInt(req.query.limit) || 50, 1), 200);
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute(
      `SELECT id, title, body, type, is_read, created_at, read_at
       FROM notifications
       WHERE user_id = ?
       ORDER BY created_at DESC
       LIMIT ${limit}`,
      [req.user.id]
    );
    res.json(rows);
  } catch (error) {
    console.error("Error fetching notifications:", error.message);
    res.status(500).json({ error: `Не удалось получить уведомления: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

app.post("/api/notifications", authenticate, async (req, res) => {
  if (!isAdminUser(req.user)) {
    return res.status(403).json({ error: "Доступ запрещён" });
  }
  const { userId, title, body, type = "info" } = req.body || {};
  if (!userId || !title) {
    return res.status(400).json({ error: "userId и title обязательны" });
  }
  let connection;
  try {
    connection = await pool.getConnection();
    await connection.execute(
      `INSERT INTO notifications (user_id, title, body, type)
       VALUES (?, ?, ?, ?)`,
      [userId, title, body || null, type]
    );
    res.status(201).json({ message: "Уведомление создано" });
  } catch (error) {
    console.error("Error creating notification:", error.message);
    res.status(500).json({ error: `Не удалось создать уведомление: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

app.patch("/api/notifications/:id/read", authenticate, async (req, res) => {
  const { id } = req.params;
  if (!id || isNaN(parseInt(id))) {
    return res.status(400).json({ error: "Некорректный идентификатор уведомления" });
  }
  let connection;
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT user_id FROM notifications WHERE id = ?",
      [parseInt(id)]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: "Уведомление не найдено" });
    }
    if (rows[0].user_id !== req.user.id) {
      return res.status(403).json({ error: "Нет доступа к этому уведомлению" });
    }
    await connection.execute(
      "UPDATE notifications SET is_read = 1, read_at = CURRENT_TIMESTAMP WHERE id = ?",
      [parseInt(id)]
    );
    res.json({ message: "Уведомление отмечено прочитанным" });
  } catch (error) {
    console.error("Error updating notification:", error.message);
    res.status(500).json({ error: `Не удалось обновить уведомление: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
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

// QR Code эндпоинты для входа в личный кабинет
// Генерация QR-кода для входа
app.get('/api/qr/generate', authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    const userId = req.user.id;
    
    // Создаем временный токен для QR-кода (действителен 5 минут)
    const qrToken = uuidv4();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 минут
    
    // Сохраняем токен в базе данных
    await connection.execute(
      `CREATE TABLE IF NOT EXISTS qr_login_tokens (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        token VARCHAR(255) NOT NULL UNIQUE,
        expires_at DATETIME NOT NULL,
        used BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_token (token),
        INDEX idx_user_id (user_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
    );
    
    await connection.execute(
      'INSERT INTO qr_login_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
      [userId, qrToken, expiresAt]
    );
    
    // Генерируем URL для QR-кода
    const qrUrl = `${publicDomain}/login?qr_token=${qrToken}`;
    
    // Генерируем QR-код как base64 изображение
    const qrCodeDataUrl = await QRCode.toDataURL(qrUrl, {
      errorCorrectionLevel: 'M',
      type: 'image/png',
      quality: 0.92,
      margin: 2,
      color: {
        dark: '#000000',
        light: '#FFFFFF'
      },
      width: 400
    });
    
    res.json({
      success: true,
      qrCode: qrCodeDataUrl,
      token: qrToken,
      url: qrUrl,
      expiresAt: expiresAt.toISOString()
    });
  } catch (error) {
    console.error('Ошибка генерации QR-кода:', error);
    res.status(500).json({ 
      success: false,
      error: 'Ошибка генерации QR-кода' 
    });
  } finally {
    if (connection) connection.release();
  }
});

// Обработка входа через QR-код
app.post('/api/qr/login', async (req, res) => {
  let connection;
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({ 
        success: false,
        error: 'Токен QR-кода не предоставлен' 
      });
    }
    
    connection = await pool.getConnection();
    
    // Проверяем токен в базе данных
    const [tokens] = await connection.execute(
      'SELECT * FROM qr_login_tokens WHERE token = ? AND used = FALSE',
      [token]
    );
    
    if (tokens.length === 0) {
      return res.status(401).json({ 
        success: false,
        error: 'Недействительный или уже использованный QR-код' 
      });
    }
    
    const qrToken = tokens[0];
    
    // Проверяем срок действия
    if (new Date(qrToken.expires_at) < new Date()) {
      await connection.execute(
        'UPDATE qr_login_tokens SET used = TRUE WHERE token = ?',
        [token]
      );
      return res.status(401).json({ 
        success: false,
        error: 'QR-код истек. Сгенерируйте новый.' 
      });
    }
    
    // Получаем информацию о пользователе
    const [users] = await connection.execute(
      'SELECT id, email, phone, first_name, last_name, role, balance FROM users1 WHERE id = ?',
      [qrToken.user_id]
    );
    
    if (users.length === 0) {
      return res.status(404).json({ 
        success: false,
        error: 'Пользователь не найден' 
      });
    }
    
    const user = users[0];
    
    // Помечаем токен как использованный
    await connection.execute(
      'UPDATE qr_login_tokens SET used = TRUE WHERE token = ?',
      [token]
    );
    
    // Генерируем JWT токен для входа
    const jwtToken = jwt.sign(
      { 
        id: user.id, 
        email: user.email,
        role: user.role 
      },
      jwtSecret,
      { expiresIn: '30d' }
    );
    
    // Обновляем токен пользователя в базе данных
    await connection.execute(
      'UPDATE users1 SET token = ? WHERE id = ?',
      [jwtToken, user.id]
    );
    
    res.json({
      success: true,
      message: 'Вход выполнен успешно',
      token: jwtToken,
      user: {
        id: user.id,
        email: user.email,
        phone: user.phone,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role,
        balance: user.balance
      }
    });
  } catch (error) {
    console.error('Ошибка входа через QR-код:', error);
    res.status(500).json({ 
      success: false,
      error: 'Ошибка сервера при обработке входа' 
    });
  } finally {
    if (connection) connection.release();
  }
});

// Получение статуса QR-кода (для проверки, был ли он использован)
app.get('/api/qr/status/:token', authenticate, async (req, res) => {
  let connection;
  try {
    const { token } = req.params;
    connection = await pool.getConnection();
    
    const [tokens] = await connection.execute(
      'SELECT * FROM qr_login_tokens WHERE token = ?',
      [token]
    );
    
    if (tokens.length === 0) {
      return res.status(404).json({ 
        success: false,
        error: 'QR-код не найден' 
      });
    }
    
    const qrToken = tokens[0];
    const isExpired = new Date(qrToken.expires_at) < new Date();
    
    res.json({
      success: true,
      used: qrToken.used === 1,
      expired: isExpired,
      expiresAt: qrToken.expires_at
    });
  } catch (error) {
    console.error('Ошибка проверки статуса QR-кода:', error);
    res.status(500).json({ 
      success: false,
      error: 'Ошибка сервера' 
    });
  } finally {
    if (connection) connection.release();
  }
});

// ==================== CHAT API ENDPOINTS ====================

// Get all chats for current user
app.get("/api/chats", authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    
    // Ensure chats and messages tables exist
    try {
      await connection.execute(`
        CREATE TABLE IF NOT EXISTS chats (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          property_id INT UNSIGNED NOT NULL,
          participant1_id INT UNSIGNED NOT NULL,
          participant2_id INT UNSIGNED NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          FOREIGN KEY (participant1_id) REFERENCES users1(id) ON DELETE CASCADE,
          FOREIGN KEY (participant2_id) REFERENCES users1(id) ON DELETE CASCADE,
          FOREIGN KEY (property_id) REFERENCES properties(id) ON DELETE CASCADE,
          UNIQUE KEY unique_chat (property_id, participant1_id, participant2_id)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci
      `);
      
      await connection.execute(`
        CREATE TABLE IF NOT EXISTS messages (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          chat_id INT UNSIGNED NOT NULL,
          sender_id INT UNSIGNED NOT NULL,
          content TEXT NOT NULL,
          type VARCHAR(20) NOT NULL DEFAULT 'text',
          sticker_id VARCHAR(255) DEFAULT NULL,
          image_url VARCHAR(500) DEFAULT NULL,
          is_read TINYINT(1) NOT NULL DEFAULT 0,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
          FOREIGN KEY (sender_id) REFERENCES users1(id) ON DELETE CASCADE,
          INDEX idx_chat_created (chat_id, created_at DESC),
          INDEX idx_sender (sender_id)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci
      `);
    } catch (tableError) {
      console.log("Tables check:", tableError.message);
    }
    
    const userId = req.user.id;

    const [chats] = await connection.execute(`
      SELECT 
        c.id,
        c.property_id,
        c.participant1_id,
        c.participant2_id,
        c.created_at,
        c.updated_at,
        p.title as property_title,
        p.photos as property_photos,
        u1.first_name as participant1_first_name,
        u1.last_name as participant1_last_name,
        u1.profile_picture as participant1_avatar,
        u2.first_name as participant2_first_name,
        u2.last_name as participant2_last_name,
        u2.profile_picture as participant2_avatar,
        (
          SELECT COUNT(*) 
          FROM messages m 
          WHERE m.chat_id = c.id 
          AND m.sender_id != ? 
          AND m.is_read = 0
        ) as unread_count,
        (
          SELECT JSON_OBJECT(
            'id', m.id,
            'chat_id', m.chat_id,
            'sender_id', m.sender_id,
            'sender_name', CONCAT(us.first_name, ' ', us.last_name),
            'sender_avatar', us.profile_picture,
            'content', m.content,
            'type', m.type,
            'sticker_id', m.sticker_id,
            'image_url', m.image_url,
            'is_read', m.is_read,
            'created_at', m.created_at
          )
          FROM messages m
          LEFT JOIN users1 us ON m.sender_id = us.id
          WHERE m.chat_id = c.id
          ORDER BY m.created_at DESC
          LIMIT 1
        ) as last_message
      FROM chats c
      LEFT JOIN properties p ON c.property_id = p.id
      LEFT JOIN users1 u1 ON c.participant1_id = u1.id
      LEFT JOIN users1 u2 ON c.participant2_id = u2.id
      WHERE c.participant1_id = ? OR c.participant2_id = ?
      ORDER BY c.updated_at DESC
    `, [userId, userId, userId]);

    const formattedChats = chats.map(chat => {
      let propertyPhoto = null;
      if (chat.property_photos) {
        try {
          const photos = JSON.parse(chat.property_photos);
          if (Array.isArray(photos) && photos.length > 0) {
            propertyPhoto = photos[0];
          }
        } catch (e) {
          console.error("Error parsing property photos:", e);
        }
      }

      let lastMessage = null;
      if (chat.last_message) {
        try {
          lastMessage = JSON.parse(chat.last_message);
        } catch (e) {
          console.error("Error parsing last message:", e);
        }
      }

      return {
        id: chat.id,
        property_id: chat.property_id,
        property_title: chat.property_title,
        property_photo: propertyPhoto,
        participant1_id: chat.participant1_id,
        participant1_name: `${chat.participant1_first_name || ''} ${chat.participant1_last_name || ''}`.trim(),
        participant1_avatar: chat.participant1_avatar,
        participant2_id: chat.participant2_id,
        participant2_name: `${chat.participant2_first_name || ''} ${chat.participant2_last_name || ''}`.trim(),
        participant2_avatar: chat.participant2_avatar,
        last_message: lastMessage,
        unread_count: chat.unread_count || 0,
        created_at: chat.created_at,
        updated_at: chat.updated_at
      };
    });

    res.json(formattedChats);
  } catch (error) {
    console.error("Error fetching chats:", error);
    res.status(500).json({ error: `Ошибка получения чатов: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Get single chat
app.get("/api/chats/:chatId", authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    
    // Ensure chats table exists
    try {
      await connection.execute(`
        CREATE TABLE IF NOT EXISTS chats (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          property_id INT UNSIGNED NOT NULL,
          participant1_id INT UNSIGNED NOT NULL,
          participant2_id INT UNSIGNED NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          FOREIGN KEY (participant1_id) REFERENCES users1(id) ON DELETE CASCADE,
          FOREIGN KEY (participant2_id) REFERENCES users1(id) ON DELETE CASCADE,
          FOREIGN KEY (property_id) REFERENCES properties(id) ON DELETE CASCADE,
          UNIQUE KEY unique_chat (property_id, participant1_id, participant2_id)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci
      `);
    } catch (tableError) {
      console.log("Chats table check:", tableError.message);
    }
    
    const userId = req.user.id;
    const chatId = parseInt(req.params.chatId);

    const [chats] = await connection.execute(`
      SELECT 
        c.id,
        c.property_id,
        c.participant1_id,
        c.participant2_id,
        c.created_at,
        c.updated_at,
        p.title as property_title,
        u1.first_name as participant1_first_name,
        u1.last_name as participant1_last_name,
        u1.profile_picture as participant1_avatar,
        u2.first_name as participant2_first_name,
        u2.last_name as participant2_last_name,
        u2.profile_picture as participant2_avatar
      FROM chats c
      LEFT JOIN properties p ON c.property_id = p.id
      LEFT JOIN users1 u1 ON c.participant1_id = u1.id
      LEFT JOIN users1 u2 ON c.participant2_id = u2.id
      WHERE c.id = ? AND (c.participant1_id = ? OR c.participant2_id = ?)
    `, [chatId, userId, userId]);

    if (chats.length === 0) {
      return res.status(404).json({ error: "Чат не найден" });
    }

    const chat = chats[0];
    res.json({
      id: chat.id,
      property_id: chat.property_id,
      property_title: chat.property_title,
      participant1_id: chat.participant1_id,
      participant1_name: `${chat.participant1_first_name || ''} ${chat.participant1_last_name || ''}`.trim(),
      participant1_avatar: chat.participant1_avatar,
      participant2_id: chat.participant2_id,
      participant2_name: `${chat.participant2_first_name || ''} ${chat.participant2_last_name || ''}`.trim(),
      participant2_avatar: chat.participant2_avatar,
      created_at: chat.created_at,
      updated_at: chat.updated_at
    });
  } catch (error) {
    console.error("Error fetching chat:", error);
    res.status(500).json({ error: `Ошибка получения чата: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Create or get existing chat
app.post("/api/chats", authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    const userId = req.user.id;
    const { property_id, other_user_id } = req.body;

    if (!property_id || !other_user_id) {
      return res.status(400).json({ error: "property_id и other_user_id обязательны" });
    }

    // Ensure chats table exists
    try {
      await connection.execute(`
        CREATE TABLE IF NOT EXISTS chats (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          property_id INT UNSIGNED NOT NULL,
          participant1_id INT UNSIGNED NOT NULL,
          participant2_id INT UNSIGNED NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          FOREIGN KEY (participant1_id) REFERENCES users1(id) ON DELETE CASCADE,
          FOREIGN KEY (participant2_id) REFERENCES users1(id) ON DELETE CASCADE,
          FOREIGN KEY (property_id) REFERENCES properties(id) ON DELETE CASCADE,
          UNIQUE KEY unique_chat (property_id, participant1_id, participant2_id)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci
      `);
    } catch (tableError) {
      // Table might already exist or foreign key constraints might fail
      // Continue anyway
      console.log("Chats table check:", tableError.message);
    }

    // Check if chat already exists
    const [existingChats] = await connection.execute(`
      SELECT id FROM chats 
      WHERE property_id = ? 
      AND ((participant1_id = ? AND participant2_id = ?) 
        OR (participant1_id = ? AND participant2_id = ?))
    `, [property_id, userId, other_user_id, other_user_id, userId]);

    if (existingChats.length > 0) {
      // Return existing chat
      const chatId = existingChats[0].id;
      const [chats] = await connection.execute(`
        SELECT 
          c.id,
          c.property_id,
          c.participant1_id,
          c.participant2_id,
          c.created_at,
          c.updated_at,
          p.title as property_title,
          u1.first_name as participant1_first_name,
          u1.last_name as participant1_last_name,
          u1.profile_picture as participant1_avatar,
          u2.first_name as participant2_first_name,
          u2.last_name as participant2_last_name,
          u2.profile_picture as participant2_avatar
        FROM chats c
        LEFT JOIN properties p ON c.property_id = p.id
        LEFT JOIN users1 u1 ON c.participant1_id = u1.id
        LEFT JOIN users1 u2 ON c.participant2_id = u2.id
        WHERE c.id = ?
      `, [chatId]);

      const chat = chats[0];
      return res.json({
        id: chat.id,
        property_id: chat.property_id,
        property_title: chat.property_title,
        participant1_id: chat.participant1_id,
        participant1_name: `${chat.participant1_first_name || ''} ${chat.participant1_last_name || ''}`.trim(),
        participant1_avatar: chat.participant1_avatar,
        participant2_id: chat.participant2_id,
        participant2_name: `${chat.participant2_first_name || ''} ${chat.participant2_last_name || ''}`.trim(),
        participant2_avatar: chat.participant2_avatar,
        created_at: chat.created_at,
        updated_at: chat.updated_at
      });
    }

    // Create new chat
    const [result] = await connection.execute(`
      INSERT INTO chats (property_id, participant1_id, participant2_id)
      VALUES (?, ?, ?)
    `, [property_id, userId, other_user_id]);

    const chatId = result.insertId;

    const [chats] = await connection.execute(`
      SELECT 
        c.id,
        c.property_id,
        c.participant1_id,
        c.participant2_id,
        c.created_at,
        c.updated_at,
        p.title as property_title,
        u1.first_name as participant1_first_name,
        u1.last_name as participant1_last_name,
        u1.profile_picture as participant1_avatar,
        u2.first_name as participant2_first_name,
        u2.last_name as participant2_last_name,
        u2.profile_picture as participant2_avatar
      FROM chats c
      LEFT JOIN properties p ON c.property_id = p.id
      LEFT JOIN users1 u1 ON c.participant1_id = u1.id
      LEFT JOIN users1 u2 ON c.participant2_id = u2.id
      WHERE c.id = ?
    `, [chatId]);

    const chat = chats[0];
    res.status(201).json({
      id: chat.id,
      property_id: chat.property_id,
      property_title: chat.property_title,
      participant1_id: chat.participant1_id,
      participant1_name: `${chat.participant1_first_name || ''} ${chat.participant1_last_name || ''}`.trim(),
      participant1_avatar: chat.participant1_avatar,
      participant2_id: chat.participant2_id,
      participant2_name: `${chat.participant2_first_name || ''} ${chat.participant2_last_name || ''}`.trim(),
      participant2_avatar: chat.participant2_avatar,
      created_at: chat.created_at,
      updated_at: chat.updated_at
    });
  } catch (error) {
    console.error("Error creating chat:", error);
    res.status(500).json({ error: `Ошибка создания чата: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Get messages for a chat
app.get("/api/chats/:chatId/messages", authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    
    // Ensure messages table exists
    try {
      await connection.execute(`
        CREATE TABLE IF NOT EXISTS messages (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          chat_id INT UNSIGNED NOT NULL,
          sender_id INT UNSIGNED NOT NULL,
          content TEXT NOT NULL,
          type VARCHAR(20) NOT NULL DEFAULT 'text',
          sticker_id VARCHAR(255) DEFAULT NULL,
          image_url VARCHAR(500) DEFAULT NULL,
          is_read TINYINT(1) NOT NULL DEFAULT 0,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
          FOREIGN KEY (sender_id) REFERENCES users1(id) ON DELETE CASCADE,
          INDEX idx_chat_created (chat_id, created_at DESC),
          INDEX idx_sender (sender_id)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci
      `);
    } catch (tableError) {
      console.log("Messages table check:", tableError.message);
    }
    
    const userId = req.user.id;
    const chatId = parseInt(req.params.chatId);
    // Ensure limit is a safe integer (max 1000 to prevent abuse)
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 50, 1), 1000);
    const before = req.query.before ? parseInt(req.query.before) : null;

    // Verify user has access to this chat
    const [chatCheck] = await connection.execute(`
      SELECT id FROM chats 
      WHERE id = ? AND (participant1_id = ? OR participant2_id = ?)
    `, [chatId, userId, userId]);

    if (chatCheck.length === 0) {
      return res.status(403).json({ error: "Нет доступа к этому чату" });
    }

    let query = `
      SELECT 
        m.id,
        m.chat_id,
        m.sender_id,
        m.content,
        m.type,
        m.sticker_id,
        m.image_url,
        m.is_read,
        m.created_at,
        u.first_name as sender_first_name,
        u.last_name as sender_last_name,
        u.profile_picture as sender_avatar
      FROM messages m
      LEFT JOIN users1 u ON m.sender_id = u.id
      WHERE m.chat_id = ?
    `;
    const params = [chatId];

    if (before) {
      query += ` AND m.id < ?`;
      params.push(before);
    }

    // MySQL doesn't support parameters in LIMIT, so we embed it directly
    // limit is already parsed as integer, so it's safe
    query += ` ORDER BY m.created_at DESC LIMIT ${limit}`;

    const [messages] = await connection.execute(query, params);

    const formattedMessages = messages.map(msg => ({
      id: msg.id,
      chat_id: msg.chat_id,
      sender_id: msg.sender_id,
      sender_name: `${msg.sender_first_name || ''} ${msg.sender_last_name || ''}`.trim(),
      sender_avatar: msg.sender_avatar,
      content: msg.content,
      type: msg.type,
      sticker_id: msg.sticker_id,
      image_url: msg.image_url,
      is_read: msg.is_read,
      created_at: msg.created_at
    }));

    res.json(formattedMessages);
  } catch (error) {
    console.error("Error fetching messages:", error);
    res.status(500).json({ error: `Ошибка получения сообщений: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Send a message
app.post("/api/chats/:chatId/messages", authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    
    // Ensure messages table exists
    try {
      await connection.execute(`
        CREATE TABLE IF NOT EXISTS messages (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          chat_id INT UNSIGNED NOT NULL,
          sender_id INT UNSIGNED NOT NULL,
          content TEXT NOT NULL,
          type VARCHAR(20) NOT NULL DEFAULT 'text',
          sticker_id VARCHAR(255) DEFAULT NULL,
          image_url VARCHAR(500) DEFAULT NULL,
          is_read TINYINT(1) NOT NULL DEFAULT 0,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
          FOREIGN KEY (sender_id) REFERENCES users1(id) ON DELETE CASCADE,
          INDEX idx_chat_created (chat_id, created_at DESC),
          INDEX idx_sender (sender_id)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci
      `);
    } catch (tableError) {
      console.log("Messages table check:", tableError.message);
    }
    
    const userId = req.user.id;
    const chatId = parseInt(req.params.chatId);
    const { content, type = 'text', sticker_id, image_url } = req.body;

    // Verify user has access to this chat
    const [chatCheck] = await connection.execute(`
      SELECT id FROM chats 
      WHERE id = ? AND (participant1_id = ? OR participant2_id = ?)
    `, [chatId, userId, userId]);

    if (chatCheck.length === 0) {
      return res.status(403).json({ error: "Нет доступа к этому чату" });
    }

    if (!content && type !== 'sticker' && !image_url) {
      return res.status(400).json({ error: "Содержимое сообщения обязательно" });
    }

    const messageContent = content || (type === 'sticker' ? '🎨' : '');

    const [result] = await connection.execute(`
      INSERT INTO messages (chat_id, sender_id, content, type, sticker_id, image_url)
      VALUES (?, ?, ?, ?, ?, ?)
    `, [chatId, userId, messageContent, type, sticker_id || null, image_url || null]);

    // Update chat updated_at
    await connection.execute(`
      UPDATE chats SET updated_at = NOW() WHERE id = ?
    `, [chatId]);

    // Get the created message with user info
    const [messages] = await connection.execute(`
      SELECT 
        m.id,
        m.chat_id,
        m.sender_id,
        m.content,
        m.type,
        m.sticker_id,
        m.image_url,
        m.is_read,
        m.created_at,
        u.first_name as sender_first_name,
        u.last_name as sender_last_name,
        u.profile_picture as sender_avatar
      FROM messages m
      LEFT JOIN users1 u ON m.sender_id = u.id
      WHERE m.id = ?
    `, [result.insertId]);

    const msg = messages[0];
    const formattedMessage = {
      id: msg.id,
      chat_id: msg.chat_id,
      sender_id: msg.sender_id,
      sender_name: `${msg.sender_first_name || ''} ${msg.sender_last_name || ''}`.trim(),
      sender_avatar: msg.sender_avatar,
      content: msg.content,
      type: msg.type,
      sticker_id: msg.sticker_id,
      image_url: msg.image_url,
      is_read: msg.is_read,
      created_at: msg.created_at
    };

    res.status(201).json(formattedMessage);
  } catch (error) {
    console.error("Error sending message:", error);
    res.status(500).json({ error: `Ошибка отправки сообщения: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Mark messages as read
app.post("/api/chats/:chatId/read", authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    
    // Ensure messages table exists
    try {
      await connection.execute(`
        CREATE TABLE IF NOT EXISTS messages (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          chat_id INT UNSIGNED NOT NULL,
          sender_id INT UNSIGNED NOT NULL,
          content TEXT NOT NULL,
          type VARCHAR(20) NOT NULL DEFAULT 'text',
          sticker_id VARCHAR(255) DEFAULT NULL,
          image_url VARCHAR(500) DEFAULT NULL,
          is_read TINYINT(1) NOT NULL DEFAULT 0,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
          FOREIGN KEY (sender_id) REFERENCES users1(id) ON DELETE CASCADE,
          INDEX idx_chat_created (chat_id, created_at DESC),
          INDEX idx_sender (sender_id)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci
      `);
    } catch (tableError) {
      console.log("Messages table check:", tableError.message);
    }
    
    const userId = req.user.id;
    const chatId = parseInt(req.params.chatId);

    // Verify user has access to this chat
    const [chatCheck] = await connection.execute(`
      SELECT id FROM chats 
      WHERE id = ? AND (participant1_id = ? OR participant2_id = ?)
    `, [chatId, userId, userId]);

    if (chatCheck.length === 0) {
      return res.status(403).json({ error: "Нет доступа к этому чату" });
    }

    // Mark all messages from other users as read
    await connection.execute(`
      UPDATE messages 
      SET is_read = 1 
      WHERE chat_id = ? AND sender_id != ?
    `, [chatId, userId]);

    res.json({ success: true });
  } catch (error) {
    console.error("Error marking messages as read:", error);
    res.status(500).json({ error: `Ошибка отметки сообщений: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Start Server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
  console.log(`Public access: ${publicDomain}:${port}`);
});