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

// Конфигурация S3
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

// Глобальный обработчик ошибок
app.use((err, req, res, next) => {
  console.error("Ошибка сервера:", err.message);
  res.status(500).json({ error: `Внутренняя ошибка сервера: ${err.message}` });
});

// Конфигурация Multer
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|pdf|doc|docx/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error("Разрешены только изображения (jpeg, jpg, png) и документы (pdf, doc, docx)"));
  },
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 МБ
});

// Пул подключений к MySQL
const dbConfig = {
  host: process.env.DB_HOST || "vh452.timeweb.ru",
  user: process.env.DB_USER || "cs51703_kgadmin",
  password: process.env.DB_PASSWORD || "Vasya11091109",
  database: process.env.DB_NAME || "cs51703_kgadmin",
  port: process.env.DB_PORT || 3306,
  connectionLimit: 10,
};
const pool = mysql.createPool(dbConfig);

// Middleware для аутентификации JWT
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Токен отсутствует" });

  try {
    const decoded = jwt.verify(token, jwtSecret);
    const connection = await pool.getConnection();
    const [users] = await connection.execute("SELECT id, role FROM users1 WHERE id = ? AND token = ?", [decoded.id, token]);
    connection.release();

    if (users.length === 0) return res.status(401).json({ error: "Недействительный токен" });

    req.user = decoded;
    next();
  } catch (error) {
    console.error("Ошибка аутентификации:", error.message);
    res.status(401).json({ error: "Недействительный токен" });
  }
};

// Проверка и настройка базы данных
async function testDatabaseConnection() {
  try {
    const connection = await pool.getConnection();
    console.log("Подключение к базе данных успешно!");

    // Создание таблицы users1
    const [tables] = await connection.execute("SHOW TABLES LIKE 'users1'");
    if (tables.length === 0) {
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
    }

    // Проверка столбца token
    const [tokenColumn] = await connection.execute("SHOW COLUMNS FROM users1 LIKE 'token'");
    if (tokenColumn.length === 0) {
      await connection.execute("ALTER TABLE users1 ADD token TEXT DEFAULT NULL");
    }

    // Проверка уникального индекса для email
    const [emailIndex] = await connection.execute("SHOW INDEX FROM users1 WHERE Column_name = 'email' AND Non_unique = 0");
    if (emailIndex.length === 0) {
      await connection.execute("ALTER TABLE users1 ADD UNIQUE (email)");
    }

    // Создание таблицы properties
    const [propTables] = await connection.execute("SHOW TABLES LIKE 'properties'");
    if (propTables.length === 0) {
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
    } else {
      // Проверка и добавление столбца phone, если отсутствует
      const [phoneColumn] = await connection.execute("SHOW COLUMNS FROM properties LIKE 'phone'");
      if (phoneColumn.length === 0) {
        console.log("Столбец phone отсутствует, добавляется...");
        await connection.execute("ALTER TABLE properties ADD phone VARCHAR(50) DEFAULT NULL");
      }
    }

    // Создание таблицы jk
    const [jkTables] = await connection.execute("SHOW TABLES LIKE 'jk'");
    if (jkTables.length === 0) {
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

    // Создание таблицы districts
    const [districtTables] = await connection.execute("SHOW TABLES LIKE 'districts'");
    if (districtTables.length === 0) {
      await connection.execute(`
        CREATE TABLE districts (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci
      `);
    }

    // Создание таблицы subdistricts
    const [subdistrictTables] = await connection.execute("SHOW TABLES LIKE 'subdistricts'");
    if (subdistrictTables.length === 0) {
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

    // Настройка администратора
    const adminEmail = process.env.ADMIN_EMAIL || "admin@example.com";
    const adminPassword = process.env.ADMIN_PASSWORD || "admin123";
    const hashedPassword = await bcrypt.hash(adminPassword, 10);

    const [existingAdmin] = await connection.execute("SELECT id FROM users1 WHERE email = ?", [adminEmail]);
    if (existingAdmin.length === 0) {
      const token = jwt.sign({ id: 1, role: "SUPER_ADMIN" }, jwtSecret, { expiresIn: "30d" });
      await connection.execute(
        "INSERT INTO users1 (first_name, last_name, email, phone, role, password, token) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ["Админ", "Пользователь", adminEmail, "123456789", "SUPER_ADMIN", hashedPassword, token]
      );
    } else {
      const token = jwt.sign({ id: existingAdmin[0].id, role: "SUPER_ADMIN" }, jwtSecret, { expiresIn: "30d" });
      await connection.execute("UPDATE users1 SET password = ?, token = ? WHERE email = ?", [hashedPassword, token, adminEmail]);
    }

    console.log("Админ настроен:", adminEmail);
    connection.release();
  } catch (error) {
    console.error("Ошибка настройки базы данных:", error.message);
  }
}

testDatabaseConnection();

// Тестовый эндпоинт
app.get("/api/message", (req, res) => {
  res.json({ message: "Привет от бэкенда Ala-Too!" });
});

// Вход администратора
app.post("/api/admin/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email и пароль обязательны" });

  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, first_name, last_name, email, phone, role, password, profile_picture AS photoUrl, token FROM users1 WHERE email = ?",
      [email]
    );

    if (rows.length === 0) {
      connection.release();
      return res.status(401).json({ error: "Неверный email или пользователь не найден" });
    }

    const user = rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      connection.release();
      return res.status(401).json({ error: "Неверный пароль" });
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
    res.json({ message: "Авторизация успешна", user: userResponse, token });
  } catch (error) {
    console.error("Ошибка входа:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Выход
app.post("/api/logout", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    await connection.execute("UPDATE users1 SET token = NULL WHERE id = ?", [req.user.id]);
    connection.release();
    res.json({ message: "Выход успешен" });
  } catch (error) {
    console.error("Ошибка выхода:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Получение пользователей
app.get("/api/users", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });

  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, first_name, last_name, email, phone, role, profile_picture AS photoUrl FROM users1"
    );
    connection.release();
    res.json(
      rows.map((user) => ({
        ...user,
        name: `${user.first_name} ${user.last_name}`,
        photoUrl: user.photoUrl ? `https://s3.twcstorage.ru/${bucketName}/${user.photoUrl}` : null,
      }))
    );
  } catch (error) {
    console.error("Ошибка получения пользователей:", error.message);
    res.status(500).json({ error: "Внутренняя ошибка сервера" });
  }
});

// Создание пользователя
app.post("/api/users", authenticate, upload.single("photo"), async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });

  const { email, name, phone, role, password } = req.body;
  const photo = req.file;

  if (!email || !name || !phone || !role || !password) {
    return res.status(400).json({ error: "Все поля, включая пароль, обязательны" });
  }

  const [first_name, last_name = ""] = name.split(" ");
  const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
  const profile_picture = photo ? `${uniqueSuffix}${path.extname(photo.originalname)}` : null;

  try {
    const connection = await pool.getConnection();
    const [existingUser] = await connection.execute("SELECT id FROM users1 WHERE email = ?", [email]);
    if (existingUser.length > 0) {
      connection.release();
      return res.status(400).json({ error: "Пользователь с таким email уже существует" });
    }

    if (photo) {
      const uploadParams = {
        Bucket: bucketName,
        Key: profile_picture,
        Body: photo.buffer,
        ContentType: photo.mimetype,
      };
      await s3Client.send(new PutObjectCommand(uploadParams));
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
    console.error("Ошибка создания пользователя:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Обновление пользователя
app.put("/api/users/:id", authenticate, upload.single("photo"), async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });

  const { id } = req.params;
  const { email, name, phone, role } = req.body;
  const photo = req.file;

  if (!email || !name || !phone || !role) {
    return res.status(400).json({ error: "Все поля обязательны" });
  }

  const [first_name, last_name = ""] = name.split(" ");
  const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
  let profile_picture = null;

  try {
    const connection = await pool.getConnection();
    const [existingUsers] = await connection.execute("SELECT profile_picture FROM users1 WHERE id = ?", [id]);
    if (existingUsers.length === 0) {
      connection.release();
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    const [emailCheck] = await connection.execute("SELECT id FROM users1 WHERE email = ? AND id != ?", [email, id]);
    if (emailCheck.length > 0) {
      connection.release();
      return res.status(400).json({ error: "Пользователь с таким email уже существует" });
    }

    profile_picture = existingUsers[0].profile_picture;
    if (photo) {
      profile_picture = `${uniqueSuffix}${path.extname(photo.originalname)}`;
      const uploadParams = {
        Bucket: bucketName,
        Key: profile_picture,
        Body: photo.buffer,
        ContentType: photo.mimetype,
      };
      await s3Client.send(new PutObjectCommand(uploadParams));

      if (existingUsers[0].profile_picture) {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: existingUsers[0].profile_picture }));
      }
    }

    const [result] = await connection.execute(
      "UPDATE users1 SET first_name = ?, last_name = ?, email = ?, phone = ?, role = ?, profile_picture = ? WHERE id = ?",
      [first_name, last_name, email, phone, role, profile_picture, id]
    );

    if (result.affectedRows === 0) {
      connection.release();
      return res.status(404).json({ error: "Пользователь не найден" });
    }

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
    console.error("Ошибка обновления пользователя:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Удаление пользователя
app.delete("/api/users/:id", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });

  const { id } = req.params;

  try {
    const connection = await pool.getConnection();
    const [users] = await connection.execute("SELECT profile_picture FROM users1 WHERE id = ?", [id]);
    if (users.length === 0) {
      connection.release();
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    const profile_picture = users[0].profile_picture;
    if (profile_picture) {
      await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: profile_picture }));
    }

    const [result] = await connection.execute("DELETE FROM users1 WHERE id = ?", [id]);
    if (result.affectedRows === 0) {
      connection.release();
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    connection.release();
    res.json({ message: "Пользователь успешно удален" });
  } catch (error) {
    console.error("Ошибка удаления пользователя:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Получение ЖК
app.get("/api/jk", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute("SELECT id, name FROM jk");
    connection.release();
    res.json(rows);
  } catch (error) {
    console.error("Ошибка получения ЖК:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Получение районов
app.get("/api/districts", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute("SELECT id, name FROM districts");
    connection.release();
    res.json(rows);
  } catch (error) {
    console.error("Ошибка получения районов:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Получение микрорайонов
app.get("/api/subdistricts", authenticate, async (req, res) => {
  const { district_id } = req.query;
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, name FROM subdistricts WHERE district_id = ?",
      [district_id]
    );
    connection.release();
    res.json(rows);
  } catch (error) {
    console.error("Ошибка получения микрорайонов:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Создание объекта недвижимости
app.post("/api/properties", authenticate, upload.fields([
  { name: "photos", maxCount: 10 },
  { name: "document", maxCount: 1 },
]), async (req, res) => {
  if (!["SUPER_ADMIN", "REALTOR"].includes(req.user.role)) {
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN или REALTOR" });
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
    return res.status(400).json({ error: "Все обязательные поля (type_id, price, rukprice, mkv, address, etaj, etajnost) должны быть предоставлены" });
  }

  if (isNaN(parseFloat(price)) || isNaN(parseFloat(rukprice)) || isNaN(parseFloat(mkv)) || isNaN(parseInt(etaj)) || isNaN(parseInt(etajnost))) {
    return res.status(400).json({ error: "Поля price, rukprice, mkv, etaj, etajnost должны быть числовыми" });
  }

  let finalCuratorIds = curator_ids || (req.user.role === "REALTOR" ? req.user.id.toString() : null);
  if (req.user.role === "REALTOR" && curator_ids && curator_ids !== req.user.id.toString()) {
    return res.status(403).json({ error: "Риелтор может назначить только себя куратором" });
  }

  try {
    const connection = await pool.getConnection();

    if (zhk_id) {
      const [jkCheck] = await connection.execute("SELECT id FROM jk WHERE id = ?", [zhk_id]);
      if (jkCheck.length === 0) {
        connection.release();
        return res.status(400).json({ error: "Недействительный ID ЖК" });
      }
    }

    if (district_id) {
      const [districtCheck] = await connection.execute("SELECT id FROM districts WHERE id = ?", [district_id]);
      if (districtCheck.length === 0) {
        connection.release();
        return res.status(400).json({ error: "Недействительный ID района" });
      }
    }

    if (subdistrict_id) {
      const [subdistrictCheck] = await connection.execute("SELECT id FROM subdistricts WHERE id = ? AND district_id = ?", [subdistrict_id, district_id || null]);
      if (subdistrictCheck.length === 0) {
        connection.release();
        return res.status(400).json({ error: "Недействительный ID микрорайона или микрорайон не принадлежит выбранному району" });
      }
    }

    for (const photo of photos) {
      const uploadParams = {
        Bucket: bucketName,
        Key: photo.filename,
        Body: photo.buffer,
        ContentType: photo.mimetype,
      };
      await s3Client.send(new PutObjectCommand(uploadParams));
    }

    if (document) {
      const uploadParams = {
        Bucket: bucketName,
        Key: document.filename,
        Body: document.buffer,
        ContentType: document.mimetype,
      };
      await s3Client.send(new PutObjectCommand(uploadParams));
    }

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
    console.error("Ошибка создания объекта недвижимости:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Обновление объекта недвижимости
app.put("/api/properties/:id", authenticate, upload.fields([
  { name: "photos", maxCount: 10 },
  { name: "document", maxCount: 1 },
]), async (req, res) => {
  if (!["SUPER_ADMIN", "REALTOR"].includes(req.user.role)) {
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN или REALTOR" });
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
    return res.status(400).json({ error: "Все обязательные поля (type_id, price, rukprice, mkv, address, etaj, etajnost) должны быть предоставлены" });
  }

  if (isNaN(parseFloat(price)) || isNaN(parseFloat(rukprice)) || isNaN(parseFloat(mkv)) || isNaN(parseInt(etaj)) || isNaN(parseInt(etajnost))) {
    return res.status(400).json({ error: "Поля price, rukprice, mkv, etaj, etajnost должны быть числовыми" });
  }

  let finalCuratorIds = curator_ids || (req.user.role === "REALTOR" ? req.user.id.toString() : null);
  if (req.user.role === "REALTOR" && curator_ids && curator_ids !== req.user.id.toString()) {
    return res.status(403).json({ error: "Риелтор может назначить только себя куратором" });
  }

  try {
    const connection = await pool.getConnection();
    const [existingProperties] = await connection.execute("SELECT photos, document, curator_ids FROM properties WHERE id = ?", [id]);
    if (existingProperties.length === 0) {
      connection.release();
      return res.status(404).json({ error: "Объект недвижимости не найден" });
    }

    const existingProperty = existingProperties[0];
    if (req.user.role === "REALTOR" && existingProperty.curator_ids !== req.user.id.toString()) {
      connection.release();
      return res.status(403).json({ error: "У вас нет прав для редактирования этого объекта" });
    }

    if (zhk_id) {
      const [jkCheck] = await connection.execute("SELECT id FROM jk WHERE id = ?", [zhk_id]);
      if (jkCheck.length === 0) {
        connection.release();
        return res.status(400).json({ error: "Недействительный ID ЖК" });
      }
    }

    if (district_id) {
      const [districtCheck] = await connection.execute("SELECT id FROM districts WHERE id = ?", [district_id]);
      if (districtCheck.length === 0) {
        connection.release();
        return res.status(400).json({ error: "Недействительный ID района" });
      }
    }

    if (subdistrict_id) {
      const [subdistrictCheck] = await connection.execute("SELECT id FROM subdistricts WHERE id = ? AND district_id = ?", [subdistrict_id, district_id || null]);
      if (subdistrictCheck.length === 0) {
        connection.release();
        return res.status(400).json({ error: "Недействительный ID микрорайона или микрорайон не принадлежит выбранному району" });
      }
    }

    let photoFiles = [];
    if (existingProperty.photos) {
      try {
        photoFiles = JSON.parse(existingProperty.photos);
        if (!Array.isArray(photoFiles)) {
          photoFiles = existingProperty.photos.split(",").filter(p => p.trim());
        }
      } catch (error) {
        photoFiles = existingProperty.photos.split(",").filter(p => p.trim());
      }
    }

    let existingPhotosList = [];
    if (existingPhotos) {
      try {
        existingPhotosList = JSON.parse(existingPhotos);
        if (!Array.isArray(existingPhotosList)) {
          existingPhotosList = [];
        }
      } catch (error) {
        existingPhotosList = [];
      }
    }

    for (const photo of photos) {
      const uploadParams = {
        Bucket: bucketName,
        Key: photo.filename,
        Body: photo.buffer,
        ContentType: photo.mimetype,
      };
      await s3Client.send(new PutObjectCommand(uploadParams));
    }

    const photosToDelete = photoFiles.filter(p => !existingPhotosList.includes(p));
    for (const oldPhoto of photosToDelete) {
      try {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: oldPhoto }));
      } catch (error) {
        console.warn(`Не удалось удалить изображение из S3: ${oldPhoto}`);
      }
    }

    const newPhotos = [...existingPhotosList, ...photos.map(img => img.filename)];
    const photosJson = newPhotos.length > 0 ? JSON.stringify(newPhotos) : null;

    let newDocument = existingProperty.document;
    if (document) {
      const uploadParams = {
        Bucket: bucketName,
        Key: document.filename,
        Body: document.buffer,
        ContentType: document.mimetype,
      };
      await s3Client.send(new PutObjectCommand(uploadParams));

      if (existingProperty.document) {
        try {
          await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: existingProperty.document }));
        } catch (error) {
          console.warn(`Не удалось удалить документ из S3: ${existingProperty.document}`);
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
      return res.status(404).json({ error: "Объект недвижимости не найден" });
    }

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
    console.error("Ошибка обновления объекта недвижимости:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Удаление объекта недвижимости
app.delete("/api/properties/:id", authenticate, async (req, res) => {
  if (!["SUPER_ADMIN", "REALTOR"].includes(req.user.role)) {
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN или REALTOR" });
  }

  const { id } = req.params;

  try {
    const connection = await pool.getConnection();
    const [properties] = await connection.execute("SELECT photos, document, curator_ids FROM properties WHERE id = ?", [id]);
    if (properties.length === 0) {
      connection.release();
      return res.status(404).json({ error: "Объект недвижимости не найден" });
    }

    const existingProperty = properties[0];
    if (req.user.role === "REALTOR" && existingProperty.curator_ids !== req.user.id.toString()) {
      connection.release();
      return res.status(403).json({ error: "У вас нет прав для удаления этого объекта" });
    }

    let photoFiles = [];
    if (existingProperty.photos) {
      try {
        photoFiles = JSON.parse(existingProperty.photos);
        if (!Array.isArray(photoFiles)) {
          photoFiles = existingProperty.photos.split(",").filter(p => p.trim());
        }
      } catch (error) {
        photoFiles = existingProperty.photos.split(",").filter(p => p.trim());
      }
      for (const img of photoFiles) {
        try {
          await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: img }));
        } catch (error) {
          console.warn(`Не удалось удалить изображение из S3: ${img}`);
        }
      }
    }
    if (existingProperty.document) {
      try {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: existingProperty.document }));
      } catch (error) {
        console.warn(`Не удалось удалить документ из S3: ${existingProperty.document}`);
      }
    }

    const [result] = await connection.execute("DELETE FROM properties WHERE id = ?", [id]);
    if (result.affectedRows === 0) {
      connection.release();
      return res.status(404).json({ error: "Объект недвижимости не найден" });
    }

    connection.release();
    res.json({ message: "Объект недвижимости успешно удален" });
  } catch (error) {
    console.error("Ошибка удаления объекта недвижимости:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Получение объектов недвижимости
app.get("/api/properties", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      `SELECT p.*, CONCAT(u.first_name, ' ', u.last_name) AS curator_name
       FROM properties p
       LEFT JOIN users1 u ON p.curator_ids = u.id`
    );

    const properties = rows.map((row) => {
      let parsedPhotos = [];
      if (row.photos) {
        try {
          parsedPhotos = JSON.parse(row.photos);
          if (!Array.isArray(parsedPhotos)) {
            parsedPhotos = row.photos.split(",").filter(p => p.trim());
          }
        } catch (error) {
          parsedPhotos = row.photos.split(",").filter(p => p.trim());
        }
      }

      return {
        ...row,
        photos: parsedPhotos.map((img) => `https://s3.twcstorage.ru/${bucketName}/${img}`),
        document: row.document ? `https://s3.twcstorage.ru/${bucketName}/${row.document}` : null,
        date: new Date(row.created_at).toLocaleDateString("ru-RU"),
        time: new Date(row.created_at).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" }),
        curator_name: row.curator_name || row.curator_ids || 'Не указан',
      };
    });

    connection.release();
    res.json(properties);
  } catch (error) {
    console.error("Ошибка получения объектов недвижимости:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Получение объявлений
app.get("/api/listings", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, type_id, price, rukprice, mkv, status, address, created_at FROM properties"
    );

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
    console.error("Ошибка получения объявлений:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Получение районов и микрорайонов
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
    console.error("Ошибка получения районов и микрорайонов:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Перенаправление объектов недвижимости
app.patch("/api/properties/redirect", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });
  }

  const { propertyIds, curator_ids } = req.body;

  if (!Array.isArray(propertyIds) || !curator_ids) {
    return res.status(400).json({ error: "propertyIds должен быть массивом, curator_ids обязателен" });
  }

  try {
    const connection = await pool.getConnection();
    const [existingProperties] = await connection.execute(
      "SELECT id, curator_ids FROM properties WHERE id IN (?)",
      [propertyIds]
    );
    if (existingProperties.length !== propertyIds.length) {
      connection.release();
      return res.status(404).json({ error: "Некоторые объекты недвижимости не найдены" });
    }

    const [result] = await connection.execute(
      "UPDATE properties SET curator_ids = ? WHERE id IN (?)",
      [curator_ids, propertyIds]
    );

    if (result.affectedRows === 0) {
      connection.release();
      return res.status(404).json({ error: "Ни один объект не был обновлен" });
    }

    connection.release();
    res.json({ message: "Объекты недвижимости успешно перенаправлены", affectedRows: result.affectedRows });
  } catch (error) {
    console.error("Ошибка перенаправления объектов недвижимости:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Запуск сервера
app.listen(port, () => {
  console.log(`Сервер запущен на http://localhost:${port}`);
  console.log(`Публичный доступ: ${publicDomain}:${port}`);
});