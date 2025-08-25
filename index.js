const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const { S3Client, PutObjectCommand, DeleteObjectCommand } = require("@aws-sdk/client-s3");
const path = require("path");
const Joi = require("joi");
const winston = require("winston");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 5000;
const publicDomain = process.env.PUBLIC_DOMAIN || "https://vasya010-backend1-10db.twc1.net";
const jwtSecret = process.env.JWT_SECRET || "your_jwt_secret_123";

// Настройка логирования с winston
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: "error.log", level: "error" }),
    new winston.transports.File({ filename: "combined.log" }),
    new winston.transports.Console(),
  ],
});

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
const corsOptions = {
  origin: [
    publicDomain,
    "http://localhost:3000",
    "https://alatooned.ru"
  ],
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
};
app.use(cors(corsOptions));
app.use(express.json());

// Глобальный обработчик ошибок
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    logger.error(`Ошибка Multer: ${err.message}`);
    return res.status(400).json({ error: `Ошибка загрузки файла: ${err.message}` });
  } else if (err) {
    logger.error(`Глобальная ошибка: ${err.message}`);
    return res.status(500).json({ error: `Внутренняя ошибка сервера: ${err.message}` });
  }
  next();
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
      logger.info(`Файл ${file.originalname} принят для загрузки`);
      return cb(null, true);
    }
    logger.error(`Файл ${file.originalname} отклонен: недопустимый тип`);
    cb(new Error("Разрешены только изображения (jpeg, jpg, png) и документы (pdf, doc, docx)"));
  },
  limits: {
    fileSize: 5 * 1024 * 1024, // Ограничение размера файла до 5 МБ
  },
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

// Схемы валидации Joi
const userSchema = Joi.object({
  email: Joi.string().email().required(),
  name: Joi.string().min(1).required(),
  phone: Joi.string().min(5).required(),
  role: Joi.string().valid("SUPER_ADMIN", "REALTOR").required(),
  password: Joi.string().min(6).required(),
});

const propertySchema = Joi.object({
  type_id: Joi.string().required(),
  price: Joi.number().positive().required(),
  rukprice: Joi.number().positive().required(),
  mkv: Joi.number().positive().required(),
  address: Joi.string().min(1).required(),
  etaj: Joi.number().integer().positive().required(),
  etajnost: Joi.number().integer().positive().required(),
  condition: Joi.string().optional().allow(null),
  series: Joi.string().optional().allow(null),
  zhk_id: Joi.string().optional().allow(null),
  owner_name: Joi.string().optional().allow(null),
  curator_ids: Joi.string().optional().allow(null),
  unit: Joi.string().optional().allow(null),
  room: Joi.string().optional().allow(null),
  phone: Joi.string().optional().allow(null),
  district_id: Joi.string().optional().allow(null),
  subdistrict_id: Joi.string().optional().allow(null),
  notes: Joi.string().optional().allow(null),
  description: Joi.string().optional().allow(null),
  status: Joi.string().optional().allow(null),
  owner_id: Joi.number().integer().optional().allow(null),
});

// Middleware для аутентификации JWT
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    logger.error("Ошибка аутентификации: Токен отсутствует");
    return res.status(401).json({ error: "Токен отсутствует" });
  }
  try {
    const decoded = jwt.verify(token, jwtSecret);
    logger.info("Токен проверен:", decoded);

    const connection = await pool.getConnection();
    const [users] = await connection.execute("SELECT id, role FROM users1 WHERE id = ? AND token = ?", [decoded.id, token]);
    connection.release();

    if (users.length === 0) {
      logger.error("Ошибка аутентификации: Токен не найден в базе данных");
      return res.status(401).json({ error: "Недействительный токен" });
    }

    req.user = decoded;
    next();
  } catch (error) {
    logger.error("Ошибка аутентификации:", error.message);
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Срок действия токена истек. Пожалуйста, войдите снова." });
    }
    res.status(401).json({ error: "Недействительный токен" });
  }
};

// Тестирование подключения к базе данных и настройка
async function testDatabaseConnection() {
  try {
    const connection = await pool.getConnection();
    logger.info("Подключение к базе данных успешно установлено!");

    // Создание таблицы users1
    const [tables] = await connection.execute("SHOW TABLES LIKE 'users1'");
    if (tables.length === 0) {
      logger.info("Таблица users1 не существует, создается...");
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
        logger.info("Столбец token не существует, добавляется...");
        await connection.execute("ALTER TABLE users1 ADD token TEXT DEFAULT NULL");
      }
      const [indexes] = await connection.execute("SHOW INDEX FROM users1 WHERE Column_name = 'email' AND Non_unique = 0");
      if (indexes.length === 0) {
        logger.info("Уникальный индекс для email не существует, добавляется...");
        await connection.execute("ALTER TABLE users1 ADD UNIQUE (email)");
      }
    }

    // Создание таблицы properties
    const [propTables] = await connection.execute("SHOW TABLES LIKE 'properties'");
    if (propTables.length === 0) {
      logger.info("Таблица properties не существует, создается...");
      await connection.execute(`
        CREATE TABLE properties (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          type_id VARCHAR(255) DEFAULT NULL,
          \`condition\` VARCHAR(255) DEFAULT NULL,
          series VARCHAR(255) DEFAULT NULL,
          zhk_id VARCHAR(255) DEFAULT NULL,
          document_id INT DEFAULT NULL,
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

    // Добавление индексов для таблицы properties
    const [indexes] = await connection.execute("SHOW INDEX FROM properties WHERE Key_name = 'idx_district_id'");
    if (indexes.length === 0) {
      logger.info("Индекс для district_id не существует, создается...");
      await connection.execute("CREATE INDEX idx_district_id ON properties (district_id)");
    }

    const [subdistrictIndexes] = await connection.execute("SHOW INDEX FROM properties WHERE Key_name = 'idx_subdistrict_id'");
    if (subdistrictIndexes.length === 0) {
      logger.info("Индекс для subdistrict_id не существует, создается...");
      await connection.execute("CREATE INDEX idx_subdistrict_id ON properties (subdistrict_id)");
    }

    const [zhkIndexes] = await connection.execute("SHOW INDEX FROM properties WHERE Key_name = 'idx_zhk_id'");
    if (zhkIndexes.length === 0) {
      logger.info("Индекс для zhk_id не существует, создается...");
      await connection.execute("CREATE INDEX idx_zhk_id ON properties (zhk_id)");
    }

    // Создание таблицы jk
    const [jkTables] = await connection.execute("SHOW TABLES LIKE 'jk'");
    if (jkTables.length === 0) {
      logger.info("Таблица jk не существует, создается...");
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
      logger.info("Таблица districts не существует, создается...");
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
      logger.info("Таблица subdistricts не существует, создается...");
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
    logger.info("Хэшированный пароль администратора:", hashedPassword);

    const [existingAdmin] = await connection.execute("SELECT id FROM users1 WHERE email = ?", [adminEmail]);

    if (existingAdmin.length === 0) {
      logger.info("Администратор не существует, создается...");
      const token = jwt.sign({ id: 1, role: "SUPER_ADMIN" }, jwtSecret, { expiresIn: "30d" });
      await connection.execute(
        "INSERT INTO users1 (first_name, last_name, email, phone, role, password, token) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ["Админ", "Пользователь", adminEmail, "123456789", "SUPER_ADMIN", hashedPassword, token]
      );
    } else {
      logger.info("Администратор существует, обновление пароля и токена...");
      const token = jwt.sign({ id: existingAdmin[0].id, role: "SUPER_ADMIN" }, jwtSecret, { expiresIn: "30d" });
      await connection.execute("UPDATE users1 SET password = ?, token = ? WHERE email = ?", [hashedPassword, token, adminEmail]);
    }

    logger.info("Данные для входа администратора:", { email: adminEmail, password: adminPassword, role: "SUPER_ADMIN" });

    const [rows] = await connection.execute("SELECT 1 AS test");
    if (rows.length > 0) {
      logger.info("База данных функционирует корректно!");
      const [tablesList] = await connection.execute("SHOW TABLES");
      logger.info("Таблицы в базе данных:", tablesList.map((t) => t[`Tables_in_${dbConfig.database}`]));
    }
    connection.release();
  } catch (error) {
    logger.error("Ошибка подключения к базе данных:", error.message);
    if (error.code === "ECONNREFUSED") {
      logger.error("Сервер MySQL не запущен или неверный хост/порт.");
    }
  }
}

testDatabaseConnection();

// Тестовый эндпоинт
app.get("/api/message", (req, res) => {
  logger.info("Тестовый эндпоинт вызван");
  res.json({ message: "Привет от бэкенда Ala-Too!" });
});

// Эндпоинт для входа администратора
app.post("/api/admin/login", async (req, res) => {
  const { email, password } = req.body;
  logger.info("Попытка входа:", { email });

  if (!email || !password) {
    logger.error("Ошибка: Отсутствует email или пароль");
    return res.status(400).json({ error: "Email и пароль обязательны" });
  }

  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, first_name, last_name, email, phone, role, password, profile_picture AS photoUrl, token FROM users1 WHERE email = ?",
      [email]
    );
    logger.info("Результат запроса к базе данных:", rows.length > 0 ? "Пользователь найден" : "Пользователь не найден");

    if (rows.length === 0) {
      connection.release();
      return res.status(401).json({ error: "Неверный email или пользователь не найден" });
    }

    const user = rows[0];
    if (!user.password) {
      logger.error("Ошибка: Пароль пользователя не установлен");
      connection.release();
      return res.status(500).json({ error: "Пароль пользователя не установлен" });
    }

    logger.info("Хэшированный пароль из базы данных:", user.password);
    const isPasswordValid = await bcrypt.compare(password, user.password);
    logger.info("Результат сравнения пароля:", isPasswordValid);

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

    logger.info("Вход успешен, токен сгенерирован и сохранен для пользователя ID:", user.id);
    connection.release();
    res.json({ message: "Авторизация успешна", user: userResponse, token });
  } catch (error) {
    logger.error("Ошибка входа:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Эндпоинт для выхода
app.post("/api/logout", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    await connection.execute("UPDATE users1 SET token = NULL WHERE id = ?", [req.user.id]);
    connection.release();
    logger.info("Выход успешен, токен аннулирован для пользователя ID:", req.user.id);
    res.json({ message: "Выход успешен" });
  } catch (error) {
    logger.error("Ошибка выхода:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Получение всех пользователей (защищено)
app.get("/api/users", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    logger.error("Доступ запрещен: Требуется роль SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });
  }

  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const offset = (page - 1) * limit;

  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, first_name, last_name, email, phone, role, profile_picture AS photoUrl FROM users1 LIMIT ? OFFSET ?",
      [limit, offset]
    );
    const [totalRows] = await connection.execute("SELECT COUNT(*) as total FROM users1");
    const total = totalRows[0].total;

    logger.info(`Пользователи получены: ${rows.length}, страница: ${page}, лимит: ${limit}`);
    connection.release();
    res.json({
      data: rows.map((user) => ({
        ...user,
        name: `${user.first_name} ${user.last_name}`,
        photoUrl: user.photoUrl ? `https://s3.twcstorage.ru/${bucketName}/${user.photoUrl}` : null,
      })),
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    logger.error("Ошибка получения пользователей:", error.message);
    res.status(500).json({ error: "Внутренняя ошибка сервера" });
  }
});

// Создание нового пользователя (защищено, только SUPER_ADMIN)
app.post("/api/users", authenticate, upload.single("photo"), async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    logger.error("Доступ запрещен: Требуется роль SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });
  }

  const { error, value } = userSchema.validate(req.body);
  if (error) {
    logger.error("Ошибка валидации:", error.details);
    return res.status(400).json({ error: error.details[0].message });
  }

  const { email, name, phone, role, password } = value;
  const photo = req.file;

  logger.info("Входные данные для создания пользователя:", { email, name, phone, role, hasPhoto: !!photo });

  const [first_name, last_name = ""] = name.split(" ");
  const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
  const profile_picture = photo ? `${uniqueSuffix}${path.extname(photo.originalname)}` : null;

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const [existingUser] = await connection.execute("SELECT id FROM users1 WHERE email = ?", [email]);
    if (existingUser.length > 0) {
      connection.release();
      logger.error("Ошибка: Email уже существует", { email });
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
      logger.info(`Фото загружено в S3: ${profile_picture}`);
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    logger.info("Хэшированный пароль для нового пользователя:", hashedPassword);

    const [result] = await connection.execute(
      "INSERT INTO users1 (first_name, last_name, email, phone, role, password, profile_picture) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [first_name, last_name, email, phone, role, hashedPassword, profile_picture]
    );
    const userId = result.insertId;
    const token = jwt.sign({ id: userId, role }, jwtSecret, { expiresIn: "30d" });
    await connection.execute("UPDATE users1 SET token = ? WHERE id = ?", [token, userId]);

    await connection.commit();
    logger.info(`Создан новый пользователь: ID=${userId}, Email=${email}, Role=${role}`);

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
    await connection.rollback();
    logger.error("Ошибка создания пользователя:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    connection.release();
  }
});

// Обновление пользователя (защищено, только SUPER_ADMIN)
app.put("/api/users/:id", authenticate, upload.single("photo"), async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    logger.error("Доступ запрещен: Требуется роль SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;
  const { error, value } = userSchema.validate(req.body);
  if (error) {
    logger.error("Ошибка валидации:", error.details);
    return res.status(400).json({ error: error.details[0].message });
  }

  const { email, name, phone, role } = value;
  const photo = req.file;

  logger.info("Входные данные для обновления пользователя:", { id, email, name, phone, role, hasPhoto: !!photo });

  const [first_name, last_name = ""] = name.split(" ");
  const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
  let profile_picture = null;

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const [existingUsers] = await connection.execute("SELECT profile_picture FROM users1 WHERE id = ?", [id]);
    if (existingUsers.length === 0) {
      connection.release();
      logger.error("Пользователь не найден по ID:", id);
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    const [emailCheck] = await connection.execute("SELECT id FROM users1 WHERE email = ? AND id != ?", [email, id]);
    if (emailCheck.length > 0) {
      connection.release();
      logger.error("Ошибка: Email уже существует", { email });
      return res.status(400).json({ error: "Пользователь с таким email уже существует" });
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
      logger.info(`Новое фото загружено в S3: ${profile_picture}`);

      if (existingPhoto) {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: existingPhoto }));
        logger.info(`Старое фото удалено из S3: ${existingPhoto}`);
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

    await connection.commit();
    logger.info("Пользователь обновлен, ID:", id);

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
    await connection.rollback();
    logger.error("Ошибка обновления пользователя:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    connection.release();
  }
});

// Удаление пользователя (защищено, только SUPER_ADMIN)
app.delete("/api/users/:id", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    logger.error("Доступ запрещен: Требуется роль SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const [users] = await connection.execute("SELECT profile_picture FROM users1 WHERE id = ?", [id]);
    if (users.length === 0) {
      connection.release();
      logger.error("Пользователь не найден по ID:", id);
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    const profile_picture = users[0].profile_picture;
    if (profile_picture) {
      await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: profile_picture }));
      logger.info(`Фото удалено из S3: ${profile_picture}`);
    }

    const [result] = await connection.execute("DELETE FROM users1 WHERE id = ?", [id]);
    if (result.affectedRows === 0) {
      connection.release();
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    await connection.commit();
    logger.info("Пользователь удален, ID:", id);

    connection.release();
    res.json({ message: "Пользователь успешно удален" });
  } catch (error) {
    await connection.rollback();
    logger.error("Ошибка удаления пользователя:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    connection.release();
  }
});

// Получение всех ЖК (защищено)
app.get("/api/jk", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute("SELECT id, name FROM jk");
    logger.info("ЖК получены:", rows.length);
    connection.release();
    res.json(rows);
  } catch (error) {
    logger.error("Ошибка получения ЖК:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Получение всех районов (защищено)
app.get("/api/districts", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute("SELECT id, name FROM districts");
    logger.info("Районы получены:", rows.length);
    connection.release();
    res.json(rows);
  } catch (error) {
    logger.error("Ошибка получения районов:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Получение микрорайонов по district_id (защищено)
app.get("/api/subdistricts", authenticate, async (req, res) => {
  const { district_id } = req.query;
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, name FROM subdistricts WHERE district_id = ?",
      [district_id]
    );
    logger.info("Микрорайоны получены:", rows.length);
    connection.release();
    res.json(rows);
  } catch (error) {
    logger.error("Ошибка получения микрорайонов:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Создание нового объекта недвижимости (защищено, SUPER_ADMIN или REALTOR)
app.post("/api/properties", authenticate, upload.fields([
  { name: "photos", maxCount: 10 },
  { name: "document", maxCount: 1 },
]), async (req, res) => {
  if (!["SUPER_ADMIN", "REALTOR"].includes(req.user.role)) {
    logger.error("Доступ запрещен: Требуется роль SUPER_ADMIN или REALTOR");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN или REALTOR" });
  }

  const { error, value } = propertySchema.validate(req.body);
  if (error) {
    logger.error("Ошибка валидации:", error.details);
    return res.status(400).json({ error: error.details[0].message });
  }

  const { type_id, condition, series, zhk_id, owner_name, curator_ids, price, unit, rukprice, mkv, room, phone, district_id, subdistrict_id, address, notes, description, status, owner_id, etaj, etajnost } = value;
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

  if ((photos.length + (document ? 1 : 0)) > 11) {
    logger.error("Ошибка: Превышено максимальное количество файлов (10 фото + 1 документ)");
    return res.status(400).json({ error: "Максимум 10 фотографий и 1 документ" });
  }

  let finalCuratorIds = curator_ids || (req.user.role === "REALTOR" ? req.user.id.toString() : null);
  if (finalCuratorIds) {
    const connection = await pool.getConnection();
    const [curatorCheck] = await connection.execute("SELECT id FROM users1 WHERE id = ?", [finalCuratorIds]);
    if (curatorCheck.length === 0) {
      connection.release();
      return res.status(400).json({ error: "Недействительный ID куратора" });
    }
    connection.release();
  }

  if (req.user.role === "REALTOR" && curator_ids && curator_ids !== req.user.id.toString()) {
    logger.error("Ошибка: Риелтор может назначить только себя куратором", { curator_ids, userId: req.user.id });
    return res.status(403).json({ error: "Риелтор может назначить только себя куратором" });
  }

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

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
      logger.info(`Изображение загружено в S3: ${photo.filename}`);
    }

    if (document) {
      const uploadParams = {
        Bucket: bucketName,
        Key: document.filename,
        Body: document.buffer,
        ContentType: document.mimetype,
      };
      await s3Client.send(new PutObjectCommand(uploadParams));
      logger.info(`Документ загружен в S3: ${document.filename}`);
    }

    const photosJson = JSON.stringify(photos.map(img => img.filename));
    // Преобразование числовых значений в строки для соответствия типам столбцов
    const queryParams = [
      type_id || null,
      condition || null,
      series || null,
      zhk_id || null,
      null,
      owner_name || null,
      finalCuratorIds,
      String(price), // Преобразование в строку
      unit || null,
      String(rukprice), // Преобразование в строку
      String(mkv), // Преобразование в строку
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
      String(etaj), // Преобразование в строку
      String(etajnost), // Преобразование в строку
    ];

    logger.info("Параметры запроса для INSERT INTO properties:", queryParams);

    const [result] = await connection.execute(
      `INSERT INTO properties (
        type_id, \`condition\`, series, zhk_id, document_id, owner_name, curator_ids, price, unit, rukprice, mkv, room, phone, 
        district_id, subdistrict_id, address, notes, description, latitude, longitude, photos, document, status, owner_id, etaj, etajnost
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      queryParams
    );

    await connection.commit();
    logger.info("Создан новый объект недвижимости, ID:", result.insertId);

    const newProperty = {
      id: result.insertId,
      type_id,
      condition,
      series,
      zhk_id,
      document_id: null,
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
    await connection.rollback();
    logger.error("Ошибка создания объекта недвижимости:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    connection.release();
  }
});

// Обновление объекта недвижимости (защищено, SUPER_ADMIN или REALTOR)
app.put("/api/properties/:id", authenticate, upload.fields([
  { name: "photos", maxCount: 10 },
  { name: "document", maxCount: 1 },
]), async (req, res) => {
  if (!["SUPER_ADMIN", "REALTOR"].includes(req.user.role)) {
    logger.error("Доступ запрещен: Требуется роль SUPER_ADMIN или REALTOR");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN или REALTOR" });
  }

  const { id } = req.params;
  const { error, value } = propertySchema.validate(req.body);
  if (error) {
    logger.error("Ошибка валидации:", error.details);
    return res.status(400).json({ error: error.details[0].message });
  }

  const { type_id, condition, series, zhk_id, owner_name, curator_ids, price, unit, rukprice, mkv, room, phone, district_id, subdistrict_id, address, notes, description, status, owner_id, etaj, etajnost, existingPhotos } = value;
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

  if ((photos.length + (document ? 1 : 0)) > 11) {
    logger.error("Ошибка: Превышено максимальное количество файлов (10 фото + 1 документ)");
    return res.status(400).json({ error: "Максимум 10 фотографий и 1 документ" });
  }

  let finalCuratorIds = curator_ids || (req.user.role === "REALTOR" ? req.user.id.toString() : null);
  if (finalCuratorIds) {
    const connection = await pool.getConnection();
    const [curatorCheck] = await connection.execute("SELECT id FROM users1 WHERE id = ?", [finalCuratorIds]);
    if (curatorCheck.length === 0) {
      connection.release();
      return res.status(400).json({ error: "Недействительный ID куратора" });
    }
    connection.release();
  }

  if (req.user.role === "REALTOR" && curator_ids && curator_ids !== req.user.id.toString()) {
    logger.error("Ошибка: Риелтор может назначить только себя куратором", { curator_ids, userId: req.user.id });
    return res.status(403).json({ error: "Риелтор может назначить только себя куратором" });
  }

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const [existingProperties] = await connection.execute("SELECT photos, document, curator_ids FROM properties WHERE id = ?", [id]);
    if (existingProperties.length === 0) {
      connection.release();
      logger.error("Объект недвижимости не найден по ID:", id);
      return res.status(404).json({ error: "Объект недвижимости не найден" });
    }

    const existingProperty = existingProperties[0];
    if (req.user.role === "REALTOR" && existingProperty.curator_ids !== req.user.id.toString()) {
      connection.release();
      logger.error("Ошибка: Риелтор не является куратором этого объекта", { id, curator_ids: existingProperty.curator_ids, userId: req.user.id });
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
          logger.warn(`Поле photos не является массивом для ID: ${id}, данные: ${existingProperty.photos}`);
          photoFiles = [];
        }
      } catch (error) {
        logger.warn(`Ошибка парсинга photos для ID: ${id}, Ошибка: ${error.message}, Данные: ${existingProperty.photos}`);
        photoFiles = [];
      }
    }

    let existingPhotosList = [];
    if (existingPhotos) {
      try {
        existingPhotosList = JSON.parse(existingPhotos);
        if (!Array.isArray(existingPhotosList)) {
          logger.warn(`existingPhotos не является массивом для ID: ${id}, данные: ${existingPhotos}`);
          existingPhotosList = [];
        }
      } catch (error) {
        logger.warn(`Ошибка парсинга existingPhotos для ID: ${id}, Ошибка: ${error.message}, Данные: ${existingPhotos}`);
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
      logger.info(`Новое изображение загружено в S3: ${photo.filename}`);
    }

    const photosToDelete = photoFiles.filter(p => !existingPhotosList.includes(p));
    for (const oldPhoto of photosToDelete) {
      try {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: oldPhoto }));
        logger.info(`Старое изображение удалено из S3: ${oldPhoto}`);
      } catch (error) {
        logger.warn(`Не удалось удалить старое изображение из S3: ${oldPhoto}, Ошибка: ${error.message}`);
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
      logger.info(`Новый документ загружен в S3: ${document.filename}`);

      if (existingProperty.document) {
        try {
          await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: existingProperty.document }));
          logger.info(`Старый документ удален из S3: ${existingProperty.document}`);
        } catch (error) {
          logger.warn(`Не удалось удалить старый документ из S3: ${existingProperty.document}, Ошибка: ${error.message}`);
        }
      }
      newDocument = document.filename;
    }

    // Преобразование числовых значений в строки для соответствия типам столбцов
    const queryParams = [
      type_id || null,
      condition || null,
      series || null,
      zhk_id || null,
      null,
      owner_name || null,
      finalCuratorIds,
      String(price), // Преобразование в строку
      unit || null,
      String(rukprice), // Преобразование в строку
      String(mkv), // Преобразование в строку
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
      String(etaj), // Преобразование в строку
      String(etajnost), // Преобразование в строку
      id,
    ];

    logger.info("Параметры запроса для UPDATE properties:", queryParams);

    const [result] = await connection.execute(
      `UPDATE properties SET
        type_id = ?, \`condition\` = ?, series = ?, zhk_id = ?, document_id = ?, owner_name = ?, curator_ids = ?, price = ?, unit = ?, rukprice = ?, mkv = ?, room = ?, phone = ?,
        district_id = ?, subdistrict_id = ?, address = ?, notes = ?, description = ?, photos = ?, document = ?, status = ?, owner_id = ?, etaj = ?, etajnost = ?
        WHERE id = ?`,
      queryParams
    );

    if (result.affectedRows === 0) {
      connection.release();
      return res.status(404).json({ error: "Объект недвижимости не найден" });
    }

    await connection.commit();
    logger.info("Объект недвижимости обновлен, ID:", id);

    const updatedProperty = {
      id: parseInt(id),
      type_id,
      condition,
      series,
      zhk_id,
      document_id: null,
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
    await connection.rollback();
    logger.error("Ошибка обновления объекта недвижимости:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    connection.release();
  }
});

// Удаление объекта недвижимости (защищено, SUPER_ADMIN или REALTOR)
app.delete("/api/properties/:id", authenticate, async (req, res) => {
  if (!["SUPER_ADMIN", "REALTOR"].includes(req.user.role)) {
    logger.error("Доступ запрещен: Требуется роль SUPER_ADMIN или REALTOR");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN или REALTOR" });
  }

  const { id } = req.params;

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const [properties] = await connection.execute("SELECT photos, document, curator_ids FROM properties WHERE id = ?", [id]);
    if (properties.length === 0) {
      connection.release();
      logger.error("Объект недвижимости не найден по ID:", id);
      return res.status(404).json({ error: "Объект недвижимости не найден" });
    }

    const existingProperty = properties[0];
    if (req.user.role === "REALTOR" && existingProperty.curator_ids !== req.user.id.toString()) {
      connection.release();
      logger.error("Ошибка: Риелтор не является куратором этого объекта", { id, curator_ids: existingProperty.curator_ids, userId: req.user.id });
      return res.status(403).json({ error: "У вас нет прав для удаления этого объекта" });
    }

    let photoFiles = [];
    if (existingProperty.photos) {
      try {
        photoFiles = JSON.parse(existingProperty.photos);
        if (!Array.isArray(photoFiles)) {
          logger.warn(`Поле photos не является массивом для ID: ${id}, данные: ${existingProperty.photos}`);
          photoFiles = [];
        }
      } catch (error) {
        logger.warn(`Ошибка парсинга photos для ID: ${id}, Ошибка: ${error.message}, Данные: ${existingProperty.photos}`);
        photoFiles = [];
      }
      for (const img of photoFiles) {
        try {
          await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: img }));
          logger.info(`Изображение удалено из S3: ${img}`);
        } catch (error) {
          logger.warn(`Не удалось удалить изображение из S3: ${img}, Ошибка: ${error.message}`);
        }
      }
    }
    if (existingProperty.document) {
      try {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: existingProperty.document }));
        logger.info(`Документ удален из S3: ${existingProperty.document}`);
      } catch (error) {
        logger.warn(`Не удалось удалить документ из S3: ${existingProperty.document}, Ошибка: ${error.message}`);
      }
    }

    const [result] = await connection.execute("DELETE FROM properties WHERE id = ?", [id]);
    if (result.affectedRows === 0) {
      connection.release();
      return res.status(404).json({ error: "Объект недвижимости не найден" });
    }

    await connection.commit();
    logger.info("Объект недвижимости удален, ID:", id);

    connection.release();
    res.json({ message: "Объект недвижимости успешно удален" });
  } catch (error) {
    await connection.rollback();
    logger.error("Ошибка удаления объекта недвижимости:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    connection.release();
  }
});

// Получение всех объектов недвижимости (защищено)
app.get("/api/properties", authenticate, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const offset = (page - 1) * limit;

  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      `SELECT p.*, CONCAT(u.first_name, ' ', u.last_name) AS curator_name
       FROM properties p
       LEFT JOIN users1 u ON p.curator_ids = u.id
       LIMIT ? OFFSET ?`,
      [limit, offset]
    );
    const [totalRows] = await connection.execute("SELECT COUNT(*) as total FROM properties");
    const total = totalRows[0].total;

    logger.info(`Объекты недвижимости получены: ${rows.length}, страница: ${page}, лимит: ${limit}`);

    const properties = rows.map((row) => {
      let parsedPhotos = [];
      if (row.photos) {
        try {
          parsedPhotos = JSON.parse(row.photos);
          if (!Array.isArray(parsedPhotos)) {
            logger.warn(`Поле photos не является массивом для ID: ${row.id}, данные: ${row.photos}`);
            parsedPhotos = [];
          }
        } catch (error) {
          logger.warn(`Ошибка парсинга photos для ID: ${row.id}, Ошибка: ${error.message}, Данные: ${row.photos}`);
          parsedPhotos = [];
        }
      }

      return {
        ...row,
        photos: parsedPhotos.map((img) => `https://s3.twcstorage.ru/${bucketName}/${img}`),
        document: row.document ? `https://s3.twcstorage.ru/${bucketName}/${row.document}` : null,
        date: new Date(row.created_at).toLocaleDateString("ru-RU"),
        time: new Date(row.created_at).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" }),
        curator_name: row.curator_name || row.curator_ids || "Не указан",
      };
    });

    connection.release();
    res.json({
      data: properties,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    logger.error("Ошибка получения объектов недвижимости:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Получение всех объявлений для AdminDashboard (защищено)
app.get("/api/listings", authenticate, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const offset = (page - 1) * limit;

  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, type_id, price, rukprice, mkv, status, address, created_at FROM properties LIMIT ? OFFSET ?",
      [limit, offset]
    );
    const [totalRows] = await connection.execute("SELECT COUNT(*) as total FROM properties");
    const total = totalRows[0].total;

    logger.info(`Объявления получены: ${rows.length}, страница: ${page}, лимит: ${limit}`);

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
    res.json({
      data: listings,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    logger.error("Ошибка получения объявлений:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Получение всех районов и микрорайонов
app.get("/api/raions", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [districts] = await connection.execute("SELECT id, name, NULL AS parentRaionId FROM districts");
    const [subdistricts] = await connection.execute("SELECT id, name, district_id AS parentRaionId FROM subdistricts");
    const raions = [
      ...districts.map(row => ({ id: row.id, name: row.name, parentRaionId: null, isRaion: true })),
      ...subdistricts.map(row => ({ id: row.id, name: row.name, parentRaionId: row.parentRaionId, isRaion: false })),
    ];
    logger.info("Районы и микрорайоны получены:", raions.length);
    connection.release();
    res.json(raions);
  } catch (error) {
    logger.error("Ошибка получения районов и микрорайонов:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Перенаправление объектов недвижимости (защищено, только SUPER_ADMIN)
app.patch("/api/properties/redirect", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    logger.error("Доступ запрещен: Требуется роль SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });
  }

  const { propertyIds, curator_ids } = req.body;

  if (!Array.isArray(propertyIds) || !curator_ids) {
    logger.error("Ошибка: propertyIds должен быть массивом, curator_ids обязателен", { propertyIds, curator_ids });
    return res.status(400).json({ error: "propertyIds должен быть массивом, curator_ids обязателен" });
  }

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const [curatorCheck] = await connection.execute("SELECT id FROM users1 WHERE id = ?", [curator_ids]);
    if (curatorCheck.length === 0) {
      connection.release();
      return res.status(400).json({ error: "Недействительный ID куратора" });
    }

    const [existingProperties] = await connection.execute(
      "SELECT id, curator_ids FROM properties WHERE id IN (?)",
      [propertyIds]
    );
    if (existingProperties.length !== propertyIds.length) {
      const existingIds = existingProperties.map(p => p.id);
      const missingIds = propertyIds.filter(id => !existingIds.includes(id));
      connection.release();
      logger.error("Некоторые объекты не найдены:", missingIds);
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

    await connection.commit();
    logger.info(`Перенаправлено ${result.affectedRows} объектов недвижимости, новые curator_ids: ${curator_ids}`);
    connection.release();
    res.json({ message: "Объекты недвижимости успешно перенаправлены", affectedRows: result.affectedRows });
  } catch (error) {
    await connection.rollback();
    logger.error("Ошибка перенаправления объектов недвижимости:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    connection.release();
  }
});

// Запуск сервера
app.listen(port, () => {
  logger.info(`Сервер запущен на http://localhost:${port}`);
  logger.info(`Публичный доступ: ${publicDomain}:${port}`);
});