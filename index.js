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
  console.error("Глобальная ошибка:", err.message);
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
      console.log(`Файл ${file.originalname} принят для загрузки`);
      return cb(null, true);
    }
    console.error(`Файл ${file.originalname} отклонен: недопустимый тип`);
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

// Middleware для аутентификации JWT
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    console.error("Ошибка аутентификации: Токен отсутствует");
    return res.status(401).json({ error: "Токен отсутствует" });
  }
  try {
    const decoded = jwt.verify(token, jwtSecret);
    console.log("Токен проверен:", decoded);

    const connection = await pool.getConnection();
    const [users] = await connection.execute("SELECT id, role FROM users1 WHERE id = ? AND token = ?", [decoded.id, token]);
    connection.release();

    if (users.length === 0) {
      console.error("Ошибка аутентификации: Токен не найден в базе данных");
      return res.status(401).json({ error: "Недействительный токен" });
    }

    req.user = decoded;
    next();
  } catch (error) {
    console.error("Ошибка аутентификации:", error.message);
    res.status(401).json({ error: "Недействительный токен" });
  }
};

// Тестирование подключения к базе данных и настройка
async function testDatabaseConnection() {
  try {
    const connection = await pool.getConnection();
    console.log("Подключение к базе данных успешно установлено!");

    // Создание таблицы users1, если она не существует
    const [tables] = await connection.execute("SHOW TABLES LIKE 'users1'");
    if (tables.length === 0) {
      console.log("Таблица users1 не существует, создается...");
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
        console.log("Столбец token не существует, добавляется...");
        await connection.execute("ALTER TABLE users1 ADD token TEXT DEFAULT NULL");
      }
      const [indexes] = await connection.execute("SHOW INDEX FROM users1 WHERE Column_name = 'email' AND Non_unique = 0");
      if (indexes.length === 0) {
        console.log("Уникальный индекс для email не существует, добавляется...");
        await connection.execute("ALTER TABLE users1 ADD UNIQUE (email)");
      }
    }

    // Создание таблицы properties, если она не существует
    const [propTables] = await connection.execute("SHOW TABLES LIKE 'properties'");
    if (propTables.length === 0) {
      console.log("Таблица properties не существует, создается...");
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

    // Создание таблицы jk, если она не существует
    const [jkTables] = await connection.execute("SHOW TABLES LIKE 'jk'");
    if (jkTables.length === 0) {
      console.log("Таблица jk не существует, создается...");
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

    // Создание таблицы districts, если она не существует
    const [districtTables] = await connection.execute("SHOW TABLES LIKE 'districts'");
    if (districtTables.length === 0) {
      console.log("Таблица districts не существует, создается...");
      await connection.execute(`
        CREATE TABLE districts (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci
      `);
    }

    // Создание таблицы subdistricts, если она не существует
    const [subdistrictTables] = await connection.execute("SHOW TABLES LIKE 'subdistricts'");
    if (subdistrictTables.length === 0) {
      console.log("Таблица subdistricts не существует, создается...");
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
    console.log("Хэшированный пароль администратора:", hashedPassword);

    const [existingAdmin] = await connection.execute("SELECT id FROM users1 WHERE email = ?", [adminEmail]);

    if (existingAdmin.length === 0) {
      console.log("Администратор не существует, создается...");
      const token = jwt.sign({ id: 1, role: "SUPER_ADMIN" }, jwtSecret, { expiresIn: "30d" });
      await connection.execute(
        "INSERT INTO users1 (first_name, last_name, email, phone, role, password, token) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ["Админ", "Пользователь", adminEmail, "123456789", "SUPER_ADMIN", hashedPassword, token]
      );
    } else {
      console.log("Администратор существует, обновление пароля и токена...");
      const token = jwt.sign({ id: existingAdmin[0].id, role: "SUPER_ADMIN" }, jwtSecret, { expiresIn: "30d" });
      await connection.execute("UPDATE users1 SET password = ?, token = ? WHERE email = ?", [hashedPassword, token, adminEmail]);
    }

    console.log("Данные для входа администратора:");
    console.log(`Email: ${adminEmail}`);
    console.log(`Пароль: ${adminPassword}`);
    console.log("Роль: SUPER_ADMIN");

    const [rows] = await connection.execute("SELECT 1 AS test");
    if (rows.length > 0) {
      console.log("База данных функционирует корректно!");
      const [tablesList] = await connection.execute("SHOW TABLES");
      console.log("Таблицы в базе данных:", tablesList.map((t) => t[`Tables_in_${dbConfig.database}`]));
    }
    connection.release();
  } catch (error) {
    console.error("Ошибка подключения к базе данных:", error.message);
    if (error.code === "ECONNREFUSED") {
      console.error("Сервер MySQL не запущен или неверный хост/порт.");
    }
  }
}

testDatabaseConnection();

// Тестовый эндпоинт
app.get("/api/message", (req, res) => {
  res.json({ message: "Привет от бэкенда Ala-Too!" });
});

// Эндпоинт для входа администратора
app.post("/api/admin/login", async (req, res) => {
  const { email, password } = req.body;
  console.log("Попытка входа:", { email });

  if (!email || !password) {
    console.error("Ошибка: Отсутствует email или пароль");
    return res.status(400).json({ error: "Email и пароль обязательны" });
  }

  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, first_name, last_name, email, phone, role, password, profile_picture AS photoUrl, token FROM users1 WHERE email = ?",
      [email]
    );
    console.log("Результат запроса к базе данных:", rows.length > 0 ? "Пользователь найден" : "Пользователь не найден");

    if (rows.length === 0) {
      connection.release();
      return res.status(401).json({ error: "Неверный email или пользователь не найден" });
    }

    const user = rows[0];
    if (!user.password) {
      console.error("Ошибка: Пароль пользователя не установлен");
      connection.release();
      return res.status(500).json({ error: "Пароль пользователя не установлен" });
    }

    console.log("Хэшированный пароль из базы данных:", user.password);
    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log("Результат сравнения пароля:", isPasswordValid);

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

    console.log("Вход успешен, токен сгенерирован и сохранен");
    connection.release();
    res.json({ message: "Авторизация успешна", user: userResponse, token });
  } catch (error) {
    console.error("Ошибка входа:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Эндпоинт для выхода
app.post("/api/logout", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    await connection.execute("UPDATE users1 SET token = NULL WHERE id = ?", [req.user.id]);
    connection.release();
    console.log("Выход успешен, токен аннулирован для пользователя ID:", req.user.id);
    res.json({ message: "Выход успешен" });
  } catch (error) {
    console.error("Ошибка выхода:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Получение всех пользователей (защищено)
app.get("/api/users", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });
  }

  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, first_name, last_name, email, phone, role, profile_picture AS photoUrl FROM users1"
    );
    console.log("Пользователи получены из базы данных:", rows.length);
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

// Создание нового пользователя (защищено, только SUPER_ADMIN)
app.post("/api/users", authenticate, upload.single("photo"), async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });
  }

  const { email, name, phone, role, password } = req.body;
  const photo = req.file;

  console.log("Входные данные для создания пользователя:", { email, name, phone, role, hasPhoto: !!photo });

  if (!email || !name || !phone || !role || !password) {
    console.error("Ошибка: Не все поля предоставлены", { email, name, phone, role, password });
    return res.status(400).json({ error: "Все поля, включая пароль, обязательны" });
  }

  if (typeof password !== "string") {
    console.error("Ошибка: Пароль должен быть строкой", { password, type: typeof password });
    return res.status(400).json({ error: "Пароль должен быть строкой" });
  }

  const [first_name, last_name = ""] = name.split(" ");
  const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
  const profile_picture = photo ? `${uniqueSuffix}${path.extname(photo.originalname)}` : null;

  try {
    const connection = await pool.getConnection();

    const [existingUser] = await connection.execute("SELECT id FROM users1 WHERE email = ?", [email]);
    if (existingUser.length > 0) {
      connection.release();
      console.error("Ошибка: Email уже существует", { email });
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
      console.log(`Фото загружено в S3: ${profile_picture}`);
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    console.log("Хэшированный пароль для нового пользователя:", hashedPassword);

    const [result] = await connection.execute(
      "INSERT INTO users1 (first_name, last_name, email, phone, role, password, profile_picture) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [first_name, last_name, email, phone, role, hashedPassword, profile_picture]
    );
    const userId = result.insertId;
    const token = jwt.sign({ id: userId, role }, jwtSecret, { expiresIn: "30d" });
    await connection.execute("UPDATE users1 SET token = ? WHERE id = ?", [token, userId]);
    console.log("Создан новый пользователь, ID:", userId, "Токен сохранен:", token);

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

// Обновление пользователя (защищено, только SUPER_ADMIN)
app.put("/api/users/:id", authenticate, upload.single("photo"), async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;
  const { email, name, phone, role } = req.body;
  const photo = req.file;

  console.log("Входные данные для обновления пользователя:", { id, email, name, phone, role, hasPhoto: !!photo });

  if (!email || !name || !phone || !role) {
    console.error("Ошибка: Не все поля предоставлены");
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
      console.error("Пользователь не найден по ID:", id);
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    const [emailCheck] = await connection.execute("SELECT id FROM users1 WHERE email = ? AND id != ?", [email, id]);
    if (emailCheck.length > 0) {
      connection.release();
      console.error("Ошибка: Email уже существует", { email });
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
      console.log(`Новое фото загружено в S3: ${profile_picture}`);

      if (existingPhoto) {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: existingPhoto }));
        console.log(`Старое фото удалено из S3: ${existingPhoto}`);
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
    console.log("Пользователь обновлен, ID:", id);

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

// Удаление пользователя (защищено, только SUPER_ADMIN)
app.delete("/api/users/:id", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;

  try {
    const connection = await pool.getConnection();
    const [users] = await connection.execute("SELECT profile_picture FROM users1 WHERE id = ?", [id]);
    if (users.length === 0) {
      connection.release();
      console.error("Пользователь не найден по ID:", id);
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    const profile_picture = users[0].profile_picture;
    if (profile_picture) {
      await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: profile_picture }));
      console.log(`Фото удалено из S3: ${profile_picture}`);
    }

    const [result] = await connection.execute("DELETE FROM users1 WHERE id = ?", [id]);
    if (result.affectedRows === 0) {
      connection.release();
      return res.status(404).json({ error: "Пользователь не найден" });
    }
    console.log("Пользователь удален, ID:", id);

    connection.release();
    res.json({ message: "Пользователь успешно удален" });
  } catch (error) {
    console.error("Ошибка удаления пользователя:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Получение всех ЖК (защищено)
app.get("/api/jk", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute("SELECT id, name FROM jk");
    console.log("ЖК получены:", rows.length);
    connection.release();
    res.json(rows);
  } catch (error) {
    console.error("Ошибка получения ЖК:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Получение всех районов (защищено)
app.get("/api/districts", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute("SELECT id, name FROM districts");
    console.log("Районы получены:", rows.length);
    connection.release();
    res.json(rows);
  } catch (error) {
    console.error("Ошибка получения районов:", error.message);
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
    console.log("Микрорайоны получены:", rows.length);
    connection.release();
    res.json(rows);
  } catch (error) {
    console.error("Ошибка получения микрорайонов:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Создание нового объекта недвижимости (защищено, SUPER_ADMIN или REALTOR)
app.post("/api/properties", authenticate, upload.fields([
  { name: "photos", maxCount: 10 },
  { name: "document", maxCount: 1 },
]), async (req, res) => {
  if (!["SUPER_ADMIN", "REALTOR"].includes(req.user.role)) {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN или REALTOR");
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
    console.error("Ошибка: Не все обязательные поля предоставлены", { type_id, price, rukprice, mkv, address, etaj, etajnost });
    return res.status(400).json({ error: "Все обязательные поля (type_id, price, rukprice, mkv, address, etaj, etajnost) должны быть предоставлены" });
  }

  if (isNaN(parseFloat(price)) || isNaN(parseFloat(rukprice)) || isNaN(parseFloat(mkv)) || isNaN(parseInt(etaj)) || isNaN(parseInt(etajnost))) {
    console.error("Ошибка: Числовые поля некорректны", { price, rukprice, mkv, etaj, etajnost });
    return res.status(400).json({ error: "Поля price, rukprice, mkv, etaj, etajnost должны быть числовыми" });
  }

  let finalCuratorIds = curator_ids || (req.user.role === "REALTOR" ? req.user.id.toString() : null);
  if (req.user.role === "REALTOR" && curator_ids && curator_ids !== req.user.id.toString()) {
    console.error("Ошибка: Риелтор может назначить только себя куратором", { curator_ids, userId: req.user.id });
    return res.status(403).json({ error: "Риелтор может назначить только себя куратором" });
  }

  try {
    const connection = await pool.getConnection();

    // Проверка zhk_id, если предоставлен
    if (zhk_id) {
      const [jkCheck] = await connection.execute("SELECT id FROM jk WHERE id = ?", [zhk_id]);
      if (jkCheck.length === 0) {
        connection.release();
        return res.status(400).json({ error: "Недействительный ID ЖК" });
      }
    }

    // Проверка district_id, если предоставлен
    if (district_id) {
      const [districtCheck] = await connection.execute("SELECT id FROM districts WHERE id = ?", [district_id]);
      if (districtCheck.length === 0) {
        connection.release();
        return res.status(400).json({ error: "Недействительный ID района" });
      }
    }

    // Проверка subdistrict_id, если предоставлен
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
      console.log(`Изображение загружено в S3: ${photo.filename}`);
    }

    if (document) {
      const uploadParams = {
        Bucket: bucketName,
        Key: document.filename,
        Body: document.buffer,
        ContentType: document.mimetype,
      };
      await s3Client.send(new PutObjectCommand(uploadParams));
      console.log(`Документ загружен в S3: ${document.filename}`);
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
    console.log("Создан новый объект недвижимости, ID:", result.insertId);

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

// Обновление объекта недвижимости (защищено, SUPER_ADMIN или REALTOR)
app.put("/api/properties/:id", authenticate, upload.fields([
  { name: "photos", maxCount: 10 },
  { name: "document", maxCount: 1 },
]), async (req, res) => {
  if (!["SUPER_ADMIN", "REALTOR"].includes(req.user.role)) {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN или REALTOR");
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
    console.error("Ошибка: Не все обязательные поля предоставлены", { type_id, price, rukprice, mkv, address, etaj, etajnost });
    return res.status(400).json({ error: "Все обязательные поля (type_id, price, rukprice, mkv, address, etaj, etajnost) должны быть предоставлены" });
  }

  if (isNaN(parseFloat(price)) || isNaN(parseFloat(rukprice)) || isNaN(parseFloat(mkv)) || isNaN(parseInt(etaj)) || isNaN(parseInt(etajnost))) {
    console.error("Ошибка: Числовые поля некорректны", { price, rukprice, mkv, etaj, etajnost });
    return res.status(400).json({ error: "Поля price, rukprice, mkv, etaj, etajnost должны быть числовыми" });
  }

  let finalCuratorIds = curator_ids || (req.user.role === "REALTOR" ? req.user.id.toString() : null);
  if (req.user.role === "REALTOR" && curator_ids && curator_ids !== req.user.id.toString()) {
    console.error("Ошибка: Риелтор может назначить только себя куратором", { curator_ids, userId: req.user.id });
    return res.status(403).json({ error: "Риелтор может назначить только себя куратором" });
  }

  try {
    const connection = await pool.getConnection();
    const [existingProperties] = await connection.execute("SELECT photos, document, curator_ids FROM properties WHERE id = ?", [id]);
    if (existingProperties.length === 0) {
      connection.release();
      console.error("Объект недвижимости не найден по ID:", id);
      return res.status(404).json({ error: "Объект недвижимости не найден" });
    }

    const existingProperty = existingProperties[0];
    if (req.user.role === "REALTOR" && existingProperty.curator_ids !== req.user.id.toString()) {
      connection.release();
      console.error("Ошибка: Риелтор не является куратором этого объекта", { id, curator_ids: existingProperty.curator_ids, userId: req.user.id });
      return res.status(403).json({ error: "У вас нет прав для редактирования этого объекта" });
    }

    // Проверка zhk_id, если предоставлен
    if (zhk_id) {
      const [jkCheck] = await connection.execute("SELECT id FROM jk WHERE id = ?", [zhk_id]);
      if (jkCheck.length === 0) {
        connection.release();
        return res.status(400).json({ error: "Недействительный ID ЖК" });
      }
    }

    // Проверка district_id, если предоставлен
    if (district_id) {
      const [districtCheck] = await connection.execute("SELECT id FROM districts WHERE id = ?", [district_id]);
      if (districtCheck.length === 0) {
        connection.release();
        return res.status(400).json({ error: "Недействительный ID района" });
      }
    }

    // Проверка subdistrict_id, если предоставлен
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
          console.warn(`Поле photos не является массивом для ID: ${id}, данные: ${existingProperty.photos}`);
          photoFiles = existingProperty.photos.split(",").filter(p => p.trim());
        }
      } catch (error) {
        console.warn(`Ошибка парсинга photos для ID: ${id}, Ошибка: ${error.message}, Данные: ${existingProperty.photos}`);
        photoFiles = existingProperty.photos.split(",").filter(p => p.trim());
      }
    }

    // Парсинг existingPhotos из запроса
    let existingPhotosList = [];
    if (existingPhotos) {
      try {
        existingPhotosList = JSON.parse(existingPhotos);
        if (!Array.isArray(existingPhotosList)) {
          console.warn(`existingPhotos не является массивом для ID: ${id}, данные: ${existingPhotos}`);
          existingPhotosList = [];
        }
      } catch (error) {
        console.warn(`Ошибка парсинга existingPhotos для ID: ${id}, Ошибка: ${error.message}, Данные: ${existingPhotos}`);
        existingPhotosList = [];
      }
    }

    // Загрузка новых фотографий в S3
    for (const photo of photos) {
      const uploadParams = {
        Bucket: bucketName,
        Key: photo.filename,
        Body: photo.buffer,
        ContentType: photo.mimetype,
      };
      await s3Client.send(new PutObjectCommand(uploadParams));
      console.log(`Новое изображение загружено в S3: ${photo.filename}`);
    }

    // Удаление фотографий, которых нет в existingPhotosList
    const photosToDelete = photoFiles.filter(p => !existingPhotosList.includes(p));
    for (const oldPhoto of photosToDelete) {
      try {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: oldPhoto }));
        console.log(`Старое изображение удалено из S3: ${oldPhoto}`);
      } catch (error) {
        console.warn(`Не удалось удалить старое изображение из S3: ${oldPhoto}, Ошибка: ${error.message}`);
      }
    }

    // Объединение существующих и новых фотографий
    const newPhotos = [...existingPhotosList, ...photos.map(img => img.filename)];
    const photosJson = newPhotos.length > 0 ? JSON.stringify(newPhotos) : null;

    // Обработка обновления документа
    let newDocument = existingProperty.document;
    if (document) {
      const uploadParams = {
        Bucket: bucketName,
        Key: document.filename,
        Body: document.buffer,
        ContentType: document.mimetype,
      };
      await s3Client.send(new PutObjectCommand(uploadParams));
      console.log(`Новый документ загружен в S3: ${document.filename}`);

      if (existingProperty.document) {
        try {
          await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: existingProperty.document }));
          console.log(`Старый документ удален из S3: ${existingProperty.document}`);
        } catch (error) {
          console.warn(`Не удалось удалить старый документ из S3: ${existingProperty.document}, Ошибка: ${error.message}`);
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
    console.log("Объект недвижимости обновлен, ID:", id);

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

// Удаление объекта недвижимости (защищено, SUPER_ADMIN или REALTOR)
app.delete("/api/properties/:id", authenticate, async (req, res) => {
  if (!["SUPER_ADMIN", "REALTOR"].includes(req.user.role)) {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN или REALTOR");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN или REALTOR" });
  }

  const { id } = req.params;

  try {
    const connection = await pool.getConnection();
    const [properties] = await connection.execute("SELECT photos, document, curator_ids FROM properties WHERE id = ?", [id]);
    if (properties.length === 0) {
      connection.release();
      console.error("Объект недвижимости не найден по ID:", id);
      return res.status(404).json({ error: "Объект недвижимости не найден" });
    }

    const existingProperty = properties[0];
    if (req.user.role === "REALTOR" && existingProperty.curator_ids !== req.user.id.toString()) {
      connection.release();
      console.error("Ошибка: Риелтор не является куратором этого объекта", { id, curator_ids: existingProperty.curator_ids, userId: req.user.id });
      return res.status(403).json({ error: "У вас нет прав для удаления этого объекта" });
    }

    let photoFiles = [];
    if (existingProperty.photos) {
      try {
        photoFiles = JSON.parse(existingProperty.photos);
        if (!Array.isArray(photoFiles)) {
          console.warn(`Поле photos не является массивом для ID: ${id}, данные: ${existingProperty.photos}`);
          photoFiles = existingProperty.photos.split(",").filter(p => p.trim());
        }
      } catch (error) {
        console.warn(`Ошибка парсинга photos для ID: ${id}, Ошибка: ${error.message}, Данные: ${existingProperty.photos}`);
        photoFiles = existingProperty.photos.split(",").filter(p => p.trim());
      }
      for (const img of photoFiles) {
        try {
          await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: img }));
          console.log(`Изображение удалено из S3: ${img}`);
        } catch (error) {
          console.warn(`Не удалось удалить изображение из S3: ${img}, Ошибка: ${error.message}`);
        }
      }
    }
    if (existingProperty.document) {
      try {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: existingProperty.document }));
        console.log(`Документ удален из S3: ${existingProperty.document}`);
      } catch (error) {
        console.warn(`Не удалось удалить документ из S3: ${existingProperty.document}, Ошибка: ${error.message}`);
      }
    }

    const [result] = await connection.execute("DELETE FROM properties WHERE id = ?", [id]);
    if (result.affectedRows === 0) {
      connection.release();
      return res.status(404).json({ error: "Объект недвижимости не найден" });
    }
    console.log("Объект недвижимости удален, ID:", id);

    connection.release();
    res.json({ message: "Объект недвижимости успешно удален" });
  } catch (error) {
    console.error("Ошибка удаления объекта недвижимости:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Получение всех объектов недвижимости (защищено)
app.get("/api/properties", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      `SELECT p.*, CONCAT(u.first_name, ' ', u.last_name) AS curator_name
       FROM properties p
       LEFT JOIN users1 u ON p.curator_ids = u.id`
    );
    console.log("Объекты недвижимости получены из базы данных:", rows.length);

    const properties = rows.map((row) => {
      let parsedPhotos = [];
      if (row.photos) {
        try {
          parsedPhotos = JSON.parse(row.photos);
          if (!Array.isArray(parsedPhotos)) {
            console.warn(`Поле photos не является массивом для ID: ${row.id}, данные: ${row.photos}`);
            parsedPhotos = row.photos.split(",").filter(p => p.trim());
          }
        } catch (error) {
          console.warn(`Ошибка парсинга photos для ID: ${row.id}, Ошибка: ${error.message}, Данные: ${row.photos}`);
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

// Получение всех объявлений для AdminDashboard (защищено)
app.get("/api/listings", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, type_id, price, rukprice, mkv, status, address, created_at FROM properties"
    );
    console.log("Объявления получены из properties:", rows.length);

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



// Получение всех районов и микрорайонов
app.get("/api/raions", authenticate, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    
    // Получение районов
    const [districts] = await connection.execute("SELECT id, name, NULL AS parentRaionId FROM districts");
    
    // Получение микрорайонов
    const [subdistricts] = await connection.execute("SELECT id, name, district_id AS parentRaionId FROM subdistricts");
    
    // Объединяем районы и микрорайоны
    const raions = [
      ...districts.map(row => ({ id: row.id, name: row.name, parentRaionId: null, isRaion: true })),
      ...subdistricts.map(row => ({ id: row.id, name: row.name, parentRaionId: row.parentRaionId, isRaion: false })),
    ];
    
    console.log("Районы и микрорайоны получены:", raions.length);
    connection.release();
    res.json(raions);
  } catch (error) {
    console.error("Ошибка получения районов и микрорайонов:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});


// Создание нового района
app.post("/api/raions", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });
  }

  const { name } = req.body;
  if (!name) {
    console.error("Ошибка: Поле name обязательно");
    return res.status(400).json({ error: "Поле name обязательно" });
  }

  try {
    const connection = await pool.getConnection();
    const [result] = await connection.execute(
      "INSERT INTO districts (name) VALUES (?)",
      [name]
    );
    console.log("Создан новый район, ID:", result.insertId);
    connection.release();
    res.json({ id: result.insertId, name, parentRaionId: null, isRaion: true });
  } catch (error) {
    console.error("Ошибка создания района:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});


// Создание нового микрорайона
app.post("/api/subraions", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });
  }

  const { name, parentRaionId } = req.body;
  if (!name || !parentRaionId) {
    console.error("Ошибка: Поля name и parentRaionId обязательны");
    return res.status(400).json({ error: "Поля name и parentRaionId обязательны" });
  }

  try {
    const connection = await pool.getConnection();
    // Проверка существования района
    const [districtCheck] = await connection.execute("SELECT id FROM districts WHERE id = ?", [parentRaionId]);
    if (districtCheck.length === 0) {
      connection.release();
      return res.status(400).json({ error: "Недействительный ID района" });
    }

    const [result] = await connection.execute(
      "INSERT INTO subdistricts (name, district_id) VALUES (?, ?)",
      [name, parentRaionId]
    );
    console.log("Создан новый микрорайон, ID:", result.insertId);
    connection.release();
    res.json({ id: result.insertId, name, parentRaionId, isRaion: false });
  } catch (error) {
    console.error("Ошибка создания микрорайона:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});


// Обновление района
app.put("/api/raions/:id", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;
  const { name } = req.body;
  if (!name) {
    console.error("Ошибка: Поле name обязательно");
    return res.status(400).json({ error: "Поле name обязательно" });
  }

  try {
    const connection = await pool.getConnection();
    const [result] = await connection.execute(
      "UPDATE districts SET name = ? WHERE id = ?",
      [name, id]
    );
    if (result.affectedRows === 0) {
      connection.release();
      return res.status(404).json({ error: "Район не найден" });
    }
    console.log("Район обновлен, ID:", id);
    connection.release();
    res.json({ id: parseInt(id), name, parentRaionId: null, isRaion: true });
  } catch (error) {
    console.error("Ошибка обновления района:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});


// Обновление микрорайона
app.put("/api/subraions/:id", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;
  const { name, parentRaionId } = req.body;
  if (!name || !parentRaionId) {
    console.error("Ошибка: Поля name и parentRaionId обязательны");
    return res.status(400).json({ error: "Поля name и parentRaionId обязательны" });
  }

  try {
    const connection = await pool.getConnection();
    // Проверка существования района
    const [districtCheck] = await connection.execute("SELECT id FROM districts WHERE id = ?", [parentRaionId]);
    if (districtCheck.length === 0) {
      connection.release();
      return res.status(400).json({ error: "Недействительный ID района" });
    }

    const [result] = await connection.execute(
      "UPDATE subdistricts SET name = ?, district_id = ? WHERE id = ?",
      [name, parentRaionId, id]
    );
    if (result.affectedRows === 0) {
      connection.release();
      return res.status(404).json({ error: "Микрорайон не найден" });
    }
    console.log("Микрорайон обновлен, ID:", id);
    connection.release();
    res.json({ id: parseInt(id), name, parentRaionId, isRaion: false });
  } catch (error) {
    console.error("Ошибка обновления микрорайона:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});



// Удаление района
app.delete("/api/raions/:id", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;

  try {
    const connection = await pool.getConnection();
    const [result] = await connection.execute("DELETE FROM districts WHERE id = ?", [id]);
    if (result.affectedRows === 0) {
      connection.release();
      return res.status(404).json({ error: "Район не найден" });
    }
    console.log("Район удален, ID:", id);
    connection.release();
    res.json({ message: "Район успешно удален" });
  } catch (error) {
    console.error("Ошибка удаления района:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Удаление микрорайона
app.delete("/api/subraions/:id", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;

  try {
    const connection = await pool.getConnection();
    const [result] = await connection.execute("DELETE FROM subdistricts WHERE id = ?", [id]);
    if (result.affectedRows === 0) {
      connection.release();
      return res.status(404).json({ error: "Микрорайон не найден" });
    }
    console.log("Микрорайон удален, ID:", id);
    connection.release();
    res.json({ message: "Микрорайон успешно удален" });
  } catch (error) {
    console.error("Ошибка удаления микрорайона:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Эндпоинт для перенаправления объектов недвижимости (защищено, только SUPER_ADMIN)
app.patch("/api/properties/redirect", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });
  }

  const { propertyIds, curator_ids } = req.body;

  if (!Array.isArray(propertyIds) || !curator_ids) {
    console.error("Ошибка: propertyIds должен быть массивом, curator_ids обязателен", { propertyIds, curator_ids });
    return res.status(400).json({ error: "propertyIds должен быть массивом, curator_ids обязателен" });
  }

  try {
    const connection = await pool.getConnection();

    // Проверка существования всех объектов недвижимости
    const [existingProperties] = await connection.execute(
      "SELECT id, curator_ids FROM properties WHERE id IN (?)",
      [propertyIds]
    );
    if (existingProperties.length !== propertyIds.length) {
      const existingIds = existingProperties.map(p => p.id);
      const missingIds = propertyIds.filter(id => !existingIds.includes(id));
      connection.release();
      console.error("Некоторые объекты не найдены:", missingIds);
      return res.status(404).json({ error: "Некоторые объекты недвижимости не найдены" });
    }

    // Обновление curator_ids для всех указанных объектов
    const [result] = await connection.execute(
      "UPDATE properties SET curator_ids = ? WHERE id IN (?)",
      [curator_ids, propertyIds]
    );

    if (result.affectedRows === 0) {
      connection.release();
      return res.status(404).json({ error: "Ни один объект не был обновлен" });
    }

    console.log(`Перенаправлено ${result.affectedRows} объектов недвижимости, новые curator_ids: ${curator_ids}`);
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