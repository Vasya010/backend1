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
    const [users] = await connection.execute("SELECT id, role FROM users1 WHERE id = ?", [decoded.id]);
    connection.release();

    if (users.length === 0) {
      console.error("Ошибка аутентификации: Пользователь не найден");
      return res.status(401).json({ error: "Недействительный токен" });
    }

    req.user = decoded;
    next();
  } catch (error) {
    console.error("Ошибка аутентификации:", error.message);
    res.status(401).json({ error: "Недействительный токен" });
  }
};

// Функция для получения имен кураторов по массиву curator_ids
async function getCuratorNames(curatorIds, connection) {
  if (!curatorIds || curatorIds.trim() === '' || curatorIds === '[]') {
    return ['Не указан'];
  }

  let curatorIdArray;
  try {
    curatorIdArray = JSON.parse(curatorIds);
    if (!Array.isArray(curatorIdArray)) {
      console.warn(`curator_ids не является массивом: ${curatorIds}, преобразование в массив`);
      curatorIdArray = [curatorIds.toString()];
    }
  } catch (error) {
    console.warn(`Ошибка парсинга curator_ids: ${curatorIds}, Ошибка: ${error.message}`);
    curatorIdArray = [curatorIds.toString()];
  }

  // Filter out invalid or non-numeric IDs
  curatorIdArray = curatorIdArray
    .map(id => id.toString())
    .filter(id => id && !isNaN(parseInt(id)));

  if (curatorIdArray.length === 0) {
    console.warn("Нет валидных curator_ids для запроса");
    return ['Не указан'];
  }

  try {
    const [curators] = await connection.execute(
      "SELECT id, CONCAT(first_name, ' ', last_name) AS curator_name FROM users1 WHERE id IN (?)",
      [curatorIdArray]
    );

    const curatorMap = {};
    curators.forEach(c => {
      curatorMap[c.id.toString()] = c.curator_name;
    });

    return curatorIdArray.map(id => curatorMap[id] || 'Неизвестный куратор');
  } catch (error) {
    console.error("Ошибка получения имен кураторов:", error.message, { curatorIds });
    return curatorIdArray.map(() => 'Неизвестный куратор');
  }
}

// Тестирование подключения к базе данных и настройка
async function testDatabaseConnection() {
  let connection;
  try {
    connection = await pool.getConnection();
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
          owner_phone VARCHAR(50) DEFAULT NULL,
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

    // Clean up invalid curator_ids in properties table
    console.log("Проверка и очистка curator_ids в таблице properties...");
    const [invalidCuratorIds] = await connection.execute(
      "SELECT id, curator_ids FROM properties WHERE curator_ids IS NOT NULL AND curator_ids NOT LIKE '[%' AND curator_ids NOT LIKE '%]'"
    );
    if (invalidCuratorIds.length > 0) {
      console.warn("Найдены некорректные curator_ids:", invalidCuratorIds);
      await connection.execute(
        "UPDATE properties SET curator_ids = CONCAT('[\"', curator_ids, '\"]') WHERE curator_ids IS NOT NULL AND curator_ids NOT LIKE '[%' AND curator_ids NOT LIKE '%]'"
      );
      console.log("Некорректные curator_ids преобразованы в JSON-массив");
    }

    const [emptyCuratorIds] = await connection.execute(
      "SELECT id, curator_ids FROM properties WHERE curator_ids = '' OR curator_ids = '[]'"
    );
    if (emptyCuratorIds.length > 0) {
      console.warn("Найдены пустые curator_ids:", emptyCuratorIds);
      await connection.execute(
        "UPDATE properties SET curator_ids = NULL WHERE curator_ids = '' OR curator_ids = '[]'"
      );
      console.log("Пустые curator_ids установлены в NULL");
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
      const token = jwt.sign({ id: 1, role: "SUPER_ADMIN" }, jwtSecret, { expiresIn: "1y" });
      await connection.execute(
        "INSERT INTO users1 (first_name, last_name, email, phone, role, password, token) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ["Админ", "Пользователь", adminEmail, "123456789", "SUPER_ADMIN", hashedPassword, token]
      );
    } else {
      console.log("Администратор существует, обновление пароля и токена...");
      const token = jwt.sign({ id: existingAdmin[0].id, role: "SUPER_ADMIN" }, jwtSecret, { expiresIn: "1y" });
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
  } catch (error) {
    console.error("Ошибка подключения к базе данных:", error.message);
    if (error.code === "ECONNREFUSED") {
      console.error("Сервер MySQL не запущен или неверный хост/порт.");
    }
  } finally {
    if (connection) connection.release();
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

  let connection;
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, first_name, last_name, email, phone, role, password, profile_picture AS photoUrl, token FROM users1 WHERE email = ?",
      [email]
    );
    console.log("Результат запроса к базе данных:", rows.length > 0 ? "Пользователь найден" : "Пользователь не найден");

    if (rows.length === 0) {
      return res.status(401).json({ error: "Неверный email или пользователь не найден" });
    }

    const user = rows[0];
    if (!user.password) {
      console.error("Ошибка: Пароль пользователя не установлен");
      return res.status(500).json({ error: "Пароль пользователя не установлен" });
    }

    console.log("Хэшированный пароль из базы данных:", user.password);
    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log("Результат сравнения пароля:", isPasswordValid);

    if (!isPasswordValid) {
      return res.status(401).json({ error: "Неверный пароль" });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, jwtSecret, { expiresIn: "1y" });
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
    res.json({ message: "Авторизация успешна", user: userResponse, token });
  } catch (error) {
    console.error("Ошибка входа:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Эндпоинт для выхода
app.post("/api/logout", authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    await connection.execute("UPDATE users1 SET token = NULL WHERE id = ?", [req.user.id]);
    console.log("Выход успешен, токен аннулирован для пользователя ID:", req.user.id);
    res.json({ message: "Выход успешен" });
  } catch (error) {
    console.error("Ошибка выхода:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Получение всех пользователей (защищено)
app.get("/api/users", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, first_name, last_name, email, phone, role, profile_picture AS photoUrl FROM users1"
    );
    console.log("Пользователи получены из базы данных:", rows.length);
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
  } finally {
    if (connection) connection.release();
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

  let connection;
  try {
    connection = await pool.getConnection();

    const [existingUser] = await connection.execute("SELECT id FROM users1 WHERE email = ?", [email]);
    if (existingUser.length > 0) {
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
    const token = jwt.sign({ id: userId, role }, jwtSecret, { expiresIn: "1y" });
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

    res.json(newUser);
  } catch (error) {
    console.error("Ошибка создания пользователя:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
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

  let connection;
  try {
    connection = await pool.getConnection();
    const [existingUsers] = await connection.execute("SELECT profile_picture FROM users1 WHERE id = ?", [id]);
    if (existingUsers.length === 0) {
      console.error("Пользователь не найден по ID:", id);
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    const [emailCheck] = await connection.execute("SELECT id FROM users1 WHERE email = ? AND id != ?", [email, id]);
    if (emailCheck.length > 0) {
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

    res.json(updatedUser);
  } catch (error) {
    console.error("Ошибка обновления пользователя:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Удаление пользователя (защищено, только SUPER_ADMIN)
app.delete("/api/users/:id", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;

  let connection;
  try {
    connection = await pool.getConnection();
    const [users] = await connection.execute("SELECT profile_picture FROM users1 WHERE id = ?", [id]);
    if (users.length === 0) {
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
      return res.status(404).json({ error: "Пользователь не найден" });
    }
    console.log("Пользователь удален, ID:", id);

    res.json({ message: "Пользователь успешно удален" });
  } catch (error) {
    console.error("Ошибка удаления пользователя:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Получение всех ЖК (защищено)
app.get("/api/jk", authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute("SELECT id, name FROM jk");
    console.log("ЖК получены:", rows.length);
    res.json(rows);
  } catch (error) {
    console.error("Ошибка получения ЖК:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Создание нового ЖК (защищено, только SUPER_ADMIN)
app.post("/api/jk", authenticate, upload.single("photo"), async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });
  }

  const { name, address, description } = req.body;
  const photo = req.file;

  if (!name || !address) {
    console.error("Ошибка: Не все обязательные поля предоставлены");
    return res.status(400).json({ error: "Поля name и address обязательны" });
  }

  const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
  const photoFilename = photo ? `${uniqueSuffix}${path.extname(photo.originalname)}` : null;

  let connection;
  try {
    connection = await pool.getConnection();

    if (photo) {
      const uploadParams = {
        Bucket: bucketName,
        Key: photoFilename,
        Body: photo.buffer,
        ContentType: photo.mimetype,
      };
      await s3Client.send(new PutObjectCommand(uploadParams));
      console.log(`Фото загружено в S3: ${photoFilename}`);
    }

    const [result] = await connection.execute(
      "INSERT INTO jk (name, address, description, photo) VALUES (?, ?, ?, ?)",
      [name, address, description || null, photoFilename]
    );

    console.log("Создан новый ЖК, ID:", result.insertId);

    const newJk = {
      id: result.insertId,
      name,
      address,
      description,
      photo: photoFilename ? `https://s3.twcstorage.ru/${bucketName}/${photoFilename}` : null,
    };

    res.json(newJk);
  } catch (error) {
    console.error("Ошибка создания ЖК:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Обновление ЖК (защищено, только SUPER_ADMIN)
app.put("/api/jk/:id", authenticate, upload.single("photo"), async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;
  const { name, address, description } = req.body;
  const photo = req.file;

  if (!name || !address) {
    console.error("Ошибка: Не все обязательные поля предоставлены");
    return res.status(400).json({ error: "Поля name и address обязательны" });
  }

  const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
  let photoFilename = null;

  let connection;
  try {
    connection = await pool.getConnection();
    const [existingJk] = await connection.execute("SELECT photo FROM jk WHERE id = ?", [id]);

    if (existingJk.length === 0) {
      console.error("ЖК не найден по ID:", id);
      return res.status(404).json({ error: "ЖК не найден" });
    }

    const existingPhoto = existingJk[0].photo;
    photoFilename = existingPhoto;

    if (photo) {
      photoFilename = `${uniqueSuffix}${path.extname(photo.originalname)}`;
      const uploadParams = {
        Bucket: bucketName,
        Key: photoFilename,
        Body: photo.buffer,
        ContentType: photo.mimetype,
      };
      await s3Client.send(new PutObjectCommand(uploadParams));
      console.log(`Новое фото загружено в S3: ${photoFilename}`);

      if (existingPhoto) {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: existingPhoto }));
        console.log(`Старое фото удалено из S3: ${existingPhoto}`);
      }
    }

    const [result] = await connection.execute(
      "UPDATE jk SET name = ?, address = ?, description = ?, photo = ? WHERE id = ?",
      [name, address, description || null, photoFilename, id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "ЖК не найден" });
    }

    console.log("ЖК обновлен, ID:", id);

    const updatedJk = {
      id: parseInt(id),
      name,
      address,
      description,
      photo: photoFilename ? `https://s3.twcstorage.ru/${bucketName}/${photoFilename}` : null,
    };

    res.json(updatedJk);
  } catch (error) {
    console.error("Ошибка обновления ЖК:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Удаление ЖК (защищено, только SUPER_ADMIN)
app.delete("/api/jk/:id", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;

  let connection;
  try {
    connection = await pool.getConnection();
    const [jk] = await connection.execute("SELECT photo FROM jk WHERE id = ?", [id]);

    if (jk.length === 0) {
      console.error("ЖК не найден по ID:", id);
      return res.status(404).json({ error: "ЖК не найден" });
    }

    const photoFilename = jk[0].photo;
    if (photoFilename) {
      await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: photoFilename }));
      console.log(`Фото удалено из S3: ${photoFilename}`);
    }

    const [result] = await connection.execute("DELETE FROM jk WHERE id = ?", [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "ЖК не найден" });
    }

    console.log("ЖК удален, ID:", id);
    res.json({ message: "ЖК успешно удален" });
  } catch (error) {
    console.error("Ошибка удаления ЖК:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Получение всех районов (защищено)
app.get("/api/districts", authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute("SELECT id, name FROM districts");
    console.log("Районы получены:", rows.length);
    res.json(rows);
  } catch (error) {
    console.error("Ошибка получения районов:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Получение микрорайонов по district_id (защищено)
app.get("/api/subdistricts", authenticate, async (req, res) => {
  const { district_id } = req.query;
  let connection;
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute(
      "SELECT id, name FROM subdistricts WHERE district_id = ?",
      [district_id]
    );
    console.log("Микрорайоны получены:", rows.length);
    res.json(rows);
  } catch (error) {
    console.error("Ошибка получения микрорайонов:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Создание нового объекта недвижимости (защищено, SUPER_ADMIN или USER)
app.post("/api/properties", authenticate, upload.fields([
  { name: "photos", maxCount: 10 },
  { name: "document", maxCount: 1 },
]), async (req, res) => {
  if (!["SUPER_ADMIN", "USER"].includes(req.user.role)) {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN или USER");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN или USER" });
  }

  const { type_id, condition, series, zhk_id, owner_name, curator_ids, price, unit, rukprice, mkv, room, owner_phone, district_id, subdistrict_id, address, notes, description, status, owner_id, etaj, etajnost } = req.body;
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

  let finalCuratorIds = null;
  if (req.user.role === "USER") {
    finalCuratorIds = JSON.stringify([req.user.id.toString()]);
    console.log("Риелтор: установка curator_ids на текущего пользователя", finalCuratorIds);
  } else if (curator_ids) {
    try {
      const parsedCurators = JSON.parse(curator_ids);
      if (!Array.isArray(parsedCurators)) {
        console.error("Ошибка: curator_ids должен быть массивом", { curator_ids });
        return res.status(400).json({ error: "curator_ids должен быть корректным JSON-массивом" });
      }
      // Validate curator IDs exist and have USER role
      const connection = await pool.getConnection();
      const [curatorCheck] = await connection.execute(
        "SELECT id FROM users1 WHERE id IN (?) AND role = 'USER'",
        [parsedCurators.map(id => id.toString())]
      );
      if (curatorCheck.length !== parsedCurators.length) {
        connection.release();
        console.error("Ошибка: Один или несколько кураторов не найдены или не являются пользователями", { curator_ids });
        return res.status(400).json({ error: "Один или несколько кураторов не найдены или не являются пользователями" });
      }
      finalCuratorIds = JSON.stringify(parsedCurators.map(id => id.toString()));
      connection.release();
    } catch (error) {
      console.error("Ошибка парсинга curator_ids:", error.message, { curator_ids });
      return res.status(400).json({ error: "curator_ids должен быть корректным JSON-массивом" });
    }
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
      const [subdistrictCheck] = await connection.execute("SELECT id FROM subdistricts WHERE id = ? AND district_id = ?", [subdistrict_id, district_id || null]);
      if (subdistrictCheck.length === 0) {
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
        type_id, \`condition\`, series, zhk_id, document_id, owner_name, curator_ids, price, unit, rukprice, mkv, room, owner_phone, 
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
        owner_phone || null,
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

    const curatorNames = await getCuratorNames(finalCuratorIds, connection);
    console.log("Создан новый объект недвижимости, ID:", result.insertId, "Кураторы:", curatorNames);

    const newProperty = {
      id: result.insertId,
      type_id,
      condition,
      series,
      zhk_id,
      document_id: 0,
      owner_name,
      curator_ids: finalCuratorIds ? JSON.parse(finalCuratorIds) : [],
      curator_name: curatorNames.join(", "),
      price,
      unit,
      rukprice,
      mkv,
      room,
      owner_phone,
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

    res.json(newProperty);
  } catch (error) {
    console.error("Ошибка создания объекта недвижимости:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Обновление объекта недвижимости (защищено, SUPER_ADMIN или USER)
app.put("/api/properties/:id", authenticate, upload.fields([
  { name: "photos", maxCount: 10 },
  { name: "document", maxCount: 1 },
]), async (req, res) => {
  if (!["SUPER_ADMIN", "USER"].includes(req.user.role)) {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN или USER");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN или USER" });
  }

  const { id } = req.params;
  const { type_id, condition, series, zhk_id, owner_name, curator_ids, price, unit, rukprice, mkv, room, owner_phone, district_id, subdistrict_id, address, notes, description, status, owner_id, etaj, etajnost, existingPhotos } = req.body;
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

  console.log("Входные данные для обновления объекта недвижимости:", {
    id, type_id, condition, series, zhk_id, owner_name, curator_ids, price, unit, rukprice, mkv, room, owner_phone, district_id, subdistrict_id, address, notes, description, status, owner_id, etaj, etajnost, existingPhotos, hasNewPhotos: photos.length > 0, hasDocument: !!document
  });

  if (!type_id || !price || !rukprice || !mkv || !address || !etaj || !etajnost) {
    console.error("Ошибка: Не все обязательные поля предоставлены", { type_id, price, rukprice, mkv, address, etaj, etajnost });
    return res.status(400).json({ error: "Все обязательные поля (type_id, price, rukprice, mkv, address, etaj, etajnost) должны быть предоставлены" });
  }

  if (isNaN(parseFloat(price)) || isNaN(parseFloat(rukprice)) || isNaN(parseFloat(mkv)) || isNaN(parseInt(etaj)) || isNaN(parseInt(etajnost))) {
    console.error("Ошибка: Числовые поля некорректны", { price, rukprice, mkv, etaj, etajnost });
    return res.status(400).json({ error: "Поля price, rukprice, mkv, etaj, etajnost должны быть числовыми" });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    const [existingProperties] = await connection.execute("SELECT photos, document, curator_ids, created_at FROM properties WHERE id = ?", [id]);
    if (existingProperties.length === 0) {
      console.error("Объект недвижимости не найден по ID:", id);
      return res.status(404).json({ error: "Объект недвижимости не найден" });
    }

    const existingProperty = existingProperties[0];
    if (req.user.role === "USER") {
      let currentCuratorIds;
      try {
        currentCuratorIds = JSON.parse(existingProperty.curator_ids);
        if (!Array.isArray(currentCuratorIds)) {
          currentCuratorIds = [existingProperty.curator_ids];
        }
      } catch (error) {
        currentCuratorIds = [existingProperty.curator_ids];
      }
      if (!currentCuratorIds.includes(req.user.id.toString())) {
        console.error("Ошибка: Риелтор не является куратором этого объекта", { id, curator_ids: existingProperty.curator_ids, userId: req.user.id });
        return res.status(403).json({ error: "У вас нет прав для редактирования этого объекта" });
      }
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
      const [subdistrictCheck] = await connection.execute("SELECT id FROM subdistricts WHERE id = ? AND district_id = ?", [subdistrict_id, district_id || null]);
      if (subdistrictCheck.length === 0) {
        return res.status(400).json({ error: "Недействительный ID микрорайона или микрорайон не принадлежит выбранному району" });
      }
    }

    let finalCuratorIds = existingProperty.curator_ids;
    if (req.user.role === "SUPER_ADMIN" && curator_ids) {
      try {
        const parsedCurators = JSON.parse(curator_ids);
        if (!Array.isArray(parsedCurators)) {
          console.error("Ошибка: curator_ids должен быть массивом", { curator_ids });
          return res.status(400).json({ error: "curator_ids должен быть корректным JSON-массивом" });
        }
        // Validate curator IDs exist and have USER role
        const [curatorCheck] = await connection.execute(
          "SELECT id FROM users1 WHERE id IN (?) AND role = 'USER'",
          [parsedCurators.map(id => id.toString())]
        );
        if (curatorCheck.length !== parsedCurators.length) {
          console.error("Ошибка: Один или несколько кураторов не найдены или не являются пользователями", { curator_ids });
          return res.status(400).json({ error: "Один или несколько кураторов не найдены или не являются пользователями" });
        }
        finalCuratorIds = JSON.stringify(parsedCurators.map(id => id.toString()));
      } catch (error) {
        console.error("Ошибка парсинга curator_ids:", error.message, { curator_ids });
        return res.status(400).json({ error: "curator_ids должен быть корректным JSON-массивом" });
      }
    } else if (req.user.role === "USER") {
      finalCuratorIds = JSON.stringify([req.user.id.toString()]);
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

    const photosToDelete = photoFiles.filter(p => !existingPhotosList.includes(p));
    for (const oldPhoto of photosToDelete) {
      try {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: oldPhoto }));
        console.log(`Старое изображение удалено из S3: ${oldPhoto}`);
      } catch (error) {
        console.warn(`Не удалось удалить старое изображение из S3: ${oldPhoto}, Ошибка: ${error.message}`);
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
        type_id = ?, \`condition\` = ?, series = ?, zhk_id = ?, document_id = ?, owner_name = ?, curator_ids = ?, price = ?, unit = ?, rukprice = ?, mkv = ?, room = ?, owner_phone = ?,
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
        owner_phone || null,
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
      return res.status(404).json({ error: "Объект недвижимости не найден" });
    }

    const curatorNames = await getCuratorNames(finalCuratorIds, connection);
    console.log("Объект недвижимости обновлен, ID:", id, "Кураторы:", curatorNames);

    const updatedProperty = {
      id: parseInt(id),
      type_id,
      condition,
      series,
      zhk_id,
      document_id: 0,
      owner_name,
      curator_ids: finalCuratorIds ? JSON.parse(finalCuratorIds) : [],
      curator_name: curatorNames.join(", "),
      price,
      unit,
      rukprice,
      mkv,
      room,
      owner_phone,
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
      date: new Date(existingProperty.created_at).toLocaleDateString("ru-RU"),
      time: new Date(existingProperty.created_at).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" }),
    };

    res.json(updatedProperty);
  } catch (error) {
    console.error("Ошибка обновления объекта недвижимости:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Удаление объекта недвижимости (защищено, SUPER_ADMIN или USER)
app.delete("/api/properties/:id", authenticate, async (req, res) => {
  if (!["SUPER_ADMIN", "USER"].includes(req.user.role)) {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN или USER");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN или USER" });
  }

  const { id } = req.params;

  let connection;
  try {
    connection = await pool.getConnection();
    const [properties] = await connection.execute("SELECT photos, document, curator_ids FROM properties WHERE id = ?", [id]);
    if (properties.length === 0) {
      console.error("Объект недвижимости не найден по ID:", id);
      return res.status(404).json({ error: "Объект недвижимости не найден" });
    }

    const existingProperty = properties[0];
    if (req.user.role === "USER") {
      let currentCuratorIds;
      try {
        currentCuratorIds = JSON.parse(existingProperty.curator_ids);
        if (!Array.isArray(currentCuratorIds)) {
          currentCuratorIds = [existingProperty.curator_ids];
        }
      } catch (error) {
        currentCuratorIds = [existingProperty.curator_ids];
      }
      if (!currentCuratorIds.includes(req.user.id.toString())) {
        console.error("Ошибка: Риелтор не является куратором этого объекта", { id, curator_ids: existingProperty.curator_ids, userId: req.user.id });
        return res.status(403).json({ error: "У вас нет прав для удаления этого объекта" });
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
      return res.status(404).json({ error: "Объект недвижимости не найден" });
    }
    console.log("Объект недвижимости удален, ID:", id);

    res.json({ message: "Объект недвижимости успешно удален" });
  } catch (error) {
    console.error("Ошибка удаления объекта недвижимости:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Получение всех объектов недвижимости (защищено)
app.get("/api/properties", authenticate, async (req, res) => {
  const { curator_ids } = req.query;

  let curatorIdArray = null;
  if (curator_ids) {
    try {
      // Handle cases where curator_ids is not a valid JSON string
      if (typeof curator_ids !== 'string' || curator_ids.trim() === '') {
        console.error("Ошибка: curator_ids должен быть непустой строкой JSON", { curator_ids });
        return res.status(400).json({ error: "curator_ids должен быть корректным JSON-массивом" });
      }
      curatorIdArray = JSON.parse(curator_ids);
      if (!Array.isArray(curatorIdArray)) {
        console.error("Ошибка: curator_ids должен быть массивом", { curator_ids });
        return res.status(400).json({ error: "curator_ids должен быть корректным JSON-массивом" });
      }
      // Convert to strings and validate IDs
      curatorIdArray = curatorIdArray
        .map(id => id.toString())
        .filter(id => id && !isNaN(parseInt(id)));
      if (curatorIdArray.length === 0) {
        console.error("Ошибка: curator_ids содержит только невалидные ID", { curator_ids });
        return res.status(400).json({ error: "curator_ids должен содержать валидные числовые ID" });
      }
    } catch (error) {
      console.error("Ошибка парсинга curator_ids:", error.message, { curator_ids });
      return res.status(400).json({ error: "curator_ids должен быть корректным JSON-массивом" });
    }
  }

  let connection;
  try {
    connection = await pool.getConnection();
    let query = `SELECT p.* FROM properties p`;
    let queryParams = [];

    if (req.user.role === "USER" && !curatorIdArray) {
      // For USER role, default to filtering by their own ID if no curator_ids provided
      query += ` WHERE JSON_CONTAINS(p.curator_ids, ?)`; // Use JSON_CONTAINS for JSON array
      queryParams.push(JSON.stringify([req.user.id.toString()]));
    } else if (curatorIdArray) {
      // Filter by provided curator_ids
      query += ` WHERE JSON_CONTAINS(p.curator_ids, ?)`; // Use JSON_CONTAINS for JSON array
      queryParams.push(JSON.stringify(curatorIdArray));
    }

    console.log("Executing query:", query, "with params:", queryParams);

    const [rows] = await connection.execute(query, queryParams);
    console.log("Объекты недвижимости получены из базы данных:", rows.length);

    const properties = await Promise.all(rows.map(async (row) => {
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

      let curatorNames = ['Не указан'];
      let parsedCuratorIds = [];
      try {
        if (row.curator_ids) {
          parsedCuratorIds = JSON.parse(row.curator_ids);
          if (!Array.isArray(parsedCuratorIds)) {
            console.warn(`curator_ids не является массивом для ID: ${row.id}, данные: ${row.curator_ids}`);
            parsedCuratorIds = [row.curator_ids.toString()];
          }
          curatorNames = await getCuratorNames(row.curator_ids, connection);
        }
      } catch (error) {
        console.warn(`Ошибка парсинга curator_ids для ID: ${row.id}, Ошибка: ${error.message}, Данные: ${row.curator_ids}`);
        parsedCuratorIds = [row.curator_ids ? row.curator_ids.toString() : ''];
      }

      return {
        ...row,
        owner_phone: row.owner_phone,
        photos: parsedPhotos.map((img) => `https://s3.twcstorage.ru/${bucketName}/${img}`),
        document: row.document ? `https://s3.twcstorage.ru/${bucketName}/${row.document}` : null,
        date: new Date(row.created_at).toLocaleDateString("ru-RU"),
        time: new Date(row.created_at).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" }),
        curator_name: curatorNames.join(", "),
        curator_ids: parsedCuratorIds, // Return as array
      };
    }));

    res.json(properties);
  } catch (error) {
    console.error("Ошибка получения объектов недвижимости:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Получение всех объявлений для AdminDashboard (защищено)
app.get("/api/listings", authenticate, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
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

    res.json(listings);
  } catch (error) {
    console.error("Ошибка получения объявлений:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Получение всех районов и микрорайонов
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
    
    console.log("Районы и микрорайоны получены:", raions.length);
    res.json(raions);
  } catch (error) {
    console.error("Ошибка получения районов и микрорайонов:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
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

  let connection;
  try {
    connection = await pool.getConnection();
    const [result] = await connection.execute(
      "INSERT INTO districts (name) VALUES (?)",
      [name]
    );
    console.log("Создан новый район, ID:", result.insertId);
    res.json({ id: result.insertId, name, parentRaionId: null, isRaion: true });
  } catch (error) {
    console.error("Ошибка создания района:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
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

  let connection;
  try {
    connection = await pool.getConnection();
    const [districtCheck] = await connection.execute("SELECT id FROM districts WHERE id = ?", [parentRaionId]);
    if (districtCheck.length === 0) {
      return res.status(400).json({ error: "Недействительный ID района" });
    }

    const [result] = await connection.execute(
      "INSERT INTO subdistricts (name, district_id) VALUES (?, ?)",
      [name, parentRaionId]
    );
    console.log("Создан новый микрорайон, ID:", result.insertId);
    res.json({ id: result.insertId, name, parentRaionId, isRaion: false });
  } catch (error) {
    console.error("Ошибка создания микрорайона:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

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

  let connection;
  try {
    connection = await pool.getConnection();
    const [result] = await connection.execute(
      "UPDATE districts SET name = ? WHERE id = ?",
      [name, id]
    );
    if (result.affectedRows === 0) {
      console.error("Район не найден по ID:", id);
      return res.status(404).json({ error: "Район не найден" });
    }
    console.log("Район обновлен, ID:", id);
    res.json({ id: parseInt(id), name, parentRaionId: null, isRaion: true });
  } catch (error) {
    console.error("Ошибка обновления района:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
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

  let connection;
  try {
    connection = await pool.getConnection();
    const [districtCheck] = await connection.execute("SELECT id FROM districts WHERE id = ?", [parentRaionId]);
    if (districtCheck.length === 0) {
      console.error("Недействительный ID района:", parentRaionId);
      return res.status(400).json({ error: "Недействительный ID района" });
    }

    const [result] = await connection.execute(
      "UPDATE subdistricts SET name = ?, district_id = ? WHERE id = ?",
      [name, parentRaionId, id]
    );
    if (result.affectedRows === 0) {
      console.error("Микрорайон не найден по ID:", id);
      return res.status(404).json({ error: "Микрорайон не найден" });
    }
    console.log("Микрорайон обновлен, ID:", id);
    res.json({ id: parseInt(id), name, parentRaionId, isRaion: false });
  } catch (error) {
    console.error("Ошибка обновления микрорайона:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Удаление района
app.delete("/api/raions/:id", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;

  let connection;
  try {
    connection = await pool.getConnection();
    const [subdistrictCheck] = await connection.execute("SELECT id FROM subdistricts WHERE district_id = ?", [id]);
    if (subdistrictCheck.length > 0) {
      console.error("Нельзя удалить район, так как он содержит микрорайоны");
      return res.status(400).json({ error: "Нельзя удалить район, так как он содержит микрорайоны" });
    }

    const [result] = await connection.execute("DELETE FROM districts WHERE id = ?", [id]);
    if (result.affectedRows === 0) {
      console.error("Район не найден по ID:", id);
      return res.status(404).json({ error: "Район не найден" });
    }
    console.log("Район удален, ID:", id);
    res.json({ message: "Район успешно удален" });
  } catch (error) {
    console.error("Ошибка удаления района:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Удаление микрорайона
app.delete("/api/subraions/:id", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;

  let connection;
  try {
    connection = await pool.getConnection();
    const [result] = await connection.execute("DELETE FROM subdistricts WHERE id = ?", [id]);
    if (result.affectedRows === 0) {
      console.error("Микрорайон не найден по ID:", id);
      return res.status(404).json({ error: "Микрорайон не найден" });
    }
    console.log("Микрорайон удален, ID:", id);
    res.json({ message: "Микрорайон успешно удален" });
  } catch (error) {
    console.error("Ошибка удаления микрорайона:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Частичное обновление объекта недвижимости (защищено, SUPER_ADMIN или USER)
app.patch("/api/properties/:id", authenticate, upload.fields([
  { name: "photos", maxCount: 10 },
  { name: "document", maxCount: 1 },
]), async (req, res) => {
  if (!["SUPER_ADMIN", "USER"].includes(req.user.role)) {
    console.error("Доступ запрещен: Требуется роль SUPER_ADMIN или USER");
    return res.status(403).json({ error: "Доступ запрещен: Требуется роль SUPER_ADMIN или USER" });
  }

  const { id } = req.params;
  const fields = req.body;
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

  console.log("Входные данные для частичного обновления объекта недвижимости:", {
    id, fields, hasNewPhotos: photos.length > 0, hasDocument: !!document
  });

  let connection;
  try {
    connection = await pool.getConnection();
    const [existingProperties] = await connection.execute("SELECT photos, document, curator_ids, created_at FROM properties WHERE id = ?", [id]);
    if (existingProperties.length === 0) {
      console.error("Объект недвижимости не найден по ID:", id);
      return res.status(404).json({ error: "Объект недвижимости не найден" });
    }

    const existingProperty = existingProperties[0];
    if (req.user.role === "USER") {
      let currentCuratorIds;
      try {
        currentCuratorIds = JSON.parse(existingProperty.curator_ids);
        if (!Array.isArray(currentCuratorIds)) {
          currentCuratorIds = [existingProperty.curator_ids];
        }
      } catch (error) {
        currentCuratorIds = [existingProperty.curator_ids];
      }
      if (!currentCuratorIds.includes(req.user.id.toString())) {
        console.error("Ошибка: Риелтор не является куратором этого объекта", { id, curator_ids: existingProperty.curator_ids, userId: req.user.id });
        return res.status(403).json({ error: "У вас нет прав для редактирования этого объекта" });
      }
    }

    // Проверки валидности данных
    if (fields.zhk_id) {
      const [jkCheck] = await connection.execute("SELECT id FROM jk WHERE id = ?", [fields.zhk_id]);
      if (jkCheck.length === 0) {
        return res.status(400).json({ error: "Недействительный ID ЖК" });
      }
    }

    if (fields.district_id) {
      const [districtCheck] = await connection.execute("SELECT id FROM districts WHERE id = ?", [fields.district_id]);
      if (districtCheck.length === 0) {
        return res.status(400).json({ error: "Недействительный ID района" });
      }
    }

    if (fields.subdistrict_id) {
      const [subdistrictCheck] = await connection.execute("SELECT id FROM subdistricts WHERE id = ? AND district_id = ?", [fields.subdistrict_id, fields.district_id || existingProperty.district_id || null]);
      if (subdistrictCheck.length === 0) {
        return res.status(400).json({ error: "Недействительный ID микрорайона или микрорайон не принадлежит выбранному району" });
      }
    }

    if (fields.curator_ids && req.user.role === "SUPER_ADMIN") {
      try {
        const parsedCurators = JSON.parse(fields.curator_ids);
        if (!Array.isArray(parsedCurators)) {
          console.error("Ошибка: curator_ids должен быть массивом", { curator_ids: fields.curator_ids });
          return res.status(400).json({ error: "curator_ids должен быть корректным JSON-массивом" });
        }
        const [curatorCheck] = await connection.execute(
          "SELECT id FROM users1 WHERE id IN (?) AND role = 'USER'",
          [parsedCurators.map(id => id.toString())]
        );
        if (curatorCheck.length !== parsedCurators.length) {
          console.error("Ошибка: Один или несколько кураторов не найдены или не являются пользователями", { curator_ids: fields.curator_ids });
          return res.status(400).json({ error: "Один или несколько кураторов не найдены или не являются пользователями" });
        }
        fields.curator_ids = JSON.stringify(parsedCurators.map(id => id.toString()));
      } catch (error) {
        console.error("Ошибка парсинга curator_ids:", error.message, { curator_ids: fields.curator_ids });
        return res.status(400).json({ error: "curator_ids должен быть корректным JSON-массивом" });
      }
    } else if (req.user.role === "USER") {
      fields.curator_ids = JSON.stringify([req.user.id.toString()]);
    }

    // Проверка числовых полей
    if (fields.price && isNaN(parseFloat(fields.price))) {
      return res.status(400).json({ error: "Поле price должно быть числовым" });
    }
    if (fields.rukprice && isNaN(parseFloat(fields.rukprice))) {
      return res.status(400).json({ error: "Поле rukprice должно быть числовым" });
    }
    if (fields.mkv && isNaN(parseFloat(fields.mkv))) {
      return res.status(400).json({ error: "Поле mkv должно быть числовым" });
    }
    if (fields.etaj && isNaN(parseInt(fields.etaj))) {
      return res.status(400).json({ error: "Поле etaj должно быть числовым" });
    }
    if (fields.etajnost && isNaN(parseInt(fields.etajnost))) {
      return res.status(400).json({ error: "Поле etajnost должно быть числовым" });
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

    let existingPhotosList = [];
    if (fields.existingPhotos) {
      try {
        existingPhotosList = JSON.parse(fields.existingPhotos);
        if (!Array.isArray(existingPhotosList)) {
          console.warn(`existingPhotos не является массивом для ID: ${id}, данные: ${fields.existingPhotos}`);
          existingPhotosList = [];
        }
      } catch (error) {
        console.warn(`Ошибка парсинга existingPhotos для ID: ${id}, Ошибка: ${error.message}, Данные: ${fields.existingPhotos}`);
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
      console.log(`Новое изображение загружено в S3: ${photo.filename}`);
    }

    const photosToDelete = photoFiles.filter(p => !existingPhotosList.includes(p));
    for (const oldPhoto of photosToDelete) {
      try {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: oldPhoto }));
        console.log(`Старое изображение удалено из S3: ${oldPhoto}`);
      } catch (error) {
        console.warn(`Не удалось удалить старое изображение из S3: ${oldPhoto}, Ошибка: ${error.message}`);
      }
    }

    let newPhotos = photoFiles;
    if (fields.existingPhotos || photos.length > 0) {
      newPhotos = [...existingPhotosList, ...photos.map(img => img.filename)];
      fields.photos = newPhotos.length > 0 ? JSON.stringify(newPhotos) : null;
    }

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
      fields.document = newDocument;
    }

    const allowedFields = [
      "type_id", "condition", "series", "zhk_id", "owner_name", "curator_ids", "price", "unit", "rukprice", 
      "mkv", "room", "owner_phone", "district_id", "subdistrict_id", "address", "notes", "description", 
      "status", "owner_id", "etaj", "etajnost", "photos", "document"
    ];
    const updateFields = {};
    allowedFields.forEach(field => {
      if (fields[field] !== undefined) {
        updateFields[field] = fields[field];
      }
    });

    if (Object.keys(updateFields).length === 0) {
      console.error("Нет полей для обновления");
      return res.status(400).json({ error: "Не предоставлены поля для обновления" });
    }

    const query = `UPDATE properties SET ${Object.keys(updateFields).map(field => `\`${field}\` = ?`).join(", ")} WHERE id = ?`;
    const values = [...Object.values(updateFields), id];

    const [result] = await connection.execute(query, values);
    if (result.affectedRows === 0) {
      console.error("Объект недвижимости не найден по ID:", id);
      return res.status(404).json({ error: "Объект недвижимости не найден" });
    }

    const curatorNames = await getCuratorNames(updateFields.curator_ids || existingProperty.curator_ids, connection);
    console.log("Объект недвижимости частично обновлен, ID:", id, "Кураторы:", curatorNames);

    const [updatedProperty] = await connection.execute("SELECT * FROM properties WHERE id = ?", [id]);
    const curatorIds = updatedProperty[0].curator_ids ? JSON.parse(updatedProperty[0].curator_ids) : [];

    res.json({
      id: parseInt(id),
      ...updatedProperty[0],
      curator_ids: curatorIds,
      curator_name: curatorNames.join(", "),
      photos: newPhotos.map(img => `https://s3.twcstorage.ru/${bucketName}/${img}`),
      document: newDocument ? `https://s3.twcstorage.ru/${bucketName}/${newDocument}` : null,
      date: new Date(updatedProperty[0].created_at).toLocaleDateString("ru-RU"),
      time: new Date(updatedProperty[0].created_at).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" }),
    });
  } catch (error) {
    console.error("Ошибка частичного обновления объекта недвижимости:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Получение объекта недвижимости по ID (защищено)
app.get("/api/properties/:id", authenticate, async (req, res) => {
  const { id } = req.params;

  let connection;
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute("SELECT * FROM properties WHERE id = ?", [id]);
    if (rows.length === 0) {
      console.error("Объект недвижимости не найден по ID:", id);
      return res.status(404).json({ error: "Объект недвижимости не найден" });
    }

    const property = rows[0];
    if (req.user.role === "USER") {
      let currentCuratorIds;
      try {
        currentCuratorIds = JSON.parse(property.curator_ids);
        if (!Array.isArray(currentCuratorIds)) {
          currentCuratorIds = [property.curator_ids];
        }
      } catch (error) {
        currentCuratorIds = [property.curator_ids];
      }
      if (!currentCuratorIds.includes(req.user.id.toString())) {
        console.error("Ошибка: Риелтор не является куратором этого объекта", { id, curator_ids: property.curator_ids, userId: req.user.id });
        return res.status(403).json({ error: "У вас нет прав для просмотра этого объекта" });
      }
    }

    let parsedPhotos = [];
    if (property.photos) {
      try {
        parsedPhotos = JSON.parse(property.photos);
        if (!Array.isArray(parsedPhotos)) {
          console.warn(`Поле photos не является массивом для ID: ${id}, данные: ${property.photos}`);
          parsedPhotos = property.photos.split(",").filter(p => p.trim());
        }
      } catch (error) {
        console.warn(`Ошибка парсинга photos для ID: ${id}, Ошибка: ${error.message}, Данные: ${property.photos}`);
        parsedPhotos = property.photos.split(",").filter(p => p.trim());
      }
    }

    let curatorNames = ['Не указан'];
    let parsedCuratorIds = [];
    try {
      if (property.curator_ids) {
        parsedCuratorIds = JSON.parse(property.curator_ids);
        if (!Array.isArray(parsedCuratorIds)) {
          console.warn(`curator_ids не является массивом для ID: ${id}, данные: ${property.curator_ids}`);
          parsedCuratorIds = [property.curator_ids.toString()];
        }
        curatorNames = await getCuratorNames(property.curator_ids, connection);
      }
    } catch (error) {
      console.warn(`Ошибка парсинга curator_ids для ID: ${id}, Ошибка: ${error.message}, Данные: ${property.curator_ids}`);
      parsedCuratorIds = [property.curator_ids ? property.curator_ids.toString() : ''];
    }

    const response = {
      ...property,
      curator_ids: parsedCuratorIds,
      curator_name: curatorNames.join(", "),
      photos: parsedPhotos.map(img => `https://s3.twcstorage.ru/${bucketName}/${img}`),
      document: property.document ? `https://s3.twcstorage.ru/${bucketName}/${property.document}` : null,
      date: new Date(property.created_at).toLocaleDateString("ru-RU"),
      time: new Date(property.created_at).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" }),
    };

    console.log("Объект недвижимости получен, ID:", id);
    res.json(response);
  } catch (error) {
    console.error("Ошибка получения объекта недвижимости:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Редирект для внешних ссылок
app.get("/api/properties/redirect", async (req, res) => {
  const { id } = req.query;
  if (!id) {
    console.error("Ошибка: Параметр id обязателен");
    return res.status(400).json({ error: "Параметр id обязателен" });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute("SELECT photos, address FROM properties WHERE id = ?", [id]);
    if (rows.length === 0) {
      console.error("Объект недвижимости не найден по ID:", id);
      return res.status(404).json({ error: "Объект недвижимости не найден" });
    }

    const property = rows[0];
    let parsedPhotos = [];
    if (property.photos) {
      try {
        parsedPhotos = JSON.parse(property.photos);
        if (!Array.isArray(parsedPhotos)) {
          console.warn(`Поле photos не является массивом для ID: ${id}, данные: ${property.photos}`);
          parsedPhotos = property.photos.split(",").filter(p => p.trim());
        }
      } catch (error) {
        console.warn(`Ошибка парсинга photos для ID: ${id}, Ошибка: ${error.message}, Данные: ${property.photos}`);
        parsedPhotos = property.photos.split(",").filter(p => p.trim());
      }
    }

    const firstPhoto = parsedPhotos.length > 0 ? `https://s3.twcstorage.ru/${bucketName}/${parsedPhotos[0]}` : null;
    const redirectUrl = `${publicDomain}/#/main/listing/${id}`;
    
    res.json({
      url: redirectUrl,
      image: firstPhoto,
      address: property.address,
    });
  } catch (error) {
    console.error("Ошибка редиректа:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  } finally {
    if (connection) connection.release();
  }
});

// Запуск сервера
app.listen(port, () => {
  console.log(`Сервер запущен на порту ${port}`);
});