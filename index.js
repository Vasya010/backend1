const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const { S3Client, PutObjectCommand, DeleteObjectCommand } = require("@aws-sdk/client-s3");
const path = require("path");

const app = express();
const port = 5000;
const publicDomain = "https://vasya010-backend1-10db.twc1.net";
const jwtSecret = "your_jwt_secret_123";

// Конфигурация S3
const s3Client = new S3Client({
  region: "ru-1",
  endpoint: "https://s3.twcstorage.ru",
  credentials: {
    accessKeyId: "GIMZKRMOGP4F0MOTLVCE",
    secretAccessKey: "WvhFfIzzCkITUrXfD8JfoDne7LmBhnNzDuDBj89I",
  },
  forcePathStyle: true,
});

const bucketName = "a2c31109-3cf2c97b-aca1-42b0-a822-3e0ade279447";

// Middleware
app.use(cors());
app.use(express.json());

// Конфигурация Multer для хранения в памяти
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
    console.error(`Файл ${file.originalname} отклонён: недопустимый тип`);
    cb(new Error("Разрешены только изображения (jpeg, jpg, png) и документы (pdf, doc, docx)"));
  },
});

// Middleware для аутентификации JWT
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    console.error("Ошибка аутентификации: токен отсутствует");
    return res.status(401).json({ error: "Токен отсутствует" });
  }
  try {
    const decoded = jwt.verify(token, jwtSecret);
    console.log("Токен успешно проверен:", decoded);

    // Проверяем токен в базе данных
    const connection = await mysql.createConnection(dbConfig);
    const [users] = await connection.execute("SELECT id, role FROM users1 WHERE id = ? AND token = ?", [decoded.id, token]);
    await connection.end();

    if (users.length === 0) {
      console.error("Ошибка аутентификации: токен не найден в базе данных");
      return res.status(401).json({ error: "Неверный токен" });
    }

    req.user = decoded;
    next();
  } catch (error) {
    console.error("Ошибка аутентификации: неверный токен", error.message);
    res.status(401).json({ error: "Неверный токен" });
  }
};

// Конфигурация подключения к БД
const dbConfig = {
  host: "vh452.timeweb.ru",
  user: "cs51703_kgadmin",
  password: "Vasya11091109",
  database: "cs51703_kgadmin",
  port: 3306,
};

// Тестирование подключения к БД и создание/обновление админа
async function testDatabaseConnection() {
  try {
    const connection = await mysql.createConnection(dbConfig);
    console.log("Подключение к базе данных успешно установлено!");

    // Создание таблицы users1, если не существует
    const [tables] = await connection.execute("SHOW TABLES LIKE 'users1'");
    if (tables.length === 0) {
      console.log("Таблица users1 не существует, создаём...");
      await connection.execute(`
        CREATE TABLE users1 (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          first_name VARCHAR(255) NOT NULL,
          last_name VARCHAR(255) NOT NULL,
          role VARCHAR(50) NOT NULL,
          email VARCHAR(255) NOT NULL,
          phone VARCHAR(255) NOT NULL,
          profile_picture VARCHAR(255) DEFAULT NULL,
          password VARCHAR(255) NOT NULL,
          token TEXT DEFAULT NULL
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci
      `);
    } else {
      // Проверяем, существует ли столбец token
      const [columns] = await connection.execute("SHOW COLUMNS FROM users1 LIKE 'token'");
      if (columns.length === 0) {
        console.log("Столбец token не существует, добавляем...");
        await connection.execute("ALTER TABLE users1 ADD token TEXT DEFAULT NULL");
      }
    }

    // Создание таблицы properties, если не существует
    const [propTables] = await connection.execute("SHOW TABLES LIKE 'properties'");
    if (propTables.length === 0) {
      console.log("Таблица properties не существует, создаём...");
      await connection.execute(`
        CREATE TABLE properties (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          type_id VARCHAR(255) DEFAULT NULL,
          condition VARCHAR(255) DEFAULT NULL,
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

    // Проверка существования админа и обновление/создание
    const adminEmail = "admin@example.com";
    const adminPassword = "admin123";
    const hashedPassword = await bcrypt.hash(adminPassword, 10);
    console.log("Хешированный пароль для администратора:", hashedPassword);

    const [existingAdmin] = await connection.execute(
      "SELECT id FROM users1 WHERE email = ?",
      [adminEmail]
    );

    if (existingAdmin.length === 0) {
      console.log("Администратор не существует, создаём...");
      const token = jwt.sign({ id: 1, role: "SUPER_ADMIN" }, jwtSecret, { expiresIn: "1h" });
      await connection.execute(
        "INSERT INTO users1 (first_name, last_name, email, phone, role, password, token) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ["Admin", "User", adminEmail, "123456789", "SUPER_ADMIN", hashedPassword, token]
      );
    } else {
      console.log("Администратор существует, обновляем пароль и токен...");
      const token = jwt.sign({ id: existingAdmin[0].id, role: "SUPER_ADMIN" }, jwtSecret, { expiresIn: "1h" });
      await connection.execute(
        "UPDATE users1 SET password = ?, token = ? WHERE email = ?",
        [hashedPassword, token, adminEmail]
      );
    }

    console.log("Данные для входа администратора:");
    console.log(`Email: ${adminEmail}`);
    console.log(`Пароль: ${adminPassword}`);
    console.log("Роль: SUPER_ADMIN");

    // Тест БД
    const [rows] = await connection.execute("SELECT 1 AS test");
    if (rows.length > 0) {
      console.log("База данных работает корректно!");
      const [tablesList] = await connection.execute("SHOW TABLES");
      console.log("Таблицы в базе данных:", tablesList.map((t) => t[`Tables_in_${dbConfig.database}`]));
    }
    await connection.end();
  } catch (error) {
    console.error("Ошибка подключения к базе данных:", error.message);
    if (error.code === "ECONNREFUSED") {
      console.error("MySQL сервер не запущен или неверный хост/порт.");
    }
  }
}

testDatabaseConnection();

// Тестовый эндпоинт
app.get("/api/message", (req, res) => {
  res.json({ message: "Привет от бэкенда Ala-Too!" });
});

// Эндпоинт для логина админа
app.post("/api/admin/login", async (req, res) => {
  const { email, password } = req.body;
  console.log("Попытка логина:", { email, password });

  if (!email || !password) {
    console.error("Ошибка: email или пароль отсутствуют");
    return res.status(400).json({ error: "Email и пароль обязательны" });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(
      "SELECT id, first_name, last_name, email, phone, role, password, profile_picture AS photoUrl, token FROM users1 WHERE email = ?",
      [email]
    );
    console.log("Результат запроса к БД:", rows.length > 0 ? "Пользователь найден" : "Пользователь не найден");

    if (rows.length === 0) {
      await connection.end();
      return res.status(401).json({ error: "Неверный email или пользователь не найден" });
    }

    const user = rows[0];
    if (!user.password) {
      console.error("Ошибка: пароль пользователя не установлен");
      await connection.end();
      return res.status(500).json({ error: "Пароль пользователя не установлен" });
    }

    console.log("Хешированный пароль из БД:", user.password);
    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log("Результат сравнения пароля:", isPasswordValid);

    if (!isPasswordValid) {
      await connection.end();
      return res.status(401).json({ error: "Неверный пароль" });
    }

    // Генерируем новый токен и сохраняем его в базе данных
    const token = jwt.sign({ id: user.id, role: user.role }, jwtSecret, { expiresIn: "1h" });
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
      token, // Возвращаем токен в ответе
    };

    console.log("Логин успешен, токен сгенерирован и сохранён");
    await connection.end();
    res.json({ message: "Авторизация успешна", user: userResponse, token });
  } catch (error) {
    console.error("Ошибка при авторизации:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Получение всех пользователей (защищённый)
app.get("/api/users", authenticate, async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(
      "SELECT id, first_name, last_name, email, phone, role, profile_picture AS photoUrl FROM users1"
    );
    console.log("Пользователи получены из БД:", rows.length);
    await connection.end();
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

// Создание нового пользователя (защищённый, только SUPER_ADMIN)
app.post("/api/users", authenticate, upload.single("photo"), async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Доступ запрещён: не SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: требуется роль SUPER_ADMIN" });
  }

  const { email, name, phone, role, password } = req.body;
  const photo = req.file;

  console.log("Входные данные для создания пользователя:", { email, name, phone, role, password, hasPhoto: !!photo });

  if (!email || !name || !phone || !role || !password) {
    console.error("Ошибка: не все поля заполнены", { email, name, phone, role, password });
    return res.status(400).json({ error: "Все поля, включая пароль, обязательны" });
  }

  if (typeof password !== 'string') {
    console.error("Ошибка: пароль должен быть строкой", { password, type: typeof password });
    return res.status(400).json({ error: "Пароль должен быть строкой" });
  }

  const [first_name, last_name = ""] = name.split(" ");
  const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
  const profile_picture = photo ? `${uniqueSuffix}${path.extname(photo.originalname)}` : null;

  try {
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

    const connection = await mysql.createConnection(dbConfig);
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log("Хеш пароля для нового пользователя:", hashedPassword);

    // Генерируем токен для нового пользователя
    const [result] = await connection.execute(
      "INSERT INTO users1 (first_name, last_name, email, phone, role, password, profile_picture) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [first_name, last_name, email, phone, role, hashedPassword, profile_picture]
    );
    const userId = result.insertId;
    const token = jwt.sign({ id: userId, role }, jwtSecret, { expiresIn: "1h" });
    await connection.execute("UPDATE users1 SET token = ? WHERE id = ?", [token, userId]);
    console.log("Новый пользователь создан, ID:", userId, "Токен сохранён:", token);

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

    await connection.end();
    res.json(newUser);
  } catch (error) {
    console.error("Ошибка создания пользователя:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Обновление пользователя (защищённый, только SUPER_ADMIN)
app.put("/api/users/:id", authenticate, upload.single("photo"), async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Доступ запрещён: не SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;
  const { email, name, phone, role } = req.body;
  const photo = req.file;

  console.log("Входные данные для обновления пользователя:", { id, email, name, phone, role, hasPhoto: !!photo });

  if (!email || !name || !phone || !role) {
    console.error("Ошибка: не все поля заполнены");
    return res.status(400).json({ error: "Все поля обязательны" });
  }

  const [first_name, last_name = ""] = name.split(" ");
  const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
  let profile_picture = null;

  try {
    const connection = await mysql.createConnection(dbConfig);
    const [existingUsers] = await connection.execute("SELECT profile_picture FROM users1 WHERE id = ?", [id]);
    if (existingUsers.length === 0) {
      await connection.end();
      console.error("Пользователь не найден по ID:", id);
      return res.status(404).json({ error: "Пользователь не найден" });
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
      await connection.end();
      return res.status(404).json({ error: "Пользователь не найден" });
    }
    console.log("Пользователь обновлён, ID:", id);

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

    await connection.end();
    res.json(updatedUser);
  } catch (error) {
    console.error("Ошибка обновления пользователя:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Удаление пользователя (защищённый, только SUPER_ADMIN)
app.delete("/api/users/:id", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Доступ запрещён: не SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;

  try {
    const connection = await mysql.createConnection(dbConfig);
    const [users] = await connection.execute("SELECT profile_picture FROM users1 WHERE id = ?", [id]);
    if (users.length === 0) {
      await connection.end();
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
      await connection.end();
      return res.status(404).json({ error: "Пользователь не найден" });
    }
    console.log("Пользователь удалён, ID:", id);

    await connection.end();
    res.json({ message: "Пользователь успешно удален" });
  } catch (error) {
    console.error("Ошибка удаления пользователя:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Создание новой записи в properties (защищённый, SUPER_ADMIN или REALTOR)
app.post("/api/properties", authenticate, upload.fields([
  { name: "photos", maxCount: 10 },
  { name: "document", maxCount: 1 },
]), async (req, res) => {
  if (!["SUPER_ADMIN", "REALTOR"].includes(req.user.role)) {
    console.error("Доступ запрещён: не SUPER_ADMIN или REALTOR");
    return res.status(403).json({ error: "Доступ запрещен: требуется роль SUPER_ADMIN или REALTOR" });
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
    console.error("Ошибка: не все обязательные поля заполнены");
    return res.status(400).json({ error: "Все обязательные поля (type_id, price, rukprice, mkv, address, etaj, etajnost) должны быть заполнены" });
  }

  try {
    // Загрузка изображений в S3
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

    // Загрузка документа в S3, если есть
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

    const connection = await mysql.createConnection(dbConfig);
    const [result] = await connection.execute(
      `INSERT INTO properties (
        type_id, condition, series, zhk_id, document_id, owner_name, curator_ids, price, unit, rukprice, mkv, room, phone, 
        district_id, subdistrict_id, address, notes, description, latitude, longitude, photos, document, status, owner_id, etaj, etajnost
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        type_id, condition || null, series || null, zhk_id || null, 0, owner_name || null, curator_ids || null, price, unit || null, rukprice, mkv,
        room || null, phone || null, district_id || null, subdistrict_id || null, address, notes || null, description || null, null, null,
        JSON.stringify(photos.map(img => img.filename)), document ? document.filename : null, status || null, owner_id || null, etaj, etajnost
      ]
    );
    console.log("Новая запись создана в properties, ID:", result.insertId);

    const newProperty = {
      id: result.insertId,
      type_id,
      condition,
      series,
      zhk_id,
      document_id: 0,
      owner_name,
      curator_ids,
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
      date: new Date().toLocaleDateString('ru-RU'),
      time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }),
    };

    await connection.end();
    res.json(newProperty);
  } catch (error) {
    console.error("Ошибка создания записи в properties:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Удаление записи из properties (защищённый, только SUPER_ADMIN)
app.delete("/api/properties/:id", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    console.error("Доступ запрещён: не SUPER_ADMIN");
    return res.status(403).json({ error: "Доступ запрещен: требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;

  try {
    const connection = await mysql.createConnection(dbConfig);
    const [properties] = await connection.execute("SELECT photos, document FROM properties WHERE id = ?", [id]);
    if (properties.length === 0) {
      await connection.end();
      console.error("Запись не найдена по ID:", id);
      return res.status(404).json({ error: "Запись не найдена" });
    }

    const { photos, document } = properties[0];
    if (photos) {
      const photoFiles = JSON.parse(photos);
      for (const img of photoFiles) {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: img }));
        console.log(`Изображение удалено из S3: ${img}`);
      }
    }
    if (document) {
      await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: document }));
      console.log(`Документ удалён из S3: ${document}`);
    }

    const [result] = await connection.execute("DELETE FROM properties WHERE id = ?", [id]);
    if (result.affectedRows === 0) {
      await connection.end();
      return res.status(404).json({ error: "Запись не найдена" });
    }
    console.log("Запись удалена, ID:", id);

    await connection.end();
    res.json({ message: "Запись успешно удалена" });
  } catch (error) {
    console.error("Ошибка удаления записи:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Получение всех записей из properties (защищённый)
app.get("/api/properties", authenticate, async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(
      `SELECT id, type_id, condition, series, zhk_id, document_id, owner_name, curator_ids, price, unit, rukprice, mkv, room, phone, 
       district_id, subdistrict_id, address, notes, description, latitude, longitude, created_at, photos, document, status, owner_id, etaj, etajnost 
       FROM properties`
    );
    console.log("Записи получены из properties:", rows.length);

    const properties = rows.map((row) => ({
      ...row,
      photos: row.photos ? JSON.parse(row.photos).map((img) => `https://s3.twcstorage.ru/${bucketName}/${img}`) : [],
      document: row.document ? `https://s3.twcstorage.ru/${bucketName}/${row.document}` : null,
      date: new Date(row.created_at).toLocaleDateString('ru-RU'),
      time: new Date(row.created_at).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }),
    }));

    await connection.end();
    res.json(properties);
  } catch (error) {
    console.error("Ошибка получения записей:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Получение всех объявлений для AdminDashboard (защищённый)
app.get("/api/listings", authenticate, async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(
      "SELECT id, type_id, price, rukprice, mkv, status, address, created_at FROM properties"
    );
    console.log("Объявления получены из properties:", rows.length);

    const listings = rows.map((row) => ({
      id: row.id,
      date: new Date(row.created_at).toLocaleDateString('ru-RU'),
      time: new Date(row.created_at).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }),
      area: row.mkv,
      district: row.address,
      price: row.price,
      status: row.status,
    }));

    await connection.end();
    res.json(listings);
  } catch (error) {
    console.error("Ошибка получения объявлений:", error.message);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Запуск сервера
app.listen(port, () => {
  console.log(`Сервер запущен на http://localhost:${port}`);
  console.log(`Публичный доступ: ${publicDomain}:${port}`);
});