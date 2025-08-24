const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const { S3Client, PutObjectCommand, DeleteObjectCommand } = require("@aws-sdk/client-s3");
const path = require("path"); // Добавлен, так как он используется в коде

const app = express();
const port = 5000;
const publicDomain = "https://vasya010-backend1-10db.twc1.net"; // Public domain for Timeweb
const jwtSecret = "your_jwt_secret_123"; // Replace with your secret key

// S3 Configuration
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

// Multer configuration for memory storage
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
});

// JWT authentication middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Токен отсутствует" });
  try {
    const decoded = jwt.verify(token, jwtSecret);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: "Неверный токен" });
  }
};

// Database connection configuration
const dbConfig = {
  host: "vh452.timeweb.ru",
  user: "cs51703_kgadmin",
  password: "Vasya11091109",
  database: "cs51703_kgadmin",
  port: 3306,
};

// Test database connection and create initial user
async function testDatabaseConnection() {
  try {
    const connection = await mysql.createConnection(dbConfig);
    console.log("Подключение к базе данных cs51703_kgadmin успешно установлено!");

    const [tables] = await connection.execute("SHOW TABLES LIKE 'users1'");
    if (tables.length === 0) {
      console.log("Таблица users1 не существует, создаем...");
      await connection.execute(`
        CREATE TABLE users1 (
          id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          first_name VARCHAR(255) NOT NULL,
          last_name VARCHAR(255) NOT NULL,
          role VARCHAR(50) NOT NULL,
          email VARCHAR(255) NOT NULL,
          phone VARCHAR(255) NOT NULL,
          profile_picture VARCHAR(255) DEFAULT NULL,
          password VARCHAR(255) NOT NULL
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci
      `);
    }

    const [users] = await connection.execute("SELECT COUNT(*) AS count FROM users1");
    if (users[0].count === 0) {
      console.log("Пользователи отсутствуют, создаем начального пользователя...");
      const hashedPassword = await bcrypt.hash("admin123", 10); // Хешируем с 10 rounds
      console.log("Хешированный пароль для admin123:", hashedPassword); // Для отладки
      await connection.execute(
        "INSERT INTO users1 (first_name, last_name, email, phone, role, password) VALUES (?, ?, ?, ?, ?, ?)",
        ["Admin", "User", "admin@example.com", "123456789", "SUPER_ADMIN", hashedPassword]
      );
      console.log("Создан пользователь: email=admin@example.com, пароль=admin123 (хешированный), роль=SUPER_ADMIN");
    }

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
      console.error("MySQL сервер не запущен или неверный хост/порт. Проверьте, что MySQL работает на", dbConfig.host, "порт", dbConfig.port || 3306);
    }
  }
}

testDatabaseConnection();

// Test endpoint
app.get("/api/message", (req, res) => {
  res.json({ message: "Привет от бэкенда Ala-Too!" });
});

// Admin login endpoint
app.post("/api/admin/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email и пароль обязательны" });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(
      "SELECT id, first_name, last_name, email, phone, role, password, profile_picture AS photoUrl FROM users1 WHERE email = ?",
      [email]
    );

    if (rows.length === 0) {
      await connection.end();
      return res.status(401).json({ error: "Неверный email или пользователь не найден" });
    }

    const user = rows[0];
    if (!user.password) {
      await connection.end();
      return res.status(500).json({ error: "Пароль пользователя не установлен" });
    }

    console.log("Введенный пароль:", password); // Отладка
    console.log("Хешированный пароль из базы:", user.password); // Отладка
    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log("Результат сравнения пароля:", isPasswordValid); // Отладка

    if (!isPasswordValid) {
      await connection.end();
      return res.status(401).json({ error: "Неверный пароль" });
    }

    const userResponse = {
      id: user.id,
      first_name: user.first_name,
      last_name: user.last_name,
      email: user.email,
      phone: user.phone,
      role: user.role,
      photoUrl: user.photoUrl ? `https://s3.twcstorage.ru/${bucketName}/${user.photoUrl}` : null,
      name: `${user.first_name} ${user.last_name}`.trim(),
    };

    const token = jwt.sign({ id: user.id, role: user.role }, jwtSecret, { expiresIn: "1h" });

    await connection.end();
    res.json({ message: "Авторизация успешна", user: userResponse, token });
  } catch (error) {
    console.error("Ошибка при авторизации:", error);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Get all users (protected)
app.get("/api/users", authenticate, async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(
      "SELECT id, first_name, last_name, email, phone, role, profile_picture AS photoUrl FROM users1"
    );
    await connection.end();
    res.json(
      rows.map((user) => ({
        ...user,
        name: `${user.first_name} ${user.last_name}`,
        photoUrl: user.photoUrl ? `https://s3.twcstorage.ru/${bucketName}/${user.photoUrl}` : null,
      }))
    );
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Внутренняя ошибка сервера" });
  }
});

// Create a new user (protected, only for SUPER_ADMIN)
app.post("/api/users", authenticate, upload.single("photo"), async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Доступ запрещен: требуется роль SUPER_ADMIN" });
  }

  const { email, name, phone, role, password } = req.body;
  const photo = req.file;

  if (!email || !name || !phone || !role || !password) {
    return res.status(400).json({ error: "Все поля обязательны" });
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
    }

    const connection = await mysql.createConnection(dbConfig);
    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await connection.execute(
      "INSERT INTO users1 (first_name, last_name, email, phone, role, password, profile_picture) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [first_name, last_name, email, phone, role, hashedPassword, profile_picture]
    );

    const newUser = {
      id: result.insertId,
      first_name,
      last_name,
      email,
      phone,
      role,
      photoUrl: profile_picture ? `https://s3.twcstorage.ru/${bucketName}/${profile_picture}` : null,
      name: `${first_name} ${last_name}`.trim(),
    };

    await connection.end();
    res.json(newUser);
  } catch (error) {
    console.error("Ошибка создания пользователя:", error);
    res.status(500).json({ error: "Внутренняя ошибка сервера" });
  }
});

// Update a user (protected, only for SUPER_ADMIN)
app.put("/api/users/:id", authenticate, upload.single("photo"), async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Доступ запрещен: требуется роль SUPER_ADMIN" });
  }

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
    const connection = await mysql.createConnection(dbConfig);
    const [existingUsers] = await connection.execute("SELECT profile_picture FROM users1 WHERE id = ?", [id]);
    if (existingUsers.length === 0) {
      await connection.end();
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

      if (existingPhoto) {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: existingPhoto }));
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
    console.error("Ошибка обновления пользователя:", error);
    res.status(500).json({ error: "Внутренняя ошибка сервера" });
  }
});

// Delete a user (protected, only for SUPER_ADMIN)
app.delete("/api/users/:id", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Доступ запрещен: требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;

  try {
    const connection = await mysql.createConnection(dbConfig);
    const [users] = await connection.execute("SELECT profile_picture FROM users1 WHERE id = ?", [id]);
    if (users.length === 0) {
      await connection.end();
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    const profile_picture = users[0].profile_picture;
    if (profile_picture) {
      await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: profile_picture }));
    }

    const [result] = await connection.execute("DELETE FROM users1 WHERE id = ?", [id]);
    if (result.affectedRows === 0) {
      await connection.end();
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    await connection.end();
    res.json({ message: "Пользователь успешно удален" });
  } catch (error) {
    console.error("Ошибка удаления пользователя:", error);
    res.status(500).json({ error: "Внутренняя ошибка сервера" });
  }
});

// Create a new option (protected, only for SUPER_ADMIN or REALTOR)
app.post("/api/options", authenticate, upload.fields([
  { name: "images", maxCount: 10 },
  { name: "document", maxCount: 1 },
]), async (req, res) => {
  if (!["SUPER_ADMIN", "REALTOR"].includes(req.user.role)) {
    return res.status(403).json({ error: "Доступ запрещен: требуется роль SUPER_ADMIN или REALTOR" });
  }

  const { type, area, price, status, owner, address, description, curator } = req.body;
  const images = req.files["images"] ? req.files["images"].map((file) => ({
    filename: `${Date.now()}-${Math.round(Math.random() * 1e9)}${path.extname(file.originalname)}`,
    buffer: file.buffer,
    mimetype: file.mimetype,
  })) : [];
  const document = req.files["document"] ? {
    filename: `${Date.now()}-${Math.round(Math.random() * 1e9)}${path.extname(req.files["document"][0].originalname)}`,
    buffer: req.files["document"][0].buffer,
    mimetype: req.files["document"][0].mimetype,
  } : null;

  if (!type || !area || !price || !status || !owner || !address || !description || !curator) {
    return res.status(400).json({ error: "Все поля обязательны" });
  }

  try {
    // Upload images to S3
    for (const image of images) {
      const uploadParams = {
        Bucket: bucketName,
        Key: image.filename,
        Body: image.buffer,
        ContentType: image.mimetype,
      };
      await s3Client.send(new PutObjectCommand(uploadParams));
    }

    // Upload document to S3 if present
    if (document) {
      const uploadParams = {
        Bucket: bucketName,
        Key: document.filename,
        Body: document.buffer,
        ContentType: document.mimetype,
      };
      await s3Client.send(new PutObjectCommand(uploadParams));
    }

    const connection = await mysql.createConnection(dbConfig);
    const [result] = await connection.execute(
      "INSERT INTO options (type, area, price, status, owner, address, description, curator, images, document, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())",
      [type, area, price, status, owner, address, description, curator, JSON.stringify(images.map(img => img.filename)), document ? document.filename : null]
    );

    const newOption = {
      id: result.insertId,
      type,
      area,
      price,
      status,
      owner,
      address,
      description,
      curator,
      images: images.map((img) => `https://s3.twcstorage.ru/${bucketName}/${img.filename}`),
      document: document ? `https://s3.twcstorage.ru/${bucketName}/${document.filename}` : null,
      date: new Date().toLocaleDateString('ru-RU'),
      time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }),
    };

    await connection.end();
    res.json(newOption);
  } catch (error) {
    console.error("Ошибка создания варианта:", error);
    res.status(500).json({ error: "Внутренняя ошибка сервера" });
  }
});

// Delete an option (protected, only for SUPER_ADMIN)
app.delete("/api/options/:id", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Доступ запрещен: требуется роль SUPER_ADMIN" });
  }

  const { id } = req.params;

  try {
    const connection = await mysql.createConnection(dbConfig);
    const [options] = await connection.execute("SELECT images, document FROM options WHERE id = ?", [id]);
    if (options.length === 0) {
      await connection.end();
      return res.status(404).json({ error: "Вариант не найден" });
    }

    const { images, document } = options[0];
    if (images) {
      const imageFiles = JSON.parse(images);
      for (const img of imageFiles) {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: img }));
      }
    }
    if (document) {
      await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: document }));
    }

    const [result] = await connection.execute("DELETE FROM options WHERE id = ?", [id]);
    if (result.affectedRows === 0) {
      await connection.end();
      return res.status(404).json({ error: "Вариант не найден" });
    }

    await connection.end();
    res.json({ message: "Вариант успешно удален" });
  } catch (error) {
    console.error("Ошибка удаления варианта:", error);
    res.status(500).json({ error: "Внутренняя ошибка сервера" });
  }
});

// Get all options (protected)
app.get("/api/options", authenticate, async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(
      "SELECT id, type, area, price, status, owner, address, description, curator, images, document, created_at FROM options"
    );

    const options = rows.map((row) => ({
      ...row,
      images: row.images ? JSON.parse(row.images).map((img) => `https://s3.twcstorage.ru/${bucketName}/${img}`) : [],
      document: row.document ? `https://s3.twcstorage.ru/${bucketName}/${row.document}` : null,
      date: new Date(row.created_at).toLocaleDateString('ru-RU'),
      time: new Date(row.created_at).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }),
    }));

    await connection.end();
    res.json(options);
  } catch (error) {
    console.error("Ошибка получения вариантов:", error);
    res.status(500).json({ error: "Внутренняя ошибка сервера" });
  }
});

// Get all listings for AdminDashboard (protected)
app.get("/api/listings", authenticate, async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(
      "SELECT id, type, area, price, status, address, created_at FROM options"
    );

    const listings = rows.map((row) => ({
      id: row.id,
      date: new Date(row.created_at).toLocaleDateString('ru-RU'),
      time: new Date(row.created_at).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }),
      area: row.area,
      district: row.address,
      price: row.price,
      status: row.status,
    }));

    await connection.end();
    res.json(listings);
  } catch (error) {
    console.error("Ошибка получения объявлений:", error);
    res.status(500).json({ error: "Внутренняя ошибка сервера" });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Сервер запущен на http://localhost:${port}`);
  console.log(`Публичный доступ: ${publicDomain}:${port}`);
});