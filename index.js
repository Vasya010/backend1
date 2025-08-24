const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const port = 5000;
const publicDomain = "https://vasya010-backend1-10db.twc1.net"; // Публичный домен для Timeweb
const jwtSecret = "your_jwt_secret_123"; // Замените на свой секретный ключ00

// Middleware
app.use(cors());
app.use(express.json());

// Serve static files from the uploads directory
app.use("/uploads", express.static(path.join(__dirname, "Uploads")));

// Database connection configuration
const dbConfig = {
  host: "vh452.timeweb.ru",
  user: "cs51703_kgadmin",
  password: "Vasya11091109",
  database: "cs51703_kgadmin",
  port: 3306, // Убедитесь, что порт правильный (по умолчанию 3306)
};

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, "Uploads");
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir);
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  },
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|pdf|doc|docx/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error("Only images (jpeg, jpg, png) and documents (pdf, doc, docx) are allowed"));
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

// Test database connection and create initial user
async function testDatabaseConnection() {
  try {
    const connection = await mysql.createConnection(dbConfig);
    console.log("Подключение к базе данных cs51703_kgadmin успешно установлено!");

    // Проверка существования таблицы users1
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

    // Проверка, есть ли пользователи в таблице
    const [users] = await connection.execute("SELECT COUNT(*) AS count FROM users1");
    if (users[0].count === 0) {
      console.log("Пользователи отсутствуют, создаем начального пользователя...");
      const hashedPassword = await bcrypt.hash("admin123", 10);
      await connection.execute(
        "INSERT INTO users1 (first_name, last_name, email, phone, role, password) VALUES (?, ?, ?, ?, ?, ?)",
        ["Admin", "User", "admin@example.com", "123456789", "SUPER_ADMIN", hashedPassword]
      );
      console.log("Создан пользователь: email=admin@example.com, пароль=admin123, роль=SUPER_ADMIN");
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

// Run database connection test on server start
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
      return res.status(401).json({ error: "Неверный email" });
    }

    const user = rows[0];
    if (!user.password) {
      await connection.end();
      return res.status(500).json({ error: "Пароль пользователя не установлен" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
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
      photoUrl: user.photoUrl ? `${publicDomain}/uploads/${user.photoUrl}` : null,
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
        photoUrl: user.photoUrl ? `${publicDomain}/uploads/${user.photoUrl}` : null,
      }))
    );
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Internal server error" });
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
    return res.status(400).json({ error: "All fields are required" });
  }

  const [first_name, last_name = ""] = name.split(" ");

  try {
    const connection = await mysql.createConnection(dbConfig);
    const hashedPassword = await bcrypt.hash(password, 10);
    const profile_picture = photo ? photo.filename : null;

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
      photoUrl: profile_picture ? `${publicDomain}/uploads/${profile_picture}` : null,
      name: `${first_name} ${last_name}`.trim(),
    };

    await connection.end();
    res.json(newUser);
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ error: "Internal server error" });
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
    return res.status(400).json({ error: "All fields are required" });
  }

  const [first_name, last_name = ""] = name.split(" ");

  try {
    const connection = await mysql.createConnection(dbConfig);
    const [existingUsers] = await connection.execute("SELECT profile_picture FROM users1 WHERE id = ?", [id]);
    if (existingUsers.length === 0) {
      await connection.end();
      return res.status(404).json({ error: "User not found" });
    }

    const existingPhoto = existingUsers[0].profile_picture;
    let profile_picture = existingPhoto;

    if (photo) {
      profile_picture = photo.filename;
      if (existingPhoto) {
        fs.unlink(path.join(__dirname, "Uploads", existingPhoto), (err) => {
          if (err) console.error("Error deleting old photo:", err);
        });
      }
    }

    const [result] = await connection.execute(
      "UPDATE users1 SET first_name = ?, last_name = ?, email = ?, phone = ?, role = ?, profile_picture = ? WHERE id = ?",
      [first_name, last_name, email, phone, role, profile_picture, id]
    );

    if (result.affectedRows === 0) {
      await connection.end();
      return res.status(404).json({ error: "User not found" });
    }

    const updatedUser = {
      id: parseInt(id),
      first_name,
      last_name,
      email,
      phone,
      role,
      photoUrl: profile_picture ? `${publicDomain}/uploads/${profile_picture}` : null,
      name: `${first_name} ${last_name}`.trim(),
    };

    await connection.end();
    res.json(updatedUser);
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ error: "Internal server error" });
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
      return res.status(404).json({ error: "User not found" });
    }

    const profile_picture = users[0].profile_picture;
    if (profile_picture) {
      fs.unlink(path.join(__dirname, "Uploads", profile_picture), (err) => {
        if (err) console.error("Error deleting photo:", err);
      });
    }

    const [result] = await connection.execute("DELETE FROM users1 WHERE id = ?", [id]);
    if (result.affectedRows === 0) {
      await connection.end();
      return res.status(404).json({ error: "User not found" });
    }

    await connection.end();
    res.json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get all districts and subdistricts (protected)
app.get("/api/raions", authenticate, async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const [districts] = await connection.execute(
      "SELECT id, name, NULL AS parentRaionId, link FROM districts"
    );
    const [subdistricts] = await connection.execute(
      "SELECT id, name, district_id AS parentRaionId, link FROM subdistricts"
    );
    await connection.end();
    res.json([...districts, ...subdistricts]);
  } catch (error) {
    console.error("Error fetching districts and subdistricts:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Create a new district (protected, only for SUPER_ADMIN)
app.post("/api/raions", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Доступ запрещен: требуется роль SUPER_ADMIN" });
  }

  const { name } = req.body;

  if (!name) {
    return res.status(400).json({ error: "Name is required" });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);
    const [result] = await connection.execute(
      "INSERT INTO districts (name, link) VALUES (?, NULL)",
      [name]
    );

    const newDistrict = {
      id: result.insertId,
      name,
      parentRaionId: null,
      link: null,
    };

    await connection.end();
    res.json(newDistrict);
  } catch (error) {
    console.error("Error creating district:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Create a new subdistrict (protected, only for SUPER_ADMIN)
app.post("/api/subraions", authenticate, async (req, res) => {
  if (req.user.role !== "SUPER_ADMIN") {
    return res.status(403).json({ error: "Доступ запрещен: требуется роль SUPER_ADMIN" });
  }

  const { name, parentRaionId } = req.body;

  if (!name || !parentRaionId) {
    return res.status(400).json({ error: "Name and parentRaionId are required" });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);
    const [parent] = await connection.execute("SELECT id FROM districts WHERE id = ?", [parentRaionId]);
    if (parent.length === 0) {
      await connection.end();
      return res.status(400).json({ error: "Parent district not found" });
    }

    const [result] = await connection.execute(
      "INSERT INTO subdistricts (name, district_id, link) VALUES (?, ?, NULL)",
      [name, parentRaionId]
    );

    const newSubDistrict = {
      id: result.insertId,
      name,
      parentRaionId,
      link: null,
    };

    await connection.end();
    res.json(newSubDistrict);
  } catch (error) {
    console.error("Error creating subdistrict:", error);
    res.status(500).json({ error: "Internal server error" });
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
      images: row.images ? JSON.parse(row.images).map((img) => `${publicDomain}/uploads/${img}`) : [],
      document: row.document ? `${publicDomain}/uploads/${row.document}` : null,
      date: new Date(row.created_at).toLocaleDateString('ru-RU'),
      time: new Date(row.created_at).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }),
    }));

    await connection.end();
    res.json(options);
  } catch (error) {
    console.error("Error fetching options:", error);
    res.status(500).json({ error: "Internal server error" });
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
  const images = req.files["images"] ? req.files["images"].map((file) => file.filename) : [];
  const document = req.files["document"] ? req.files["document"][0].filename : null;

  if (!type || !area || !price || !status || !owner || !address || !description || !curator) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);
    const [result] = await connection.execute(
      "INSERT INTO options (type, area, price, status, owner, address, description, curator, images, document, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())",
      [type, area, price, status, owner, address, description, curator, JSON.stringify(images), document]
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
      images: images.map((img) => `${publicDomain}/uploads/${img}`),
      document: document ? `${publicDomain}/uploads/${document}` : null,
      date: new Date().toLocaleDateString('ru-RU'),
      time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }),
    };

    await connection.end();
    res.json(newOption);
  } catch (error) {
    console.error("Error creating option:", error);
    res.status(500).json({ error: "Internal server error" });
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
      return res.status(404).json({ error: "Option not found" });
    }

    const { images, document } = options[0];
    if (images) {
      JSON.parse(images).forEach((img) => {
        fs.unlink(path.join(__dirname, "Uploads", img), (err) => {
          if (err) console.error("Error deleting image:", err);
        });
      });
    }
    if (document) {
      fs.unlink(path.join(__dirname, "Uploads", document), (err) => {
        if (err) console.error("Error deleting document:", err);
      });
    }

    const [result] = await connection.execute("DELETE FROM options WHERE id = ?", [id]);
    if (result.affectedRows === 0) {
      await connection.end();
      return res.status(404).json({ error: "Option not found" });
    }

    await connection.end();
    res.json({ message: "Option deleted successfully" });
  } catch (error) {
    console.error("Error deleting option:", error);
    res.status(500).json({ error: "Internal server error" });
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
    console.error("Error fetching listings:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Сервер запущен на http://localhost:${port}`);
  console.log(`Публичный доступ: ${publicDomain}:${port}`);
});