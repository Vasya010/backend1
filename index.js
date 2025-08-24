const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const port = 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Serve static files from the uploads directory
app.use("/uploads", express.static(path.join(__dirname, "Uploads")));

// Database connection configuration
const dbConfig = {
  host: "localhost",
  user: "cs51703_kgadmin",
  password: "Vasya11091109",
  database: "cs51703_kgadmin",
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

// Test database connection
async function testDatabaseConnection() {
  try {
    const connection = await mysql.createConnection(dbConfig);
    console.log("Подключение к базе данных cs51703_kgadmin успешно установлено!");
    const [rows] = await connection.execute("SELECT 1 AS test");
    if (rows.length > 0) {
      console.log("База данных работает корректно!");
    }
    await connection.end();
  } catch (error) {
    console.error("Ошибка подключения к базе данных:", error.message);
  }
}

// Run database connection test on server start
testDatabaseConnection();

// Test endpoint
app.get("/api/message", (req, res) => {
  res.json({ message: "Привет от бэкенда Ala-Too!" });
});

// Admin login endpoint (Updated to allow any role)
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
      photoUrl: user.photoUrl ? `http://localhost:${port}/Uploads/${user.photoUrl}` : null,
      name: `${user.first_name} ${user.last_name}`.trim(),
    };

    await connection.end();
    res.json({ message: "Авторизация успешна", user: userResponse });
  } catch (error) {
    console.error("Ошибка при авторизации:", error);
    res.status(500).json({ error: `Внутренняя ошибка сервера: ${error.message}` });
  }
});

// Get all users
app.get("/api/users", async (req, res) => {
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
        photoUrl: user.photoUrl ? `http://localhost:${port}/Uploads/${user.photoUrl}` : null,
      }))
    );
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Create a new user
app.post("/api/users", upload.single("photo"), async (req, res) => {
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
      photoUrl: profile_picture ? `http://localhost:${port}/Uploads/${profile_picture}` : null,
      name: `${first_name} ${last_name}`.trim(),
    };

    await connection.end();
    res.json(newUser);
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Update a user
app.put("/api/users/:id", upload.single("photo"), async (req, res) => {
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
      photoUrl: profile_picture ? `http://localhost:${port}/Uploads/${profile_picture}` : null,
      name: `${first_name} ${last_name}`.trim(),
    };

    await connection.end();
    res.json(updatedUser);
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Delete a user
app.delete("/api/users/:id", async (req, res) => {
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

// Get all districts and subdistricts
app.get("/api/raions", async (req, res) => {
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

// Create a new district
app.post("/api/raions", async (req, res) => {
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

// Create a new subdistrict
app.post("/api/subraions", async (req, res) => {
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

// Get all options
app.get("/api/options", async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(
      "SELECT id, type, area, price, status, owner, address, description, curator, images, document FROM options"
    );

    const options = rows.map((row) => ({
      ...row,
      images: row.images ? JSON.parse(row.images).map((img) => `http://localhost:${port}/Uploads/${img}`) : [],
      document: row.document ? `http://localhost:${port}/Uploads/${row.document}` : null,
    }));

    await connection.end();
    res.json(options);
  } catch (error) {
    console.error("Error fetching options:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Create a new option
app.post("/api/options", upload.fields([
  { name: "images", maxCount: 10 },
  { name: "document", maxCount: 1 },
]), async (req, res) => {
  const { type, area, price, status, owner, address, description, curator } = req.body;
  const images = req.files["images"] ? req.files["images"].map((file) => file.filename) : [];
  const document = req.files["document"] ? req.files["document"][0].filename : null;

  if (!type || !area || !price || !status || !owner || !address || !description || !curator) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const connection = await mysql.createConnection(dbConfig);
    const [result] = await connection.execute(
      "INSERT INTO options (type, area, price, status, owner, address, description, curator, images, document) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
      images: images.map((img) => `http://localhost:${port}/Uploads/${img}`),
      document: document ? `http://localhost:${port}/Uploads/${document}` : null,
    };

    await connection.end();
    res.json(newOption);
  } catch (error) {
    console.error("Error creating option:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Delete an option
app.delete("/api/options/:id", async (req, res) => {
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

// Start server
app.listen(port, () => {
  console.log(`Сервер запущен на http://localhost:${port}`);
});