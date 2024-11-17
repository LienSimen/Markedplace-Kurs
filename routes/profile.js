const express = require("express");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const db = require("../config/db");
const router = express.Router();

// === Multer Setup for Avatar Uploads ===
const upload = multer({
  dest: "public/uploads/", // Destination folder for uploaded files
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB cap
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png/;
    const extname = filetypes.test(file.originalname.toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    if (mimetype && extname) return cb(null, true);
    cb(new Error("Only JPEG, JPG, or PNG files are allowed."));
  },
});

// === Middleware to Check Authentication ===
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) {
    return next();
  }
  if (req.session && req.session.isLoggedIn) {
    return next();
  }
  res.redirect("/login");
}

// === GET /profile ===
router.get("/", isAuthenticated, (req, res) => {
  const query = `
    SELECT username, email, avatar_url, dark_mode
    FROM users WHERE username = ?
  `;
  db.query(query, [req.session.username], (err, results) => {
    if (err) {
      console.error("Error fetching profile data:", err);
      return res.status(500).send("Error loading profile.");
    }

    if (results.length > 0) {
      const user = results[0];
      res.render("profile", {
        username: user.username,
        email: user.email,
        avatarUrl: user.avatar_url,
        darkMode: user.dark_mode || false,
        message: req.session.message || null,
      });
      req.session.message = null; // Clear flash message
    } else {
      res.redirect("/login");
    }
  });
});

// === POST /profile/update ===
router.post("/update", isAuthenticated, upload.single("avatar"), async (req, res) => {
  const { username, email, password } = req.body;
  let avatarUrl = req.session.avatarUrl; // Default to current avatar if none is uploaded

  if (req.file) {
    avatarUrl = `/uploads/${req.file.filename}`;
  }

  let passwordHash = null;
  if (password) {
    const salt = await bcrypt.genSalt(10);
    passwordHash = await bcrypt.hash(password, salt);
  }

  const query = `
    UPDATE users 
    SET username = ?, email = ?, ${passwordHash ? "password_hash = ?," : ""} avatar_url = ? 
    WHERE username = ?
  `;
  const values = [
    username,
    email,
    ...(passwordHash ? [passwordHash] : []),
    avatarUrl,
    req.session.username,
  ];

  db.query(query, values, (err) => {
    if (err) {
      console.error("Error updating profile:", err);
      return res.status(500).send("Error updating profile.");
    }

    req.session.username = username;
    req.session.avatarUrl = avatarUrl;
    req.session.message = "Profile updated successfully!";
    res.redirect("/profile");
  });
});

// === POST /profile/delete ===
router.post("/delete", isAuthenticated, (req, res) => {
  const query = "DELETE FROM users WHERE username = ?";
  db.query(query, [req.session.username], (err) => {
    if (err) {
      console.error("Error deleting account:", err);
      return res.status(500).send("Error deleting account.");
    }

    req.session.destroy((err) => {
      if (err) {
        console.error("Error destroying session:", err);
        return res.status(500).send("Error logging out.");
      }
      res.clearCookie("connect.sid"); // Clear session cookie
      res.redirect("/"); // Redirect to home page
    });
  });
});

module.exports = router;
