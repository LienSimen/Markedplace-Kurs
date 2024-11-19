const express = require("express");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const db = require("../config/db");
const router = express.Router();

const upload = multer({
  dest: "public/uploads/", // Destination folder for uploaded files
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB cap
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png/;
    const extname = filetypes.test(file.originalname.toLowerCase());
    const mimetype = filetypes.test(file.mimetype);

    if (mimetype && extname) {
      return cb(null, true);
    }

    // Set flash message for invalid file type
    req.session.message = "Only JPEG, JPG, or PNG files are allowed.";
    return cb(null, false); // Reject file but don't trigger a fatal error
  },
});


//  Middleware to Check Authentication 
function isAuthenticated(req, res, next) {
  if (req.session || req.session.isLoggedIn) {
    return next();
  }
  res.redirect("/login");
}

//  GET /profile 
router.get("/", isAuthenticated, (req, res) => {
  const query = `
    SELECT username, email, avatar_url, dark_mode, two_factor_enabled
    FROM users WHERE id = ?
  `;
  db.query(query, [req.session.userId], (err, results) => {
    if (err || results.length === 0) {
      req.session.message = "Error loading profile.";
      return res.redirect("/login");
    }

    const user = results[0];

    res.render("profile", {
      username: user.username,
      email: user.email,
      avatarUrl: user.avatar_url,
      darkMode: user.dark_mode,
      twoFactorEnabled: user.two_factor_enabled,
      message: req.session.message,
    });
  });
});


router.post("/update", isAuthenticated, upload.single("avatar"), async (req, res) => {
  const { username, email, password } = req.body;

  // Validation for required fields
  if (!username || !email) {
    req.session.message = "Username and email cannot be empty.";
    return res.redirect("/profile");
  }

  // Handle invalid file upload
  if (!req.file && req.session.message) {
    console.log("Flash Message for File Error:", req.session.message); // Debugging log
    return res.redirect("/profile");
  }

  let avatarUrl = req.session.avatarUrl || "/images/default-avatar.png";
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
    WHERE id = ?
  `;
  const values = [
    username,
    email,
    ...(passwordHash ? [passwordHash] : []),
    avatarUrl,
    req.session.userId,
  ];

  db.query(query, values, (err) => {
    if (err) {
      req.session.message = "Error updating profile. Please try again.";
      return res.redirect("/profile");
    }

    req.session.username = username;
    req.session.avatarUrl = avatarUrl;
    req.session.message = "Profile updated successfully!";
    res.redirect("/profile");
  });
});

//  POST /profile/delete 
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
      res.clearCookie("connect.sid");
      res.redirect("/");
    });
  });
});

module.exports = router;
