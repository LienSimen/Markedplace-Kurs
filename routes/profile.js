const express = require("express");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const db = require("../db");
const router = express.Router();

// Multer for avatar uploads
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

// Route to handle profile updates
router.post("/update", upload.single("avatar"), async (req, res) => {
  const { username, email, password } = req.body;
  let avatarUrl = req.session.avatarUrl; // Default to current avatar if none is uploaded

  // Update avatar if a new file is uploaded
  if (req.file) {
    avatarUrl = `/uploads/${req.file.filename}`;
  }

  // Hash the password if a new one is provided
  let passwordHash = null;
  if (password) {
    const salt = await bcrypt.genSalt(10);
    passwordHash = await bcrypt.hash(password, salt);
  }

  // SQL query to update user data
  const query = `
    UPDATE users 
    SET username = ?, email = ?, ${
      passwordHash ? "password_hash = ?," : ""
    } avatar_url = ? 
    WHERE username = ?
  `;
  const values = [
    username,
    email,
    ...(passwordHash ? [passwordHash] : []),
    avatarUrl,
    req.session.username,
  ];

  db.query(query, values, (err, result) => {
    if (err) {
      console.error("Error updating profile:", err);
      return res.send("Error updating profile.");
    }

    // Update session values
    req.session.username = username;
    req.session.avatarUrl = avatarUrl;
    req.session.message = "Profile updated successfully!";
    res.redirect("/profile");
  });
});

router.post("/delete", async (req, res) => {
  const username = req.session.username;

  // SQL query to delete the user account
  const query = `DELETE FROM users WHERE username = ?`;
  db.query(query, [username], (err, result) => {
    if (err) {
      console.error("Error deleting account:", err);
      return res.send("Error deleting account.");
    }

    // Destroy session and redirect to homepage or login page
    req.session.destroy((err) => {
      if (err) {
        console.error("Error destroying session:", err);
        return res.send("Error logging out.");
      }
      res.redirect("/"); // redirect home
    });
  });
});


module.exports = router;
