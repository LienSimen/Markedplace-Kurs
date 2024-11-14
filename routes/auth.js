const express = require("express");
const bcrypt = require("bcryptjs");
const db = require("../db"); // Use the database connection
const router = express.Router();


router.get("/login", (req, res) => {
  res.render("login", { message: req.session.message });
  delete req.session.message;
});

router.get("/register", (req, res) => {
  res.render("register", { message: req.session.message });
  delete req.session.message;
});

// Registration route
router.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  const salt = await bcrypt.genSalt(10);
  const passwordHash = await bcrypt.hash(password, salt);

  const query =
    "INSERT INTO users (username, email, password_hash, avatar_url) VALUES (?, ?, ?, ?)";
  db.query(
    query,
    [username, email, passwordHash, "/images/default-avatar.png"],
    (err, result) => {
      if (err) {
        console.error("Error inserting user data:", err);
        return res.send("Error registering user.");
      }
      req.session.isLoggedIn = true;
      req.session.username = username;
      req.session.avatarUrl = "/images/default-avatar.png"; // Set default avatar URL
      res.redirect("/");
    }
  );
});

// Login route
router.post("/login", (req, res) => {
  const { username, password } = req.body;
  const query = "SELECT * FROM users WHERE username = ?";

  db.query(query, [username], async (err, results) => {
    if (err) {
      console.error("Error fetching user data:", err);
      return res.send("Error logging in.");
    }
    if (results.length === 0) return res.send("Invalid username or password.");

    const user = results[0];
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);

    if (isPasswordValid) {
      req.session.isLoggedIn = true;
      req.session.username = username;
      req.session.avatarUrl = user.avatar_url; // Store avatar URL in session
      req.session.message = "Successfully logged in!";
      res.redirect("/");
    } else {
      res.send("Invalid username or password.");
    }
  });
});

// Logout route
router.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.send("Error logging out.");
    res.clearCookie("connect.sid");
    res.redirect("/");
  });
});

module.exports = router;
