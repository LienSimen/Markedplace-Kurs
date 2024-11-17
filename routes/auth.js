const express = require("express");
const bcrypt = require("bcryptjs");
const db = require("../config/db"); // Use the database connection
const passport = require("passport");
const router = express.Router();

// Middleware to check if the user is logged in
const redirectIfLoggedIn = (req, res, next) => {
  if (req.session.isLoggedIn) {
    return res.redirect("/");
  }
  next();
};


// Google Authentication
router.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

router.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    req.session.isLoggedIn = true;
    req.session.username = req.user.username;
    req.session.avatarUrl = req.user.avatar_url;
    req.session.message = `Welcome back, ${req.user.username}!`;
    res.redirect("/"); // Redirect to home after login
  }
);

// GitHub Authentication
router.get("/auth/github", passport.authenticate("github", { scope: ["user:email"] }));

router.get(
  "/auth/github/callback",
  passport.authenticate("github", { failureRedirect: "/login" }),
  (req, res) => {
    req.session.isLoggedIn = true;
    req.session.username = req.user.username;
    req.session.avatarUrl = req.user.avatar_url;
    req.session.message = `Welcome back, ${req.user.username}!`;
    res.redirect("/"); // Redirect to home after login
  }
);


// Register Route
router.get("/register", redirectIfLoggedIn, (req, res) => {
  res.render("register", {
    darkMode: req.session.darkMode || false, // Pass darkMode to the view
  });
});

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
        req.session.message = "Error registering user. Please try again.";
        return res.redirect("/register");
      }
      req.session.isLoggedIn = true;
      req.session.username = username;
      req.session.avatarUrl = "/images/default-avatar.png";
      req.session.message =
        "Registration successful! Welcome, " + username + "!";
      res.redirect("/");
    }
  );
});

// Login Route
router.get("/login", redirectIfLoggedIn, (req, res) => {
  res.render("login", {
    darkMode: req.session.darkMode || false, // Pass darkMode, default to false
  });
});


router.post("/login", (req, res) => {
  const { username, password } = req.body;
  const query = "SELECT * FROM users WHERE username = ?";

  db.query(query, [username], async (err, results) => {
    if (err) {
      console.error("Error fetching user data:", err);
      req.session.message = "An error occurred. Please try again.";
      return res.redirect("/login");
    }
    if (results.length === 0) {
      req.session.message = "Invalid username or password.";
      return res.redirect("/login");
    }

    const user = results[0];
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);

    if (isPasswordValid) {
      req.session.isLoggedIn = true;
      req.session.username = username;
      req.session.avatarUrl = user.avatar_url;
      req.session.darkMode = user.dark_mode; // Retrieve dark_mode from DB
      req.session.message = "Successfully logged in!";
      res.redirect("/");
    } else {
      req.session.message = "Invalid username or password.";
      res.redirect("/login");
    }
  });
});


router.post("/dark-mode", (req, res) => {
  if (!req.session.isLoggedIn) {
    return res.status(401).send("Unauthorized");
  }

  // Log the request body for debugging
  console.log("Request body:", req.body);

  const darkMode = req.body.darkMode ? 1 : 0; // Convert boolean to integer for MySQL
  const query = "UPDATE users SET dark_mode = ? WHERE username = ?";

  db.query(query, [darkMode, req.session.username], (err, result) => {
    if (err) {
      console.error("Error updating dark mode preference:", err);
      return res.status(500).send("Failed to update dark mode preference.");
    }

    req.session.darkMode = darkMode; // Update session value
    console.log("Dark mode updated in DB:", darkMode);
    res.send("Dark mode preference updated successfully.");
  });
});

// Logout Route
router.post("/logout", (req, res) => {
  if (req.session) {
    req.session.destroy((err) => {
      if (err) {
        console.error("Error destroying session:", err);
        return res.status(500).send("Error logging out.");
      }
      res.clearCookie("connect.sid");
      res.redirect("/login"); // Redirect to login page after logout
    });
  } else {
    res.redirect("/login"); // Redirect even if session is undefined
  }
});

// Profile Update Route
router.post("/profile/update", async (req, res) => {
  const { username, email, password } = req.body;
  let avatarUrl = req.session.avatarUrl;

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
      req.session.message = "Error updating profile. Please try again.";
      return res.redirect("/profile");
    }
    req.session.username = username;
    req.session.avatarUrl = avatarUrl;
    req.session.message = "Profile updated successfully!";
    res.redirect("/profile");
  });
});

// Account Deletion Route
router.post("/account/delete", (req, res) => {
  const query = "DELETE FROM users WHERE username = ?";
  db.query(query, [req.session.username], (err, result) => {
    if (err) {
      console.error("Error deleting account:", err);
      req.session.message = "Error deleting account. Please try again.";
      return res.redirect("/profile");
    }
    req.session.destroy((err) => {
      if (err) {
        console.error("Error logging out after account deletion:", err);
        req.session.message = "Account deleted, but error logging out.";
        return res.redirect("/profile");
      }
      res.clearCookie("connect.sid");
      req.session.message = "Account deleted successfully.";
      res.redirect("/login");
    });
  });
});

module.exports = router;
