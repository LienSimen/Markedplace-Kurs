const express = require("express");
const bcrypt = require("bcryptjs");
const speakeasy = require("speakeasy");
const db = require("../config/db"); 
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
    const username = req.user.username;
    db.query("SELECT * FROM users WHERE username = ?", [username], (err, results) => {
      if (err || results.length === 0) {
        req.session.message = "An error occurred. Please try again.";
        return res.redirect("/login");
      }
      const user = results[0];
      if (user.two_factor_enabled) {
        // Store minimal session data
        req.session.tempUserId = user.id;
        req.session.tempUsername = username;
        // Redirect to 2FA verification page
        return res.redirect("/2fa/login");
      } else {
        // Complete login
        req.session.isLoggedIn = true;
        req.session.userId = user.id;
        req.session.username = username;
        req.session.avatarUrl = user.avatar_url;
        req.session.darkMode = user.dark_mode;
        req.session.message = `Welcome back, ${username}!`;
        res.redirect("/");
      }
    });
  }
);

// GitHub Authentication
router.get("/auth/github", passport.authenticate("github", { scope: ["user:email"] }));

router.get(
  "/auth/github/callback",
  passport.authenticate("github", { failureRedirect: "/login" }),
  (req, res) => {
    const username = req.user.username;
    db.query("SELECT * FROM users WHERE username = ?", [username], (err, results) => {
      if (err || results.length === 0) {
        req.session.message = "An error occurred. Please try again.";
        return res.redirect("/login");
      }
      const user = results[0];
      if (user.two_factor_enabled) {
        // Store minimal session data
        req.session.tempUserId = user.id;
        req.session.tempUsername = username;
        req.session.avatarUrl = user.avatar_url;
        // Redirect to 2FA verification page
        return res.redirect("/2fa/login");
      } else {
        // Complete login
        req.session.isLoggedIn = true;
        req.session.userId = user.id;
        req.session.username = username;
        req.session.avatarUrl = user.avatar_url;
        req.session.message = `Welcome back, ${username}!`;
        res.redirect("/");
      }
    });
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


// Login Route
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
      if (user.two_factor_enabled) {
        // Store minimal session data
        req.session.tempUserId = user.id;
        req.session.tempUsername = username;
        // Redirect to 2FA verification page
        return res.redirect("/2fa/login");
      } else {
        // Complete login
        req.session.isLoggedIn = true;
        req.session.userId = user.id;
        req.session.username = username;
        req.session.avatarUrl = user.avatar_url;
        req.session.darkMode = user.dark_mode;
        req.session.message = "Successfully logged in!";
        res.redirect("/");
      }
    } else {
      req.session.message = "Invalid username or password.";
      res.redirect("/login");
    }
  });
});

// GET 2FA Login Page
router.get("/2fa/login", (req, res) => {
  if (!req.session.tempUserId) {
    return res.redirect("/login");
  }
  res.render("2fa-login", {
    username: req.session.tempUsername,
    message: req.session.message || null,
    darkMode: req.session.darkMode || false,
  });
});

// POST 2FA Verification During Login
router.post("/2fa/login", (req, res) => {
  const { token } = req.body;
  const userId = req.session.tempUserId;

  if (!userId || !token) {
    req.session.message = "Invalid request.";
    return res.redirect("/login");
  }

  db.query("SELECT * FROM users WHERE id = ?", [userId], (err, results) => {
    if (err || results.length === 0) {
      req.session.message = "Failed to verify 2FA.";
      return res.redirect("/login");
    }

    const user = results[0];

    const isValid = speakeasy.totp.verify({
      secret: user.two_factor_secret,
      encoding: "base32",
      token,
    });

    if (isValid) {
      // Complete login
      req.session.isLoggedIn = true;
      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.avatarUrl = user.avatar_url;
      req.session.darkMode = user.dark_mode;
      // Clear temporary session variables
      req.session.tempUserId = null;
      req.session.tempUsername = null;
      req.session.message = "Successfully logged in!";
      res.redirect("/");
    } else {
      req.session.message = "Invalid 2FA token. Try again.";
      res.redirect("/2fa/login");
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


module.exports = router;
