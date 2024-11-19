const express = require("express");
const bcrypt = require("bcryptjs");
const speakeasy = require("speakeasy");
const db = require("../config/db");
const passport = require("passport");
const router = express.Router();

// for email verification and password reset
const crypto = require("crypto");
const sendEmail = require("../utils/email");

// Middleware to check if the user is logged in
const redirectIfLoggedIn = (req, res, next) => {
  if (req.session.isLoggedIn) {
    return res.redirect("/");
  }
  next();
};

// Google Authentication
router.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

router.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    const username = req.user.username;
    db.query(
      "SELECT * FROM users WHERE username = ?",
      [username],
      (err, results) => {
        if (err || results.length === 0) {
          req.session.message = "An error occurred. Please try again.";
          return res.redirect("/login");
        }
        const user = results[0];
        if (user.two_factor_enabled) {
          req.session.isLoggedIn = false; // Wait for 2FA to complete
          req.session.userId = user.id;
          req.session.username = username;
          res.redirect("/2fa/login");
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
      }
    );
  }
);

// GitHub Authentication
router.get(
  "/auth/github",
  passport.authenticate("github", { scope: ["user:email"] })
);

router.get(
  "/auth/github/callback",
  passport.authenticate("github", { failureRedirect: "/login" }),
  (req, res) => {
    const username = req.user.username;
    db.query(
      "SELECT * FROM users WHERE username = ?",
      [username],
      (err, results) => {
        if (err || results.length === 0) {
          req.session.message = "An error occurred. Please try again.";
          return res.redirect("/login");
        }
        const user = results[0];
        if (user.two_factor_enabled) {
          req.session.isLoggedIn = false;
          req.session.userId = user.id;
          req.session.username = username;
          res.redirect("/2fa/login");
        } else {
          req.session.isLoggedIn = true;
          req.session.userId = user.id;
          req.session.username = username;
          req.session.avatarUrl = user.avatar_url;
          req.session.message = `Welcome back, ${username}!`;
          res.redirect("/");
        }
      }
    );
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
      req.session.userId = result.insertId;
      req.session.username = username;
      req.session.avatarUrl = "/images/default-avatar.png";
      req.session.message = `Registration successful! Welcome, ${username}!`;
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
      req.session.userId = user.id; // Store user ID in session
      req.session.username = user.username; // Store username in session
      req.session.email = user.email; // Store email in session
      req.session.avatarUrl = user.avatar_url;
      req.session.message = "Successfully logged in!";
      res.redirect("/profile");
    } else {
      req.session.message = "Invalid username or password.";
      res.redirect("/login");
    }
  });
});

router.get("/forgot-password", (req, res) => {
  res.render("forgot-password", {
    message: req.session.message || null, // Pass any flash messages
    darkMode: req.session.darkMode || false, // Pass dark mode preference
  });
});


router.post("/forgot-password", (req, res) => {
  const { email } = req.body;

  // Generate a new random password
  const newPassword = crypto.randomBytes(8).toString("hex");
  console.log("Generated Password:", newPassword); // Log the plain text password

  // Hash the new password
  bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
    if (err) {
      console.error("Error hashing password:", err);
      req.session.message = "An error occurred. Please try again.";
      return res.redirect("/forgot-password");
    }

    console.log("Hashed Password:", hashedPassword); // Log the hashed password

    // Update the user's password in the database
    const query = "UPDATE users SET password_hash = ? WHERE email = ?";
    db.query(query, [hashedPassword, email], (dbErr, result) => {
      if (dbErr || result.affectedRows === 0) {
        console.error("Error updating password:", dbErr);
        req.session.message = "Email not found. Please try again.";
        return res.redirect("/forgot-password");
      }

      // Send the new password via email
      sendEmail(
        email,
        "Your New Password",
        `Your new password is: ${newPassword}`
      )
        .then(() => {
          req.session.message = "New password sent to your email.";
          res.redirect("/login");
        })
        .catch((emailErr) => {
          console.error("Error sending email:", emailErr);
          req.session.message = "Failed to send email. Please try again.";
          res.redirect("/forgot-password");
        });
    });
  });
});


// 2FA Login Page
router.get("/2fa/login", (req, res) => {
  if (!req.session.userId) {
    return res.redirect("/login");
  }
  res.render("2fa-login", {
    username: req.session.username,
    message: req.session.message || null,
    darkMode: req.session.darkMode || false,
  });
});

// 2FA Verification During Login
router.post("/2fa/login", (req, res) => {
  const { token } = req.body;

  if (!req.session.userId || !token) {
    req.session.message = "Invalid request.";
    return res.redirect("/login");
  }

  db.query(
    "SELECT * FROM users WHERE id = ?",
    [req.session.userId],
    (err, results) => {
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
        req.session.isLoggedIn = true;
        req.session.avatarUrl = user.avatar_url;
        req.session.darkMode = user.dark_mode;
        req.session.message = "Successfully logged in!";
        res.redirect("/");
      } else {
        req.session.message = "Invalid 2FA token. Try again.";
        res.redirect("/2fa/login");
      }
    }
  );
});

// Update Dark Mode Preference
router.post("/dark-mode", (req, res) => {
  if (!req.session.isLoggedIn) {
    return res.status(401).send("Unauthorized");
  }

  const darkMode = req.body.darkMode ? 1 : 0; // Convert boolean to integer for MySQL
  const query = "UPDATE users SET dark_mode = ? WHERE username = ?";

  db.query(query, [darkMode, req.session.username], (err, result) => {
    if (err) {
      console.error("Error updating dark mode preference:", err);
      return res.status(500).send("Failed to update dark mode preference.");
    }

    req.session.darkMode = darkMode; // Update session value
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
