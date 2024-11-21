const express = require("express");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const db = require("../config/db");
const router = express.Router();
const crypto = require("crypto");
const sendEmail = require("../utils/email"); // Utility for sending emails

//  Middleware to Check Authentication 
function isAuthenticated(req, res, next) {
  if (req.session || req.session.isLoggedIn) {
    return next();
  }
  res.redirect("/login");
}

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
    });
  });
});

router.post(
  "/update",
  isAuthenticated,
  upload.single("avatar"),
  async (req, res) => {
    const {
      username,
      email,
      currentPassword,
      newPassword,
      confirmNewPassword,
    } = req.body;

    // Ensure username and email fields are not empty
    if (!username || !email) {
      req.session.message = "Username and email cannot be empty.";
      return res.redirect("/profile");
    }

    let avatarUrl = req.session.avatarUrl || "/images/default-avatar.png";
    if (req.file) {
      avatarUrl = `/uploads/${req.file.filename}`;
    }

    const currentEmail = req.session.email;
    const isEmailChanged = email !== currentEmail;

    // 1. Handle Email Change
    if (isEmailChanged) {
      const emailUpdateToken = crypto
        .createHash("sha256")
        .update(email + process.env.SECRET_KEY)
        .digest("hex");

      const confirmationUrl = `${req.protocol}://${req.get(
        "host"
      )}/profile/confirm-email?token=${emailUpdateToken}&newEmail=${encodeURIComponent(
        email
      )}`;
      await sendEmail(
        currentEmail,
        "Confirm Your Email Update",
        `Click this link to confirm email: ${confirmationUrl}`
      )
        .then(() => {
          req.session.message =
            "Confirmation email sent. Please verify your email.";
        })
        .catch((err) => {
          console.error("Error sending email:", err);
          req.session.message =
            "Failed to send email confirmation. Please try again.";
        });
    }

    // 2. Handle Password Change
    if (currentPassword || newPassword || confirmNewPassword) {
      if (!currentPassword || !newPassword || !confirmNewPassword) {
        req.session.message = "All password fields are required.";
        return res.redirect("/profile");
      }

      if (newPassword !== confirmNewPassword) {
        req.session.message = "New password and confirmation do not match.";
        return res.redirect("/profile");
      }

      const passwordQuery = "SELECT password_hash FROM users WHERE id = ?";
      db.query(passwordQuery, [req.session.userId], async (err, results) => {
        if (err || results.length === 0) {
          req.session.message =
            "Error verifying current password. Please try again.";
          return res.redirect("/profile");
        }

        const isPasswordValid = await bcrypt.compare(
          currentPassword,
          results[0].password_hash
        );

        if (!isPasswordValid) {
          req.session.message = "Current password is incorrect.";
          return res.redirect("/profile");
        }

        const passwordHash = await bcrypt.hash(newPassword, 10);
        const updatePasswordQuery =
          "UPDATE users SET password_hash = ? WHERE id = ?";
        db.query(
          updatePasswordQuery,
          [passwordHash, req.session.userId],
          (err) => {
            if (err) {
              req.session.message = "Error updating password.";
              return res.redirect("/profile");
            }

            req.session.message = "Password updated successfully!";
          }
        );
      });
    }

    // 3. Handle Username and Avatar Change
    const query = `
      UPDATE users 
      SET username = ?, avatar_url = ? 
      WHERE id = ?
    `;
    db.query(query, [username, avatarUrl, req.session.userId], (err) => {
      if (err) {
        req.session.message = "Error updating profile.";
        return res.redirect("/profile");
      }

      req.session.username = username;
      req.session.avatarUrl = avatarUrl;
      req.session.message = "Profile updated successfully!";
      res.redirect("/profile");
    });
  }
);



router.get("/confirm-email", isAuthenticated, (req, res) => {
  const { token, newEmail } = req.query;

  if (!token || !newEmail) {
    req.session.message = "Invalid confirmation link.";
    return res.redirect("/profile");
  }

  // Generate the expected token for comparison
  const expectedToken = crypto
    .createHash("sha256")
    .update(newEmail + process.env.SECRET_KEY)
    .digest("hex");

  // Validate the token
  if (token !== expectedToken) {
    req.session.message = "Invalid or expired confirmation link.";
    return res.redirect("/profile");
  }

  // Update the email in the database
  const query = "UPDATE users SET email = ? WHERE id = ?";
  db.query(query, [newEmail, req.session.userId], (err) => {
    if (err) {
      console.error("Error updating email:", err);
      req.session.message = "Error updating email. Please try again.";
      return res.redirect("/profile");
    }

    // Update the session email
    req.session.email = newEmail;
    req.session.message = "Email updated successfully!";
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