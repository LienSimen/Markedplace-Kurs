const express = require("express");
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");
const db = require("../config/db");

const router = express.Router();

// Generate QR Code and Secret
router.get("/setup", (req, res) => {
  const userId = req.session.userId;

  if (!userId) {
    return res.status(401).json({ message: "Please log in to set up 2FA." });
  }

  const secret = speakeasy.generateSecret({
    length: 20,
    name: `Gadgetzan Markedplace (${req.session.username})`,
  });

  db.query(
    "UPDATE users SET two_factor_secret = ? WHERE id = ?",
    [secret.base32, userId],
    (err) => {
      if (err) {
        console.error("Error saving 2FA secret:", err);
        return res.status(500).json({ message: "Failed to enable 2FA." });
      }

      qrcode.toDataURL(secret.otpauth_url, (err, qrCode) => {
        if (err) {
          console.error("Error generating QR Code:", err);
          return res.status(500).json({ message: "Failed to generate QR code." });
        }

        res.json({ qrCode, secret: secret.base32 });
      });
    }
  );
});

// Verify 2FA Token
router.post("/verify", (req, res) => {
  const userId = req.session.userId;
  const { token } = req.body;

  if (!userId || !token) {
    return res.status(400).json({ message: "Invalid request." });
  }

  db.query("SELECT two_factor_secret FROM users WHERE id = ?", [userId], (err, results) => {
    if (err || results.length === 0) {
      return res.status(500).json({ message: "Failed to verify 2FA." });
    }

    const isValid = speakeasy.totp.verify({
      secret: results[0].two_factor_secret,
      encoding: "base32",
      token,
    });

    if (isValid) {
      // Enable 2FA after successful verification
      db.query(
        "UPDATE users SET two_factor_enabled = ? WHERE id = ?",
        [true, userId],
        (err) => {
          if (err) {
            console.error("Error updating 2FA status:", err);
            return res.status(500).json({ message: "Failed to enable 2FA." });
          }
          return res.json({ message: "2FA verified and enabled successfully!" });
        }
      );
    } else {
      return res.status(400).json({ message: "Invalid token. Try again." });
    }
  });
});

// Disable 2FA
router.post("/disable", (req, res) => {
  const userId = req.session.userId;
  const { token } = req.body;

  if (!userId || !token) {
    req.session.message = "Invalid request.";
    return res.redirect("/profile");
  }

  db.query("SELECT two_factor_secret FROM users WHERE id = ?", [userId], (err, results) => {
    if (err || results.length === 0) {
      req.session.message = "Failed to disable 2FA.";
      return res.redirect("/profile");
    }

    const isValid = speakeasy.totp.verify({
      secret: results[0].two_factor_secret,
      encoding: "base32",
      token,
    });

    if (isValid) {
      db.query(
        "UPDATE users SET two_factor_enabled = ?, two_factor_secret = NULL WHERE id = ?",
        [false, userId],
        (err) => {
          if (err) {
            console.error("Error disabling 2FA:", err);
            req.session.message = "Failed to disable 2FA.";
            return res.redirect("/profile");
          }
          req.session.message = "Successfully disabled two-factor authentication.";
          return res.redirect("/profile");
        }
      );
    } else {
      req.session.message = "Invalid 2FA token. Try again.";
      res.redirect("/profile");
    }
  });
});


module.exports = router;
