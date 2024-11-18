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
      name: `YourAppName (${req.session.username})`,
    });
  
    db.query(
      "UPDATE users SET two_factor_secret = ?, two_factor_enabled = ? WHERE id = ?",
      [secret.base32, true, userId],
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
      return res.json({ message: "2FA verified successfully!" });
    } else {
      return res.status(400).json({ message: "Invalid token. Try again." });
    }
  });
});

module.exports = router;
