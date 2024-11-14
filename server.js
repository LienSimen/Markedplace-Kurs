require("dotenv").config();
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const authRoutes = require("./routes/auth");

const db = require("./db"); 
const app = express();
const port = 3000;

// Session setup
app.use(
  session({
    secret: "your_secret_key",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false },
  })
);

const profileRoutes = require("./routes/profile");
app.use("/profile", profileRoutes);

// Static files and middleware
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));


// Middleware to handle flash messages
app.use((req, res, next) => {
  res.locals.message = req.session.message;
  delete req.session.message; // Clear the message after displaying it
  next();
});

// Template engine setup
app.set("view engine", "ejs");
app.set("views", "./views");

// Configure multer for avatar uploads
const upload = multer({
  dest: "public/uploads/", // Destination folder for uploaded files
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB file size limit
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png/;
    const extname = filetypes.test(file.originalname.toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    if (mimetype && extname) return cb(null, true);
    cb(new Error("Only JPEG, JPG, or PNG files are allowed."));
  },
});

// Home route
app.get("/", (req, res) => {
  res.render("index", {
    isLoggedIn: req.session.isLoggedIn,
    avatarUrl: req.session.avatarUrl, // Pass avatar URL to the view
  });
});

// Profile GET route for viewing profile
app.get("/profile", (req, res) => {
  if (!req.session.isLoggedIn) {
    return res.redirect("/login");
  }

  // Fetch the user's data from the database
  const query =
    "SELECT username, email, avatar_url FROM users WHERE username = ?";
  db.query(query, [req.session.username], (err, results) => {
    if (err) {
      console.error("Error fetching profile data:", err);
      return res.send("Error loading profile.");
    }

    if (results.length > 0) {
      const user = results[0];
      res.render("profile", {
        username: user.username,
        email: user.email, // Pass email to the view
        avatarUrl: user.avatar_url, // Pass avatar URL to the view
      });
    } else {
      res.redirect("/login");
    }
  });
});

// Profile POST route for updating profile
app.post("/profile/update", upload.single("avatar"), async (req, res) => {
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
    avatarUrl, // Make sure avatarUrl is included in the query values
    req.session.username,
  ];

  db.query(query, values, (err, result) => {
    if (err) {
      console.error("Error updating profile:", err);
      return res.send("Error updating profile.");
    }

    // Update session values only if the database update is successful
    req.session.username = username;
    req.session.avatarUrl = avatarUrl;
    req.session.message = "Profile updated successfully!";
    res.redirect("/profile");
  });
});


// Use auth routes for login, register, and logout
app.use("/", authRoutes);

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
