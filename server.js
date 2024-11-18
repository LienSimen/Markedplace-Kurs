require("dotenv").config();
const express = require("express");
const session = require("express-session");
const authRoutes = require("./routes/auth");
const profileRoutes = require("./routes/profile");
const passport = require("./config/passport-config");
const twoFactorRoutes = require("./routes/twoFactor");
const app = express();
const port = 3000;

//  Session Setup 
app.use(
  session({
    secret: "your_secret_key",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false },
  })
);

//  Passport Middleware 
app.use(passport.initialize());
app.use(passport.session());

//  Middleware for Static Files and Parsing 
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

//  Flash Messages Middleware 
app.use((req, res, next) => {
  res.locals.message = req.session.message || null;
  delete req.session.message; // Clear flash message after displaying
  next();
});

//  Template Engine Setup 
app.set("view engine", "ejs");
app.set("views", "./views");

//  Home Route 
app.get("/", (req, res) => {
  res.render("index", {
    isLoggedIn: req.session.isLoggedIn || false,
    avatarUrl: req.session.avatarUrl || null,
    darkMode: req.session.darkMode || false,
  });
});

// 2FA Routes
app.use("/2fa", twoFactorRoutes);

//  Authentication Routes 
app.use("/", authRoutes);

//  Profile Routes 
app.use("/profile", profileRoutes);

//  Start the Server 
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
