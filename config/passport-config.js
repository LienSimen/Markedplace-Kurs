const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const GitHubStrategy = require("passport-github2").Strategy;
const db = require("./db");

// Serialize user to session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser((id, done) => {
  db.query("SELECT * FROM users WHERE id = ?", [id], (err, results) => {
    if (err) return done(err);
    done(null, results[0]);
  });
});

// Google OAuth Strategy
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "/auth/google/callback",
      },
      (accessToken, refreshToken, profile, done) => {
        // Check if user exists or create a new one
        db.query(
          "SELECT * FROM users WHERE provider_id = ? AND provider = 'google'",
          [profile.id],
          (err, results) => {
            if (err) return done(err);

            if (results.length > 0) {
              // Existing user
              return done(null, results[0]);
            } else {
              // New user
              const newUser = {
                username: profile.displayName,
                email: profile.emails?.[0]?.value || null,
                provider: "google",
                provider_id: profile.id,
                avatar_url: profile.photos?.[0]?.value || "/images/default-avatar.png",
              };

              db.query(
                "INSERT INTO users (username, email, provider, provider_id, avatar_url) VALUES (?, ?, ?, ?, ?)",
                [
                  newUser.username,
                  newUser.email,
                  newUser.provider,
                  newUser.provider_id,
                  newUser.avatar_url,
                ],
                (err, result) => {
                  if (err) return done(err);
                  newUser.id = result.insertId;
                  return done(null, newUser);
                }
              );
            }
          }
        );
      }
    )
  );
} else {
  console.warn("Google OAuth environment variables are missing. Google login will be disabled.");
}

// GitHub OAuth Strategy
if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  passport.use(
    new GitHubStrategy(
      {
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL: "/auth/github/callback",
      },
      (accessToken, refreshToken, profile, done) => {
        // Check if user exists or create a new one
        db.query(
          "SELECT * FROM users WHERE provider_id = ? AND provider = 'github'",
          [profile.id],
          (err, results) => {
            if (err) return done(err);

            if (results.length > 0) {
              // Existing user
              return done(null, results[0]);
            } else {
              // New user
              const newUser = {
                username: profile.username,
                email: profile.emails?.[0]?.value || null,
                provider: "github",
                provider_id: profile.id,
                avatar_url: profile.photos?.[0]?.value || "/images/default-avatar.png",
              };

              db.query(
                "INSERT INTO users (username, email, provider, provider_id, avatar_url) VALUES (?, ?, ?, ?, ?)",
                [
                  newUser.username,
                  newUser.email,
                  newUser.provider,
                  newUser.provider_id,
                  newUser.avatar_url,
                ],
                (err, result) => {
                  if (err) return done(err);
                  newUser.id = result.insertId;
                  return done(null, newUser);
                }
              );
            }
          }
        );
      }
    )
  );
} else {
  console.warn("GitHub OAuth environment variables are missing. GitHub login will be disabled.");
}

module.exports = passport;
