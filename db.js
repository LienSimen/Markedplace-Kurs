const mysql = require("mysql2");

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
});

db.connect((err) => {
  if (err) {
    console.error("Error connecting to database:", err);
    return;
  }
  console.log("Connected to database.");

  // Create the users table if it doesn't exist
  const createUsersTable = `
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) NOT NULL,
      email VARCHAR(100) NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      avatar_url VARCHAR(255) DEFAULT '/images/default-avatar.png',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;
  db.query(createUsersTable, (err, result) => {
    if (err) {
      console.error("Error creating users table:", err);
      return;
    }
    console.log("Users table ready or already exists.");
  });
});

module.exports = db;
