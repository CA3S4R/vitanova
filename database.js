const Database = require("better-sqlite3")

const db = new Database("./data/users.db")

db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT,
        github_id TEXT UNIQUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`).run();

console.log("Database ready.");

module.exports = db;