-- Drop existing tables if they exist
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS files;
DROP TABLE IF EXISTS keys;
DROP TABLE IF EXISTS file_hashes;

-- Create tables
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);

CREATE TABLE files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    content BLOB NOT NULL,
    encrypted_content BLOB,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- Added upload_date column
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    key_data TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE file_hashes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL,
    hash_type TEXT NOT NULL,
    hash_value TEXT NOT NULL,
    FOREIGN KEY(file_id) REFERENCES files(id)
);
