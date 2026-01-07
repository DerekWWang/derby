-- Create Contracts Table
CREATE TABLE IF NOT EXISTS contracts (
    id TEXT PRIMARY KEY NOT NULL,          -- UUID stored as TEXT
    m_id TEXT NOT NULL,
    c_id TEXT NOT NULL,                    -- creator UUID
    total_amount INTEGER NOT NULL,
    rules TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    closing_timestamp INTEGER NOT NULL,
    state INTEGER NOT NULL DEFAULT 0       -- 0=Open, 1=Filled, 2=Cancelled
);

-- Create Orders Table
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    u_id TEXT NOT NULL,                    -- user UUID
    contract_id TEXT NOT NULL,             -- contract UUID
    side INTEGER NOT NULL,                 -- 0=Yes, 1=No
    amount INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    FOREIGN KEY (contract_id) REFERENCES contracts (id) ON DELETE CASCADE
);

-- Create Users Table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

-- Create Wallets Table
CREATE TABLE IF NOT EXISTS wallets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    current_amount INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);