-- Create database (run this separately first)
-- CREATE DATABASE beekeeper;

-- Connect to the database and run the following:

-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Hives table
CREATE TABLE hives (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    location VARCHAR(200),
    type VARCHAR(50),
    strength VARCHAR(50),
    queen_age INTEGER,
    queen_color VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Inspections table
CREATE TABLE inspections (
    id SERIAL PRIMARY KEY,
    hive_id INTEGER REFERENCES hives(id) ON DELETE CASCADE,
    date DATE NOT NULL,
    brood_pattern VARCHAR(50),
    temperament VARCHAR(50),
    varroa_count INTEGER,
    honey_stores VARCHAR(50),
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Treatments table
CREATE TABLE treatments (
    id SERIAL PRIMARY KEY,
    hive_id INTEGER REFERENCES hives(id) ON DELETE CASCADE,
    type VARCHAR(100) NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    withdrawal_period INTEGER,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Harvests table
CREATE TABLE harvests (
    id SERIAL PRIMARY KEY,
    hive_id INTEGER REFERENCES hives(id) ON DELETE CASCADE,
    date DATE NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tasks table
CREATE TABLE tasks (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    hive_id INTEGER REFERENCES hives(id) ON DELETE CASCADE,
    date DATE NOT NULL,
    priority VARCHAR(20),
    completed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX idx_hives_user_id ON hives(user_id);
CREATE INDEX idx_inspections_hive_id ON inspections(hive_id);
CREATE INDEX idx_treatments_hive_id ON treatments(hive_id);
CREATE INDEX idx_harvests_hive_id ON harvests(hive_id);
CREATE INDEX idx_tasks_user_id ON tasks(user_id);
CREATE INDEX idx_tasks_hive_id ON tasks(hive_id);
