-- Create group_auth_config table
CREATE TABLE IF NOT EXISTS group_auth_config (
    id INTEGER PRIMARY KEY,
    application TEXT NOT NULL,
    region TEXT NOT NULL,
    environment TEXT NOT NULL,
    auth_url TEXT NOT NULL,
    auth_username TEXT NOT NULL,
    auth_password TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(application, region, environment)
);
