-- Create alert_contacts table
CREATE TABLE IF NOT EXISTS alert_contacts (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create group_alert_contacts table for mapping contacts to groups
CREATE TABLE IF NOT EXISTS group_alert_contacts (
    id INTEGER PRIMARY KEY,
    contact_id INTEGER NOT NULL,
    application TEXT NOT NULL,
    region TEXT NOT NULL,
    environment TEXT NOT NULL,
    notify_on_warning BOOLEAN NOT NULL DEFAULT 1,
    notify_on_critical BOOLEAN NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (contact_id) REFERENCES alert_contacts(id),
    UNIQUE(contact_id, application, region, environment)
);
