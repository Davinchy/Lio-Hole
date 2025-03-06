-- LioHole Database Schema
-- Schema for the main SQLite database

PRAGMA foreign_keys = ON;

-- Information table for database metadata
CREATE TABLE IF NOT EXISTS info (
    key TEXT PRIMARY KEY,
    value TEXT
);

-- Table for configuration settings
CREATE TABLE IF NOT EXISTS config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE,
    value TEXT,
    comment TEXT
);

-- Table for statistics
CREATE TABLE IF NOT EXISTS stats (
    key TEXT PRIMARY KEY,
    value TEXT
);

-- Table for blocklist sources
CREATE TABLE IF NOT EXISTS blocklists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE,
    enabled INTEGER DEFAULT 1,
    status TEXT DEFAULT 'new',
    domain_count INTEGER DEFAULT 0,
    last_updated TIMESTAMP DEFAULT NULL, 
    date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    comment TEXT
);

-- Table for domains from blocklists
CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT,
    blocklist_id INTEGER,
    date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (blocklist_id) REFERENCES blocklists(id) ON DELETE CASCADE,
    UNIQUE(domain, blocklist_id)
);

-- Index for faster domain lookups
CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain);

-- Table for exact matched allowlisted domains
CREATE TABLE IF NOT EXISTS allowlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE,
    enabled INTEGER DEFAULT 1,
    date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    comment TEXT
);

-- Table for exact matched blocklisted domains
CREATE TABLE IF NOT EXISTS blocklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE,
    enabled INTEGER DEFAULT 1,
    date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    comment TEXT
);

-- Table for regex patterns for allowlisting
CREATE TABLE IF NOT EXISTS regex_allowlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    regex TEXT UNIQUE,
    enabled INTEGER DEFAULT 1,
    date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    comment TEXT
);

-- Table for regex patterns for blocklisting
CREATE TABLE IF NOT EXISTS regex_blocklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    regex TEXT UNIQUE,
    enabled INTEGER DEFAULT 1,
    date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    comment TEXT
);

-- Table for DNS query log
CREATE TABLE IF NOT EXISTS query_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    client TEXT,
    domain TEXT,
    type TEXT,
    blocked INTEGER DEFAULT 0,
    forwarded INTEGER DEFAULT 0,
    cached INTEGER DEFAULT 0
);

-- Index for faster timestamp queries in the log
CREATE INDEX IF NOT EXISTS idx_query_log_timestamp ON query_log(timestamp);

-- Table for clients
CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE,
    hostname TEXT,
    description TEXT,
    date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Initialize info table
INSERT OR IGNORE INTO info (key, value) VALUES ('schema_version', '1');
INSERT OR IGNORE INTO info (key, value) VALUES ('created_date', CURRENT_TIMESTAMP);

-- Initialize stats
INSERT OR IGNORE INTO stats (key, value) VALUES ('total_domains', '0');
INSERT OR IGNORE INTO stats (key, value) VALUES ('queries_today', '0');
INSERT OR IGNORE INTO stats (key, value) VALUES ('blocked_today', '0');
INSERT OR IGNORE INTO stats (key, value) VALUES ('last_gravity_update', NULL);

-- Add some default adlist sources
INSERT OR IGNORE INTO blocklists (url, comment) VALUES 
('https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', 'StevenBlack unified hosts list'),
('https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt', 'Disconnect.me Ads'),
('https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt', 'Disconnect.me Tracking');