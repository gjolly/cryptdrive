-- Migration: 001_initial_schema
-- Description: Initial database schema setup
-- Created: 2026-03-07

-- Create users table
CREATE TABLE IF NOT EXISTS users (
	user_id TEXT PRIMARY KEY,
	public_key TEXT NOT NULL,
	username TEXT NOT NULL UNIQUE,
	created_at TEXT NOT NULL,
	salt TEXT NOT NULL
);

-- Create files table
CREATE TABLE IF NOT EXISTS files (
	file_id TEXT PRIMARY KEY,
	owner_hash TEXT NOT NULL,
	public BOOLEAN NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

-- Create index on owner_hash for efficient queries
CREATE INDEX IF NOT EXISTS idx_owner_hash ON files(owner_hash);

-- Create config table
CREATE TABLE IF NOT EXISTS config (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

-- Create auth_rate_limits table
CREATE TABLE IF NOT EXISTS auth_rate_limits (
	id TEXT PRIMARY KEY,
	type TEXT NOT NULL,
	attempts INTEGER DEFAULT 0,
	failed_attempts INTEGER DEFAULT 0,
	last_attempt TEXT NOT NULL,
	window_start TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_type_window ON auth_rate_limits(type, window_start);

-- Create registration_rate_limits table
CREATE TABLE IF NOT EXISTS registration_rate_limits (
	fingerprint TEXT PRIMARY KEY,
	registrations INTEGER DEFAULT 0,
	captcha_required INTEGER DEFAULT 0,
	window_start TEXT NOT NULL
);

-- Create file_operation_limits table
CREATE TABLE IF NOT EXISTS file_operation_limits (
	user_id TEXT PRIMARY KEY,
	read_requests INTEGER DEFAULT 0,
	write_requests INTEGER DEFAULT 0,
	window_start TEXT NOT NULL
);

-- Create anonymous_download_limits table
CREATE TABLE IF NOT EXISTS anonymous_download_limits (
	ip_hash TEXT PRIMARY KEY,
	downloads INTEGER DEFAULT 0,
	captcha_required INTEGER DEFAULT 0,
	window_start TEXT NOT NULL
);

-- Create auth_challenges table
CREATE TABLE IF NOT EXISTS auth_challenges (
	nonce TEXT PRIMARY KEY
);
