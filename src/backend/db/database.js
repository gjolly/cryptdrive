/**
 * Initialize database schema if needed
 */
export async function initializeDatabase(db) {
	// Create users table
	await db
		.prepare(
			`
		CREATE TABLE IF NOT EXISTS users (
			user_id TEXT PRIMARY KEY,
			public_key TEXT NOT NULL,
			username TEXT NOT NULL UNIQUE,
			created_at TEXT NOT NULL,
			salt TEXT NOT NULL
		)
	`
		)
		.run();

	// Create files table
	await db
		.prepare(
			`
		CREATE TABLE IF NOT EXISTS files (
			file_id TEXT PRIMARY KEY,
			owner_hash TEXT NOT NULL,
			public BOOLEAN NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)
	`
		)
		.run();

	// Create index on owner_hash for efficient queries
	await db
		.prepare(
			`
		CREATE INDEX IF NOT EXISTS idx_owner_hash ON files(owner_hash)
	`
		)
		.run();

	// Create config table
	await db
		.prepare(
			`
		CREATE TABLE IF NOT EXISTS config (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)
	`
		)
		.run();

	// Create auth_rate_limits table
	await db
		.prepare(
			`
		CREATE TABLE IF NOT EXISTS auth_rate_limits (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			attempts INTEGER DEFAULT 0,
			failed_attempts INTEGER DEFAULT 0,
			last_attempt TEXT NOT NULL,
			window_start TEXT NOT NULL
		)
	`
		)
		.run();

	await db
		.prepare(
			`
		CREATE INDEX IF NOT EXISTS idx_type_window ON auth_rate_limits(type, window_start)
	`
		)
		.run();

	// Create registration_rate_limits table
	await db
		.prepare(
			`
		CREATE TABLE IF NOT EXISTS registration_rate_limits (
			fingerprint TEXT PRIMARY KEY,
			registrations INTEGER DEFAULT 0,
			captcha_required INTEGER DEFAULT 0,
			window_start TEXT NOT NULL
		)
	`
		)
		.run();

	// Create file_operation_limits table
	await db
		.prepare(
			`
		CREATE TABLE IF NOT EXISTS file_operation_limits (
			user_id TEXT PRIMARY KEY,
			read_requests INTEGER DEFAULT 0,
			write_requests INTEGER DEFAULT 0,
			window_start TEXT NOT NULL
		)
	`
		)
		.run();

	// Create anonymous_download_limits table
	await db
		.prepare(
			`
		CREATE TABLE IF NOT EXISTS anonymous_download_limits (
			ip_hash TEXT PRIMARY KEY,
			downloads INTEGER DEFAULT 0,
			captcha_required INTEGER DEFAULT 0,
			window_start TEXT NOT NULL
		)
	`
		)
		.run();

	// Create auth_challenges table
	await db
		.prepare(
			`
		CREATE TABLE IF NOT EXISTS auth_challenges (
			nonce TEXT PRIMARY KEY
		)
	`
		)
		.run();
}
