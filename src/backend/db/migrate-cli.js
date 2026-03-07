#!/usr/bin/env node

/**
 * Database Migration CLI Helper
 *
 * This script helps apply database migrations to Cloudflare D1
 *
 * Usage:
 *   npm run migrate:local          # Apply migrations to local D1 database
 *   npm run migrate:prod           # Apply migrations to production D1 database
 *   npm run migrate:status:local   # Check migration status locally
 *   npm run migrate:status:prod    # Check migration status in production
 */

import { execSync } from 'child_process';
import { readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = join(__dirname, 'migrations');
const DB_NAME = 'cryptdrive';

// Parse command line arguments
const args = process.argv.slice(2);
const command = args[0] || 'apply';
const environment = args[1] || 'local';

const isLocal = environment === 'local';
const envFlag = isLocal ? '--local' : '--remote';

console.log(`🗄️  Database Migration Tool`);
console.log(`Environment: ${environment}`);
console.log(`Database: ${DB_NAME}`);
console.log('');

/**
 * Get all migration files sorted by number
 */
function getMigrationFiles() {
	try {
		const files = readdirSync(MIGRATIONS_DIR)
			.filter((file) => file.endsWith('.sql') && file.match(/^\d+_/))
			.sort();
		return files;
	} catch (error) {
		console.error('❌ Error reading migrations directory:', error.message);
		process.exit(1);
	}
}

/**
 * Execute a SQL file against D1
 */
function executeMigration(filename) {
	const filepath = join(MIGRATIONS_DIR, filename);
	const cmd = `npx wrangler d1 execute ${DB_NAME} ${envFlag} --file="${filepath}"`;

	console.log(`📝 Applying: ${filename}`);
	try {
		execSync(cmd, { stdio: 'inherit' });
		console.log(`✅ Success: ${filename}\n`);
		return true;
	} catch (error) {
		console.error(`❌ Failed: ${filename}:`, error.message);
		return false;
	}
}

/**
 * Initialize migrations table
 */
function initializeMigrationsTable() {
	const sql = `
		CREATE TABLE IF NOT EXISTS migrations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			applied_at TEXT NOT NULL
		);
	`;

	const cmd = `npx wrangler d1 execute ${DB_NAME} ${envFlag} --command="${sql}"`;

	try {
		execSync(cmd, { stdio: 'pipe' });
		return true;
	} catch (error) {
		console.error('❌ Failed to initialize migrations table:', error.message);
		return false;
	}
}

/**
 * Get applied migrations from database
 */
function getAppliedMigrations() {
	const cmd = `npx wrangler d1 execute ${DB_NAME} ${envFlag} --command="SELECT name FROM migrations ORDER BY id" --json`;

	try {
		const output = execSync(cmd, { encoding: 'utf8' });
		const result = JSON.parse(output);

		// Wrangler returns an array with results
		if (result && result[0] && result[0].results) {
			return result[0].results.map((row) => row.name);
		}

		return [];
	} catch {
		// Table might not exist yet
		return [];
	}
}

/**
 * Record a migration as applied
 */
function recordMigration(filename) {
	const name = filename.replace('.sql', '');
	const timestamp = new Date().toISOString();
	const sql = `INSERT INTO migrations (name, applied_at) VALUES ('${name}', '${timestamp}')`;
	const cmd = `npx wrangler d1 execute ${DB_NAME} ${envFlag} --command="${sql}"`;

	try {
		execSync(cmd, { stdio: 'pipe' });
		return true;
	} catch (error) {
		console.error(`❌ Failed to record migration: ${filename}:`, error.message);
		return false;
	}
}

/**
 * Show migration status
 */
function showStatus() {
	console.log('📊 Migration Status\n');

	// Initialize migrations table
	initializeMigrationsTable();

	const allMigrations = getMigrationFiles();
	const appliedMigrations = getAppliedMigrations();
	const appliedSet = new Set(appliedMigrations.map((m) => m + '.sql'));

	console.log(`Total migrations: ${allMigrations.length}`);
	console.log(`Applied: ${appliedMigrations.length}`);
	console.log(`Pending: ${allMigrations.length - appliedMigrations.length}\n`);

	if (allMigrations.length === 0) {
		console.log('⚠️  No migration files found');
		return;
	}

	console.log('Migrations:');
	for (const migration of allMigrations) {
		const isApplied = appliedSet.has(migration);
		const status = isApplied ? '✅' : '⏳';
		console.log(`  ${status} ${migration}`);
	}
}

/**
 * Apply all pending migrations
 */
function applyMigrations() {
	console.log('🚀 Applying Migrations\n');

	// Initialize migrations table
	if (!initializeMigrationsTable()) {
		process.exit(1);
	}

	const allMigrations = getMigrationFiles();
	const appliedMigrations = getAppliedMigrations();
	const appliedSet = new Set(appliedMigrations.map((m) => m + '.sql'));

	const pendingMigrations = allMigrations.filter((m) => !appliedSet.has(m));

	if (pendingMigrations.length === 0) {
		console.log('✨ No pending migrations. Database is up to date!\n');
		return;
	}

	console.log(`Found ${pendingMigrations.length} pending migration(s)\n`);

	let success = 0;
	let failed = 0;

	for (const migration of pendingMigrations) {
		if (executeMigration(migration)) {
			if (recordMigration(migration)) {
				success++;
			} else {
				failed++;
				console.error('⚠️  Migration applied but not recorded in migrations table');
			}
		} else {
			failed++;
			console.error('❌ Stopping migration process due to failure\n');
			break;
		}
	}

	console.log('\n📊 Summary:');
	console.log(`  ✅ Applied: ${success}`);
	if (failed > 0) {
		console.log(`  ❌ Failed: ${failed}`);
		process.exit(1);
	}
	console.log('\n✨ All migrations completed successfully!');
}

// Main execution
switch (command) {
	case 'status':
		showStatus();
		break;
	case 'apply':
		applyMigrations();
		break;
	default:
		console.error('❌ Unknown command:', command);
		console.log('\nUsage:');
		console.log('  node migrate-cli.js apply [local|prod]   # Apply pending migrations');
		console.log('  node migrate-cli.js status [local|prod]  # Show migration status');
		process.exit(1);
}
