import { jsonResponse } from '../utils/response.js';
import { checkRegistrationRateLimit } from '../middleware/rate-limiting.js';
import { computeOwnerHash } from '../utils/crypto.js';
import { initializeDatabase } from '../db/database.js';

/**
 * Handle POST /user - Create new user
 */
export async function handleCreateUser(request, env, corsHeaders) {
	// Initialize database first
	await initializeDatabase(env.DB);

	// Check registration rate limit
	const rateLimitCheck = await checkRegistrationRateLimit(request, env);
	if (!rateLimitCheck.allowed) {
		return jsonResponse({ error: rateLimitCheck.error }, rateLimitCheck.status, corsHeaders);
	}

	let body;
	try {
		body = await request.json();
	} catch {
		return jsonResponse({ error: 'Invalid JSON' }, 400, corsHeaders);
	}

	const { public_key, keychain_id, salt, username } = body;

	// Validate input
	if (!public_key || typeof public_key !== 'string') {
		return jsonResponse({ error: 'public_key is required and must be a string' }, 400, corsHeaders);
	}

	// keychain_id should be a UUID string
	if (!keychain_id || typeof keychain_id !== 'string' || !/^[0-9a-fA-F-]{36}$/.test(keychain_id)) {
		return jsonResponse({ error: 'keychain_id is required and must be a valid UUID string' }, 400, corsHeaders);
	}

	// Validate salt
	if (!salt || typeof salt !== 'string') {
		return jsonResponse({ error: 'salt is required and must be a string' }, 400, corsHeaders);
	}

	// Validate username
	if (!username || typeof username !== 'string' || username.length < 3 || username.length > 30) {
		return jsonResponse({ error: 'username is required and must be between 3 and 30 characters' }, 400, corsHeaders);
	}

	// Validate public key format (base64)
	try {
		const decoded = atob(public_key);
		if (decoded.length !== 32) {
			return jsonResponse({ error: 'public_key must be a base64-encoded 32-byte Ed25519 public key' }, 400, corsHeaders);
		}
	} catch {
		return jsonResponse({ error: 'public_key must be valid base64' }, 400, corsHeaders);
	}

	// Generate unique IDs
	const user_id = crypto.randomUUID();

	// Check if public key already exists
	const existing = await env.DB.prepare('SELECT user_id FROM users WHERE username = ?').bind(username).first();

	if (existing) {
		return jsonResponse({ error: 'Username already registered' }, 409, corsHeaders);
	}

	// Create user in database
	await env.DB.prepare('INSERT INTO users (user_id, username, salt, public_key, created_at) VALUES (?, ?, ?, ?, ?)')
		.bind(user_id, username, salt, public_key, new Date().toISOString())
		.run();

	// create empty keychain file in R2
	await env.BUCKET.put(keychain_id, new Uint8Array(0));

	// Store file metadata in database
	const owner_hash = await computeOwnerHash(user_id, env);
	await env.DB.prepare('INSERT INTO files (file_id, owner_hash, created_at, updated_at) VALUES (?, ?, ?, ?)')
		.bind(keychain_id, owner_hash, new Date().toISOString(), new Date().toISOString())
		.run();

	// Return user_id to client
	return jsonResponse(
		{
			user_id,
		},
		201,
		corsHeaders
	);
}
