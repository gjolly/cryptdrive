import { authenticateRequest } from '../middleware/auth.js';
import { jsonResponse } from '../utils/response.js';
import { checkFileOperationRateLimit, checkAnonymousDownloadRateLimit } from '../middleware/rate-limiting.js';
import { initializeDatabase } from '../db/database.js';
import { computeOwnerHash } from '../utils/crypto.js';
import { getClient, getDownloadUrl } from '../utils/multipart.js';

/**
 * Handle GET /files - List files owned by authenticated user
 */
export async function handleListFiles(request, env, corsHeaders) {
	// Authenticate request
	const auth = await authenticateRequest(request, env);
	if (auth.error) {
		return jsonResponse({ error: auth.error }, auth.status, corsHeaders);
	}

	const user_id = auth.user_id;

	// Check rate limit (read operation)
	const rateLimitCheck = await checkFileOperationRateLimit(user_id, env, false);
	if (!rateLimitCheck.allowed) {
		return jsonResponse({ error: rateLimitCheck.error }, rateLimitCheck.status, corsHeaders);
	}

	// Initialize database
	await initializeDatabase(env.DB);

	// Compute owner hash
	const owner_hash = await computeOwnerHash(user_id, env);

	// Query files owned by this user
	const files = await env.DB.prepare('SELECT file_id, created_at, updated_at FROM files WHERE owner_hash = ? ORDER BY created_at DESC')
		.bind(owner_hash)
		.all();

	// Return file list
	return jsonResponse(
		{
			files: files.results || [],
		},
		200,
		corsHeaders
	);
}

/**
 * Handle POST /file - Create new file
 */
export async function handleCreateFile(request, env, corsHeaders) {
	// Initialize database
	await initializeDatabase(env.DB);

	// Authenticate request
	const { user_id, error, status } = await authenticateRequest(request, env);
	if (error) {
		return jsonResponse({ error }, status, corsHeaders);
	}

	// Check rate limit (write operation)
	const rateLimitCheck = await checkFileOperationRateLimit(user_id, env, true);
	if (!rateLimitCheck.allowed) {
		return jsonResponse({ error: rateLimitCheck.error }, rateLimitCheck.status, corsHeaders);
	}

	// Generate unique file ID
	const fileId = crypto.randomUUID();

	// Compute owner hash
	const ownerHash = await computeOwnerHash(user_id, env);

	// Store metadata in D1
	const now = new Date().toISOString();

	try {
		await env.DB.prepare(
			`
			INSERT INTO files (file_id, owner_hash, created_at, updated_at)
			VALUES (?, ?, ?, ?)
		`
		)
			.bind(fileId, ownerHash, now, now)
			.run();
	} catch (err) {
		// Rollback R2 upload on database error
		console.error('Database insert error:', err);
		return jsonResponse({ error: 'Failed to store file metadata' }, 500, corsHeaders);
	}

	// Return file ID
	return jsonResponse(
		{
			file_id: fileId,
		},
		201,
		corsHeaders
	);
}

/**
 * Handle GET /file/:file_id - Get file
 */
export async function handleGetFile(request, env, corsHeaders, fileId) {
	// Initialize database
	await initializeDatabase(env.DB);

	// Check if file exists
	const file = await env.DB.prepare('SELECT * FROM files WHERE file_id = ?').bind(fileId).first();

	if (!file) {
		return jsonResponse({ error: 'File not found' }, 404, corsHeaders);
	}

	if (!file.public) {
		// Authenticate request
		const { user_id, error, status } = await authenticateRequest(request, env);
		if (error) {
			return jsonResponse({ error }, status, corsHeaders);
		}

		// Compute owner hash for authenticated user
		const ownerHash = await computeOwnerHash(user_id, env);

		if (file.owner_hash !== ownerHash) {
			return jsonResponse({ error: 'File not found' }, 404, corsHeaders);
		}
	} else {
		// Check rate limit for anonymous downloads
		const checkAnonymousDownloadRateLimitResult = await checkAnonymousDownloadRateLimit(request, env);
		if (!checkAnonymousDownloadRateLimitResult.allowed) {
			return jsonResponse(
				{
					error: checkAnonymousDownloadRateLimitResult.error,
				},
				checkAnonymousDownloadRateLimitResult.status,
				corsHeaders
			);
		}
	}

	// Get file from R2
	try {
		const { client, r2Url } = getClient(env);
		const url = await getDownloadUrl(client, r2Url, fileId, 300); // URL valid for 5min
		return jsonResponse({ url }, 200, corsHeaders);
	} catch (err) {
		console.error('R2 get error:', err);
		return jsonResponse({ error: 'Failed to retrieve file' }, 500, corsHeaders);
	}
}

/*
 * Handle POST /file/:file_id/publish - Publish file (make it public)
 * This doesn't mean the file content is readable by everyone,
 * it's still encrypted and can only be decrypted by someone with the key.
 */
export async function handlePublishFile(request, env, corsHeaders, fileId) {
	// Initialize database
	await initializeDatabase(env.DB);

	// Authenticate request
	const { user_id, error, status } = await authenticateRequest(request, env);
	if (error) {
		return jsonResponse({ error }, status, corsHeaders);
	}

	// Check rate limit (write operation)
	const rateLimitCheck = await checkFileOperationRateLimit(user_id, env, true);
	if (!rateLimitCheck.allowed) {
		return jsonResponse({ error: rateLimitCheck.error }, rateLimitCheck.status, corsHeaders);
	}

	// Compute owner hash for authenticated user
	const ownerHash = await computeOwnerHash(user_id, env);

	// Check if file exists and verify ownership
	const file = await env.DB.prepare('SELECT owner_hash FROM files WHERE file_id = ?').bind(fileId).first();

	if (!file) {
		return jsonResponse({ error: 'File not found' }, 404, corsHeaders);
	}

	if (file.owner_hash !== ownerHash) {
		return jsonResponse({ error: 'Not file owner' }, 403, corsHeaders);
	}

	// Update file to be public
	try {
		await env.DB.prepare('UPDATE files SET public = 1, updated_at = ? WHERE file_id = ?').bind(new Date().toISOString(), fileId).run();
	} catch (err) {
		console.error('Database update error:', err);
		return jsonResponse({ error: 'Failed to publish file' }, 500, corsHeaders);
	}

	return jsonResponse({ success: true }, 200, corsHeaders);
}

/**
 * Handle DELETE /file/:file_id - Delete file
 */
export async function handleDeleteFile(request, env, fileId, corsHeaders) {
	// Initialize database
	await initializeDatabase(env.DB);

	// Authenticate request
	const { user_id, error, status } = await authenticateRequest(request, env);
	if (error) {
		return jsonResponse({ error }, status, corsHeaders);
	}

	// Check rate limit (write operation)
	const rateLimitCheck = await checkFileOperationRateLimit(user_id, env, true);
	if (!rateLimitCheck.allowed) {
		return jsonResponse({ error: rateLimitCheck.error }, rateLimitCheck.status, corsHeaders);
	}

	// Compute owner hash for authenticated user
	const ownerHash = await computeOwnerHash(user_id, env);

	// Check if file exists and verify ownership
	const file = await env.DB.prepare('SELECT owner_hash FROM files WHERE file_id = ?').bind(fileId).first();

	if (!file) {
		return jsonResponse({ error: 'File not found' }, 404, corsHeaders);
	}

	if (file.owner_hash !== ownerHash) {
		return jsonResponse({ error: 'Not file owner' }, 403, corsHeaders);
	}

	// Delete file from R2
	try {
		await env.BUCKET.delete(fileId);
	} catch (err) {
		console.error('R2 delete error:', err);
		// Continue even if R2 deletion fails - we'll still remove from DB
	}

	// Delete metadata from D1
	try {
		await env.DB.prepare('DELETE FROM files WHERE file_id = ?').bind(fileId).run();
	} catch (err) {
		console.error('Database delete error:', err);
		return jsonResponse({ error: 'Failed to delete file metadata' }, 500, corsHeaders);
	}

	// Return success response
	return jsonResponse(
		{
			success: true,
		},
		200,
		corsHeaders
	);
}
