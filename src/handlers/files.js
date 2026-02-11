import { authenticateRequest } from '../middleware/auth.js';
import { jsonResponse } from '../utils/response.js';
import { checkFileOperationRateLimit, checkAnonymousDownloadRateLimit } from '../middleware/rate-limiting.js';
import { initializeDatabase } from '../db/database.js';
import { computeOwnerHash } from '../utils/crypto.js';

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
	const files = await env.DB.prepare(
		'SELECT file_id, size, created_at, updated_at FROM files WHERE owner_hash = ? ORDER BY created_at DESC'
	)
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

	// TODO: Enforce file count/quota limits based on user tier
	// TODO: Stream file data instead of reading all at once for large files

	// Read file data from request body
	const fileData = await request.arrayBuffer();
	if (!fileData || fileData.byteLength === 0) {
		return jsonResponse({ error: 'File data is required' }, 400, corsHeaders);
	}

	if (fileData.byteLength > 10 * 1024 * 1024) {
		// 10 MB limit for example
		return jsonResponse({ error: 'File size exceeds maximum allowed limit of 10 MB' }, 400, corsHeaders);
	}

	// Validate file format (basic check for magic bytes)
	const fileArray = new Uint8Array(fileData);
	if (fileArray.byteLength < 33) {
		return jsonResponse({ error: 'Invalid file format: file too small' }, 400, corsHeaders);
	}

	// Check magic bytes "SECF"
	const magic = String.fromCharCode(...fileArray.slice(0, 4));
	if (magic !== 'SECF') {
		return jsonResponse({ error: 'Invalid file format: invalid magic bytes' }, 400, corsHeaders);
	}

	// Check version
	const version = fileArray[4];
	if (version !== 0x01) {
		return jsonResponse({ error: 'Invalid file format: unsupported version' }, 400, corsHeaders);
	}

	// Generate unique file ID
	const fileId = crypto.randomUUID();

	// Compute owner hash
	const ownerHash = await computeOwnerHash(user_id, env);

	// Store file in R2
	try {
		await env.BUCKET.put(fileId, fileData);
	} catch (err) {
		console.error('R2 put error:', err);
		return jsonResponse({ error: 'Failed to store file' }, 500, corsHeaders);
	}

	// Store metadata in D1
	const now = new Date().toISOString();
	const size = fileArray.byteLength;

	try {
		await env.DB.prepare(
			`
			INSERT INTO files (file_id, owner_hash, size, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?)
		`
		)
			.bind(fileId, ownerHash, size, now, now)
			.run();
	} catch (err) {
		// Rollback R2 upload on database error
		try {
			await env.BUCKET.delete(fileId);
		} catch (deleteErr) {
			console.error('R2 delete rollback error:', deleteErr);
		}
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
 * Handle PUT /file/:file_id - Update file
 */
export async function handleUpdateFile(request, env, corsHeaders, fileId) {
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

	// Read new file data from request body
	const fileData = await request.arrayBuffer();
	if (!fileData || fileData.byteLength === 0) {
		return jsonResponse({ error: 'File data is required' }, 400, corsHeaders);
	}

	// Validate file format
	const fileArray = new Uint8Array(fileData);
	if (fileArray.byteLength < 33) {
		return jsonResponse({ error: 'Invalid file format: file too small' }, 400, corsHeaders);
	}

	// Check magic bytes "SECF"
	const magic = String.fromCharCode(...fileArray.slice(0, 4));
	if (magic !== 'SECF') {
		return jsonResponse({ error: 'Invalid file format: invalid magic bytes' }, 400, corsHeaders);
	}

	// Check version
	const version = fileArray[4];
	if (version !== 0x01) {
		return jsonResponse({ error: 'Invalid file format: unsupported version' }, 400, corsHeaders);
	}

	// Update file in R2
	try {
		await env.BUCKET.put(fileId, fileData);
	} catch (err) {
		console.error('R2 put error:', err);
		return jsonResponse({ error: 'Failed to update file' }, 500, corsHeaders);
	}

	// Update metadata in D1
	const now = new Date().toISOString();
	const size = fileArray.byteLength;

	try {
		await env.DB.prepare(
			`
			UPDATE files
			SET size = ?, updated_at = ?
			WHERE file_id = ?
		`
		)
			.bind(size, now, fileId)
			.run();
	} catch (err) {
		console.error('Database update error:', err);
		return jsonResponse({ error: 'Failed to update file metadata' }, 500, corsHeaders);
	}

	// Return success response
	return jsonResponse(
		{
			success: true,
			updated_at: now,
		},
		200,
		corsHeaders
	);
}

/**
 * Handle GET /file/:file_id - Get file
 */
export async function handleGetFile(request, env, corsHeaders, fileId) {
	// Initialize database
	await initializeDatabase(env.DB);

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

	// Check if file exists
	const file = await env.DB.prepare('SELECT * FROM files WHERE file_id = ?').bind(fileId).first();

	if (!file) {
		return jsonResponse({ error: 'File not found' }, 404, corsHeaders);
	}

	// TODO: Redirect to R2 signed URL instead of proxying through worker for large files

	// Get file from R2
	try {
		const object = await env.BUCKET.get(fileId);

		if (!object) {
			return jsonResponse({ error: 'File not found in storage' }, 404, corsHeaders);
		}

		// Return file data
		return new Response(object.body, {
			headers: {
				'Content-Type': 'application/octet-stream',
				'Content-Length': file.size.toString(),
				...corsHeaders,
			},
		});
	} catch (err) {
		console.error('R2 get error:', err);
		return jsonResponse({ error: 'Failed to retrieve file' }, 500, corsHeaders);
	}
}

/**
 * Handle DELETE /file/:file_id - Delete file
 */
export async function handleDeleteFile(request, env, corsHeaders, fileId) {
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
