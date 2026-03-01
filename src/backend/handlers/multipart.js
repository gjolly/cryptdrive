import {
	getClient,
	completeMultipartUpload,
	createMultipartUpload,
	listMultipartUploadParts,
	getUploadUrlForPart,
	abortMultipartUpload,
	validateUploadedParts,
} from '../utils/multipart.js';
import { initializeDatabase } from '../db/database.js';
import { computeOwnerHash } from '../utils/crypto.js';
import { jsonResponse } from '../utils/response.js';
import { authenticateRequest } from '../middleware/auth.js';
import { checkFileOperationRateLimit } from '../middleware/rate-limiting.js';

export const handleCreateMultipartUpload = async (request, env, fileId, corsHeaders) => {
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

	const { client, r2Url } = getClient(env);
	let upload_id;
	try {
		upload_id = await createMultipartUpload(client, r2Url, fileId);
	} catch (error) {
		console.error('Error creating multipart upload:', error);
		return jsonResponse({ error: 'Error creating multipart upload' }, 500, corsHeaders);
	}

	return jsonResponse({ upload_id }, 200, corsHeaders);
};

export const handleGetMultipartUploadUrl = async (request, env, fileId, uploadId, partNumber, corsHeaders) => {
	const { client, r2Url } = getClient(env);
	const multipartExpiry = 300; // 5min
	if (!uploadId || !partNumber || !fileId) {
		return jsonResponse({ error: 'Missing uploadId, partNumber, or fileId' }, 400, corsHeaders);
	}

	const parts = await listMultipartUploadParts(client, r2Url, fileId, uploadId);

	try {
		validateUploadedParts(parts, env.FILE_BLOCK_SIZE, env.FILE_MAX_SIZE);
	} catch (error) {
		await abortMultipartUpload(client, r2Url, fileId, uploadId);
		return jsonResponse({ error: error.message }, 400, corsHeaders);
	}

	const upload_url = await getUploadUrlForPart(client, r2Url, fileId, uploadId, partNumber, env.FILE_BLOCK_SIZE, multipartExpiry);

	return jsonResponse({ upload_url }, 200, corsHeaders);
};

export const handleCompleteMultipartUpload = async (request, env, fileId, uploadId, corsHeaders) => {
	const { client, r2Url } = getClient(env);
	const { parts } = await request.json();
	try {
		const parts = await listMultipartUploadParts(client, r2Url, fileId, uploadId);
		validateUploadedParts(parts, env.FILE_BLOCK_SIZE, env.FILE_MAX_SIZE);
	} catch (error) {
		await abortMultipartUpload(client, r2Url, fileId, uploadId, corsHeaders);
		return jsonResponse({ error: error.message }, 400, corsHeaders);
	}
	await completeMultipartUpload(client, r2Url, fileId, uploadId, parts);
	return jsonResponse({}, 200, corsHeaders);
};

export const handleAbortMultipartUpload = async (request, env, fileId, uploadId, corsHeaders) => {
	const { client, r2Url } = getClient(env);
	await abortMultipartUpload(client, r2Url, fileId, uploadId);
	return jsonResponse({}, 200, corsHeaders);
};
