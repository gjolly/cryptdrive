/**
 * CryptDrive - End-to-End Encrypted Storage System
 * Cloudflare Workers implementation
 */
import { handleCreateUser } from './handlers/user.js';
import { handleAuthToken } from './handlers/auth.js';
import { handleListFiles, handleCreateFile, handleDeleteFile, handlePublishFile } from './handlers/files.js';
import {
	handleCreateMultipartUpload,
	handleGetMultipartUploadUrl,
	handleCompleteMultipartUpload,
	handleAbortMultipartUpload,
} from './handlers/multipart.js';
import { handleScheduled } from './schedule.js';
import { jsonResponse } from './utils/response.js';
import { getDownloadUrl, getClient } from './utils/multipart.js';

export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		const path = url.pathname;
		const method = request.method;

		const apiBase = '/api/v1';

		// Check if the secrets are set in environment variables
		// and refuse to operate if they are missing to prevent security issues.
		if (!env.SERVER_PEPPER || !env.JWT_SECRET) {
			return jsonResponse({ error: 'Server error.' }, 500);
		}

		// CORS headers
		const corsHeaders = {
			'Access-Control-Allow-Origin': env.CORS_ORIGIN || '*',
			'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
			'Access-Control-Allow-Headers': 'Content-Type, Authorization',
		};

		// Handle CORS preflight
		if (method === 'OPTIONS') {
			return new Response(null, { headers: corsHeaders });
		}

		try {
			// Route: POST /user - Create new user
			if (path === apiBase + '/user' && method === 'POST') {
				return await handleCreateUser(request, env, corsHeaders);
			}

			// Route: POST /auth/token - Authentication
			if (path === apiBase + '/auth/token' && method === 'POST') {
				return await handleAuthToken(request, env, corsHeaders);
			}

			// Route: GET /files - List files owned by user
			if (path === apiBase + '/files' && method === 'GET') {
				return await handleListFiles(request, env, corsHeaders);
			}

			// Route: POST /file - Create new file
			if (path === apiBase + '/file' && method === 'POST') {
				return await handleCreateFile(request, env, corsHeaders);
			}

			// Route: GET /file/:file_id - Get file
			const fileMatch = path.match(new RegExp(`^${apiBase}/file/([a-f0-9-]+)$`));
			if (fileMatch && method === 'GET') {
				const fileId = fileMatch[1];
				const { client, r2Url } = getClient(env);

				const downloadUrl = await getDownloadUrl(client, r2Url, fileId, 300);

				return jsonResponse({ downloadUrl }, 200, corsHeaders);
			}

			// Route: DELETE /file/:file_id - Delete file
			if (fileMatch && method === 'DELETE') {
				const fileId = fileMatch[1];
				return await handleDeleteFile(request, env, fileId, corsHeaders);
			}

			// Route: POST /file/:file_id/publish - Publish file
			const filePublishMatch = path.match(new RegExp(`^${apiBase}/file/([a-f0-9-]+)/publish$`));
			if (filePublishMatch && method === 'POST') {
				const fileId = filePublishMatch[1];
				return await handlePublishFile(request, env, corsHeaders, fileId);
			}

			// Route: GET /file/:file_id/upload - Start mulitpart upload and get upload ID
			const fileUploadMatch = path.match(new RegExp(`^${apiBase}/file/([a-f0-9-]+)/upload$`));
			if (fileUploadMatch && method === 'GET') {
				const fileId = fileUploadMatch[1];
				return await handleCreateMultipartUpload(request, env, fileId, corsHeaders);
			}

			// Route: POST /file/:file_id/upload/:upload_id - Complete multipart upload
			const fileUploadCompleteMatch = path.match(new RegExp(`^${apiBase}/file/([a-f0-9-]+)/upload/([^/]+)$`));
			if (fileUploadCompleteMatch && method === 'POST') {
				const fileId = fileUploadCompleteMatch[1];
				const uploadId = fileUploadCompleteMatch[2];
				return await handleCompleteMultipartUpload(request, env, fileId, uploadId, corsHeaders);
			}

			// Route: DELETE /file/:file_id/upload/:upload_id - Abort multipart upload
			if (fileUploadCompleteMatch && method === 'DELETE') {
				const fileId = fileUploadCompleteMatch[1];
				const uploadId = fileUploadCompleteMatch[2];
				return await handleAbortMultipartUpload(request, env, fileId, uploadId, corsHeaders);
			}

			// Route: GET /upload/:upload_id/part/:partNumber - Get presigned URL for uploading a part
			const filePartUploadMatch = path.match(new RegExp(`^${apiBase}/file/([a-f0-9-]+)/upload/([^/]+)/part/([0-9]+)$`));
			if (filePartUploadMatch && method === 'GET') {
				const fileId = filePartUploadMatch[1];
				const uploadId = filePartUploadMatch[2];
				const partNumber = filePartUploadMatch[3];
				return await handleGetMultipartUploadUrl(request, env, fileId, uploadId, partNumber, corsHeaders);
			}

			// Default 404
			return jsonResponse({ error: 'Not found' }, 404, corsHeaders);
		} catch (error) {
			console.error('Error:', error);
			return jsonResponse({ error: 'Internal server error' }, 500, corsHeaders);
		}
	},

	async scheduled(event, env) {
		return await handleScheduled(event, env);
	},
};
