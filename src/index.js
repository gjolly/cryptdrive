/**
 * CryptDrive - End-to-End Encrypted Storage System
 * Cloudflare Workers implementation
 */
import { handleCreateUser } from './handlers/user.js';
import { handleAuthToken } from './handlers/auth.js';
import { handleListFiles, handleCreateFile, handleUpdateFile, handleDeleteFile, handleGetFile } from './handlers/files.js';
import { handleScheduled } from './schedule.js';
import { jsonResponse } from './utils/response.js';

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

			// Route: PUT /file/:file_id - Update file
			const fileMatch = path.match(new RegExp(`^${apiBase}/file/([a-f0-9-]+)$`));
			if (fileMatch && method === 'PUT') {
				const fileId = fileMatch[1];
				return await handleUpdateFile(request, env, corsHeaders, fileId);
			}

			if (fileMatch && method === 'DELETE') {
				const fileId = fileMatch[1];
				return await handleDeleteFile(request, env, corsHeaders, fileId);
			}

			// Route: GET /file/:file_id - Get file
			if (fileMatch && method === 'GET') {
				const fileId = fileMatch[1];
				return await handleGetFile(request, env, corsHeaders, fileId);
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
