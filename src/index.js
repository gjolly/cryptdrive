/**
 * CryptDrive - End-to-End Encrypted Storage System
 * Cloudflare Workers implementation
 */

export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		const path = url.pathname;
		const method = request.method;

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
			// Route: GET / - Serve UI
			if (path === '/' && method === 'GET') {
				return await handleServeUI(env);
			}

			if (path === '/user' && method === 'POST') {
				return await handleCreateUser(request, env, corsHeaders);
			}

			// Route: POST /auth/token - Authentication
			if (path === '/auth/token' && method === 'POST') {
				return await handleAuthToken(request, env, corsHeaders);
			}

			// Route: GET /files - List files owned by user
			if (path === '/files' && method === 'GET') {
				return await handleListFiles(request, env, corsHeaders);
			}

			// Route: POST /file - Create new file
			if (path === '/file' && method === 'POST') {
				return await handleCreateFile(request, env, corsHeaders);
			}

			// Route: PUT /file/:file_id - Update file
			const fileMatch = path.match(/^\/file\/([a-f0-9-]+)$/);
			if (fileMatch && method === 'PUT') {
				const fileId = fileMatch[1];
				return await handleUpdateFile(request, env, corsHeaders, fileId);
			}

			if (fileMatch && method === 'DELETE') {
				const fileId = fileMatch[1];
				return await handleDeleteFile(request, env, corsHeaders, fileId);
			}

			// Route: GET /file/:file_id - Get file
			const getMatch = path.match(/^\/file\/([a-f0-9-]+)$/);
			if (getMatch && method === 'GET') {
				const fileId = getMatch[1];
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
		console.log('Running daily cleanup job at', new Date(event.scheduledTime).toISOString());

		try {
			// Calculate cutoff time (24 hours ago)
			const cutoffTime = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

			// Get all Tier 0 users
			const tier0Users = await env.DB.prepare('SELECT user_id FROM users WHERE tier = 0').all();

			if (!tier0Users.results || tier0Users.results.length === 0) {
				console.log('No Tier 0 users found');
				return;
			}

			let totalDeleted = 0;

			// For each Tier 0 user, compute their owner_hash and delete old files
			for (const user of tier0Users.results) {
				const ownerHash = await computeOwnerHash(user.user_id, env);

				// Get old files for this user
				const oldFiles = await env.DB.prepare('SELECT file_id FROM files WHERE owner_hash = ? AND created_at < ?')
					.bind(ownerHash, cutoffTime)
					.all();

				if (oldFiles.results && oldFiles.results.length > 0) {
					for (const file of oldFiles.results) {
						// Delete from R2
						try {
							await env.BUCKET.delete(file.file_id);
						} catch (e) {
							console.error('Failed to delete from R2:', file.file_id, e);
						}

						// Delete from database
						await env.DB.prepare('DELETE FROM files WHERE file_id = ?').bind(file.file_id).run();

						totalDeleted++;
					}
				}
			}

			console.log(`Cleanup completed: deleted ${totalDeleted} files older than 24 hours for Tier 0 users`);
		} catch (error) {
			console.error('Cleanup job error:', error);
		}
	},
};

/**
 * Helper function to create JSON responses
 */
function jsonResponse(data, status = 200, additionalHeaders = {}) {
	return new Response(JSON.stringify(data), {
		status,
		headers: {
			'Content-Type': 'application/json',
			...additionalHeaders,
		},
	});
}

/**
 * Generate a UUID v4
 */
function generateUUID() {
	return crypto.randomUUID();
}

/**
 * Handle GET / - Serve UI
 */
async function handleServeUI(env) {
	try {
		// Get HTML file from R2
		const html = await env.BUCKET.get('index.html');

		if (!html) {
			// Fallback: return basic HTML if file not found
			return new Response('<h1>CryptDrive</h1><p>UI file not found. Please upload public/index.html to R2.</p>', {
				headers: { 'Content-Type': 'text/html' },
			});
		}

		return new Response(html.body, {
			headers: {
				'Content-Type': 'text/html',
				'Cache-Control': 'public, max-age=3600',
			},
		});
	} catch (error) {
		console.error('Error serving UI:', error);
		return new Response('Error loading UI', { status: 500 });
	}
}

/**
 * Handle POST /user - Create new user
 */
async function handleCreateUser(request, env, corsHeaders) {
	// Initialize database first
	await initializeDatabase(env.DB);

	// Check registration rate limit
	const rateLimitCheck = await checkRegistrationRateLimit(request, env);
	if (!rateLimitCheck.allowed) {
		return jsonResponse({ error: rateLimitCheck.error }, rateLimitCheck.status, corsHeaders);
	}

	// Note: In production, you would check for CAPTCHA if captcha_required is true
	// if (rateLimitCheck.captcha_required && !verifyCaptcha(request)) {
	//     return jsonResponse({ error: 'CAPTCHA verification required' }, 403, corsHeaders);
	// }

	let body;
	try {
		body = await request.json();
	} catch {
		return jsonResponse({ error: 'Invalid JSON' }, 400, corsHeaders);
	}

	const { public_key, keychain_id } = body;

	// Validate input
	if (!public_key || typeof public_key !== 'string') {
		return jsonResponse({ error: 'public_key is required and must be a string' }, 400, corsHeaders);
	}

	// keychain_id should be a UUID string
	if (!keychain_id || typeof keychain_id !== 'string' || !/^[0-9a-fA-F-]{36}$/.test(keychain_id)) {
		return jsonResponse({ error: 'keychain_id is required and must be a valid UUID string' }, 400, corsHeaders);
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
	const user_id = generateUUID();

	// Check if public key already exists
	const existing = await env.DB.prepare('SELECT user_id FROM users WHERE public_key = ?').bind(public_key).first();

	if (existing) {
		return jsonResponse({ error: 'Public key already registered' }, 409, corsHeaders);
	}

	console.log(`Creating user ${user_id} with public key ${public_key}`);

	// Create user in database
	await env.DB.prepare('INSERT INTO users (user_id, public_key, created_at) VALUES (?, ?, ?)')
		.bind(user_id, public_key, new Date().toISOString())
		.run();

	// create empty keychain file in R2
	await env.BUCKET.put(keychain_id, new Uint8Array(0));

	// Store file metadata in database
	const owner_hash = await computeOwnerHash(user_id, env);
	await env.DB.prepare('INSERT INTO files (file_id, owner_hash, size, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
		.bind(keychain_id, owner_hash, 0, new Date().toISOString(), new Date().toISOString())
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

/**
 * Compute blind index (owner hash) for a user
 */
async function computeOwnerHash(user_id, env) {
	// Get server pepper from environment or use a default for development
	const pepper = env.SERVER_PEPPER || 'default-pepper-change-in-production';

	// Use HMAC-SHA256 as specified in design document
	const encoder = new TextEncoder();
	const key = await crypto.subtle.importKey('raw', encoder.encode(pepper), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);

	const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(user_id));

	const hashArray = Array.from(new Uint8Array(signature));
	const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

	return hashHex;
}

/**
 * Compute fingerprint for rate limiting registration
 * SHA256(ip_address + user_agent + accept_language)
 */
async function computeFingerprint(request) {
	const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
	const userAgent = request.headers.get('User-Agent') || '';
	const acceptLanguage = request.headers.get('Accept-Language') || '';

	const combined = ip + userAgent + acceptLanguage;
	const encoder = new TextEncoder();
	const data = encoder.encode(combined);
	const hashBuffer = await crypto.subtle.digest('SHA-256', data);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Compute SHA256 hash of IP address for rate limiting
 */
async function hashIP(request) {
	const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
	const encoder = new TextEncoder();
	const data = encoder.encode(ip);
	const hashBuffer = await crypto.subtle.digest('SHA-256', data);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Check and update authentication rate limits (dual: IP + user)
 * Returns {allowed: boolean, error?: string, status?: number}
 */
async function checkAuthRateLimit(request, env, user_id = null) {
	const now = Date.now();
	const oneMinute = 60 * 1000;

	// Check IP-based limit (10 per minute)
	const ipHash = await hashIP(request);
	const ipRecord = await env.DB.prepare('SELECT * FROM auth_rate_limits WHERE id = ? AND type = ?').bind(ipHash, 'ip').first();

	if (ipRecord) {
		const windowAge = now - new Date(ipRecord.window_start).getTime();
		if (windowAge < oneMinute) {
			if (ipRecord.attempts >= 10) {
				return { allowed: false, error: 'IP rate limit exceeded', status: 429 };
			}
			// Update attempts
			await env.DB.prepare('UPDATE auth_rate_limits SET attempts = ?, last_attempt = ? WHERE id = ? AND type = ?')
				.bind(ipRecord.attempts + 1, new Date().toISOString(), ipHash, 'ip')
				.run();
		} else {
			// Reset window
			await env.DB.prepare(
				'UPDATE auth_rate_limits SET attempts = 1, failed_attempts = 0, last_attempt = ?, window_start = ? WHERE id = ? AND type = ?'
			)
				.bind(new Date().toISOString(), new Date().toISOString(), ipHash, 'ip')
				.run();
		}
	} else {
		// Create new record
		await env.DB.prepare(
			'INSERT INTO auth_rate_limits (id, type, attempts, failed_attempts, last_attempt, window_start) VALUES (?, ?, ?, ?, ?, ?)'
		)
			.bind(ipHash, 'ip', 1, 0, new Date().toISOString(), new Date().toISOString())
			.run();
	}

	// Check user-based limit (5 per minute) if user_id provided
	if (user_id) {
		const userRecord = await env.DB.prepare('SELECT * FROM auth_rate_limits WHERE id = ? AND type = ?').bind(user_id, 'user').first();

		if (userRecord) {
			const windowAge = now - new Date(userRecord.window_start).getTime();
			if (windowAge < oneMinute) {
				// Check for exponential backoff
				const backoffDelay = userRecord.failed_attempts >= 3 ? Math.pow(2, userRecord.failed_attempts - 3) * 1000 : 0;

				const timeSinceLastAttempt = now - new Date(userRecord.last_attempt).getTime();
				if (backoffDelay > 0 && timeSinceLastAttempt < backoffDelay) {
					return {
						allowed: false,
						error: `Too many failed attempts. Try again in ${Math.ceil((backoffDelay - timeSinceLastAttempt) / 1000)}s`,
						status: 429,
					};
				}

				if (userRecord.attempts >= 5) {
					return { allowed: false, error: 'User rate limit exceeded', status: 429 };
				}
				// Update attempts
				await env.DB.prepare('UPDATE auth_rate_limits SET attempts = ?, last_attempt = ? WHERE id = ? AND type = ?')
					.bind(userRecord.attempts + 1, new Date().toISOString(), user_id, 'user')
					.run();
			} else {
				// Reset window
				await env.DB.prepare(
					'UPDATE auth_rate_limits SET attempts = 1, failed_attempts = 0, last_attempt = ?, window_start = ? WHERE id = ? AND type = ?'
				)
					.bind(new Date().toISOString(), new Date().toISOString(), user_id, 'user')
					.run();
			}
		} else {
			// Create new record
			await env.DB.prepare(
				'INSERT INTO auth_rate_limits (id, type, attempts, failed_attempts, last_attempt, window_start) VALUES (?, ?, ?, ?, ?, ?)'
			)
				.bind(user_id, 'user', 1, 0, new Date().toISOString(), new Date().toISOString())
				.run();
		}
	}

	return { allowed: true };
}

/**
 * Record failed authentication attempt for exponential backoff
 */
async function recordFailedAuth(env, user_id) {
	await env.DB.prepare('UPDATE auth_rate_limits SET failed_attempts = failed_attempts + 1, last_attempt = ? WHERE id = ? AND type = ?')
		.bind(new Date().toISOString(), user_id, 'user')
		.run();
}

/**
 * Check and update registration rate limits (fingerprint-based)
 * Returns {allowed: boolean, captcha_required?: boolean, error?: string, status?: number}
 */
async function checkRegistrationRateLimit(request, env) {
	const fingerprint = await computeFingerprint(request);
	const now = Date.now();
	const oneHour = 60 * 60 * 1000;

	const record = await env.DB.prepare('SELECT * FROM registration_rate_limits WHERE fingerprint = ?').bind(fingerprint).first();

	if (record) {
		const windowAge = now - new Date(record.window_start).getTime();
		if (windowAge < oneHour) {
			if (record.registrations >= 3) {
				return {
					allowed: false,
					error: 'Registration rate limit exceeded',
					status: 429,
				};
			}

			// Check if CAPTCHA is required
			const captchaRequired = record.registrations >= 2;

			// Update registrations
			await env.DB.prepare('UPDATE registration_rate_limits SET registrations = ?, captcha_required = ? WHERE fingerprint = ?')
				.bind(record.registrations + 1, captchaRequired ? 1 : 0, fingerprint)
				.run();

			return { allowed: true, captcha_required: captchaRequired };
		} else {
			// Reset window
			await env.DB.prepare(
				'UPDATE registration_rate_limits SET registrations = 1, captcha_required = 0, window_start = ? WHERE fingerprint = ?'
			)
				.bind(new Date().toISOString(), fingerprint)
				.run();
		}
	} else {
		// Create new record
		await env.DB.prepare(
			'INSERT INTO registration_rate_limits (fingerprint, registrations, captcha_required, window_start) VALUES (?, ?, ?, ?)'
		)
			.bind(fingerprint, 1, 0, new Date().toISOString())
			.run();
	}

	return { allowed: true, captcha_required: false };
}

/**
 * Check and update file operation rate limits (user-based)
 * Returns {allowed: boolean, error?: string, status?: number}
 */
async function checkFileOperationRateLimit(user_id, env, isWrite = false) {
	const now = Date.now();
	const oneMinute = 60 * 1000;
	const limit = isWrite ? 20 : 50;

	const record = await env.DB.prepare('SELECT * FROM file_operation_limits WHERE user_id = ?').bind(user_id).first();

	if (record) {
		const windowAge = now - new Date(record.window_start).getTime();
		const currentRequests = isWrite ? record.write_requests : record.read_requests;

		if (windowAge < oneMinute) {
			if (currentRequests >= limit) {
				return {
					allowed: false,
					error: `File operation rate limit exceeded (${limit}/${isWrite ? 'write' : 'read'} per minute)`,
					status: 429,
				};
			}
			// Update requests
			if (isWrite) {
				await env.DB.prepare('UPDATE file_operation_limits SET write_requests = ? WHERE user_id = ?')
					.bind(record.write_requests + 1, user_id)
					.run();
			} else {
				await env.DB.prepare('UPDATE file_operation_limits SET read_requests = ? WHERE user_id = ?')
					.bind(record.read_requests + 1, user_id)
					.run();
			}
		} else {
			// Reset window
			await env.DB.prepare('UPDATE file_operation_limits SET read_requests = ?, write_requests = ?, window_start = ? WHERE user_id = ?')
				.bind(isWrite ? 0 : 1, isWrite ? 1 : 0, new Date().toISOString(), user_id)
				.run();
		}
	} else {
		// Create new record
		await env.DB.prepare('INSERT INTO file_operation_limits (user_id, read_requests, write_requests, window_start) VALUES (?, ?, ?, ?)')
			.bind(user_id, isWrite ? 0 : 1, isWrite ? 1 : 0, new Date().toISOString())
			.run();
	}

	return { allowed: true };
}

/**
 * Check and update anonymous download rate limits (IP-based)
 * Returns {allowed: boolean, captcha_required?: boolean, error?: string, status?: number}
 */
async function checkAnonymousDownloadRateLimit(request, env) {
	const ipHash = await hashIP(request);
	const now = Date.now();
	const oneMinute = 60 * 1000;

	const record = await env.DB.prepare('SELECT * FROM anonymous_download_limits WHERE ip_hash = ?').bind(ipHash).first();

	if (record) {
		const windowAge = now - new Date(record.window_start).getTime();
		if (windowAge < oneMinute) {
			if (record.downloads >= 100) {
				return {
					allowed: false,
					captcha_required: true,
					error: 'Anonymous download rate limit exceeded. Please authenticate or complete CAPTCHA.',
					status: 429,
				};
			}
			// Update downloads
			await env.DB.prepare('UPDATE anonymous_download_limits SET downloads = ?, captcha_required = ? WHERE ip_hash = ?')
				.bind(record.downloads + 1, record.downloads >= 99 ? 1 : 0, ipHash)
				.run();
		} else {
			// Reset window
			await env.DB.prepare('UPDATE anonymous_download_limits SET downloads = 1, captcha_required = 0, window_start = ? WHERE ip_hash = ?')
				.bind(new Date().toISOString(), ipHash)
				.run();
		}
	} else {
		// Create new record
		await env.DB.prepare('INSERT INTO anonymous_download_limits (ip_hash, downloads, captcha_required, window_start) VALUES (?, ?, ?, ?)')
			.bind(ipHash, 1, 0, new Date().toISOString())
			.run();
	}

	return { allowed: true, captcha_required: false };
}

/**
 * Generate a random hex string of specified length
 */
function randomHex(length) {
	const bytes = new Uint8Array(length);
	crypto.getRandomValues(bytes);
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

/**
 * Create a JWT token
 */
async function createJWT(payload, secret, expiresIn) {
	const header = { alg: 'HS256', typ: 'JWT' };

	const now = Math.floor(Date.now() / 1000);
	const fullPayload = {
		...payload,
		iat: now,
		exp: now + expiresIn,
	};

	// Encode header and payload
	const encodedHeader = base64UrlEncode(JSON.stringify(header));
	const encodedPayload = base64UrlEncode(JSON.stringify(fullPayload));

	// Create signature
	const data = `${encodedHeader}.${encodedPayload}`;
	const encoder = new TextEncoder();
	const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);

	const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
	const encodedSignature = base64UrlEncode(signature);

	return `${data}.${encodedSignature}`;
}

/**
 * Verify and decode a JWT token
 */
async function verifyJWT(token, secret) {
	const parts = token.split('.');
	if (parts.length !== 3) {
		throw new Error('Invalid token format');
	}

	const [encodedHeader, encodedPayload, encodedSignature] = parts;

	// Verify signature
	const data = `${encodedHeader}.${encodedPayload}`;
	const encoder = new TextEncoder();
	const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);

	const signature = base64UrlDecode(encodedSignature);
	const valid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data));

	if (!valid) {
		throw new Error('Invalid signature');
	}

	// Decode payload
	const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(encodedPayload)));

	// Check expiration
	const now = Math.floor(Date.now() / 1000);
	if (payload.exp && payload.exp < now) {
		throw new Error('Token expired');
	}

	return payload;
}

/**
 * Base64 URL encode
 */
function base64UrlEncode(data) {
	let base64;
	if (typeof data === 'string') {
		base64 = btoa(data);
	} else if (data instanceof ArrayBuffer) {
		base64 = btoa(String.fromCharCode(...new Uint8Array(data)));
	} else {
		base64 = btoa(String.fromCharCode(...data));
	}
	return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Base64 URL decode
 */
function base64UrlDecode(str) {
	str = str.replace(/-/g, '+').replace(/_/g, '/');
	while (str.length % 4) {
		str += '=';
	}
	const binary = atob(str);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

/**
 * Verify Ed25519 signature
 */
async function verifyEd25519Signature(publicKeyBase64, message, signatureBase64) {
	try {
		// Decode public key and signature
		const publicKeyBytes = base64Decode(publicKeyBase64);
		const signatureBytes = base64Decode(signatureBase64);

		// Import public key
		const publicKey = await crypto.subtle.importKey('raw', publicKeyBytes, { name: 'Ed25519', namedCurve: 'Ed25519' }, false, ['verify']);

		// Verify signature
		const encoder = new TextEncoder();
		const messageBytes = encoder.encode(message);

		const valid = await crypto.subtle.verify('Ed25519', publicKey, signatureBytes, messageBytes);

		return valid;
	} catch (e) {
		console.error('Ed25519 verification error:', e);
		return false;
	}
}

/**
 * Base64 decode (standard, not URL-safe)
 */
function base64Decode(str) {
	const binary = atob(str);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

/**
 * Handle POST /auth/token - Authentication endpoint
 */
async function handleAuthToken(request, env, corsHeaders) {
	let body;
	try {
		body = await request.json();
	} catch {
		return jsonResponse({ error: 'Invalid JSON' }, 400, corsHeaders);
	}

	const { public_key, challenge, signature } = body;

	// Validate public_key
	if (!public_key || typeof public_key !== 'string') {
		return jsonResponse({ error: 'public_key is required and must be a string' }, 400, corsHeaders);
	}

	// Initialize database
	await initializeDatabase(env.DB);

	console.log(`Auth request for public_key: ${public_key}`);

	// Check if user exists
	const user = await env.DB.prepare('SELECT * FROM users WHERE public_key = ?').bind(public_key).first();
	if (!user) {
		return jsonResponse({ error: 'User not found' }, 404, corsHeaders);
	}

	// Get JWT secret from environment
	const jwtSecret = env.JWT_SECRET || 'default-jwt-secret-change-in-production';

	// First request: generate challenge
	if (!challenge && !signature) {
		// Check rate limit (IP-based only for challenge generation)
		const rateLimitCheck = await checkAuthRateLimit(request, env, null);
		if (!rateLimitCheck.allowed) {
			return jsonResponse({ error: rateLimitCheck.error }, rateLimitCheck.status, corsHeaders);
		}

		const nonce = randomHex(32); // 64 character hex string

		const challengeJWT = await createJWT(
			{ nonce, user_id: user.user_id },
			jwtSecret,
			300 // 5 minutes
		);

		return jsonResponse({ challenge: challengeJWT }, 200, corsHeaders);
	}

	// Second request: verify signature and issue token
	if (!challenge || !signature) {
		return jsonResponse({ error: 'Both challenge and signature are required' }, 400, corsHeaders);
	}

	// Check rate limit (both IP and user-based)
	const rateLimitCheck = await checkAuthRateLimit(request, env, user.user_id);
	if (!rateLimitCheck.allowed) {
		return jsonResponse({ error: rateLimitCheck.error }, rateLimitCheck.status, corsHeaders);
	}

	// Verify challenge JWT
	let challengePayload;
	try {
		challengePayload = await verifyJWT(challenge, jwtSecret);
	} catch (e) {
		// Record failed attempt
		await recordFailedAuth(env, user.user_id);
		return jsonResponse({ error: `Invalid challenge: ${e.message}` }, 400, corsHeaders);
	}

	// Verify user_id matches challenge
	if (challengePayload.user_id !== user.user_id) {
		// Record failed attempt
		await recordFailedAuth(env, user.user_id);
		return jsonResponse({ error: 'user_id does not match challenge' }, 400, corsHeaders);
	}

	// Verify signature with user's public key
	const signatureValid = await verifyEd25519Signature(user.public_key, challenge, signature);

	if (!signatureValid) {
		// Record failed attempt for exponential backoff
		await recordFailedAuth(env, user.user_id);
		return jsonResponse({ error: 'Invalid signature' }, 401, corsHeaders);
	}

	// Issue access token (successful authentication)
	const accessToken = await createJWT(
		{ sub: user.user_id },
		jwtSecret,
		3600 // 1 hour
	);

	return jsonResponse(
		{
			token: accessToken,
			expires_in: 3600,
		},
		200,
		corsHeaders
	);
}

/**
 * Authenticate request and extract user_id from JWT
 */
async function authenticateRequest(request, env) {
	const authHeader = request.headers.get('Authorization');
	if (!authHeader || !authHeader.startsWith('Bearer ')) {
		return { error: 'Authorization header required', status: 401 };
	}

	const token = authHeader.substring(7); // Remove 'Bearer ' prefix
	const jwtSecret = env.JWT_SECRET || 'default-jwt-secret-change-in-production';

	try {
		const payload = await verifyJWT(token, jwtSecret);
		return { user_id: payload.sub };
	} catch (e) {
		return { error: `Invalid or expired token: ${e.message}`, status: 401 };
	}
}

/**
 * Handle GET /files - List files owned by authenticated user
 */
async function handleListFiles(request, env, corsHeaders) {
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
async function handleCreateFile(request, env, corsHeaders) {
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
async function handleUpdateFile(request, env, corsHeaders, fileId) {
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
async function handleGetFile(request, env, corsHeaders, fileId) {
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
async function handleDeleteFile(request, env, corsHeaders, fileId) {
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

/**
 * Initialize database schema if needed
 */
async function initializeDatabase(db) {
	// Create users table
	await db
		.prepare(
			`
		CREATE TABLE IF NOT EXISTS users (
			user_id TEXT PRIMARY KEY,
			public_key TEXT NOT NULL UNIQUE,
			created_at TEXT NOT NULL
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
			size INTEGER NOT NULL,
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
}
