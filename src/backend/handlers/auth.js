import { createJWT, verifyJWT } from '../utils/jwt.js';
import { jsonResponse } from '../utils/response.js';
import { checkAuthRateLimit, recordFailedAuth } from '../middleware/rate-limiting.js';
import { initializeDatabase } from '../db/database.js';
import { verifyEd25519Signature } from '../middleware/auth.js';

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
 * Handle POST /auth/token - Authentication endpoint
 */
export async function handleAuthToken(request, env, corsHeaders) {
	let body;
	try {
		body = await request.json();
	} catch {
		return jsonResponse({ error: 'Invalid JSON' }, 400, corsHeaders);
	}

	const { username, challenge, signature } = body;

	// Validate username
	if (!username || typeof username !== 'string' || username.length < 3 || username.length > 30) {
		return jsonResponse({ error: 'username is required and must be between 3 and 30 characters' }, 400, corsHeaders);
	}

	// Initialize database
	await initializeDatabase(env.DB);

	// Check if user exists
	const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
	if (!user) {
		return jsonResponse({ error: 'User not found' }, 404, corsHeaders);
	}

	// Get JWT secret from environment
	const jwtSecret = env.JWT_SECRET;

	// First request: generate challenge
	if (!challenge && !signature) {
		// Check rate limit (IP-based only for challenge generation)
		const rateLimitCheck = await checkAuthRateLimit(request, env, null);
		if (!rateLimitCheck.allowed) {
			return jsonResponse({ error: rateLimitCheck.error }, rateLimitCheck.status, corsHeaders);
		}

		const nonce = randomHex(32);

		const challengeJWT = await createJWT(
			{ nonce, user_id: user.user_id, username: user.username, salt: user.salt },
			jwtSecret,
			30 // seconds
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

	// Verify this is not a replay
	const replayRecord = await env.DB.prepare('SELECT * FROM auth_challenges WHERE nonce = ?').bind(challengePayload.nonce).first();
	if (replayRecord) {
		// Record failed attempt
		await recordFailedAuth(env, user.user_id);
		return jsonResponse({ error: 'Challenge has already been used' }, 400, corsHeaders);
	}

	// Store nonce to prevent replay
	await env.DB.prepare('INSERT INTO auth_challenges (nonce) VALUES (?)').bind(challengePayload.nonce).run();

	// At this point, we know
	//  * the signagure is valid for the challenge
	//  * the challenge has not expired
	//  * the challenge has not been replayed
	// Now we can verify if the user is who they claim to be by checking the signature against their public key

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
