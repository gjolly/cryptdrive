import { verifyJWT } from '../utils/jwt.js';

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
 * Verify Ed25519 signature
 */
export async function verifyEd25519Signature(publicKeyBase64, message, signatureBase64) {
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
 * Authenticate request and extract user_id from JWT
 */
export async function authenticateRequest(request, env) {
	const authHeader = request.headers.get('Authorization');
	if (!authHeader || !authHeader.startsWith('Bearer ')) {
		return { error: 'Authorization header required', status: 401 };
	}

	const token = authHeader.substring(7); // Remove 'Bearer ' prefix
	const jwtSecret = env.JWT_SECRET;

	try {
		const payload = await verifyJWT(token, jwtSecret);

		// Verify that the payload contains a valid user_id
		if (!payload.sub || typeof payload.sub !== 'string') {
			return { error: 'Invalid token: missing or invalid user_id', status: 401 };
		}

		return { user_id: payload.sub };
	} catch (e) {
		return { error: `Invalid or expired token: ${e.message}`, status: 401 };
	}
}
