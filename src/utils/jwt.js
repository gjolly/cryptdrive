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
 * Create a JWT token
 */
export async function createJWT(payload, secret, expiresIn) {
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
export async function verifyJWT(token, secret) {
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
