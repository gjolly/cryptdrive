/**
 * Compute blind index (owner hash) for a user
 */
export async function computeOwnerHash(user_id, env) {
	// Get server pepper from environment or use a default for development
	const pepper = env.SERVER_PEPPER;

	// Use HMAC-SHA256 as specified in design document
	const encoder = new TextEncoder();
	const key = await crypto.subtle.importKey('raw', encoder.encode(pepper), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);

	const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(user_id));

	const hashArray = Array.from(new Uint8Array(signature));
	const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

	return hashHex;
}
