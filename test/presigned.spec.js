import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import worker from '../src';

const v1ApiPrefix = 'api/v1';

// Set test secrets for all tests
beforeEach(() => {
	env.SERVER_PEPPER = 'test-server-pepper-32-bytes-for-hmac-sha256-security-ok';
	env.JWT_SECRET = 'test-jwt-secret-key-32-bytes-for-hmac-sha256-signing-ok';
});

// TODO: we need a way to mock R2 because this is going
// to be slow and exprensive.
afterAll(async () => {
	const files = Object.keys(env.BUCKET.list()?.objects || {});
	for (const file of files) {
		await env.BUCKET.delete(file);
	}
});

describe('Presigned URL Tests', () => {
	let testUserId;
	let testPublicKey;
	let testToken;
	let testFileId;
	const testUserName = 'deletefileuser';
	const salt = 'deletesalt';

	beforeEach(async () => {
		// Clean up database before each test
		try {
			await env.DB.prepare('DELETE FROM users').run();
			await env.DB.prepare('DELETE FROM files').run();
		} catch {
			// Tables might not exist yet, that's ok
		}

		// Create a test user
		testPublicKey = btoa('j'.repeat(32));

		const createUserRequest = new Request(`http://example.com/${v1ApiPrefix}/user`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				public_key: testPublicKey,
				keychain_id: crypto.randomUUID(),
				username: testUserName,
				salt: salt,
			}),
		});

		let ctx = createExecutionContext();
		const createUserResponse = await worker.fetch(createUserRequest, env, ctx);
		await waitOnExecutionContext(ctx);

		const userData = await createUserResponse.json();
		testUserId = userData.user_id;

		// Create an authentication token
		const jwtSecret = env.JWT_SECRET || 'default-jwt-secret-change-in-production';
		const now = Math.floor(Date.now() / 1000);
		const payload = {
			sub: testUserId,
			iat: now,
			exp: now + 3600,
		};

		const header = { alg: 'HS256', typ: 'JWT' };
		const encodedHeader = btoa(JSON.stringify(header)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
		const encodedPayload = btoa(JSON.stringify(payload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
		const data = `${encodedHeader}.${encodedPayload}`;

		const encoder = new TextEncoder();
		const key = await crypto.subtle.importKey('raw', encoder.encode(jwtSecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);

		const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
		const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)))
			.replace(/\+/g, '-')
			.replace(/\//g, '_')
			.replace(/=/g, '');
		testToken = `${data}.${encodedSignature}`;

		// Create a test file (just metadata, no file data)
		const createFileRequest = new Request(`http://example.com/${v1ApiPrefix}/file`, {
			method: 'POST',
			headers: { Authorization: `Bearer ${testToken}` },
		});

		ctx = createExecutionContext();
		const createFileResponse = await worker.fetch(createFileRequest, env, ctx);
		await waitOnExecutionContext(ctx);
		if (!createFileResponse.ok) {
			const errorData = await createFileResponse.json();
			throw new Error(`Failed to create test file: ${errorData.error}`);
		}

		const fileResult = await createFileResponse.json();
		testFileId = fileResult.file_id;
	});

	it('create a multipart upload and complete it successfully', async () => {
		// Start multipart upload and get the upload ID
		const startRequest = new Request(`http://example.com/${v1ApiPrefix}/file/${testFileId}/upload`, {
			method: 'GET',
			headers: { Authorization: `Bearer ${testToken}` },
		});

		const ctx = createExecutionContext();
		const startResponse = await worker.fetch(startRequest, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(startResponse.status).toBe(200);
		const startData = await startResponse.json();
		expect(startData.upload_id).toBeDefined();
		const upload_id = startData.upload_id;

		// Get upload URL for part 1
		const partRequest = new Request(`http://example.com/${v1ApiPrefix}/file/${testFileId}/upload/${upload_id}/part/1`, {
			method: 'GET',
			headers: { Authorization: `Bearer ${testToken}` },
		});

		const partResponse = await worker.fetch(partRequest, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(partResponse.status).toBe(200);
		const partData = await partResponse.json();
		expect(partData.upload_url).toBeDefined();

		// Generate some random data for the file part
		const partDataBuffer = crypto.getRandomValues(new Uint8Array(1024)); // 1 KB of random data

		// Upload the part directly to R2 using the provided upload URL
		const uploadResponse = await fetch(partData.upload_url, {
			method: 'PUT',
			headers: {
				'Content-Type': 'application/octet-stream',
			},
			body: partDataBuffer,
		});

		expect(uploadResponse.status).toBe(200);

		// Complete the multipart upload
		const completeRequest = new Request(`http://example.com/${v1ApiPrefix}/file/${testFileId}/upload/${upload_id}`, {
			method: 'POST',
			headers: {
				Authorization: `Bearer ${testToken}`,
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({
				parts: [
					{
						part_number: 1,
						etag: uploadResponse.headers.get('ETag'),
					},
				],
			}),
		});

		const completeResponse = await worker.fetch(completeRequest, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(completeResponse.status).toBe(200);
	});
});
