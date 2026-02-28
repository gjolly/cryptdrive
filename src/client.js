/* global argon2 */
import * as nobleEd25519 from '@noble/ed25519';

// Set up sha512 using Web Crypto API (browser native)
nobleEd25519.etc.sha512Sync = (...messages) => {
	nobleEd25519.etc.concatBytes(...messages);
	// For sync, we'll use a polyfill approach
	throw new Error('Use async methods only');
};
nobleEd25519.etc.sha512Async = async (...messages) => {
	const message = nobleEd25519.etc.concatBytes(...messages);
	const hash = await crypto.subtle.digest('SHA-512', message);
	return new Uint8Array(hash);
};

// Configuration
const API_BASE = window.location.origin + '/api/v1';
// Plaintext bytes per encrypted chunk when uploading files (must be <= server FILE_BLOCK_SIZE - GCM_TAG_LENGTH)
const FILE_CHUNK_PLAINTEXT_SIZE = 5 * 1024 * 1024 - 16; // 5 MiB block size (minimum R2) minus 16-byte GCM tag

// Load session from sessionStorage if available
function loadSession() {
	const stored = sessionStorage.getItem('cryptdrive_session');
	if (stored) {
		try {
			const parsed = JSON.parse(stored);
			// Convert base64 strings back to Uint8Arrays
			if (parsed.keychainKey) parsed.keychainKey = base64ToArray(parsed.keychainKey);
			if (parsed.privateKey) parsed.privateKey = base64ToArray(parsed.privateKey);
			if (parsed.publicKey) parsed.publicKey = base64ToArray(parsed.publicKey);
			return parsed;
		} catch (e) {
			console.error('Failed to load session:', e);
			sessionStorage.removeItem('cryptdrive_session');
		}
	}
	return {
		userId: null,
		keychainId: null,
		token: null,
		keychainKey: null,
		privateKey: null,
		publicKey: null,
		keychain: null,
	};
}

// Save session to sessionStorage
function saveSession() {
	try {
		const toStore = { ...session };
		// Convert Uint8Arrays to base64 for storage
		if (toStore.keychainKey) toStore.keychainKey = arrayToBase64(toStore.keychainKey);
		if (toStore.privateKey) toStore.privateKey = arrayToBase64(toStore.privateKey);
		if (toStore.publicKey) toStore.publicKey = arrayToBase64(toStore.publicKey);
		sessionStorage.setItem('cryptdrive_session', JSON.stringify(toStore));
	} catch (e) {
		console.error('Failed to save session:', e);
	}
}

// Session state
let session = loadSession();

// ===== UI Navigation =====

function showSection(sectionId) {
	['landingPage', 'registerPage', 'loginPage', 'filesPage'].forEach((id) => {
		document.getElementById(id).classList.add('hidden');
	});
	document.getElementById(sectionId).classList.remove('hidden');
}

function showLanding() {
	showSection('landingPage');
}
function showRegister() {
	showSection('registerPage');
}
function showLogin() {
	showSection('loginPage');
}

function showError(elementId, message) {
	const el = document.getElementById(elementId);
	el.textContent = message;
	el.classList.remove('hidden');
	setTimeout(() => el.classList.add('hidden'), 5000);
}

function showSuccess(elementId, message) {
	const el = document.getElementById(elementId);
	el.textContent = message;
	el.classList.remove('hidden');
	setTimeout(() => el.classList.add('hidden'), 3000);
}

// ===== Cryptographic Functions =====

async function deriveMasterKey(passphrase, salt) {
	// Convert username to Uint8Array and ensure it's at least 8 bytes (Argon2 requirement)
	const encoder = new TextEncoder();
	const saltBytes = encoder.encode(salt);

	// Pad to at least 8 bytes if needed
	if (saltBytes.length < 8) {
		throw new Error('Salt must be at least 8 bytes long');
	}

	const result = await argon2.hash({
		pass: passphrase,
		salt: saltBytes,
		time: 3,
		mem: 65536,
		hashLen: 32,
		parallelism: 4,
		type: argon2.ArgonType.Argon2id,
	});
	return result.hash;
}

async function hkdf(masterKey, info, length = 32) {
	const ikm = masterKey;
	const salt = new TextEncoder().encode('cryptdrive-v1');
	const infoBytes = new TextEncoder().encode(info);

	const key = await crypto.subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveBits']);

	const bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: infoBytes }, key, length * 8);

	return new Uint8Array(bits);
}

async function deriveKeys(passphrase, salt) {
	const masterKey = await deriveMasterKey(passphrase, salt);
	const authSeed = await hkdf(masterKey, 'auth-v1');
	const keychainKey = await hkdf(masterKey, 'keychain-v1');
	const keychainIdSeed = await hkdf(masterKey, 'keychain-id-v1', 16);

	const privateKey = authSeed;
	const publicKey = await nobleEd25519.getPublicKeyAsync(privateKey);

	// Derive keychain_id as a UUID-like string from keychainIdSeed
	const hex = Array.from(keychainIdSeed)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
	const keychainId = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;

	return { privateKey, publicKey, keychainKey, keychainId };
}

function arrayToBase64(array) {
	return btoa(String.fromCharCode(...array));
}

function base64ToArray(base64) {
	return new Uint8Array(
		atob(base64)
			.split('')
			.map((c) => c.charCodeAt(0))
	);
}

// ===== API Functions =====

async function apiCall(endpoint, options = {}) {
	const url = `${API_BASE}${endpoint}`;
	const headers = { ...options.headers };

	if (session.token) {
		headers['Authorization'] = `Bearer ${session.token}`;
	}

	const response = await fetch(url, { ...options, headers });

	if (!response.ok && response.headers.get('content-type')?.includes('application/json')) {
		const error = await response.json();
		throw new Error(error.error || `HTTP ${response.status}`);
	}

	return response;
}

// ===== Authentication =====

async function handleRegister(event) {
	event.preventDefault();
	const btn = document.getElementById('registerBtn');
	btn.disabled = true;
	btn.textContent = 'Creating...';

	try {
		const username = document.getElementById('regUsername').value;
		const passphrase = document.getElementById('regPassphrase').value;

		// generate a random salt for this user
		const saltBytes = crypto.getRandomValues(new Uint8Array(16));
		const salt = arrayToBase64(saltBytes);

		// Derive keys
		const keys = await deriveKeys(passphrase, salt);

		// Register user
		const response = await apiCall('/user', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				username,
				public_key: arrayToBase64(keys.publicKey),
				keychain_id: keys.keychainId,
				salt, // Send the salt to the server for storage
			}),
		});

		const data = await response.json();

		// Store session
		session.userId = data.user_id;
		session.keychainId = keys.keychainId; // Use derived keychain_id
		session.privateKey = keys.privateKey;
		session.publicKey = keys.publicKey;
		session.keychainKey = keys.keychainKey;

		// Initialize empty keychain
		session.keychain = { version: 1, files: {} };

		// Auto-login first to get token
		await performLogin(username, passphrase);

		// Now upload keychain with the token (using v2 format)
		const keychainJson = JSON.stringify(session.keychain);
		const keychainBlob = new Blob([keychainJson]);
		await uploadFile(keychainBlob, session.keychainKey, session.keychainId, 'keychain.json');

		// Save session to sessionStorage
		saveSession();
	} catch (error) {
		showError('registerError', error.message);
		btn.disabled = false;
		btn.textContent = 'Create Account';
	}
}

async function handleLogin(event) {
	event.preventDefault();
	const username = document.getElementById('loginUsername').value;
	const passphrase = document.getElementById('loginPassphrase').value;
	await performLogin(username, passphrase);
}

async function performLogin(username, passphrase) {
	const btn = document.getElementById('loginBtn');
	if (btn) {
		btn.disabled = true;
		btn.textContent = 'Logging in...';
	}

	try {
		// Get challenge using public key
		const challengeResp = await apiCall('/auth/token', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				username,
				challenge: null,
				signature: null,
			}),
		});

		const { challenge } = await challengeResp.json();

		// decode the challenge JWT to extract the salt (and user_id for verification)
		const decoded = JSON.parse(atob(challenge.split('.')[1]));
		const salt = decoded.salt;
		const user_id = decoded.user_id;

		if (!salt || !user_id) {
			throw new Error('Invalid challenge format: missing salt or user_id');
		}

		// Derive keys
		const keys = await deriveKeys(passphrase, salt);
		session.privateKey = keys.privateKey;
		session.publicKey = keys.publicKey;
		session.keychainKey = keys.keychainKey;
		session.keychainId = keys.keychainId;

		// Sign challenge
		const signature = await nobleEd25519.signAsync(new TextEncoder().encode(challenge), keys.privateKey);

		// Exchange for token using the actual user_id returned
		const tokenResp = await apiCall('/auth/token', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				username,
				challenge,
				signature: arrayToBase64(signature),
			}),
		});

		const { token } = await tokenResp.json();
		session.token = token;

		// Load keychain to get keychain_id
		await loadFiles();

		// Save session to sessionStorage
		saveSession();

		showSection('filesPage');
	} catch (error) {
		showError('loginError', error.message);
		if (btn) {
			btn.disabled = false;
			btn.textContent = 'Login';
		}
	}
}

function logout() {
	session = {
		userId: null,
		keychainId: null,
		token: null,
		keychainKey: null,
		privateKey: null,
		publicKey: null,
		keychain: null,
	};
	sessionStorage.removeItem('cryptdrive_session');
	showLanding();
}

// ===== File Management =====

/**
 * Download and decrypt a file stored in v2 format (multipart with chunks)
 * Streams the download and decrypts incrementally to handle large files efficiently
 */
async function downloadAndDecryptFile(fileId, fileKey, triggerDownload = false) {
	const METADATA_SIZE = 512; // Fixed plaintext metadata size
	const ENCRYPTED_METADATA_SIZE = METADATA_SIZE + 16; // +16 for GCM tag
	const BASE_NONCE_SIZE = 12;
	const HEADER_SIZE = BASE_NONCE_SIZE + ENCRYPTED_METADATA_SIZE; // 12 + 528 = 540 bytes

	// Get download URL for the complete file (all parts concatenated by R2)
	const urlResp = await apiCall(`/file/${fileId}`);
	if (!urlResp.ok) {
		throw new Error('Failed to get download URL');
	}
	const { downloadUrl } = await urlResp.json();

	// Start streaming download
	const fileResp = await fetch(downloadUrl);
	if (!fileResp.ok) {
		throw new Error('Failed to download file');
	}

	const reader = fileResp.body.getReader();
	let buffer = new Uint8Array(0);

	// Helper to append data to buffer
	const appendToBuffer = (newData) => {
		const combined = new Uint8Array(buffer.length + newData.length);
		combined.set(buffer);
		combined.set(newData, buffer.length);
		buffer = combined;
	};

	// Read enough data to get header: baseNonce (12 bytes) + encrypted metadata (528 bytes)
	while (buffer.length < HEADER_SIZE) {
		const { done, value } = await reader.read();
		if (done) {
			throw new Error('Stream ended before header could be read');
		}
		appendToBuffer(value);
	}

	// Extract baseNonce (unencrypted)
	const baseNonce = buffer.slice(0, BASE_NONCE_SIZE);

	// Extract and decrypt metadata
	const encryptedMeta = buffer.slice(BASE_NONCE_SIZE, HEADER_SIZE);
	const aesKey = await crypto.subtle.importKey('raw', fileKey, { name: 'AES-GCM' }, false, ['decrypt']);

	// Decrypt metadata using baseNonce + chunkIndex=-1
	const metaNonce = new Uint8Array(12);
	metaNonce.set(baseNonce);
	new DataView(metaNonce.buffer).setInt32(8, -1, false);

	const decryptedMetaBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: metaNonce }, aesKey, encryptedMeta);
	const decryptedMeta = new Uint8Array(decryptedMetaBuffer);

	// Parse metadata JSON (trim null bytes used for padding)
	const metadataText = new TextDecoder().decode(decryptedMeta).replace(/\0+$/, '');
	const metadata = JSON.parse(metadataText);

	// Validate format
	if (metadata.magic !== 'SECF' || metadata.version !== 2) {
		throw new Error('Invalid or unsupported file format');
	}

	const { totalChunks, originalSize, chunkSize, filename } = metadata;

	// Remove header from buffer
	buffer = buffer.slice(HEADER_SIZE);

	// For browser downloads, we'll decrypt to a file handle if available, or accumulate in memory
	let fileHandle = null;
	let writable = null;
	const decryptedChunks = []; // Fallback for browsers without File System Access API

	// Try to use File System Access API for direct-to-disk writes (if triggerDownload is true)
	if (triggerDownload && 'showSaveFilePicker' in window) {
		try {
			fileHandle = await window.showSaveFilePicker({
				suggestedName: filename,
				types: [
					{
						description: 'Downloaded file',
						accept: { '*/*': [] },
					},
				],
			});
			writable = await fileHandle.createWritable();
		} catch (e) {
			// User cancelled or API not available, fall back to memory accumulation
			console.log('File System Access API not available or cancelled, using fallback: ', e);
		}
	}

	// Process encrypted chunks incrementally
	let chunkIndex = 0;
	let offset = 0;
	const HEADER_OVERHEAD = 12 + 528;
	const FIRST_CHUNK_SIZE = chunkSize - HEADER_OVERHEAD; // First chunk is smaller

	while (chunkIndex < totalChunks) {
		const isLastChunk = chunkIndex === totalChunks - 1;
		let plaintextSize;
		if (chunkIndex === 0) {
			// First chunk is smaller to account for header
			plaintextSize = Math.min(FIRST_CHUNK_SIZE, originalSize);
		} else if (isLastChunk) {
			// Last chunk is whatever remains
			plaintextSize = originalSize - FIRST_CHUNK_SIZE - (chunkIndex - 1) * chunkSize;
		} else {
			// Middle chunks are full size
			plaintextSize = chunkSize;
		}
		const encryptedSize = plaintextSize + 16; // +16 for GCM tag

		// Make sure we have enough data in buffer for this chunk
		while (buffer.length < offset + encryptedSize) {
			const { done, value } = await reader.read();
			if (done) {
				if (buffer.length < offset + encryptedSize) {
					throw new Error('Stream ended unexpectedly');
				}
				break;
			}
			appendToBuffer(value);
		}

		// Extract and decrypt chunk
		const encryptedChunk = buffer.slice(offset, offset + encryptedSize);

		// Derive chunk nonce
		const chunkNonce = new Uint8Array(12);
		chunkNonce.set(baseNonce);
		new DataView(chunkNonce.buffer).setUint32(8, chunkIndex, false);

		// Decrypt chunk
		const decryptedBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: chunkNonce }, aesKey, encryptedChunk);
		const decryptedChunk = new Uint8Array(decryptedBuffer);

		// Write to file or accumulate in memory
		if (writable) {
			await writable.write(decryptedChunk);
		} else {
			decryptedChunks.push(decryptedChunk);
		}

		offset += encryptedSize;
		chunkIndex++;

		// Free memory by removing processed encrypted data from buffer
		if (offset > 10 * 1024 * 1024) {
			// Keep at most 10MB in buffer
			buffer = buffer.slice(offset);
			offset = 0;
		}
	}

	// Close writable stream if we used it
	if (writable) {
		await writable.close();
		return { filename, content: null }; // Content already written to disk
	}

	// Fallback: combine chunks in memory
	const combined = new Uint8Array(originalSize);
	let combineOffset = 0;
	for (const chunk of decryptedChunks) {
		combined.set(chunk, combineOffset);
		combineOffset += chunk.length;
	}

	return { filename, content: combined };
}

async function loadFiles() {
	document.getElementById('filesLoading').classList.remove('hidden');
	document.getElementById('filesList').innerHTML = '';

	try {
		// Get file list
		const response = await apiCall('/files');
		const data = await response.json();

		// Find keychain file (it's one of the files)
		for (const file of data.files) {
			// Try to decrypt as keychain
			try {
				const { content } = await downloadAndDecryptFile(file.file_id, session.keychainKey, false);
				const json = new TextDecoder().decode(content);
				const keychain = JSON.parse(json);

				if (keychain.version === 1 && keychain.files) {
					session.keychain = keychain;
					session.keychainId = file.file_id;
					break;
				}
			} catch {
				// Not the keychain, continue
			}
		}

		// Initialize keychain if not found (e.g., during fresh registration)
		if (!session.keychain) {
			session.keychain = { version: 1, files: {} };
		}

		if (!session.keychainId && data.files.length > 0) {
			console.warn('Keychain file not found but files exist!');
		}

		// Display files
		const filesList = document.getElementById('filesList');
		const files = data.files.filter((f) => f.file_id !== session.keychainId);

		if (files.length === 0) {
			filesList.innerHTML = '<p>No files yet. Upload your first file!</p>';
		} else {
			files.forEach((file) => {
				const fileInfo = session.keychain.files[file.file_id] || {};
				const filename = fileInfo.filename || file.file_id;
				const fileSize = fileInfo.size || 0;

				const fileItem = document.createElement('div');
				fileItem.className = 'file-item';

				// Create info div with filename and size (using textContent to prevent XSS)
				const infoDiv = document.createElement('div');
				const nameStrong = document.createElement('strong');
				nameStrong.textContent = filename;
				const sizeSmall = document.createElement('small');
				sizeSmall.textContent = ` (${formatBytes(fileSize)})`;
				infoDiv.appendChild(nameStrong);
				infoDiv.appendChild(sizeSmall);

				// Create actions div with buttons
				const actionsDiv = document.createElement('div');
				const shareBtn = document.createElement('button');
				shareBtn.textContent = 'Share';
				shareBtn.onclick = () => generateShareLink(file.file_id);
				const downloadBtn = document.createElement('button');
				downloadBtn.textContent = 'Download';
				downloadBtn.onclick = () => downloadFile(file.file_id);
				actionsDiv.appendChild(shareBtn);
				actionsDiv.appendChild(downloadBtn);

				fileItem.appendChild(infoDiv);
				fileItem.appendChild(actionsDiv);
				filesList.appendChild(fileItem);
			});
		}
	} catch (error) {
		showError('filesError', error.message);
	} finally {
		document.getElementById('filesLoading').classList.add('hidden');
	}
}

async function uploadFile(file, fileKey, fileId = null, filename = null) {
	const baseNonce = crypto.getRandomValues(new Uint8Array(12));
	const METADATA_SIZE = 512; // Fixed plaintext metadata size (before encryption)
	const HEADER_OVERHEAD = 12 + 528; // baseNonce + encrypted metadata in Part 1
	const FIRST_CHUNK_PLAINTEXT_SIZE = FILE_CHUNK_PLAINTEXT_SIZE - HEADER_OVERHEAD; // Smaller first chunk to keep Part 1 at exactly 5 MiB

	// Calculate total chunks considering the smaller first chunk
	const firstChunkSize = Math.min(FIRST_CHUNK_PLAINTEXT_SIZE, file.size);
	const remainingSize = Math.max(0, file.size - firstChunkSize);
	const remainingChunks = Math.ceil(remainingSize / FILE_CHUNK_PLAINTEXT_SIZE);
	const totalChunks = 1 + remainingChunks;

	// 1) Create or reuse file_id
	let file_id = fileId;
	if (!file_id) {
		// Create new file metadata record on the server
		const createResp = await apiCall('/file', {
			method: 'POST',
		});
		if (!createResp.ok) {
			throw new Error('Failed to create file on server');
		}
		const result = await createResp.json();
		file_id = result.file_id;
	}

	// 2) Initiate multipart upload to get upload_id
	const startResp = await apiCall(`/file/${file_id}/upload`, {
		method: 'GET',
	});
	if (!startResp.ok) {
		throw new Error('Failed to initiate multipart upload');
	}
	const { upload_id } = await startResp.json();

	const parts = [];
	const encoder = new TextEncoder();
	const aesKey = await crypto.subtle.importKey('raw', fileKey, { name: 'AES-GCM' }, false, ['encrypt']);

	// Helper to abort multipart upload on failures
	const abortUpload = async () => {
		try {
			await apiCall(`/file/${file_id}/upload/${upload_id}`, { method: 'DELETE' });
		} catch (e) {
			console.error('Failed to abort multipart upload:', e);
		}
	};

	// 3) Prepare and encrypt metadata
	const metadata = {
		magic: 'SECF',
		version: 2,
		baseNonce: Array.from(baseNonce),
		chunkSize: FILE_CHUNK_PLAINTEXT_SIZE,
		filename: filename || file.name || 'file',
		originalSize: file.size,
		totalChunks,
	};
	const metadataJson = JSON.stringify(metadata);
	const metadataBytes = encoder.encode(metadataJson);

	// Pad metadata to fixed size (remaining bytes are zeros)
	const metadataPadded = new Uint8Array(METADATA_SIZE);
	metadataPadded.set(metadataBytes);

	// Encrypt metadata with chunkIndex=-1 (special value for metadata)
	const metaNonce = new Uint8Array(12);
	metaNonce.set(baseNonce);
	new DataView(metaNonce.buffer).setInt32(8, -1, false); // Use -1 for metadata

	const encryptedMetaBuffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: metaNonce }, aesKey, metadataPadded);
	const encryptedMeta = new Uint8Array(encryptedMetaBuffer);

	// 4) Encrypt first chunk of file data (chunkIndex=0) - smaller to account for header overhead
	const firstChunkBuffer = await file.slice(0, firstChunkSize).arrayBuffer();
	const firstChunkData = new Uint8Array(firstChunkBuffer);

	const firstChunkNonce = new Uint8Array(12);
	firstChunkNonce.set(baseNonce);
	new DataView(firstChunkNonce.buffer).setUint32(8, 0, false);

	const encryptedFirstChunkBuffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: firstChunkNonce }, aesKey, firstChunkData);
	const encryptedFirstChunk = new Uint8Array(encryptedFirstChunkBuffer);

	// 5) Upload part 1: baseNonce + encrypted metadata + encrypted first chunk
	const part1UrlResp = await apiCall(`/file/${file_id}/upload/${upload_id}/part/1`, {
		method: 'GET',
	});
	if (!part1UrlResp.ok) {
		await abortUpload();
		throw new Error('Failed to get upload URL for part 1');
	}
	const { upload_url: part1Url } = await part1UrlResp.json();

	// Concatenate: baseNonce (unencrypted) + encrypted metadata + encrypted first chunk
	const part1Data = new Uint8Array(baseNonce.length + encryptedMeta.length + encryptedFirstChunk.length);
	part1Data.set(baseNonce, 0);
	part1Data.set(encryptedMeta, baseNonce.length);
	part1Data.set(encryptedFirstChunk, baseNonce.length + encryptedMeta.length);

	const part1Resp = await fetch(part1Url, {
		method: 'PUT',
		headers: { 'Content-Type': 'application/octet-stream' },
		body: part1Data,
	});
	if (!part1Resp.ok) {
		await abortUpload();
		throw new Error('Failed to upload part 1');
	}
	parts.push({ part_number: 1, etag: part1Resp.headers.get('ETag') });

	// 6) Upload remaining encrypted chunks (chunkIndex 1 to totalChunks-1)
	for (let chunkIndex = 1; chunkIndex < totalChunks; chunkIndex++) {
		const partNumber = chunkIndex + 1;
		const partUrlResp = await apiCall(`/file/${file_id}/upload/${upload_id}/part/${partNumber}`, {
			method: 'GET',
		});
		if (!partUrlResp.ok) {
			await abortUpload();
			throw new Error(`Failed to get upload URL for part ${partNumber}`);
		}
		const { upload_url } = await partUrlResp.json();

		// Start after the first (smaller) chunk
		const start = firstChunkSize + (chunkIndex - 1) * FILE_CHUNK_PLAINTEXT_SIZE;
		const end = Math.min(start + FILE_CHUNK_PLAINTEXT_SIZE, file.size);
		const chunkBuffer = await file.slice(start, end).arrayBuffer();
		const chunkData = new Uint8Array(chunkBuffer);

		// Derive unique nonce for this chunk from baseNonce and chunkIndex
		const chunkNonce = new Uint8Array(12);
		chunkNonce.set(baseNonce);
		new DataView(chunkNonce.buffer).setUint32(8, chunkIndex, false);

		const encryptedChunkBuffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: chunkNonce }, aesKey, chunkData);
		const encryptedChunk = new Uint8Array(encryptedChunkBuffer);

		const uploadResp = await fetch(upload_url, {
			method: 'PUT',
			headers: {
				'Content-Type': 'application/octet-stream',
			},
			body: encryptedChunk,
		});
		if (!uploadResp.ok) {
			await abortUpload();
			throw new Error(`Failed to upload part ${partNumber}`);
		}
		parts.push({ part_number: partNumber, etag: uploadResp.headers.get('ETag') });
	}

	// 7) Complete multipart upload
	const completeResp = await apiCall(`/file/${file_id}/upload/${upload_id}`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ parts }),
	});
	if (!completeResp.ok) {
		await abortUpload();
		throw new Error('Failed to complete multipart upload');
	}

	return file_id;
}

async function handleUpload(event) {
	event.preventDefault();
	const btn = document.getElementById('uploadBtn');
	btn.disabled = true;
	btn.textContent = 'Uploading...';

	try {
		const fileInput = document.getElementById('fileInput');
		const file = fileInput.files[0];

		if (!file) {
			throw new Error('Please select a file to upload.');
		}

		// Generate file key
		const fileKey = crypto.getRandomValues(new Uint8Array(32));

		// Upload file
		const file_id = await uploadFile(file, fileKey);

		// 6) Update keychain with new file entry (stores original size)
		session.keychain.files[file_id] = {
			key: Array.from(fileKey)
				.map((b) => b.toString(16).padStart(2, '0'))
				.join(''),
			filename: file.name,
			created: new Date().toISOString(),
			size: file.size,
		};

		// Upload updated keychain (as raw JSON using v2 format)
		const keychainJson = JSON.stringify(session.keychain);
		const keychainBlob = new Blob([keychainJson]);
		await uploadFile(keychainBlob, session.keychainKey, session.keychainId, 'keychain.json');

		showSuccess('filesSuccess', `File "${file.name}" uploaded successfully!`);
		fileInput.value = '';
		await loadFiles();
	} catch (error) {
		showError('filesError', error.message);
	} finally {
		btn.disabled = false;
		btn.textContent = 'Upload';
	}
}

async function downloadFile(fileId, fileKeyBase64 = null) {
	try {
		let fileKey;

		// Check if file key provided (from shared link)
		if (fileKeyBase64) {
			fileKey = base64ToArray(fileKeyBase64);
		} else if (session.keychain && session.keychain.files[fileId]) {
			// Get file key from keychain (for logged-in owner)
			const fileInfo = session.keychain.files[fileId];
			fileKey = new Uint8Array(fileInfo.key.match(/.{2}/g).map((byte) => parseInt(byte, 16)));
		} else {
			throw new Error('File not found in keychain. You may need a share link to access this file.');
		}

		// Download and decrypt file (v2 format) with streaming
		const { filename, content } = await downloadAndDecryptFile(fileId, fileKey, true);

		// If content is null, file was already saved to disk via File System Access API
		if (content === null) {
			showSuccess('filesSuccess', `Downloaded "${filename}"`);
			return;
		}

		// Fallback for browsers without File System Access API: trigger download via blob URL
		const blob = new Blob([content]);
		const blobUrl = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = blobUrl;
		a.download = filename;
		a.click();
		URL.revokeObjectURL(blobUrl);

		showSuccess('filesSuccess', `Downloaded "${filename}"`);
	} catch (error) {
		showError('filesError', error.message);
	}
}

function formatBytes(bytes) {
	if (bytes === 0) return '0 Bytes';
	const k = 1024;
	const sizes = ['Bytes', 'KB', 'MB', 'GB'];
	const i = Math.floor(Math.log(bytes) / Math.log(k));
	return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

async function generateShareLink(fileId) {
	// First we need to call the API to make the file publically accessible
	// (without authentication) so that the download URL can be accessed by
	// anyone with the link
	const response = await apiCall(`/file/${fileId}/publish`, { method: 'POST' });
	if (!response.ok) {
		showError('filesError', 'Failed to publish file for sharing');
		return;
	}

	try {
		const fileInfo = session.keychain.files[fileId];
		if (!fileInfo) {
			throw new Error('File not found in keychain');
		}

		// Get file key as bytes
		const fileKey = new Uint8Array(fileInfo.key.match(/.{2}/g).map((byte) => parseInt(byte, 16)));
		const fileKeyBase64 = arrayToBase64(fileKey);

		// Generate shareable URL with key in fragment
		const shareUrl = `${window.location.origin}#${fileId}:${fileKeyBase64}`;

		// Copy to clipboard
		navigator.clipboard
			.writeText(shareUrl)
			.then(() => {
				showSuccess('filesSuccess', `Share link copied! Anyone with this link can download "${fileInfo.filename}". Keep it secure!`);
			})
			.catch(() => {
				// Fallback: show the URL
				prompt('Share this link (Ctrl+C to copy):', shareUrl);
			});
	} catch (error) {
		showError('filesError', error.message);
	}
}

// Expose functions to window for inline onclick handlers
window.showLanding = showLanding;
window.showRegister = showRegister;
window.showLogin = showLogin;
window.handleRegister = handleRegister;
window.handleLogin = handleLogin;
window.logout = logout;
window.handleUpload = handleUpload;
window.downloadFile = downloadFile;
window.generateShareLink = generateShareLink;

// Check if user is already logged in on page load
(async function checkSession() {
	// Check for shared file link in URL fragment
	const hash = window.location.hash.substring(1); // Remove #
	if (hash && hash.includes(':')) {
		const [fileId, fileKeyBase64] = hash.split(':');
		if (fileId && fileKeyBase64) {
			// Clear the hash from URL for privacy (without reloading page)
			history.replaceState(null, '', window.location.pathname + window.location.search);

			// Show a message and download the shared file
			showSection('landingPage');
			showSuccess('landingPage', 'Downloading shared file...');
			await downloadFile(fileId, fileKeyBase64);
			return;
		}
	}

	// Normal session check
	if (session.token && session.keychainId) {
		try {
			// Verify token is still valid by trying to fetch files
			await loadFiles();
			showSection('filesPage');
		} catch {
			// Token expired or invalid, clear session
			console.log('Session expired, please login again');
			sessionStorage.removeItem('cryptdrive_session');
			showLanding();
		}
	}
})();
