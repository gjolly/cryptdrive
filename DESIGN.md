# End-to-End Encrypted Storage System - Design Document

**Version:** 2.0
**Date:** February 8, 2026
**Status:** Draft

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Cryptographic Design](#cryptographic-design)
4. [API Specification](#api-specification)
5. [Data Formats](#data-formats)
6. [Workflows](#workflows)
7. [Security Considerations](#security-considerations)

---

## Overview

### Purpose

This document describes an end-to-end encrypted (E2EE) storage system where:

- Users can store files encrypted on the server
- The server cannot read file contents (zero-knowledge)
- Users can share files with read-only access
- Only file owners can modify or delete their files

### Key Features

- **End-to-End Encryption**: All files encrypted client-side before upload
- **Zero-Knowledge**: Server never sees plaintext content or encryption keys
- **Read-Only Sharing**: Share files by distributing file keys without granting write permissions
- **Passphrase-Based Key Derivation**: All keys derived from user passphrase (no key storage needed)
- **Blind Index Privacy**: Server uses hashed owner identifiers for privacy
- **Stateless Authentication**: JWT-based authentication with challenge-response

---

## Architecture

### High-Level Components

```
┌─────────────┐
│   Client    │
│  (Browser)  │
│             │
│ - Crypto    │
│ - Key Mgmt  │
│ - UI        │
└──────┬──────┘
       │ HTTPS
       │ REST API
       ▼
┌─────────────┐
│   Server    │
│             │
│ - Auth      │
│ - Storage   │
│ - Access    │
│   Control   │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Database   │
│             │
│ - Users     │
│ - Files     │
│ - Metadata  │
└─────────────┘
```

### Technology Stack

**Client-Side:**

- Argon2 for key derivation
- Ed25519 for authentication signatures
- AES-256-GCM for file encryption
- HMAC-SHA256 for capability proofs

**Server-Side:**

- JWT for session tokens
- HMAC-SHA256 for blind indexes
- Any database (PostgreSQL, MongoDB, etc.)

---

## Cryptographic Design

### Key Hierarchy

```
User Passphrase
      │
      ▼
   Argon2(passphrase, salt=username)
      │
      ▼
  Master Key (MK)
      │
      ├──────────────────┬──────────────────┐
      ▼                  ▼                  ▼
   HKDF(MK,         HKDF(MK,         HKDF(MK,
   "auth-v1")       "keychain-v1")   "...")
      │                  │
      ▼                  ▼
Auth Key Seed      Keychain Key
      │                 (KK)
      ▼
Ed25519 Key Pair
(PrivKey, PubKey)
```

### Key Types

| Key Name          | Derivation                      | Purpose                          | Storage                      |
| ----------------- | ------------------------------- | -------------------------------- | ---------------------------- |
| Master Key (MK)   | `Argon2(passphrase, username)`  | Root key for derivation          | Never stored                 |
| Auth Private Key  | `HKDF(MK, "auth-v1")` → Ed25519 | Sign authentication challenges   | Never stored                 |
| Auth Public Key   | Derived from PrivKey            | Verify signatures                | Server stores                |
| Keychain Key (KK) | `HKDF(MK, "keychain-v1")`       | Encrypt/decrypt keychain         | Never stored                 |
| File Key (FK)     | `random(32 bytes)` per file     | Encrypt/decrypt individual files | Stored in encrypted keychain |

### Algorithms

- **Key Derivation**: Argon2id (time=3, memory=65536, parallelism=4)
- **HKDF**: HMAC-SHA256
- **Asymmetric Auth**: Ed25519
- **File Encryption**: AES-256-GCM
- **Keychain Encryption**: AES-256-GCM
- **Blind Index**: HMAC-SHA256(UID, server_pepper)

---

## API Specification

### Base URL

```
https://api.example.com/v1
```

### Authentication

All authenticated endpoints require:

```
Authorization: Bearer <JWT>
```

---

### Endpoints

#### 1. Create user

**Request:**

```http
POST /user
Content-Type: application/json

{
    "username": "username",
    "salt": "random_salt",
    "public_key": "base64_ed25519_public_key_derived_from_passphrase",
    "keychain_id": "uuid_dervied_from_passphrase"
}
```

**Response:**

```json
{
	"user_id": "uuid-v4"
}
```

**Description:**

- Creates a new user account
- Associates public key with client ID
- Store salt for key derivation on login

  **Server Actions:**

1. Generate unique `user_id` (UUID)
2. Store `user_id` → `public_key` mapping
3. Store `user_id` → `keychain_id` mapping

---

#### 2. Get Authentication Challenge

**Request:**

```http
POST /auth/token
Content-Type: application/json

{
    "username": "username",
    "challenge": null,
    "signature": null
}
```

**Response:**

```json
{
	"challenge": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Challenge JWT Payload:**

```json
{
	"nonce": "32_char_hex_string",
	"user_id": "uuid",
	"username": "username",
	"salt": "user_salt_for_key_derivation",
	"iat": 1234567890,
	"exp": 1234568190
}
```

**Description:**

- Server generates a signed JWT challenge
- Challenge expires in 30 seconds
- Nonce is random 32-character hex string

---

#### 3. Exchange Signature for Token

**Request:**

```http
POST /auth/token
Content-Type: application/json

{
    "user_id": "uuid",
    "challenge": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "signature": "base64_ed25519_signature"
}
```

**Response:**

```json
{
	"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
	"expires_in": 3600
}
```

**Access Token JWT Payload:**

```json
{
	"sub": "user_id",
	"iat": 1234567890,
	"exp": 1234571490
}
```

**Description:**

- Client signs the challenge JWT with their Ed25519 private key
- Server verifies:
  1. Challenge JWT is valid and not expired
  2. `user_id` matches challenge payload
  3. Signature is valid for the user's public key
- Returns access token (1 hour expiry)
- Stores nonce as used to prevent replay attacks

---

#### 4. List Files

**Request:**

```http
GET /files
Authorization: Bearer <JWT>
```

**Response:**

```json
{
	"files": [
		{
			"file_id": "uuid",
			"created_at": "2026-02-03T10:00:00Z",
			"updated_at": "2026-02-03T10:00:00Z",
			"size": 12345
		},
		{
			"file_id": "uuid2",
			"created_at": "2026-02-03T11:00:00Z",
			"updated_at": "2026-02-03T11:00:00Z",
			"size": 67890
		}
	]
}
```

**Description:**

- Returns list of files owned by authenticated user
- Uses blind index to find files: `HMAC(user_id, server_pepper)`
- Does not include filenames (they're encrypted in the files)
- Client must cross-reference with keychain to get filenames

---

#### 5. Create File

**Request:**

```http
POST /file
Authorization: Bearer <JWT>
```

**Response:**

```json
{
	"file_id": "uuid"
}
```

**Description:**

- Initiates a new file in the system

**Server Actions:**

1. Extract `user_id` from JWT
2. Compute `owner_hash = HMAC-SHA256(user_id, server_pepper)`
3. Generate unique `file_id`
4. Return `file_id

**Security:**

- Server cannot read file contents (encrypted with FK)
- Owner hash prevents non-owners from modifying file

---

#### 6. Initiate Multipart Upload

**Request:**

```http
GET /file/{file_id}/upload
Authorization: Bearer <JWT>
```

\*_Response:_

```json
{
	"upload_id": "r2_multipart_upload_id"
}
```

**Description:**

- Initiates a multipart upload in R2 for the specified file

**Server Actions:**

1. Verify user owns the file (compare JWT user_id hash with stored owner_hash)
2. Initiate multipart upload in R2 for key: `{file_id}`

#### 6. Get Presigned Upload URL

**Request:**

```http
GET /upload/{upload_id}/part/{part_number}
Authorization: Bearer <JWT>
```

**Parameters:**

- `upload_id`: The upload ID from initiate upload
- `part_number`: Part number (0 for metadata, 1-N for data chunks)

**Response:**

```json
{
	"url": "https://bucket.r2.cloudflarestorage.com/...",
	"expires_in": 300
}
```

**Description:**

- Returns a presigned URL for uploading a specific part
- URL expires in 5 minutes
- Client uploads directly to R2 using PUT request
- Part 0 is always the metadata JSON
- Parts 1 "total_chunks": 21
  through N are encrypted file chunks
- Client stores ETags returned from each PUT request for completion

**Server Actions:**

1. Verify user owns the file (compare JWT user_id hash with stored owner_hash)
2. Verify upload is in `pending` state
3. Generate presigned R2 URL for part: `{file_id}/part_{part_number}`
4. Return URL with expiration

**Security:**

- Only file owner can get upload URLs
- Presigned URLs are time-limited
- Each part requires a separate URL

---

#### 7. Complete File Upload

**Request:**

```http
POST /upload/{upload_id}
Authorization: Bearer <JWT>
Content-Type: application/json

{
    "parts": [
        {
            "part_number": 0,
            "etag": "\"abc123...\""
        },
        {
            "part_number": 1,
            "etag": "\"def456...\""
        }
    ]
}
```

**Response:**

```json
{
	"success": true,
	"file_id": "uuid",
	"size": 104857600,
	"created_at": "2026-02-08T10:00:00Z"
}
```

**Description:**

- Completes the multipart upload in R2
- Combines all parts into final file
- Marks file as available
- All parts must be uploaded before calling this endpoint

**Server Actions:**

1. Verify user owns the file
2. Verify all expected parts (0 through total_chunks-1) are present in request
3. Complete R2 multipart upload with provided ETags
4. Update file status to `complete`
5. Store final file size and creation timestamp
6. Return success

**Security:**

- Only file owner can complete upload
- Server verifies all parts are present

---

#### 7. Abort File Upload

**Request:**

```http
DELETE /upload/{upload_id}
Authorization: Bearer <JWT>
```

**Response:**

```json
{
	"success": true
}
```

**Description:**

- Aborts a multipart upload in R2
- Only file owner can abort

**Server Actions:**

1. Verify user owns the file (compare JWT user_id hash with stored owner_hash)
2. Abort R2 multipart upload
3. Mark upload as `aborted`
4. Return success

---

#### 8. Get File Download URL

**Request:**

```http
GET /files/{file_id}
Authorization: Bearer <JWT> (optional)
```

**Parameters:**

- `file_id`: The file ID to download
- `part_number`: Part number (0 for metadata, 1-N for data chunks)

**Response:**

```json
{
	"url": "https://bucket.r2.cloudflarestorage.com/...",
	"expires_in": 300
}
```

**Description:**

- Returns a presigned URL for downloading a specific part
- Anyone can download any file if they know the file ID (read-only sharing)
- Authorization optional (supports anonymous read)
- Client downloads part 0 first to get metadata, then downloads encrypted chunks
- URL expires in 5 minutes

**Server Actions:**

1. Verify file exists and is `complete`
2. Generate presigned R2 download URL for part: `{file_id}/part_{part_number}`
3. Return URL with expiration

**Client Actions:**

1. Download metadata (part 0)
2. Parse metadata to get chunk count and encryption parameters
3. Download encrypted chunks (parts 1-N) in parallel if desired
4. Decrypt each chunk with File Key (FK) from keychain
5. Combine decrypted chunks into final file

---

#### 9. Update File

**Request:**

```http
PUT /files/{file_id}
Authorization: Bearer <JWT>
Content-Type: application/json

{
    "total_size": 104857600
}
```

**Response:**

```json
{
	"upload_id": "r2_multipart_upload_id"
}
```

**Description:**

- Initiates a new multipart upload for replacing an existing file
- Same process as creating a new file, but replaces existing file_id
- Only file owner can update
- After completion, old file parts are deleted

**Server Actions:**

1. Verify user owns file (check owner_hash)
2. Mark old file as `replacing`
3. Initiate new R2 multipart upload
4. Return `upload_id`
5. Client follows same upload process (get URLs for each part, upload, complete)
6. After successful completion, delete old file parts

---

#### 10. Delete File

**Request:**

```http
DELETE /files/{file_id}
Authorization: Bearer <JWT>
```

**Response:**

```json
{
	"success": true
}
```

**Description:**

- Deletes file and all its parts from R2
- Only file owner can delete

**Server Actions:**

1. Verify user owns file (check owner_hash)
2. Delete all file parts from R2: `{file_id}/part_*`
3. Delete file metadata from database
4. Return success

**Client Actions After:**

1. Remove file entry from keychain
2. Encrypt keychain with KK
3. Upload updated keychain using same multipart process

---

## Data Formats

### File Format (Version 2)

Files are stored in R2 as multiple parts using multipart upload. Each logical file consists of:

#### Part 0: Metadata (JSON)

```json
{
	"magic": "SECF",
	"version": 2,
	"baseNonce": [12, 34, 56, ...],
	"chunkSize": 5242880,
	"filename": "example.pdf",
	"originalSize": 15728640,
	"totalChunks": 3
}
```

**Fields:**

| Field        | Type     | Description                                |
| ------------ | -------- | ------------------------------------------ |
| magic        | string   | Always "SECF" (Secure Encrypted File)      |
| version      | number   | Format version (2 for multipart)           |
| baseNonce    | number[] | 12-byte base nonce as array                |
| chunkSize    | number   | Plaintext chunk size in bytes (e.g., 5MB)  |
| filename     | string   | Original filename                          |
| originalSize | number   | Original file size before encryption       |
| totalChunks  | number   | Number of data chunks (excluding metadata) |

#### Parts 1-N: Encrypted Data Chunks

Each data chunk is encrypted with AES-256-GCM:

```
┌─────────────────────────────────────────────────────────────┐
│ Encrypted Data (chunkSize bytes, except last chunk)        │
├─────────────────────────────────────────────────────────────┤
│ Auth Tag (16 bytes): AES-GCM authentication tag            │
└─────────────────────────────────────────────────────────────┘
```

**Chunk Nonce Derivation:**

Each chunk has a unique nonce derived from the base nonce and chunk index:

```
chunkNonce[0-7] = baseNonce[0-7]
chunkNonce[8-11] = chunk_index (uint32, big-endian)

Where:
- Part 1 = chunk index 0
- Part 2 = chunk index 1
- Part N = chunk index (N-1)
```

**Encryption Per Chunk:**

```javascript
// For each chunk
const chunkNonce = new Uint8Array(12);
chunkNonce.set(baseNonce); // Copy base nonce
new DataView(chunkNonce.buffer).setUint32(8, chunkIndex, false); // Add index

const encryptedChunk = AES-256-GCM.encrypt(
	key: FK,
	plaintext: chunkData,
	nonce: chunkNonce,
	additional_data: none
);
// Returns: encrypted_data || auth_tag (chunkSize + 16 bytes)
```

**Complete File Structure in R2:**

```
files/{file_id}/part_0      → Metadata JSON
files/{file_id}/part_1      → Encrypted chunk 0 + tag
files/{file_id}/part_2      → Encrypted chunk 1 + tag
files/{file_id}/part_N      → Encrypted chunk (N-1) + tag
```

**Comparison with Version 1:**

| Feature                  | Version 1            | Version 2                              |
| ------------------------ | -------------------- | -------------------------------------- |
| Storage                  | Single blob          | Multiple parts                         |
| Encryption               | Entire file at once  | Chunked encryption                     |
| Resume capability        | ❌ No                | ✅ Yes                                 |
| Parallel upload/download | ❌ No                | ✅ Yes                                 |
| Memory efficiency        | ❌ Loads entire file | ✅ Streams chunks                      |
| Max file size            | Limited by memory    | Unlimited (practical limit: R2 limits) |

---

### Keychain Format

The keychain is a special file (stored at `keychain_id` returned during registration) containing all file keys.

**Plaintext Structure (JSON):**

```json
{
	"version": 1,
	"files": {
		"file_id_1": {
			"key": "hex_encoded_32_byte_key",
			"filename": "document.pdf",
			"created": "2026-02-03T10:00:00Z",
			"size": 12345
		},
		"file_id_2": {
			"key": "hex_encoded_32_byte_key",
			"filename": "photo.jpg",
			"created": "2026-02-03T11:00:00Z",
			"size": 67890
		}
	}
}
```

**Encrypted Keychain File Format:**

Same as regular file format, encrypted with Keychain Key (KK):

```
┌─────────────────────────────────────────┐
│ Magic: "SECF"                           │
│ Version: 0x01                           │
│ Nonce: 12 random bytes                  │
│ Encrypted: JSON keychain                │
│ Auth Tag: 16 bytes                      │
└─────────────────────────────────────────┘
```

**Why encrypt filename in keychain?**

The filename field in the keychain is base64-encoded encrypted filename. This allows the client to:

1. Quickly list all files without decrypting file contents
2. Display filenames in UI
3. Search files by name

Alternative: Store plaintext filenames in keychain if acceptable for your threat model.

---

### Rate Limiting and Abuse Prevention

**Rate Limiting Policies:**

Authentication endpoints (POST /auth/token):

- Dual limiting approach:
  - IP-based: 10 requests per minute (prevents brute force from single source)
  - User-based: 5 requests per minute per user_id (prevents distributed attacks on specific account)
  - Exponential backoff after 3 failed attempts per user_id
  - Optional: CAPTCHA after 5 failures

User registration (POST /user):

- Fingerprint-based (SHA256 of IP + User-Agent + Accept-Language): 3 registrations per hour
- CAPTCHA required after 2 registrations from same fingerprint

Authenticated file operations (GET /files, POST/PUT/DELETE /file):

- User-based (extracted from JWT): 50 requests per minute for reads, 20 requests per minute for writes
- Immune to IP changes (mobile networks, VPN switches)

Anonymous file downloads (GET /file/{id} without auth):

- IP-based: 100 requests per minute (supports legitimate sharing)
- After limit exceeded: require CAPTCHA or authentication

Individual file size limit:

- max 10 MB per file for free tier (tier 0)
- max 100 MB per file for tier 1

Total storage quota per user:

- max 100 MB for free tier (tier 0)
- max 10 GB for tier 1

**Fingerprinting Method:**

```javascript
const fingerprint = SHA256(ip_address + user_agent + accept_language);
```

---

### File Sharing

A file can be shared by distributing its `file_id` and corresponding `File Key (FK)`.

This is done by generating a URL of the form:

```
https://app.example.com/file/<file_id>/#<base64_encoded_FK>
```

The client can parse the URL fragment to extract the FK and use it to decrypt the file after downloading.

---

### Data retention and cleanup

Tier 0 (free) users should have their files deleted after 24 hours. Tier 1 users have no automatic deletion.

---

### Database Schema

**Users Table:**

```sql
CREATE TABLE users (
    user_id VARCHAR(36) PRIMARY KEY,  -- UUID
    public_key TEXT NOT NULL,            -- Base64 Ed25519 public key
    keychain_id VARCHAR(36) NOT NULL,    -- UUID of keychain file
    created_at TIMESTAMP DEFAULT NOW(),
    tiered INTEGER DEFAULT 0,            -- User tier for rate limiting
    UNIQUE(public_key)
);
```

**Files Table:**

```sql
CREATE TABLE files (
    file_id VARCHAR(36) PRIMARY KEY,         -- UUID
    owner_hash VARCHAR(64) NOT NULL,         -- HMAC(user_id, pepper)
    upload_id VARCHAR(255),                  -- R2 multipart upload ID
    total_chunks INTEGER NOT NULL,           -- Total number of parts (including metadata)
    size BIGINT,                             -- Final file size in bytes (set after completion)
    status VARCHAR(20) DEFAULT 'pending',    -- 'pending', 'complete', 'replacing'
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,                  -- When upload was completed
    INDEX idx_owner_hash (owner_hash),
    INDEX idx_status (status)
);

-- Note: Actual file data is stored in R2 at:
-- - {file_id}/part_0 (metadata JSON)
-- - {file_id}/part_1 through part_N (encrypted chunks)
```

**Server Configuration:**

```sql
CREATE TABLE config (
    key VARCHAR(255) PRIMARY KEY,
    value TEXT NOT NULL
);

-- Store server pepper (keep secret!)
INSERT INTO config VALUES ('pepper', 'random_64_byte_hex');
```

**Rate Limiting Tables:**

```sql
-- Authentication rate limiting (dual: IP-based and user-based)
CREATE TABLE auth_rate_limits (
    id VARCHAR(64) PRIMARY KEY,           -- SHA256 hash of IP or user_id
    type VARCHAR(10) NOT NULL,            -- 'ip' or 'user'
    attempts INTEGER DEFAULT 0,           -- Total attempts in current window
    failed_attempts INTEGER DEFAULT 0,    -- Failed attempts (for exponential backoff)
    last_attempt TIMESTAMP DEFAULT NOW(),
    window_start TIMESTAMP DEFAULT NOW(),
    INDEX idx_type_window (type, window_start)
);

-- Registration rate limiting (fingerprint-based)
CREATE TABLE registration_rate_limits (
    fingerprint VARCHAR(64) PRIMARY KEY,  -- SHA256(ip + user_agent + accept_language)
    registrations INTEGER DEFAULT 0,      -- Registrations in current window
    captcha_required BOOLEAN DEFAULT FALSE,
    window_start TIMESTAMP DEFAULT NOW()
);

-- Authenticated file operations (user-based)
CREATE TABLE file_operation_limits (
    user_id VARCHAR(36) PRIMARY KEY,      -- User's UUID
    read_requests INTEGER DEFAULT 0,      -- GET /files, GET /file (authenticated)
    write_requests INTEGER DEFAULT 0,     -- POST, PUT, DELETE
    window_start TIMESTAMP DEFAULT NOW()
);

-- Anonymous downloads (IP-based)
CREATE TABLE anonymous_download_limits (
    ip_hash VARCHAR(64) PRIMARY KEY,      -- SHA256 hash of IP address
    downloads INTEGER DEFAULT 0,          -- GET /file/{id} without auth
    captcha_required BOOLEAN DEFAULT FALSE,
    window_start TIMESTAMP DEFAULT NOW()
);
```

---

## Workflows

### User Registration

```
┌────────┐                                   ┌────────┐
│ Client │                                   │ Server │
└───┬────┘                                   └───┬────┘
    │                                            │
    │ 1. User enters passphrase                 │
    ├─ Derive keys locally ────────────────────►│
    │    MK = Argon2(passphrase, username)      │
    │    AuthSeed = HKDF(MK, "auth-v1")         │
    │    PrivKey, PubKey = Ed25519(AuthSeed)    │
    │    KK = HKDF(MK, "keychain-v1")           │
    │                                            │
    │ 2. POST /client                            │
    │    {public_key: PubKey}                    │
    ├───────────────────────────────────────────►│
    │                                            │
    │                                            │ 3. Create user
    │                                            │    client_id = UUID()
    │                                            │    keychain_id = UUID()
    │                                            │    owner_hash = HMAC(client_id, pepper)
    │                                            │
    │                                            │ 4. Create empty keychain
    │                                            │    keychain = {version: 1, files: {}}
    │                                            │    Store as file
    │                                            │
    │ 5. Response                                │
    │    {client_id, keychain_id}                │
    │◄───────────────────────────────────────────┤
    │                                            │
    │ 6. Store client_id, keychain_id locally   │
    │                                            │
```

---

### User Login (Authentication)

```
┌────────┐                                   ┌────────┐
│ Client │                                   │ Server │
└───┬────┘                                   └───┬────┘
    │                                            │
    │ 1. User enters passphrase                 │
    ├─ Re-derive keys ─────────────────────────►│
    │    MK = Argon2(passphrase, username)      │
    │    PrivKey = derive_ed25519(HKDF(MK,...)) │
    │    KK = HKDF(MK, "keychain-v1")           │
    │                                            │
    │ 2. POST /auth/token (get challenge)       │
    │    {client_id, challenge: null}            │
    ├───────────────────────────────────────────►│
    │                                            │
    │                                            │ 3. Generate challenge JWT
    │                                            │    nonce = random(32)
    │                                            │    jwt = sign({nonce, client_id, exp}, secret)
    │                                            │
    │ 4. {challenge: JWT}                        │
    │◄───────────────────────────────────────────┤
    │                                            │
    │ 5. Sign challenge                          │
    │    sig = Ed25519.sign(PrivKey, challenge)  │
    │                                            │
    │ 6. POST /auth/token (exchange)             │
    │    {client_id, challenge, signature}       │
    ├───────────────────────────────────────────►│
    │                                            │
    │                                            │ 7. Verify
    │                                            │    Decode challenge JWT
    │                                            │    Check not expired
    │                                            │    Verify signature with PubKey
    │                                            │
    │                                            │ 8. Issue access token
    │                                            │    token = JWT(sub: client_id, exp: 1h)
    │                                            │
    │ 9. {token, expires_in: 3600}               │
    │◄───────────────────────────────────────────┤
    │                                            │
    │ 10. Store token                            │
    │     Use for all subsequent requests        │
    │                                            │
```

---

### Creating a File

```
┌────────┐                                   ┌────────┐
│ Client │                                   │ Server │
└───┬────┘                                   └───┬────┘
    │                                            │
    │ 1. User selects file to upload            │
    │    filename = "document.pdf"               │
    │    content = <binary data>                 │
    │    size = 50MB                             │
    │                                            │
    │ 2. Calculate chunks                        │
    │    CHUNK_SIZE = 5MB                        │
    │    totalChunks = ceil(size / CHUNK_SIZE) = 10
    │                                            │
    │ 3. Generate random file key                │
    │    FK = random(32 bytes)                   │
    │    baseNonce = random(12 bytes)            │
    │                                            │
    │ 4. POST /files                             │
    │    {total_size: 50MB, total_chunks: 11}    │
    │    (11 = 1 metadata + 10 data chunks)      │
    ├───────────────────────────────────────────►│
    │                                            │
    │                                            │ 5. Initiate multipart upload
    │                                            │    file_id = UUID()
    │                                            │    owner_hash = HMAC(jwt.sub, pepper)
    │                                            │    upload_id = R2.createMultipartUpload()
    │                                            │
    │ 6. {file_id, upload_id}                    │
    │◄───────────────────────────────────────────┤
    │                                            │
    │ 7. Upload metadata (part 0)                │
    │    GET /files/{file_id}/upload/0           │
    ├───────────────────────────────────────────►│
    │                                            │
    │                                            │ 8. Generate presigned URL
    │                                            │
    │ 9. {url: presigned_url_part_0}             │
    │◄───────────────────────────────────────────┤
    │                                            │
    │ 10. Create metadata JSON                   │
    │     metadata = {                           │
    │       magic: "SECF",                       │
    │       version: 2,                          │
    │       baseNonce: [12,34,56,...],           │
    │       chunkSize: 5242880,                  │
    │       filename: "document.pdf",            │
    │       originalSize: 50000000,              │
    │       totalChunks: 10                      │
    │     }                                      │
    │                                            │
    │ 11. PUT presigned_url_part_0               │
    │     Body: JSON.stringify(metadata)         │
    ├──────────────────────────────────────────► R2
    │                           ETag_0 ◄─────────┤
    │                                            │
    │ 12. For each chunk (parallel):             │
    │     a. Get presigned URL                   │
    │        GET /files/{file_id}/upload/{N}     │
    ├───────────────────────────────────────────►│
    │◄───────────────────────────────────────────┤
    │                                            │
    │     b. Encrypt chunk                       │
    │        chunkNonce = baseNonce + index      │
    │        encrypted = AES-GCM(FK, chunk, chunkNonce)
    │                                            │
    │     c. PUT presigned_url_part_N            │
    │        Body: encrypted                     │
    ├──────────────────────────────────────────► R2
    │                         ETag_N ◄───────────┤
    │                                            │
    │ 13. POST /files/{file_id}/complete         │
    │     {parts: [{part_number: 0, etag: ETag_0},
    │              {part_number: 1, etag: ETag_1},
    │              ...]}                         │
    ├───────────────────────────────────────────►│
    │                                            │
    │                                            │ 14. Complete multipart upload
    │                                            │     R2.completeMultipartUpload()
    │                                            │     Update file status: complete
    │                                            │
    │ 15. {success: true, file_id, size}         │
    │◄───────────────────────────────────────────┤
    │                                            │
    │ 16. Update keychain                        │
    │     Download keychain                      │
    │     GET /files/{keychain_id}/download/0    │
    ├───────────────────────────────────────────►│
    │◄───────────────────────────────────────────┤
    │                                            │
    │ 17. Decrypt keychain with KK               │
    │     keychain = decrypt(keychain_data, KK)  │
    │                                            │
    │ 18. Add new file entry                     │
    │     keychain.files[file_id] = {            │
    │         key: FK.hex(),                     │
    │         filename: "document.pdf",          │
    │         created: now(),                    │
    │         size: 50000000                     │
    │     }                                      │
    │                                            │
    │ 19. Re-encrypt and upload keychain         │
    │     (Same multipart process)               │
    │     Initiate → Upload parts → Complete     │
    │                                            │
    │ Done!                                      │
    │                                            │
```

---

### Reading a File (Owner)

```
┌────────┐                                   ┌────────┐
│ Client │                                   │ Server │
└───┬────┘                                   └───┬────┘
    │                                            │
    │ 1. User wants to read a file              │
    │                                            │
    │ 2. GET /files (list owned files)          │
    ├───────────────────────────────────────────►│
    │                                            │
    │                                            │ 3. Query files by owner_hash
    │                                            │    owner_hash = HMAC(jwt.sub, pepper)
    │                                            │
    │ 4. [{file_id, size, created_at, ...}]     │
    │◄───────────────────────────────────────────┤
    │                                            │
    │ 5. Download keychain metadata              │
    │    GET /files/{keychain_id}/download/0     │
    ├───────────────────────────────────────────►│
    │◄───────────────────────────────────────────┤
    │                                            │
    │ 6. Get keychain download URLs              │
    │    Get presigned URLs for all keychain parts
    │    Download and decrypt keychain chunks    │
    │    keychain = decrypt(keychain_data, KK)   │
    │                                            │
    │ 7. Display files with names                │
    │    For each file in list:                  │
    │      filename = keychain.files[file_id].filename
    │                                            │
    │ 8. User selects file to open               │
    │                                            │
    │ 9. Download file metadata (part 0)         │
    │    GET /files/{file_id}/download/0         │
    ├───────────────────────────────────────────►│
    │                                            │
    │                                            │ 10. Generate presigned URL
    │                                            │
    │ 11. {url: presigned_url_part_0}            │
    │◄───────────────────────────────────────────┤
    │                                            │
    │ 12. Download and parse metadata            │
    │     GET presigned_url_part_0              │
    │◄──────────────────────────────────────────R2
    │                                            │
    │     metadata = {                           │
    │       magic: "SECF",                       │
    │       version: 2,                          │
    │       baseNonce: [...],                    │
    │       chunkSize: 5242880,                  │
    │       filename: "document.pdf",            │
    │       originalSize: 50000000,              │
    │       totalChunks: 10                      │
    │     }                                      │
    │                                            │
    │ 13. Get FK from keychain                   │
    │     FK = hex_decode(keychain.files[file_id].key)
    │                                            │
    │ 14. For each encrypted chunk (parallel):   │
    │     a. Get presigned URL                   │
    │        GET /files/{file_id}/download/{N}   │
    ├───────────────────────────────────────────►│
    │◄───────────────────────────────────────────┤
    │                                            │
    │     b. Download encrypted chunk            │
    │        GET presigned_url_part_N            │
    │◄──────────────────────────────────────────R2
    │                                            │
    │     c. Decrypt chunk                       │
    │        chunkNonce = baseNonce + index      │
    │        decrypted = AES-GCM.decrypt(        │
    │          encrypted, FK, chunkNonce)        │
    │                                            │
    │ 15. Combine all decrypted chunks           │
    │     content = chunk_0 + chunk_1 + ...      │
    │                                            │
    │ 16. Display/download file                  │
    │                                            │
```

---

### Sharing a File (Read-Only)

```
┌─────────┐                  ┌─────────┐                  ┌────────┐
│  Alice  │                  │   Bob   │                  │ Server │
│ (Owner) │                  │(Reader) │                  │        │
└────┬────┘                  └────┬────┘                  └───┬────┘
     │                            │                           │
     │ 1. Alice wants to share    │                           │
     │    file_id = "abc-123"     │                           │
     │                            │                           │
     │ 2. Get FK from keychain    │                           │
     │    FK = keychain.files["abc-123"].key                  │
     │                            │                           │
     │ 3. Send to Bob via secure channel                     │
     │    (Signal, email, etc.)   │                           │
     ├───────────────────────────►│                           │
     │    file_id: "abc-123"      │                           │
     │    file_key: FK            │                           │
     │                            │                           │
     │                            │ 4. Bob downloads file     │
     │                            │    GET /file/abc-123      │
     │                            ├──────────────────────────►│
     │                            │                           │
     │                            │                           │ 5. Anyone can download
     │                            │                           │    (no ownership check)
     │                            │                           │
     │                            │ 6. Encrypted file         │
     │                            │◄──────────────────────────┤
     │                            │                           │
     │                            │ 7. Decrypt with FK        │
     │                            │    content = decrypt(file, FK)
     │                            │                           │
     │                            │ 8. Bob can read file      │
     │                            │                           │
     │                            │ 9. Bob tries to modify    │
     │                            │    PUT /file/abc-123      │
     │                            ├──────────────────────────►│
     │                            │                           │
     │                            │                           │ 10. Check ownership
     │                            │                           │     owner_hash(Bob) != file.owner_hash
     │                            │                           │
     │                            │ 11. 403 Forbidden         │
     │                            │◄──────────────────────────┤
     │                            │    "Not file owner"       │
     │                            │                           │
```

**Key Points:**

- Bob can read (has FK) but cannot write (not owner)
- File ID can be public/shared
- Security relies on FK secrecy
- Server enforces write permissions via blind index

---

### Revoking Access

```
┌─────────┐                                   ┌────────┐
│  Alice  │                                   │ Server │
│ (Owner) │                                   │        │
└────┬────┘                                   └───┬────┘
     │                                            │
     │ 1. Alice wants to revoke Bob's access     │
     │    to file "abc-123"                      │
     │                                            │
     │ 2. Download original file                 │
     │    GET /file/abc-123                      │
     ├───────────────────────────────────────────►│
     │◄───────────────────────────────────────────┤
     │                                            │
     │ 3. Decrypt with old FK                     │
     │    FK_old = keychain.files["abc-123"].key  │
     │    content = decrypt(file, FK_old)         │
     │                                            │
     │ 4. Generate new file key                   │
     │    FK_new = random(32)                     │
     │                                            │
     │ 5. Re-encrypt file with FK_new             │
     │    new_file = encrypt(content, FK_new)     │
     │                                            │
     │ 6. Create new file                         │
     │    POST /file                              │
     │    Body: new_file                          │
     ├───────────────────────────────────────────►│
     │                                            │
     │                                            │ 7. Create new file
     │                                            │    new_file_id = "def-456"
     │                                            │
     │ 8. {file_id: "def-456"}                    │
     │◄───────────────────────────────────────────┤
     │                                            │
     │ 9. Update keychain                         │
     │    - Remove old entry for "abc-123"        │
     │    - Add new entry for "def-456" with FK_new
     │                                            │
     │ 10. Upload updated keychain                │
     │     PUT /file/{keychain_id}                │
     ├───────────────────────────────────────────►│
     │◄───────────────────────────────────────────┤
     │                                            │
     │ 11. Delete old file                        │
     │     DELETE /file/abc-123                   │
     ├───────────────────────────────────────────►│
     │◄───────────────────────────────────────────┤
     │                                            │
     │ Done! Bob's FK_old is now useless          │
     │                                            │
```

**Note:** This is expensive but necessary for true revocation in E2EE systems.

---

## Security Considerations

### Threat Model

**What the server CANNOT do:**

- ❌ Read file contents (encrypted with FK)
- ❌ Read filenames (encrypted in files)
- ❌ Impersonate users (doesn't have private keys)
- ❌ Forge authentication (uses public key crypto)
- ❌ Easily map users to files (uses blind index)

**What the server CAN do:**

- ✅ See file sizes and access patterns
- ✅ Count files per user (via blind index queries)
- ✅ Delete files
- ✅ Deny service
- ✅ Map users to files if they have the server pepper

**What an attacker with server access CANNOT do:**

- ❌ Read file contents (no encryption keys)
- ❌ Impersonate users (no private keys)

**What an attacker with server access CAN do:**

- ✅ See encrypted files and metadata
- ✅ Attempt brute-force on weak passphrases (if they capture auth flow)
- ✅ Perform timing attacks on authentication
- ✅ Delete or corrupt data

### Security Properties

1. **Confidentiality**: Files encrypted E2E, server never sees plaintext
2. **Integrity**: AES-GCM provides authentication, detects tampering
3. **Authentication**: Ed25519 signatures prove identity
4. **Authorization**: Blind index prevents unauthorized writes
5. **Forward Secrecy**: Not applicable (symmetric encryption)
6. **Non-Repudiation**: Not provided (symmetric file encryption)

### Key Security Measures

#### 1. Passphrase Requirements

Enforce strong passphrases:

- Minimum 12 characters
- Mix of uppercase, lowercase, numbers, symbols
- Reject common passwords
- Consider zxcvbn strength estimation

#### 2. Key Derivation Parameters

Argon2id configuration:

```javascript
{
    time: 3,        // iterations
    memory: 65536,  // 64 MB
    parallelism: 4, // threads
    hashLength: 32  // bytes
}
```

Adjust based on target delay (e.g., 1-2 seconds on average hardware).

#### 3. Transport Security

- Enforce HTTPS/TLS 1.3
- Use HSTS headers
- Certificate pinning (mobile apps)

#### 4. Rate Limiting

Prevent brute-force attacks:

```
/auth/token: 5 attempts per 15 minutes per IP
/client: 3 registrations per hour per IP
File operations: 100 per hour per user
```

#### 5. Server Pepper Rotation

Periodically rotate server pepper:

1. Generate new pepper
2. Re-compute all owner_hash values
3. Update database
4. Retire old pepper

**Complexity:** O(n) where n = number of files

#### 6. JWT Security

- Short expiry (1 hour)
- Secure random secret (256 bits)
- HS256 or RS256 algorithm
- Include `jti` for revocation if needed

#### 7. Nonce/IV Generation

- Use cryptographically secure random (crypto.getRandomValues)
- Never reuse nonce with same key
- 12 bytes for AES-GCM (96 bits)

#### 8. Key Management

**Client-side:**

- Never store master key
- Never transmit encryption keys to server
- Clear keys from memory after use
- Consider using Web Crypto API for key derivation

**Server-side:**

- Protect server pepper (environment variable, KMS)
- Rotate JWT secrets periodically
- Use HSM for sensitive operations (optional)

### Privacy Considerations

#### Metadata Leakage

Server knows:

- When files are created/modified/accessed
- File sizes
- Approximate number of files per user (via queries)

**Mitigations:**

- Pad file sizes to fixed buckets
- Add random delay to operations
- Use Tor/VPN for IP privacy

#### Blind Index Limitations

Blind index provides privacy against:

- Casual database inspection
- SQL injection attacks

But NOT against:

- Server operator with pepper
- Court order compelling pepper disclosure

**For stronger privacy:**

- Use client-side file tracking only (no server mapping)
- Accept limitation: no write access control

### Attack Scenarios

#### 1. Compromised Server

**Attacker gains:**

- All encrypted files
- User metadata
- Server pepper (can map users to files)

**Attacker CANNOT:**

- Decrypt files (no file keys)
- Impersonate users (no private keys)

**Mitigation:**

- Regular security audits
- Intrusion detection
- Encrypted backups

#### 2. Stolen JWT

**Attacker gains:**

- Temporary access (until token expires)
- Can read user's file list
- Can upload/modify/delete files

**Attacker CANNOT:**

- Decrypt files (no keychain key KK)
- Continue access after token expiry

**Mitigation:**

- Short token expiry (1 hour)
- Token revocation list
- Anomaly detection (IP changes, etc.)

#### 3. Phishing Attack

**Attacker tricks user into:**

- Revealing passphrase
- Running malicious code

**Attacker gains:**

- Full account access
- All encryption keys
- All file contents

**Mitigation:**

- User education
- 2FA (future enhancement)
- Passkey support (future enhancement)

#### 4. Man-in-the-Middle

**Attacker intercepts:**

- Authentication challenges
- File uploads/downloads

**Mitigations:**

- Enforce HTTPS/TLS
- Certificate pinning
- Check for certificate transparency
