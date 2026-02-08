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
Content-Type: application/octet-stream

<binary_encrypted_file_data>
```

**Response:**

```json
{
	"file_id": "uuid"
}
```

**Description:**

- Creates a new file owned by authenticated user
- File data must be encrypted client-side before upload
- Server generates unique file ID
- Server computes owner hash from JWT

**Server Actions:**

1. Extract `user_id` from JWT
2. Compute `owner_hash = HMAC(user_id, server_pepper)`
3. Generate unique `file_id`
4. Store file with metadata:
   - `file_id`
   - `owner_hash`
   - `created_at`
   - `updated_at`
   - `size`
   - `data` (encrypted blob)
5. Return `file_id`

**Client Actions After:**

1. Generate random File Key (FK)
2. Update local keychain with new entry: `{file_id: {key: FK, filename: ...}}`
3. Encrypt keychain with Keychain Key (KK)
4. Upload updated keychain via `PUT /file/{keychain_id}`

---

#### 6. Get File

**Request:**

```http
GET /file/{file_id}
Authorization: Bearer <JWT> (optional)
```

**Response:**

```
Content-Type: application/octet-stream
Content-Length: <size>

<binary_encrypted_file_data>
```

**Description:**

- Anyone can download any file if they know the file ID
- Authorization optional (supports anonymous read)
- Cannot decrypt without the File Key (FK)
- Enables read-only sharing

**Use Cases:**

- Owner downloads their own file
- Shared user downloads file (has FK but not owner)
- Public file access (if file ID is public)

---

#### 7. Get File Metadata

**Request:**

```http
HEAD /file/{file_id}
Authorization: Bearer <JWT> (optional)
```

**Response Headers:**

```
Content-Length: 12345
Last-Modified: Tue, 03 Feb 2026 10:00:00 GMT
X-Created-At: 2026-02-03T10:00:00Z
X-Updated-At: 2026-02-03T10:00:00Z
```

**Description:**

- Returns file metadata without downloading content
- Useful for checking file size before download
- No body in response

---

#### 8. Update File

**Request:**

```http
PUT /file/{file_id}
Authorization: Bearer <JWT>
Content-Type: application/octet-stream

<binary_encrypted_file_data>
```

**Response:**

```json
{
	"success": true,
	"updated_at": "2026-02-03T12:00:00Z"
}
```

**Description:**

- Only file owner can update
- Replaces entire file content
- Updates `updated_at` timestamp

**Server Authorization:**

```python
owner_hash = HMAC(jwt.sub, server_pepper)
file = db.get_file(file_id)
if file.owner_hash != owner_hash:
    return 403 Forbidden
```

---

#### 9. Delete File

**Request:**

```http
DELETE /file/{file_id}
Authorization: Bearer <JWT>
```

**Response:**

```json
{
	"success": true
}
```

**Description:**

- Only file owner can delete
- Permanently removes file and metadata

**Server Authorization:**

```python
owner_hash = HMAC(jwt.sub, server_pepper)
file = db.get_file(file_id)
if file.owner_hash != owner_hash:
    return 403 Forbidden
db.delete_file(file_id)
```

**Client Actions After:**

1. Remove file entry from keychain
2. Encrypt keychain with KK
3. Upload updated keychain via `PUT /file/{keychain_id}`

---

## Data Formats

### File Format

Binary format for encrypted files:

```
┌─────────────────────────────────────────┐
│ Magic Bytes (4 bytes): "SECF"          │
├─────────────────────────────────────────┤
│ Version (1 byte): 0x01                  │
├─────────────────────────────────────────┤
│ Nonce (12 bytes): random IV             │
├─────────────────────────────────────────┤
│ Encrypted Payload (variable):          │
│   ┌───────────────────────────────────┐ │
│   │ Filename Length (2 bytes)         │ │
│   ├───────────────────────────────────┤ │
│   │ Filename (UTF-8, variable)        │ │
│   ├───────────────────────────────────┤ │
│   │ File Content (variable)           │ │
│   └───────────────────────────────────┘ │
├─────────────────────────────────────────┤
│ Auth Tag (16 bytes): GCM tag            │
└─────────────────────────────────────────┘

Total: 33 + filename_length + content_length bytes
```

**Encryption:**

```
plaintext = filename_length || filename || content
ciphertext, tag = AES-256-GCM.encrypt(
    key=FK,
    plaintext=plaintext,
    nonce=nonce,
    additional_data=b""
)
```

**File Structure Details:**

| Field           | Size     | Description                    |
| --------------- | -------- | ------------------------------ |
| Magic           | 4 bytes  | `SECF` (Secure Encrypted File) |
| Version         | 1 byte   | Format version (0x01)          |
| Nonce           | 12 bytes | Random nonce/IV for AES-GCM    |
| Filename Length | 2 bytes  | Big-endian uint16 (max 65535)  |
| Filename        | Variable | UTF-8 encoded filename         |
| Content         | Variable | Raw file content               |
| Auth Tag        | 16 bytes | AES-GCM authentication tag     |

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
			"filename": "encrypted_base64_filename",
			"created": "2026-02-03T10:00:00Z",
			"size": 12345
		},
		"file_id_2": {
			"key": "hex_encoded_32_byte_key",
			"filename": "encrypted_base64_filename",
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
    data BYTEA NOT NULL,                     -- Encrypted file blob
    size INTEGER NOT NULL,                   -- File size in bytes
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    INDEX idx_owner_hash (owner_hash)
);
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
    │                                            │
    │ 2. Generate random file key                │
    │    FK = random(32 bytes)                   │
    │                                            │
    │ 3. Encrypt file                            │
    │    plaintext = len(filename) || filename || content
    │    nonce = random(12)                      │
    │    encrypted, tag = AES-GCM(FK, plaintext, nonce)
    │    file_data = "SECF" || 0x01 || nonce || encrypted || tag
    │                                            │
    │ 4. POST /file                              │
    │    Headers: Authorization: Bearer <token>  │
    │    Body: file_data                         │
    ├───────────────────────────────────────────►│
    │                                            │
    │                                            │ 5. Create file
    │                                            │    file_id = UUID()
    │                                            │    owner_hash = HMAC(jwt.sub, pepper)
    │                                            │    Store file
    │                                            │
    │ 6. {file_id}                               │
    │◄───────────────────────────────────────────┤
    │                                            │
    │ 7. Update keychain                         │
    │    Download keychain                       │
    │    GET /file/{keychain_id}                 │
    ├───────────────────────────────────────────►│
    │◄───────────────────────────────────────────┤
    │                                            │
    │ 8. Decrypt keychain with KK                │
    │    keychain = decrypt(keychain_data, KK)   │
    │                                            │
    │ 9. Add new file entry                      │
    │    keychain.files[file_id] = {             │
    │        key: FK.hex(),                      │
    │        filename: base64(encrypt(filename)),│
    │        created: now(),                     │
    │        size: file_size                     │
    │    }                                       │
    │                                            │
    │ 10. Re-encrypt and upload keychain         │
    │     encrypted_keychain = encrypt(keychain, KK)
    │     PUT /file/{keychain_id}                │
    ├───────────────────────────────────────────►│
    │◄───────────────────────────────────────────┤
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
    │ 5. Download keychain                       │
    │    GET /file/{keychain_id}                 │
    ├───────────────────────────────────────────►│
    │◄───────────────────────────────────────────┤
    │                                            │
    │ 6. Decrypt keychain                        │
    │    keychain = decrypt(keychain_data, KK)   │
    │                                            │
    │ 7. Display files with names                │
    │    For each file in list:                  │
    │      filename = decrypt(keychain.files[file_id].filename)
    │                                            │
    │ 8. User selects file to open               │
    │                                            │
    │ 9. GET /file/{file_id}                     │
    ├───────────────────────────────────────────►│
    │◄───────────────────────────────────────────┤
    │                                            │
    │ 10. Get FK from keychain                   │
    │     FK = hex_decode(keychain.files[file_id].key)
    │                                            │
    │ 11. Decrypt file                           │
    │     Parse file format                      │
    │     plaintext = AES-GCM.decrypt(encrypted, FK, nonce, tag)
    │     filename_len = plaintext[0:2]          │
    │     filename = plaintext[2:2+len]          │
    │     content = plaintext[2+len:]            │
    │                                            │
    │ 12. Display/download file                  │
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
