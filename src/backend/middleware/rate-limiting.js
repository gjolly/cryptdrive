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
 * Check and update authentication rate limits (dual: IP + user)
 * Returns {allowed: boolean, error?: string, status?: number}
 */
export async function checkAuthRateLimit(request, env, user_id = null) {
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
export async function recordFailedAuth(env, user_id) {
	await env.DB.prepare('UPDATE auth_rate_limits SET failed_attempts = failed_attempts + 1, last_attempt = ? WHERE id = ? AND type = ?')
		.bind(new Date().toISOString(), user_id, 'user')
		.run();
}

/**
 * Check and update registration rate limits (fingerprint-based)
 * Returns {allowed: boolean, captcha_required?: boolean, error?: string, status?: number}
 */
export async function checkRegistrationRateLimit(request, env) {
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
export async function checkFileOperationRateLimit(user_id, env, isWrite = false) {
	const now = Date.now();
	const oneMinute = 60 * 1000;
	const limit = isWrite ? 20 : 50;
	let record = null;

	try {
		record = await env.DB.prepare('SELECT * FROM file_operation_limits WHERE user_id = ?').bind(user_id).first();
	} catch (e) {
		console.error('Error checking file operation rate limit:', e);
		return { allowed: false, error: 'Internal server error', status: 500 };
	}

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
export async function checkAnonymousDownloadRateLimit(request, env) {
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
