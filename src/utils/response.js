/**
 * Helper function to create JSON responses
 */
export function jsonResponse(data, status = 200, additionalHeaders = {}) {
	return new Response(JSON.stringify(data), {
		status,
		headers: {
			'Content-Type': 'application/json',
			...additionalHeaders,
		},
	});
}
