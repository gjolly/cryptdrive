import { computeOwnerHash } from './utils/crypto.js';

/**
 * Daily cleanup job for Tier 0 users
 * Deletes files older than 24 hours
 */
export async function handleScheduled(event, env) {
	console.log('Running daily cleanup job at', new Date(event.scheduledTime).toISOString());

	try {
		// Calculate cutoff time (24 hours ago)
		const cutoffTime = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

		// Get all Tier 0 users
		const tier0Users = await env.DB.prepare('SELECT user_id FROM users WHERE tier = 0').all();

		if (!tier0Users.results || tier0Users.results.length === 0) {
			console.log('No Tier 0 users found');
			return;
		}

		let totalDeleted = 0;

		// For each Tier 0 user, compute their owner_hash and delete old files
		for (const user of tier0Users.results) {
			const ownerHash = await computeOwnerHash(user.user_id, env);

			// Get old files for this user
			const oldFiles = await env.DB.prepare('SELECT file_id FROM files WHERE owner_hash = ? AND created_at < ?')
				.bind(ownerHash, cutoffTime)
				.all();

			if (oldFiles.results && oldFiles.results.length > 0) {
				for (const file of oldFiles.results) {
					// Delete from R2
					try {
						await env.BUCKET.delete(file.file_id);
					} catch (e) {
						console.error('Failed to delete from R2:', file.file_id, e);
					}

					// Delete from database
					await env.DB.prepare('DELETE FROM files WHERE file_id = ?').bind(file.file_id).run();

					totalDeleted++;
				}
			}
		}

		console.log(`Cleanup completed: deleted ${totalDeleted} files older than 24 hours for Tier 0 users`);
	} catch (error) {
		console.error('Cleanup job error:', error);
	}
}
