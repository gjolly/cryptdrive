import { XMLParser, XMLBuilder } from 'fast-xml-parser';
import { AwsClient } from 'aws4fetch';

export const getClient = (env) => {
	const client = new AwsClient({
		accessKeyId: env.R2_ACCESS_KEY_ID,
		secretAccessKey: env.R2_SECRET_ACCESS_KEY,
	});
	const r2Url = `${env.R2_URL}/${env.R2_BUCKET_NAME}`;
	return { client, r2Url };
};

/*
 * Verify that the uploaded parts do not exceed block size and that
 * the total uploaded size does not exceed the maximum quota.
 */
export const validateUploadedParts = (parts, blockSize, maxSize) => {
	if (!Array.isArray(parts)) {
		throw new Error('Parts should be an array');
	}

	let uploadedSize = 0;
	for (const part of parts) {
		if (!part.Size || !part.PartNumber) {
			throw new Error('Each part must have Size and PartNumber');
		}
		if (part.Size > blockSize) {
			throw new Error(`Part ${part.PartNumber} exceeds block size limit`);
		}
		uploadedSize += part.Size;
	}

	if (uploadedSize > maxSize) {
		throw new Error(`Total uploaded size exceeds quota`);
	}
};

export const listMultipartUploadParts = async (awsClient, r2Url, key, uploadId) => {
	const response = await awsClient.fetch(`${r2Url}/${key}?uploadId=${uploadId}`, {
		method: 'GET',
	});
	const responseData = await response.text();
	const parser = new XMLParser();
	const parsedData = parser.parse(responseData);
	const parts = parsedData?.ListPartsResult?.Part || [];

	return Array.isArray(parts) ? parts : [parts];
};

export const createMultipartUpload = async (awsClient, r2Url, fileKey) => {
	const response = await awsClient.fetch(`${r2Url}/${fileKey}?uploads`, {
		method: 'POST',
		headers: {
			//'Content-Type': 'application/octet-stream',
			//expires: new Date(Date.now() + multipartExpiry * 1000).toISOString(),
		},
	});
	if (!response.ok) {
		const errorText = await response.text();
		console.error('Error creating multipart upload:', errorText);
		throw new Error(`Failed to create multipart upload: ${response.status}`);
	}
	const responseData = await response.text();
	const parser = new XMLParser();
	const parsedData = parser.parse(responseData);
	const upload_id = parsedData?.InitiateMultipartUploadResult?.UploadId;

	return upload_id;
};

export const getUploadUrlForPart = async (awsClient, r2Url, key, upload_id, partNumber, blockSize, expiry) => {
	const url = (
		await awsClient.sign(
			new Request(`${r2Url}/${key}?X-Amz-Expires=${expiry}&partNumber=${partNumber}&uploadId=${upload_id}`, {
				method: 'PUT',
			}),
			{
				aws: {
					signQuery: true,
				},
			}
		)
	).url.toString();

	return url;
};

export const buildCompleteMultipartUploadXml = (parts) => {
	const builder = new XMLBuilder({
		ignoreAttributes: false,
		format: true,
	});

	return builder.build({
		CompleteMultipartUpload: {
			Part: parts.map((part) => ({
				PartNumber: part.part_number,
				ETag: part.etag,
			})),
		},
	});
};

export const completeMultipartUpload = async (awsClient, r2Url, key, upload_id, parts) => {
	const response = await awsClient.fetch(`${r2Url}/${key}?uploadId=${upload_id}`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/xml',
		},
		body: buildCompleteMultipartUploadXml(parts),
	});

	if (!response.ok) {
		const errorText = await response.text();
		console.error('Error completing multipart upload:', errorText);
		console.log('Request body:', buildCompleteMultipartUploadXml(parts));
		throw new Error(`Failed to complete multipart upload: ${response.status}`);
	}
};

export const abortMultipartUpload = async (awsClient, r2Url, key, upload_id) => {
	// create multipart upload and get upload ID
	const response = await awsClient.fetch(`${r2Url}/${key}?uploadId=${upload_id}`, {
		method: 'DELETE',
	});
	if (!response.ok) {
		const errorText = await response.text();
		console.error('Error aborting multipart upload:', errorText);
		throw new Error(`Failed to abort multipart upload: ${response.status}`);
	}
};

/*
 * Generates a presigned URL for downloading a file from R2, with an expiration time.
 * Strickly speaking, this is not multipart-related but I don't want to create
 * a separate source file only for this trivial helper.
 */
export const getDownloadUrl = async (awsClient, r2Url, key, expiry) => {
	const url = (
		await awsClient.sign(
			new Request(`${r2Url}/${key}?X-Amz-Expires=${expiry}`, {
				method: 'GET',
			}),
			{
				aws: {
					signQuery: true,
				},
			}
		)
	).url.toString();

	return url;
};
