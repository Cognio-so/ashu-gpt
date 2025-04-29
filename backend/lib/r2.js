const { S3Client, PutObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

let s3Client;
try {
    s3Client = new S3Client({
        region: 'auto',
        endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
        credentials: {
            accessKeyId: process.env.R2_ACCESS_KEY_ID,
            secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
        },
    });
} catch (error) {
    console.error("Error initializing S3Client:", error);
    throw new Error("Failed to initialize R2 client. Check credentials."); 
}

/**
 * Upload a file to Cloudflare R2
 * @param {Buffer} fileBuffer - The file buffer
 * @param {string} fileName - Original file name
 * @param {string} folder - Folder to store the file in (e.g., 'images', 'knowledge')
 * @returns {Promise<{fileUrl: string, key: string}>} - URL and key of the uploaded file
 */
async function uploadToR2(fileBuffer, fileName, folder = '') {
    // Create a unique filename to prevent collisions
    const fileExtension = path.extname(fileName);
    const key = folder 
        ? `${folder}/${uuidv4()}${fileExtension}` 
        : `${uuidv4()}${fileExtension}`;

    // Set up the upload parameters
    const uploadParams = {
        Bucket: process.env.R2_BUCKET_NAME,
        Key: key,
        Body: fileBuffer,
        ContentType: getContentType(fileExtension),
    };

    try {
        // Upload to R2
        await s3Client.send(new PutObjectCommand(uploadParams));
        
        // Generate the public URL
        const fileUrl = `${process.env.R2_PUBLIC_URL}/${key}`;
        
        return {
            fileUrl,
            key,
        };
    } catch (error) {
        console.error('Error uploading to R2:', error);
        throw new Error('Failed to upload file to storage');
    }
}

/**
 * Delete a file from Cloudflare R2
 * @param {string} key - The file key
 * @returns {Promise<void>}
 */
async function deleteFromR2(key) {
    const deleteParams = {
        Bucket: process.env.R2_BUCKET_NAME,
        Key: key,
    };

    try {
        await s3Client.send(new DeleteObjectCommand(deleteParams));
    } catch (error) {
        console.error('Error deleting from R2:', error);
        throw new Error('Failed to delete file from storage');
    }
}

/**
 * Get content type based on file extension
 * @param {string} extension - File extension
 * @returns {string} - MIME type
 */
function getContentType(extension) {
    const contentTypes = {
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.gif': 'image/gif',
        '.pdf': 'application/pdf',
        '.doc': 'application/msword',
        '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        '.txt': 'text/plain',
    };

    return contentTypes[extension.toLowerCase()] || 'application/octet-stream';
}

module.exports = {
    uploadToR2,
    deleteFromR2,
}; 