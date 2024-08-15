const { Storage } = require('@google-cloud/storage');

// Initialize Google Cloud Storage with your credentials
const storage = new Storage({
    projectId: process.env.GOOGLE_CLOUD_PROJECT_ID,
    keyFilename: './key.json',
});

// Define the bucket name
const bucketName = process.env.GOOGLE_CLOUD_BUCKET_NAME;

// Export the storage and bucket name
module.exports = { storage, bucketName };
