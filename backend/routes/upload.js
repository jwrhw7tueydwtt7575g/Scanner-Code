const express = require('express');
const multer = require('multer');
const AdmZip = require('adm-zip');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const fs = require('fs');
const path = require('path');

const router = express.Router();

// Multer setup for file upload
const upload = multer({ dest: 'uploads/' });

// AWS S3 setup
const s3 = new S3Client({
  region: 'eu-north-1',
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});
const BUCKET_NAME = 'codescanner125';

// Upload and extract zip, then dump to S3
router.post('/upload', upload.single('file'), async (req, res) => {
  const timeline = [];
  try {
    timeline.push({ step: 'Received file', time: new Date().toISOString() });
    const zipPath = req.file.path;
    timeline.push({ step: 'Extracting zip', time: new Date().toISOString() });
    const zip = new AdmZip(zipPath);
    const zipEntries = zip.getEntries();
    let uploadedFiles = [];
    for (const entry of zipEntries) {
      if (!entry.isDirectory) {
        timeline.push({ step: `Uploading ${entry.entryName} to S3`, time: new Date().toISOString() });
        const fileContent = entry.getData();
        const params = {
          Bucket: BUCKET_NAME,
          Key: entry.entryName,
          Body: fileContent,
        };
        await s3.send(new PutObjectCommand(params));
        uploadedFiles.push(entry.entryName);
      }
    }
    fs.unlinkSync(zipPath); // Clean up uploaded zip
    timeline.push({ step: 'Upload complete', time: new Date().toISOString() });
    res.status(200).json({ message: 'Files extracted and uploaded to S3.', uploadedFiles, timeline });
  } catch (err) {
    console.error('S3 upload error:', err);
    timeline.push({ step: 'Error', time: new Date().toISOString(), error: err.message, stack: err.stack });
    res.status(500).json({ message: 'Error processing zip file.', timeline });
  }
});

module.exports = router;
