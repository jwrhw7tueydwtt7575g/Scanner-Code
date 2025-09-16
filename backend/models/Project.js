const mongoose = require('mongoose');

const projectSchema = new mongoose.Schema({
  name: String,
  fileCount: Number,
  uploadTime: Date,
  status: { type: String, default: 'completed' },
  files: [String]
});

module.exports = mongoose.model('Project', projectSchema);