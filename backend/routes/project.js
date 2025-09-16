const express = require('express');
const Project = require('../models/Project');
const router = express.Router();

// Get all projects (history)
router.get('/history', async (req, res) => {
  try {
    const projects = await Project.find().sort({ uploadTime: -1 });
    res.json(projects);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching history.' });
  }
});

// Get dashboard stats
router.get('/dashboard', async (req, res) => {
  try {
    const totalProjects = await Project.countDocuments();
    const completedScans = await Project.countDocuments({ status: 'completed' });
    // Example: security score and issues can be calculated later
    res.json({
      totalProjects,
      completedScans,
      avgSecurityScore: 80,
      totalIssues: 60
    });
  } catch (err) {
    res.status(500).json({ message: 'Error fetching dashboard.' });
  }
});

module.exports = router;
