import React, { useEffect, useState } from 'react';

export default function Dashboard() {
  const [stats, setStats] = useState({ totalProjects: 0, completedScans: 0, avgSecurityScore: 0, totalIssues: 0 });
  const [recent, setRecent] = useState([]);

  useEffect(() => {
    fetch('http://localhost:5000/api/project/dashboard')
      .then(res => res.json())
      .then(data => setStats(data));
    fetch('http://localhost:5000/api/project/history')
      .then(res => res.json())
      .then(data => setRecent(data.slice(0, 3)));
  }, []);

  return (
    <div className="dashboard-bg-pro">
      <header className="dashboard-header-pro">
        <h1 className="dashboard-title-pro">Code Analysis Dashboard</h1>
        <div className="dashboard-subtitle-pro">Monitor your code quality across all projects</div>
        <button className="dashboard-new-btn-pro">+ New Analysis</button>
      </header>
      <section className="dashboard-cards-pro">
        <div className="dashboard-card-pro dashboard-card-blue-pro">
          <span className="dashboard-card-icon-pro"><span className="material-icons">code</span></span>
          <div>
            <div className="dashboard-card-value-pro">{stats.totalProjects}</div>
            <div className="dashboard-card-label-pro">Total Projects</div>
            <div className="dashboard-card-desc-pro">Analyzed projects</div>
          </div>
        </div>
        <div className="dashboard-card-pro dashboard-card-green-pro">
          <span className="dashboard-card-icon-pro"><span className="material-icons">check_circle</span></span>
          <div>
            <div className="dashboard-card-value-pro">{stats.completedScans}</div>
            <div className="dashboard-card-label-pro">Completed Scans</div>
            <div className="dashboard-card-desc-pro">Successful analyses</div>
          </div>
        </div>
        <div className="dashboard-card-pro dashboard-card-orange-pro">
          <span className="dashboard-card-icon-pro"><span className="material-icons">security</span></span>
          <div>
            <div className="dashboard-card-value-pro">{stats.avgSecurityScore}</div>
            <div className="dashboard-card-label-pro">Avg Security Score</div>
            <div className="dashboard-card-desc-pro">Overall security rating</div>
          </div>
        </div>
        <div className="dashboard-card-pro dashboard-card-red-pro">
          <span className="dashboard-card-icon-pro"><span className="material-icons">timer</span></span>
          <div>
            <div className="dashboard-card-value-pro">{stats.totalIssues}</div>
            <div className="dashboard-card-label-pro">Total Issues</div>
            <div className="dashboard-card-desc-pro">Across all projects</div>
          </div>
        </div>
      </section>
      <section className="dashboard-analyses-pro">
        <h2 className="dashboard-analyses-title-pro">Recent Analyses</h2>
        <div className="dashboard-analyses-subtitle-pro">Your latest code scans and results</div>
        <div className="dashboard-analyses-list-pro">
          {recent.map((proj, idx) => (
            <div className="dashboard-analyses-card-pro" key={idx}>
              <span className="dashboard-analyses-icon-pro"><span className="material-icons">code</span></span>
              <div className="dashboard-analyses-content-pro">
                <div className="dashboard-analyses-card-title-pro">{proj.name}</div>
                <div className="dashboard-analyses-card-meta-pro">{new Date(proj.uploadTime).toLocaleString()}</div>
                <div className="dashboard-analyses-card-status-pro">{proj.status}</div>
                <div className="dashboard-analyses-card-langs-pro">{proj.fileCount} files</div>
              </div>
              <button className="dashboard-analyses-view-btn-pro">View Results</button>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
