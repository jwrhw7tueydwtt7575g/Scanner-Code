import React from 'react';

export default function Dashboard() {
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
            <div className="dashboard-card-value-pro">3</div>
            <div className="dashboard-card-label-pro">Total Projects</div>
            <div className="dashboard-card-desc-pro">Analyzed projects</div>
          </div>
        </div>
        <div className="dashboard-card-pro dashboard-card-green-pro">
          <span className="dashboard-card-icon-pro"><span className="material-icons">check_circle</span></span>
          <div>
            <div className="dashboard-card-value-pro">3</div>
            <div className="dashboard-card-label-pro">Completed Scans</div>
            <div className="dashboard-card-desc-pro">Successful analyses</div>
          </div>
        </div>
        <div className="dashboard-card-pro dashboard-card-orange-pro">
          <span className="dashboard-card-icon-pro"><span className="material-icons">security</span></span>
          <div>
            <div className="dashboard-card-value-pro">80</div>
            <div className="dashboard-card-label-pro">Avg Security Score</div>
            <div className="dashboard-card-desc-pro">Overall security rating</div>
          </div>
        </div>
        <div className="dashboard-card-pro dashboard-card-red-pro">
          <span className="dashboard-card-icon-pro"><span className="material-icons">timer</span></span>
          <div>
            <div className="dashboard-card-value-pro">60</div>
            <div className="dashboard-card-label-pro">Total Issues</div>
            <div className="dashboard-card-desc-pro">Across all projects</div>
          </div>
        </div>
      </section>
      <section className="dashboard-analyses-pro">
        <h2 className="dashboard-analyses-title-pro">Recent Analyses</h2>
        <div className="dashboard-analyses-subtitle-pro">Your latest code scans and results</div>
        <div className="dashboard-analyses-list-pro">
          <div className="dashboard-analyses-card-pro">
            <span className="dashboard-analyses-icon-pro"><span className="material-icons">code</span></span>
            <div className="dashboard-analyses-content-pro">
              <div className="dashboard-analyses-card-title-pro">E-commerce Platform</div>
              <div className="dashboard-analyses-card-meta-pro">Sep 16, 2025 AM1757980376 5:22 AM</div>
              <div className="dashboard-analyses-card-status-pro">Completed</div>
              <div className="dashboard-analyses-card-langs-pro">3 languages</div>
            </div>
            <button className="dashboard-analyses-view-btn-pro">View Results</button>
          </div>
          <div className="dashboard-analyses-card-pro">
            <span className="dashboard-analyses-icon-pro"><span className="material-icons">code</span></span>
            <div className="dashboard-analyses-content-pro">
              <div className="dashboard-analyses-card-title-pro">Mobile Banking App</div>
              <div className="dashboard-analyses-card-meta-pro">Sep 16, 2025 AM1757980376 5:22 AM</div>
              <div className="dashboard-analyses-card-status-pro">Completed</div>
              <div className="dashboard-analyses-card-langs-pro">3 languages</div>
            </div>
            <button className="dashboard-analyses-view-btn-pro">View Results</button>
          </div>
        </div>
      </section>
    </div>
  );
}
