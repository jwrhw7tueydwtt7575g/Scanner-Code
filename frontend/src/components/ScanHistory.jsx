import React from 'react';

export default function ScanHistory() {
  return (
    <div className="history-bg-pro">
      <div className="history-header-pro">
        <h1 className="history-title-pro">Analysis History</h1>
        <div className="history-subtitle-pro">View and manage all your code analysis projects</div>
      </div>
      <div className="history-searchbar-pro">
        <span className="material-icons history-search-icon-pro">search</span>
        <input type="text" placeholder="Search projects..." className="history-search-pro" />
        <div className="history-filter-group-pro">
          <button className="history-filter-btn-pro active">All</button>
          <button className="history-filter-btn-pro">Completed</button>
          <button className="history-filter-btn-pro">In Progress</button>
          <button className="history-filter-btn-pro">Failed</button>
        </div>
      </div>
      <div className="history-list-pro">
        <div className="history-card-pro">
          <div className="history-card-icon-pro"><span className="material-icons">code</span></div>
          <div className="history-card-content-pro">
            <div className="history-card-title-pro">E-commerce Platform</div>
            <div className="history-card-meta-pro"><span className="material-icons">calendar_today</span> Sep 16, 2025 &nbsp; <span className="material-icons">insert_drive_file</span> 78 files &nbsp; 62s</div>
            <div className="history-card-badges-pro">
              <span className="history-badge-pro">python</span>
              <span className="history-badge-pro">javascript</span>
              <span className="history-badge-pro">java</span>
              <span className="history-badge-green-pro">completed</span>
            </div>
          </div>
          <button className="history-view-btn-pro">View Results</button>
        </div>
        <div className="history-card-pro">
          <div className="history-card-icon-pro"><span className="material-icons">code</span></div>
          <div className="history-card-content-pro">
            <div className="history-card-title-pro">Mobile Banking App</div>
            <div className="history-card-meta-pro"><span className="material-icons">calendar_today</span> Sep 16, 2025 &nbsp; <span className="material-icons">insert_drive_file</span> 85 files &nbsp; 74s</div>
            <div className="history-card-badges-pro">
              <span className="history-badge-pro">java</span>
              <span className="history-badge-pro">cpp</span>
              <span className="history-badge-pro">javascript</span>
              <span className="history-badge-green-pro">completed</span>
            </div>
          </div>
          <button className="history-view-btn-pro">View Results</button>
        </div>
        <div className="history-card-pro">
          <div className="history-card-icon-pro"><span className="material-icons">code</span></div>
          <div className="history-card-content-pro">
            <div className="history-card-title-pro">Data Analytics Dashboard</div>
            <div className="history-card-meta-pro"><span className="material-icons">calendar_today</span> Sep 16, 2025 &nbsp; <span className="material-icons">insert_drive_file</span> 56 files &nbsp; 45s</div>
            <div className="history-card-badges-pro">
              <span className="history-badge-pro">python</span>
              <span className="history-badge-pro">javascript</span>
              <span className="history-badge-green-pro">completed</span>
            </div>
          </div>
          <button className="history-view-btn-pro">View Results</button>
        </div>
      </div>
    </div>
  );
}
