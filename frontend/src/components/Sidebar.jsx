import React from 'react';
import { NavLink } from 'react-router-dom';

export default function Sidebar() {
  return (
    <aside className="sidebar-pro">
      <div className="sidebar-header-pro">
        <div className="sidebar-logo-gradient">
          <svg width="32" height="32" fill="none" viewBox="0 0 32 32">
            <rect width="32" height="32" rx="8" fill="#fff"/>
            <path d="M16 8v16M8 16h16" stroke="#7c3aed" strokeWidth="2" strokeLinecap="round"/>
          </svg>
        </div>
        <div>
          <div className="sidebar-title-pro">CodeScan Pro</div>
          <div className="sidebar-subtitle-pro">Multi-Language Analysis</div>
        </div>
      </div>
      <nav className="sidebar-nav-pro">
        <NavLink to="/" className={({ isActive }) => isActive ? 'sidebar-nav-active-pro' : 'sidebar-nav-link-pro'} end>
          <span className="sidebar-nav-icon-pro"><span className="material-icons">dashboard</span></span> Dashboard
        </NavLink>
        <NavLink to="/upload" className={({ isActive }) => isActive ? 'sidebar-nav-active-pro' : 'sidebar-nav-link-pro'}>
          <span className="sidebar-nav-icon-pro"><span className="material-icons">cloud_upload</span></span> Upload Project
        </NavLink>
        <NavLink to="/history" className={({ isActive }) => isActive ? 'sidebar-nav-active-pro' : 'sidebar-nav-link-pro'}>
          <span className="sidebar-nav-icon-pro"><span className="material-icons">history</span></span> Scan History
        </NavLink>
        <NavLink to="/logout" className={({ isActive }) => isActive ? 'sidebar-nav-active-pro' : 'sidebar-nav-link-pro'}>
          <span className="sidebar-nav-icon-pro"><span className="material-icons">logout</span></span> Logout
        </NavLink>
      </nav>
      <div className="sidebar-languages-pro">
        <div className="sidebar-languages-title-pro">SUPPORTED LANGUAGES</div>
        <div className="sidebar-languages-list-pro">
          <span className="sidebar-lang-dot-pro sidebar-lang-yellow-pro"></span> Python<br/>
          <span className="sidebar-lang-dot-pro sidebar-lang-orange-pro"></span> Java<br/>
          <span className="sidebar-lang-dot-pro sidebar-lang-blue-pro"></span> C++<br/>
          <span className="sidebar-lang-dot-pro sidebar-lang-green-pro"></span> JavaScript
        </div>
      </div>
      <div className="sidebar-ai-pro">
        <span className="sidebar-ai-icon-gradient-pro"><span className="material-icons">bolt</span></span>
        <div>
          <div className="sidebar-ai-title-pro">AI Powered</div>
          <div className="sidebar-ai-subtitle-pro">Enhanced Analysis</div>
        </div>
      </div>
    </aside>
  );
}
