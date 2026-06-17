import React, { useState } from 'react';
import './dashboard-Header.css';

const DashboardHeader = ({ onMenuToggle }) => {
  const [isProfileOpen, setIsProfileOpen] = useState(false);
  const [isNotificationOpen, setIsNotificationOpen] = useState(false);

  const toggleProfile = () => {
    setIsProfileOpen(!isProfileOpen);
    setIsNotificationOpen(false);
  };

  const toggleNotification = () => {
    setIsNotificationOpen(!isNotificationOpen);
    setIsProfileOpen(false);
  };

  return (
    <header className="dashboard-header">
      <div className="header-left">
        <button className="sidebar-toggle" onClick={onMenuToggle}>
          ☰
        </button>
        <div className="header-title">
          <h1>Guardlynx</h1>
        </div>
      </div>

      <div className="header-right">
        <div className="search-box">
          <input type="text" placeholder="Search..." />
          <span className="search-icon">🔍</span>
        </div>

        <div className="header-actions">
          <button className="notification-btn" onClick={toggleNotification}>
            🔔
            <span className="notification-badge">3</span>
            {isNotificationOpen && (
              <div className="notification-dropdown">
                <div className="notification-item">New agent connected</div>
                <div className="notification-item">Agent disconnected</div>
                <div className="notification-item">System update available</div>
              </div>
            )}
          </button>

          <div className="profile-section">
            <button className="profile-btn" onClick={toggleProfile}>
              <span className="avatar">👤</span>
              <span className="user-name">Admin</span>
            </button>
            {isProfileOpen && (
              <div className="profile-dropdown">
                <div className="profile-item">My Profile</div>
                <div className="profile-item">Settings</div>
                <div className="profile-item">Help</div>
                <hr />
                <div className="profile-item logout">Logout</div>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};

export default DashboardHeader;
