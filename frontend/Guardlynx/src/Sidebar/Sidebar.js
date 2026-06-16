import React, { useState } from 'react';
import './Sidebar.css';

const Sidebar = ({ isOpen, onClose }) => {
  const [activeMenu, setActiveMenu] = useState('dashboard');

  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: '📊', href: '/dashboard' },
    { id: 'endpoints', label: 'Endpoints', icon: '🖥️', href: '/endpoints' },
    { id: 'assets', label: 'Assets', icon: '📦', href: '/assets' },
    { id: 'monitoring', label: 'Monitoring', icon: '👁️', href: '/monitoring' },
    { id: 'reports', label: 'Reports', icon: '📈', href: '/reports' },
    { id: 'users', label: 'Users', icon: '👥', href: '/users' },
  ];

  const settingsItems = [
    { id: 'settings', label: 'Settings', icon: '⚙️', href: '/settings' },
    { id: 'help', label: 'Help & Support', icon: '❓', href: '/help' },
  ];

  return (
    <>
      <div className={`sidebar-overlay ${isOpen ? 'visible' : ''}`} onClick={onClose}></div>
      <aside className={`sidebar ${isOpen ? 'open' : ''}`}>
        <div className="sidebar-header">
          <h2 className="sidebar-logo">G</h2>
          <button className="close-btn" onClick={onClose}>✕</button>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section">
            <h3 className="nav-section-title">Main</h3>
            <ul className="nav-menu">
              {menuItems.map((item) => (
                <li key={item.id}>
                  <a
                    href={item.href}
                    className={`nav-item ${activeMenu === item.id ? 'active' : ''}`}
                    onClick={() => setActiveMenu(item.id)}
                  >
                    <span className="nav-icon">{item.icon}</span>
                    <span className="nav-label">{item.label}</span>
                  </a>
                </li>
              ))}
            </ul>
          </div>

          <div className="nav-section">
            <h3 className="nav-section-title">Other</h3>
            <ul className="nav-menu">
              {settingsItems.map((item) => (
                <li key={item.id}>
                  <a
                    href={item.href}
                    className={`nav-item ${activeMenu === item.id ? 'active' : ''}`}
                    onClick={() => setActiveMenu(item.id)}
                  >
                    <span className="nav-icon">{item.icon}</span>
                    <span className="nav-label">{item.label}</span>
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </nav>

        <div className="sidebar-footer">
          <div className="version-info">v1.0.0</div>
        </div>
      </aside>
    </>
  );
};

export default Sidebar;
