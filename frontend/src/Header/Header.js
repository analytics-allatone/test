import React, { useState } from 'react';
import './Header.css';

const Header = () => {
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  const toggleMenu = () => {
    setIsMenuOpen(!isMenuOpen);
  };

  return (
    <header className="header">
      <div className="header-container">
        <div className="header-logo">
          <h1><a href="/">Guardlynx</a></h1>
        </div>

        <button className="menu-toggle" onClick={toggleMenu}>
          ☰
        </button>

        <nav className={`nav-menu ${isMenuOpen ? 'open' : ''}`}>
          <ul>
            {/* <li><a href="/">Dashboard</a></li>
            <li><a href="/assets">Assets</a></li>
            <li><a href="/users">Users</a></li>
            <li><a href="/settings">Settings</a></li> */}
            <li><a href="/login" className="nav-link-btn">Login</a></li>
          </ul>
        </nav>
      </div>
    </header>
  );
};

export default Header;
