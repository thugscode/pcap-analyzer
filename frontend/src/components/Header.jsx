import React from 'react';
import { Link } from 'react-router-dom';
import './Header.css';

const Header = () => {
  return (
    <header className="main-header">
      <div className="header-content">
        <div className="app-title-container">
          <div className="app-icon">
            <svg width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M6 8H26C27.1 8 28 8.9 28 10V22C28 23.1 27.1 24 26 24H6C4.9 24 4 23.1 4 22V10C4 8.9 4.9 8 6 8Z" stroke="#3498db" strokeWidth="2" fill="none"/>
              <path d="M8 12H24M8 16H20M8 20H16" stroke="#3498db" strokeWidth="2" strokeLinecap="round"/>
              <circle cx="22" cy="18" r="2" fill="#e74c3c"/>
              <circle cx="26" cy="14" r="1" fill="#2ecc71"/>
              <path d="M2 6L30 6M2 26L30 26" stroke="#f39c12" strokeWidth="2" strokeLinecap="round"/>
            </svg>
          </div>
          <h1 className="app-title">PCAP Analyzer</h1>
        </div>
        <nav className="main-nav">
          <Link to="/" className="nav-link">Dashboard</Link>
          <Link to="/packets" className="nav-link">Packets</Link>
          <Link to="/network" className="nav-link">Network Graph</Link>
        </nav>
      </div>
    </header>
  );
};

export default Header;