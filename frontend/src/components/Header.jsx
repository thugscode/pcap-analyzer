import React from 'react';
import { Link } from 'react-router-dom';
import './Header.css';

const Header = () => {
  return (
    <header className="main-header">
      <div className="header-content">
        <h1 className="app-title">PCAP Analyzer</h1>
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