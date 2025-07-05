import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import PacketTable from './components/PacketTable';
import PacketDetail from './components/PacketDetail';
import Dashboard from './components/Dashboard';
import NetworkGraph from './components/NetworkGraph';
import Header from './components/Header';
import './App.css';

function App() {
  return (
    <Router>
      <div className="app">
        <Header />
        <main className="app-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/packets" element={<PacketTable />} />
            <Route path="/packets/:id" element={<PacketDetail />} />
            <Route path="/network" element={<NetworkGraph />} />
          </Routes>
        </main>
        
        <footer className="app-footer">
          <p>PCAP Analyzer - Connected to server at localhost:18080</p>
        </footer>
      </div>
    </Router>
  );
}

export default App;