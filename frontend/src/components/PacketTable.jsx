import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import packetService from '../services/api';
// Remove this import: import Header from './Header';
import './PacketTable.css';

// Debounce utility function
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

const PacketTable = () => {
  const [packets, setPackets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filtering, setFiltering] = useState(false);
  const [filters, setFilters] = useState({
    protocol: '',
    src_ip: '',
    dst_ip: '',
    startTime: '',
    endTime: '',
    port: ''
  });
  const navigate = useNavigate();

  // Debounced filter application
  const debouncedApplyFilters = useCallback(
    debounce((filterParams) => {
      fetchPackets(filterParams);
    }, 500),
    []
  );

  useEffect(() => {
    fetchPackets();
  }, []);

  // Auto-apply filters when they change (with debounce)
  useEffect(() => {
    const activeFilters = Object.fromEntries(
      Object.entries(filters).filter(([_, value]) => value !== '')
    );
    
    if (Object.keys(activeFilters).length > 0) {
      debouncedApplyFilters(activeFilters);
    }
  }, [filters, debouncedApplyFilters]);

  const fetchPackets = async (filterParams = {}) => {
    try {
      const isFiltering = Object.keys(filterParams).length > 0;
      
      if (isFiltering) {
        setFiltering(true);
      } else {
        setLoading(true);
      }
      
      const data = await packetService.getPackets(filterParams);
      setPackets(data);
      setError(null);
    } catch (err) {
      setError('Failed to load packets. Is the server running?');
      console.error(err);
    } finally {
      setLoading(false);
      setFiltering(false);
    }
  };

  const handleFilterChange = (e) => {
    const { name, value } = e.target;
    setFilters(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const applyFilters = () => {
    console.log('Applying filters:', filters);
    // Remove empty filters
    const activeFilters = Object.fromEntries(
      Object.entries(filters).filter(([_, value]) => value !== '')
    );
    
    console.log('Active filters:', activeFilters);
    fetchPackets(activeFilters);
  };

  const resetFilters = () => {
    setFilters({
      protocol: '',
      src_ip: '',
      dst_ip: '',
      startTime: '',
      endTime: '',
      port: ''
    });
    fetchPackets();
  };

  const handlePacketSelect = (packetIndex) => {
    navigate(`/packets/${packetIndex}`);
  };

  // Helper function to determine packet info based on protocol
  const getPacketInfo = (packet) => {
    if (packet.protocol === 'TCP') {
      let info = packet.tcp_flags || '';
      
      if (packet.http_method) {
        info = `${packet.http_method} ${packet.http_uri || ''} (${packet.http_host || ''})`;
      } else if (packet.is_tls) {
        info = `TLS${packet.tls_sni ? ` - ${packet.tls_sni}` : ''}`;
      } else if (packet.potential_credentials) {
        info = `${info} [CREDENTIALS]`;
      } else if (packet.potential_file_transfer) {
        info = `${info} [FILE TRANSFER]`;
      } else {
        info = `${info} Seq=${packet.seq_num} Ack=${packet.ack_num}`;
      }
      
      return info;
    } 
    else if (packet.protocol === 'UDP') {
      if (packet.dns_queries) {
        return `DNS Query: ${packet.dns_queries.join(', ')}`;
      }
      return '';
    }
    else if (packet.protocol === 'ICMP') {
      return `Type=${packet.type}, Code=${packet.code}`;
    }
    else if (packet.protocol === 'ARP') {
      return packet.potential_arp_spoofing ? 'Potential ARP Spoofing' : 'ARP Request';
    }
    
    return '';
  };

  // Helper function to determine if a packet has security concerns
  const hasSecurityConcern = (packet) => {
    return packet.potential_credentials || 
           packet.potential_file_transfer || 
           packet.potential_arp_spoofing;
  };

  if (loading) return (
    // Remove Header component
    <div className="loading-container">Loading packets...</div>
  );
  
  if (error) return (
    // Remove Header component
    <div className="error-container">{error}</div>
  );

  // Check if any filters are active
  const hasActiveFilters = Object.values(filters).some(value => value !== '');

  return (
    // Remove the outer Header component
    <div className="packet-table-container">
      <h2>Network Packets</h2>
      
      <div className="filter-panel">
          <h3>
            Filters 
            {hasActiveFilters && <span className="filter-indicator">● Active</span>}
            {filtering && <span className="filter-loading">🔄 Filtering...</span>}
          </h3>
          <div className="filter-controls">
            <div className="filter-group">
              <label>Protocol:</label>
              <input
                type="text"
                name="protocol"
                value={filters.protocol}
                onChange={handleFilterChange}
                placeholder="e.g., TCP, UDP, ICMP"
              />
            </div>
            
            <div className="filter-group">
              <label>Source IP:</label>
              <input
                type="text"
                name="src_ip"
                value={filters.src_ip}
                onChange={handleFilterChange}
                placeholder="e.g., 192.168.1.1"
              />
            </div>
            
            <div className="filter-group">
              <label>Destination IP:</label>
              <input
                type="text"
                name="dst_ip"
                value={filters.dst_ip}
                onChange={handleFilterChange}
                placeholder="e.g., 10.0.0.1"
              />
            </div>
            
            <div className="filter-group">
              <label>Port:</label>
              <input
                type="text"
                name="port"
                value={filters.port}
                onChange={handleFilterChange}
                placeholder="e.g., 80, 443"
              />
            </div>
            
            <div className="filter-group">
              <label>Start Time:</label>
              <input
                type="datetime-local"
                name="startTime"
                value={filters.startTime}
                onChange={handleFilterChange}
              />
            </div>
            
            <div className="filter-group">
              <label>End Time:</label>
              <input
                type="datetime-local"
                name="endTime"
                value={filters.endTime}
                onChange={handleFilterChange}
              />
            </div>
            
            <div className="filter-actions">
              <button className="apply-btn" onClick={applyFilters}>Apply Filters</button>
              <button className="reset-btn" onClick={resetFilters}>Clear All</button>
              {hasActiveFilters && (
                <span className="active-filters-count">
                  {Object.values(filters).filter(v => v !== '').length} filter(s) active
                </span>
              )}
            </div>
          </div>
        </div>
        
        <div className="table-wrapper">
          <table className="packet-table">
            <thead>
              <tr>
                <th>No.</th>
                <th>Time</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Protocol</th>
                <th>Length</th>
                <th>Info</th>
              </tr>
            </thead>
            <tbody>
              {packets.length > 0 ? (
                packets.map((packet, index) => (
                  <tr 
                    key={packet.id} 
                    onClick={() => handlePacketSelect(packet.id)}
                    className={`packet-row ${hasSecurityConcern(packet) ? 'has-security-concern' : ''}`}
                  >
                    <td>{index + 1}</td>
                    <td>{packet.timestamp}</td>
                    <td>{`${packet.src_ip}:${packet.src_port || '-'}`}</td>
                    <td>{`${packet.dst_ip}:${packet.dst_port || '-'}`}</td>
                    <td>{packet.protocol}</td>
                    <td>{packet.length}</td>
                    <td>
                      {getPacketInfo(packet)}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="7" className="no-data">No packets found</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        
        <div className="table-stats">
          Displaying {packets.length} packets
          {hasActiveFilters && (
            <span className="filter-info"> (filtered)</span>
          )}
        </div>
      </div>
  );
};

export default PacketTable;