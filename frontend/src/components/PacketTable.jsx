import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import packetService from '../services/api';
// Remove this import: import Header from './Header';
import './PacketTable.css';

const PacketTable = () => {
  const [packets, setPackets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filters, setFilters] = useState({
    protocol: '',
    src_ip: '',
    dst_ip: '',
    startTime: '',
    endTime: '',
    port: ''
  });
  const navigate = useNavigate();

  useEffect(() => {
    fetchPackets();
  }, []);

  const fetchPackets = async (filterParams = {}) => {
    try {
      setLoading(true);
      const data = await packetService.getPackets(filterParams);
      setPackets(data);
      setError(null);
    } catch (err) {
      setError('Failed to load packets. Is the server running?');
      console.error(err);
    } finally {
      setLoading(false);
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
    // Remove empty filters
    const activeFilters = Object.fromEntries(
      Object.entries(filters).filter(([_, value]) => value !== '')
    );
    
    // Handle port filtering separately since it can be in src_port or dst_port
    const { port, ...otherFilters } = activeFilters;
    
    fetchPackets(otherFilters);
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

  return (
    // Remove the outer Header component
    <div className="packet-table-container">
      <h2>Network Packets</h2>
      
      <div className="filter-panel">
          <h3>Filters</h3>
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
              <button className="reset-btn" onClick={resetFilters}>Reset</button>
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
        </div>
      </div>
  );
};

export default PacketTable;