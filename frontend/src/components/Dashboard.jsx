import React, { useState, useEffect } from 'react';
import { ResponsiveContainer, PieChart, Pie, Cell, Legend, Tooltip, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';
import api from '../services/api';
import './Dashboard.css';

const Dashboard = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [stats, setStats] = useState({
    protocolDistribution: [],
    topSourceIPs: [],
    topDestinationIPs: [],
    packetSizeDistribution: { small: 0, medium: 0, large: 0 },
    totalPackets: 0,
    totalBytes: 0,
    averagePacketSize: 0,
    timeRange: { start: null, end: null },
    securityAlerts: []
  });

  const colors = ['#3498db', '#2ecc71', '#e74c3c', '#f39c12', '#9b59b6', '#1abc9c', '#34495e', '#e67e22'];

  useEffect(() => {
    const fetchStats = async () => {
      try {
        setLoading(true);
        const response = await api.getPacketStats();
        
        // Get packets for additional statistics
        const packets = await api.getPackets();
        
        // Calculate additional metrics
        let totalBytes = 0;
        let timestamps = [];
        const securityAlerts = [];
        
        packets.forEach(packet => {
          // Calculate total bytes
          totalBytes += packet.length || 0;
          
          // Collect timestamps for time range
          if (packet.timestamp) {
            timestamps.push(packet.timestamp);
          }
          
          // Check for security-relevant items
          if (packet.potential_credentials || packet.potential_file_transfer ||
              (packet.tcp_flags && packet.tcp_flags.includes("RST")) ||
              (packet.icmp_type === 8 || packet.icmp_type === 0)) {
            securityAlerts.push({
              timestamp: packet.timestamp,
              src_ip: packet.src_ip,
              dst_ip: packet.dst_ip,
              alert_type: packet.potential_credentials ? 'Potential Credentials' : 
                          packet.potential_file_transfer ? 'File Transfer' :
                          packet.tcp_flags && packet.tcp_flags.includes("RST") ? 'TCP Reset' :
                          'ICMP Activity',
              details: packet.credential_info || packet.file_transfer_info || packet.protocol
            });
          }
          
          // Check for potential credential exposure
          if (packet.potential_credentials) {
            securityAlerts.push({
              timestamp: packet.timestamp,
              src_ip: packet.src_ip,
              dst_ip: packet.dst_ip,
              alert_type: 'Credential Exposure',
              severity: 'high',
              details: packet.credential_info || 'Potential credentials detected'
            });
          }
          
          // Check for port scanning (many SYN packets, few ACKs)
          if (packet.syn_flag && !packet.ack_flag) {
            // We'd need more logic for true port scan detection, this is simplified
            securityAlerts.push({
              timestamp: packet.timestamp,
              src_ip: packet.src_ip,
              dst_ip: packet.dst_ip,
              alert_type: 'Potential Port Scan',
              severity: 'medium',
              details: `SYN to port ${packet.dst_port}`
            });
          }
          
          // Check for file transfers
          if (packet.potential_file_transfer) {
            securityAlerts.push({
              timestamp: packet.timestamp,
              src_ip: packet.src_ip,
              dst_ip: packet.dst_ip,
              alert_type: 'File Transfer',
              severity: 'low',
              details: packet.file_transfer_info || 'File transfer detected'
            });
          }
          
          // Check for potential DoS (high packet rate from same source)
          // This is simplified; real DoS detection needs more sophisticated logic
          if (packet.protocol === 'TCP' && packet.syn_flag) {
            securityAlerts.push({
              timestamp: packet.timestamp,
              src_ip: packet.src_ip,
              dst_ip: packet.dst_ip,
              alert_type: 'Potential DoS',
              severity: 'high',
              details: `TCP SYN flood to ${packet.dst_ip}:${packet.dst_port}`
            });
          }

          // Add ARP spoofing detection (repeated ARP replies with different MAC addresses)
          if (packet.protocol === 'ARP' && packet.arp_operation === 2) { // ARP Reply
            securityAlerts.push({
              timestamp: packet.timestamp,
              src_ip: packet.src_ip || packet.arp_src_ip,
              dst_ip: packet.dst_ip || packet.arp_dst_ip,
              alert_type: 'Potential ARP Spoofing',
              severity: 'high',
              details: `ARP reply from ${packet.src_mac}`
            });
          }
        });
        
        // Sort timestamps and get range
        timestamps.sort();
        const timeRange = {
          start: timestamps.length > 0 ? new Date(timestamps[0] * 1000).toLocaleString() : 'Unknown',
          end: timestamps.length > 0 ? new Date(timestamps[timestamps.length-1] * 1000).toLocaleString() : 'Unknown'
        };
        
        // Make sure response has the expected structure
        setStats({
          protocolDistribution: response?.protocolDistribution || [],
          topSourceIPs: response?.topSourceIPs || [],
          topDestinationIPs: response?.topDestinationIPs || [],
          packetSizeDistribution: response?.packetSizeDistribution || { small: 0, medium: 0, large: 0 },
          totalPackets: response?.totalPackets || packets.length || 0,
          totalBytes: totalBytes,
          averagePacketSize: packets.length ? Math.round(totalBytes / packets.length) : 0,
          timeRange: timeRange,
          securityAlerts: securityAlerts.slice(0, 10) // Top 10 alerts
        });
        
        // Identify potential security events
        const uniqueAlerts = securityAlerts.filter((alert, index, self) =>
          index === self.findIndex((a) => (
            a.src_ip === alert.src_ip && 
            a.dst_ip === alert.dst_ip && 
            a.alert_type === alert.alert_type
          ))
        );

        // Sort by severity then timestamp
        uniqueAlerts.sort((a, b) => {
          const severityOrder = { high: 0, medium: 1, low: 2 };
          return severityOrder[a.severity] - severityOrder[b.severity] || 
                 b.timestamp - a.timestamp;
        });

        // Add to stats
        setStats(prev => ({
          ...prev,
          securityAlerts: uniqueAlerts.slice(0, 10) // Top 10 alerts
        }));
        
        setError(null);
      } catch (err) {
        console.error('Failed to load packet statistics:', err);
        setError('Failed to load packet statistics. Is the server running?');
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
  }, []);

  // Convert packet size distribution to array format for charts
  const packetSizeData = Object.entries(stats.packetSizeDistribution || {}).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value
  }));

  if (loading) return <div className="loading">Loading dashboard statistics...</div>;
  
  if (error) return <div className="error-message">{error}</div>;

  return (
    <div className="dashboard">
      <h1>PCAP Analysis Dashboard</h1>
      
      <div className="stats-overview">
        <div className="stat-card">
          <h3>Total Packets</h3>
          <div className="stat-value">{stats.totalPackets.toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <h3>Total Data</h3>
          <div className="stat-value">{formatBytes(stats.totalBytes)}</div>
        </div>
        <div className="stat-card">
          <h3>Avg. Packet Size</h3>
          <div className="stat-value">{stats.averagePacketSize.toLocaleString()} bytes</div>
        </div>
        <div className="stat-card">
          <h3>Time Period</h3>
          <div className="time-period">
            <div>From: {stats.timeRange.start}</div>
            <div>To: {stats.timeRange.end}</div>
          </div>
        </div>
      </div>
      
      <div className="chart-container">
        <div className="chart-card">
          <h3>Protocol Distribution</h3>
          {stats.protocolDistribution && stats.protocolDistribution.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={stats.protocolDistribution}
                  dataKey="count"
                  nameKey="protocol"
                  cx="50%"
                  cy="50%"
                  outerRadius={100}
                  fill="#8884d8"
                  label={({protocol, percent}) => `${protocol} ${(percent * 100).toFixed(0)}%`}
                >
                  {stats.protocolDistribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={colors[index % colors.length]} />
                  ))}
                </Pie>
                <Tooltip formatter={(value) => value.toLocaleString()} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="no-data">No protocol data available</div>
          )}
        </div>
        
        <div className="chart-card">
          <h3>Packet Size Distribution</h3>
          {packetSizeData && packetSizeData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={packetSizeData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="value" fill="#3498db" />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="no-data">No packet size data available</div>
          )}
        </div>
      </div>
      
      <div className="tables-container">
        <div className="table-card">
          <h3>Top Source IPs</h3>
          {stats.topSourceIPs && stats.topSourceIPs.length > 0 ? (
            <table>
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Packet Count</th>
                  <th>% of Total</th>
                </tr>
              </thead>
              <tbody>
                {stats.topSourceIPs.map((item, index) => (
                  <tr key={index}>
                    <td>{item.ip}</td>
                    <td>{item.count.toLocaleString()}</td>
                    <td>{((item.count / stats.totalPackets) * 100).toFixed(1)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="no-data">No source IP data available</div>
          )}
        </div>
        
        <div className="table-card">
          <h3>Top Destination IPs</h3>
          {stats.topDestinationIPs && stats.topDestinationIPs.length > 0 ? (
            <table>
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Packet Count</th>
                  <th>% of Total</th>
                </tr>
              </thead>
              <tbody>
                {stats.topDestinationIPs.map((item, index) => (
                  <tr key={index}>
                    <td>{item.ip}</td>
                    <td>{item.count.toLocaleString()}</td>
                    <td>{((item.count / stats.totalPackets) * 100).toFixed(1)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="no-data">No destination IP data available</div>
          )}
        </div>
      </div>
      
      <div className="security-section">
        <h2>Potential Security Events</h2>
        <div className="table-card">
          <h3>Detected Security Events</h3>
          {stats.securityAlerts && stats.securityAlerts.length > 0 ? (
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Type</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {stats.securityAlerts.map((alert, index) => (
                  <tr key={index} className={`security-alert-${alert.severity || 'medium'}`}>
                    <td>{alert.timestamp ? new Date(alert.timestamp * 1000).toLocaleString() : 'Unknown'}</td>
                    <td>{alert.alert_type}</td>
                    <td>{alert.src_ip}</td>
                    <td>{alert.dst_ip}</td>
                    <td>{alert.details || 'N/A'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="no-data">No security events detected</div>
          )}
        </div>
      </div>
    </div>
  );
};

// Helper function to format bytes
const formatBytes = (bytes, decimals = 2) => {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
};

export default Dashboard;