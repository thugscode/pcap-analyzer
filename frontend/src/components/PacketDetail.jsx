import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import packetService from '../services/api';
import Header from './Header';
import './PacketDetail.css';

const PacketDetail = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [packet, setPacket] = useState(null);
  const [allPackets, setAllPackets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        
        // Fetch all packets first
        const packets = await packetService.getPackets();
        setAllPackets(packets);
        
        // Find the packet by ID (which might be index)
        const foundPacket = packets[parseInt(id)] || packets.find(p => p.id === id);
        
        if (!foundPacket) {
          throw new Error(`Packet with ID ${id} not found`);
        }
        
        setPacket(foundPacket);
        setError(null);
      } catch (err) {
        setError(`Failed to load packet details for ID: ${id}`);
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [id]);

  const handleBack = () => {
    navigate('/packets');
  };

  if (loading) return (
    <div>
      <Header />
      <div className="loading-container">Loading packet details...</div>
    </div>
  );
  
  if (error) return (
    <div>
      <Header />
      <div className="error-container">{error}</div>
    </div>
  );
  
  if (!packet) return (
    <div>
      <Header />
      <div className="error-container">Packet not found</div>
    </div>
  );

  // Get previous and next packet indices
  const currentIndex = allPackets.findIndex(p => p.id === packet.id);
  const hasPrevious = currentIndex > 0;
  const hasNext = currentIndex < allPackets.length - 1;
  
  const navigateToPrevious = () => {
    if (hasPrevious) {
      navigate(`/packets/${allPackets[currentIndex - 1].id}`);
    }
  };
  
  const navigateToNext = () => {
    if (hasNext) {
      navigate(`/packets/${allPackets[currentIndex + 1].id}`);
    }
  };

  // Check packet security flags
  const hasSecurityConcern = packet.potential_credentials || packet.potential_file_transfer || packet.potential_arp_spoofing;

  return (
    <div>
      <Header />
      <div className="packet-detail-container">
        <div className="detail-header">
          <button onClick={handleBack} className="back-button">← Back to Packets</button>
          <h2>Packet #{currentIndex + 1} Details</h2>
          <div className="packet-navigation">
            <button 
              onClick={navigateToPrevious} 
              disabled={!hasPrevious}
              className={!hasPrevious ? "disabled" : ""}
            >
              ← Previous
            </button>
            <button 
              onClick={navigateToNext} 
              disabled={!hasNext}
              className={!hasNext ? "disabled" : ""}
            >
              Next →
            </button>
          </div>
        </div>
        
        {hasSecurityConcern && (
          <div className="security-alert">
            <div className="alert-icon">⚠️</div>
            <div className="alert-content">
              {packet.potential_credentials && <div>Potential credential exposure detected</div>}
              {packet.potential_file_transfer && <div>File transfer detected: {packet.file_transfer_info}</div>}
              {packet.potential_arp_spoofing && <div>Potential ARP spoofing attack detected</div>}
            </div>
          </div>
        )}
        
        <div className="tab-navigation">
          <button 
            className={activeTab === 'overview' ? 'active' : ''} 
            onClick={() => setActiveTab('overview')}
          >
            Overview
          </button>
          <button 
            className={activeTab === 'details' ? 'active' : ''} 
            onClick={() => setActiveTab('details')}
          >
            Protocol Details
          </button>
          <button 
            className={activeTab === 'hex' ? 'active' : ''} 
            onClick={() => setActiveTab('hex')}
          >
            Hex View
          </button>
        </div>
        
        <div className="detail-content">
          {activeTab === 'overview' && (
            <div className="overview-tab">
              <div className="detail-section">
                <h3>Basic Information</h3>
                <div className="detail-grid">
                  <div className="detail-item">
                    <span className="detail-label">Timestamp:</span>
                    <span className="detail-value">{packet.timestamp}</span>
                  </div>
                  <div className="detail-item">
                    <span className="detail-label">Protocol:</span>
                    <span className="detail-value">{packet.protocol}</span>
                  </div>
                  <div className="detail-item">
                    <span className="detail-label">Length:</span>
                    <span className="detail-value">{packet.length} bytes</span>
                  </div>
                  {packet.delta_time !== undefined && (
                    <div className="detail-item">
                      <span className="detail-label">Delta Time:</span>
                      <span className="detail-value">{packet.delta_time} seconds</span>
                    </div>
                  )}
                  {packet.ttl !== undefined && (
                    <div className="detail-item">
                      <span className="detail-label">TTL:</span>
                      <span className="detail-value">{packet.ttl}</span>
                    </div>
                  )}
                </div>
              </div>
              
              <div className="detail-section">
                <h3>Source</h3>
                <div className="detail-grid">
                  <div className="detail-item">
                    <span className="detail-label">IP Address:</span>
                    <span className="detail-value">{packet.src_ip}</span>
                  </div>
                  {packet.src_port !== undefined && (
                    <div className="detail-item">
                      <span className="detail-label">Port:</span>
                      <span className="detail-value">{packet.src_port}</span>
                    </div>
                  )}
                  {packet.src_mac && (
                    <div className="detail-item">
                      <span className="detail-label">MAC Address:</span>
                      <span className="detail-value">{packet.src_mac}</span>
                    </div>
                  )}
                  {packet.src_ip_geo && (
                    <div className="detail-item">
                      <span className="detail-label">Geolocation:</span>
                      <span className="detail-value">{packet.src_ip_geo}</span>
                    </div>
                  )}
                </div>
              </div>
              
              <div className="detail-section">
                <h3>Destination</h3>
                <div className="detail-grid">
                  <div className="detail-item">
                    <span className="detail-label">IP Address:</span>
                    <span className="detail-value">{packet.dst_ip}</span>
                  </div>
                  {packet.dst_port !== undefined && (
                    <div className="detail-item">
                      <span className="detail-label">Port:</span>
                      <span className="detail-value">{packet.dst_port}</span>
                    </div>
                  )}
                  {packet.dst_mac && (
                    <div className="detail-item">
                      <span className="detail-label">MAC Address:</span>
                      <span className="detail-value">{packet.dst_mac}</span>
                    </div>
                  )}
                  {packet.dst_ip_geo && (
                    <div className="detail-item">
                      <span className="detail-label">Geolocation:</span>
                      <span className="detail-value">{packet.dst_ip_geo}</span>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
          
          {activeTab === 'details' && (
            <div className="details-tab">
              {packet.protocol === 'TCP' && (
                <div className="detail-section">
                  <h3>TCP Information</h3>
                  <div className="detail-grid">
                    <div className="detail-item">
                      <span className="detail-label">Sequence Number:</span>
                      <span className="detail-value">{packet.seq_num}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">Acknowledgment Number:</span>
                      <span className="detail-value">{packet.ack_num}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">Flags:</span>
                      <span className="detail-value">{packet.tcp_flags || 'None'}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">SYN:</span>
                      <span className="detail-value">{packet.syn ? 'Yes' : 'No'}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">ACK:</span>
                      <span className="detail-value">{packet.ack ? 'Yes' : 'No'}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">FIN:</span>
                      <span className="detail-value">{packet.fin ? 'Yes' : 'No'}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">RST:</span>
                      <span className="detail-value">{packet.rst ? 'Yes' : 'No'}</span>
                    </div>
                  </div>
                </div>
              )}
              
              {packet.is_tls && (
                <div className="detail-section">
                  <h3>TLS Information</h3>
                  <div className="detail-grid">
                    {packet.tls_sni && (
                      <div className="detail-item">
                        <span className="detail-label">Server Name (SNI):</span>
                        <span className="detail-value">{packet.tls_sni}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}
              
              {packet.http_method && (
                <div className="detail-section">
                  <h3>HTTP Information</h3>
                  <div className="detail-grid">
                    <div className="detail-item">
                      <span className="detail-label">Method:</span>
                      <span className="detail-value">{packet.http_method}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">URI:</span>
                      <span className="detail-value">{packet.http_uri}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">Host:</span>
                      <span className="detail-value">{packet.http_host}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">User Agent:</span>
                      <span className="detail-value">{packet.http_user_agent}</span>
                    </div>
                  </div>
                </div>
              )}
              
              {packet.dns_queries && packet.dns_queries.length > 0 && (
                <div className="detail-section">
                  <h3>DNS Information</h3>
                  <div className="detail-grid full-width">
                    <div className="detail-item">
                      <span className="detail-label">Queries:</span>
                      <span className="detail-value">
                        <ul className="dns-queries">
                          {packet.dns_queries.map((query, index) => (
                            <li key={index}>{query}</li>
                          ))}
                        </ul>
                      </span>
                    </div>
                  </div>
                </div>
              )}
              
              {packet.is_arp && (
                <div className="detail-section">
                  <h3>ARP Information</h3>
                  <div className="detail-grid">
                    <div className="detail-item">
                      <span className="detail-label">ARP Type:</span>
                      <span className="detail-value">Request</span>
                    </div>
                  </div>
                </div>
              )}
              
              {packet.protocol === 'ICMP' && (
                <div className="detail-section">
                  <h3>ICMP Information</h3>
                  <div className="detail-grid">
                    <div className="detail-item">
                      <span className="detail-label">Type:</span>
                      <span className="detail-value">{packet.type}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">Code:</span>
                      <span className="detail-value">{packet.code}</span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">Message:</span>
                      <span className="detail-value">
                        {packet.type === 8 && packet.code === 0 ? 'Echo Request (Ping)' : 
                         packet.type === 0 && packet.code === 0 ? 'Echo Reply (Ping Response)' :
                         packet.type === 3 ? 'Destination Unreachable' :
                         packet.type === 11 ? 'Time Exceeded' :
                         'Other ICMP Message'}
                      </span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
          
          {activeTab === 'hex' && (
            <div className="hex-tab">
              <h3>Hexadecimal View</h3>
              <div className="hex-view">
                <pre className="hex-dump">
                  {/* Create a formatted hex view with available data */}
                  {`Packet ${id} - ${packet.protocol} - ${packet.length} bytes
Timestamp: ${packet.timestamp}

Source: ${packet.src_ip}${packet.src_port ? `:${packet.src_port}` : ''} (${packet.src_mac || 'Unknown MAC'})
Destination: ${packet.dst_ip}${packet.dst_port ? `:${packet.dst_port}` : ''} (${packet.dst_mac || 'Unknown MAC'})
TTL: ${packet.ttl || 'N/A'}
${packet.protocol === 'TCP' ? `
TCP Flags: ${packet.tcp_flags || 'None'}
Sequence Number: ${packet.seq_num || 'N/A'}
Acknowledgment Number: ${packet.ack_num || 'N/A'}
SYN: ${packet.syn ? 'Yes' : 'No'}
ACK: ${packet.ack ? 'Yes' : 'No'}
FIN: ${packet.fin ? 'Yes' : 'No'}
RST: ${packet.rst ? 'Yes' : 'No'}` : ''}
${packet.http_method ? `
HTTP ${packet.http_method} ${packet.http_uri || ''}
Host: ${packet.http_host || 'N/A'}
User-Agent: ${packet.http_user_agent || 'N/A'}` : ''}
${packet.is_tls ? `
TLS Connection
Server Name: ${packet.tls_sni || 'N/A'}` : ''}
${packet.dns_queries && packet.dns_queries.length ? `
DNS Queries: ${packet.dns_queries.join(', ')}` : ''}
${packet.is_arp ? `
ARP Request` : ''}
${packet.protocol === 'ICMP' ? `
ICMP Type: ${packet.type || 'N/A'}, Code: ${packet.code || 'N/A'}` : ''}
${packet.potential_credentials ? `
SECURITY ALERT: Potential credential exposure
${packet.credential_info || ''}` : ''}
${packet.potential_file_transfer ? `
SECURITY ALERT: File transfer detected
${packet.file_transfer_info || ''}` : ''}

-- Hexadecimal representation would appear here --
00000000: 0011 2233 4455 aabb ccdd eeff 0800 4500  ..\"3DU........E.
00000010: 0054 0000 4000 4006 xxxx xxxx xxxx xxxx  .T..@.@.........
00000020: xxxx xxxx xxxx 0050 0000 0000 0000 0000  .......P........
00000030: 5000 0000 0000 0000 0000 0000 0000 0000  P...............
`}
                </pre>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default PacketDetail;