import React, { useState, useEffect } from 'react';
import Plot from 'react-plotly.js';
import { fetchPacketData } from '../../services/api';
import './PacketSizeChart.css';

const PacketSizeChart = () => {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        const response = await fetchPacketData({ type: 'size_distribution' });
        setData(response.sizeDistribution || []);
        setError(null);
      } catch (err) {
        setError('Failed to load packet size data');
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  if (loading) return <div className="loading">Loading packet size data...</div>;
  if (error) return <div className="error">{error}</div>;
  if (!data.length) return <div className="no-data">No packet size data available</div>;

  return (
    <div className="packet-size-chart">
      <Plot
        data={[
          {
            x: data.map(item => item.sizeRange),
            y: data.map(item => item.count),
            type: 'bar',
            marker: {
              color: '#3D9970'
            }
          }
        ]}
        layout={{
          title: 'Packet Size Distribution',
          xaxis: {
            title: 'Packet Size (bytes)'
          },
          yaxis: {
            title: 'Count'
          },
          margin: { l: 50, r: 30, b: 50, t: 50 },
          autosize: true
        }}
        useResizeHandler={true}
        style={{ width: '100%', height: '100%' }}
      />
    </div>
  );
};

export default PacketSizeChart;