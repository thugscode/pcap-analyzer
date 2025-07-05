import React from 'react';
import { Pie } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import usePacketData from '../../hooks/usePacketData';
import './ProtocolDistribution.css';

// Register Chart.js components
ChartJS.register(ArcElement, Tooltip, Legend);

const ProtocolDistribution = () => {
  const { data, loading, error } = usePacketData({ type: 'protocol_distribution' });

  if (loading) return <div className="loading">Loading protocol data...</div>;
  if (error) return <div className="error">{error}</div>;
  if (!data || !data.protocolDistribution) return <div className="no-data">No protocol data available</div>;

  // Colors for different protocols
  const colorPalette = [
    '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', 
    '#FF9F40', '#8BC34A', '#FF5722', '#607D8B', '#E91E63'
  ];
  
  const protocols = Object.keys(data.protocolDistribution);
  const counts = Object.values(data.protocolDistribution);
  
  // Prepare chart data
  const chartData = {
    labels: protocols,
    datasets: [
      {
        data: counts,
        backgroundColor: protocols.map((_, i) => colorPalette[i % colorPalette.length]),
        borderWidth: 1,
        borderColor: '#fff',
      },
    ],
  };
  
  // Chart options
  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right',
        labels: {
          boxWidth: 15,
          padding: 15
        }
      },
      tooltip: {
        callbacks: {
          label: function(context) {
            const label = context.label || '';
            const value = context.raw || 0;
            const total = context.dataset.data.reduce((a, b) => a + b, 0);
            const percentage = Math.round((value / total) * 100);
            return `${label}: ${value} packets (${percentage}%)`;
          }
        }
      }
    }
  };

  return (
    <div className="protocol-distribution">
      <div className="chart-container">
        <Pie data={chartData} options={options} />
      </div>
    </div>
  );
};

export default ProtocolDistribution;