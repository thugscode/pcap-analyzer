import { useState, useEffect } from 'react';
import { fetchPacketData } from '../services/api';

/**
 * Custom hook to fetch and manage packet data for visualizations
 * @param {Object} options - Options for filtering the data
 * @returns {Object} The packet data state and utility functions
 */
export const usePacketData = (options = {}) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Function to load the data
  const loadData = async (queryOptions = {}) => {
    try {
      setLoading(true);
      const result = await fetchPacketData({ ...options, ...queryOptions });
      setData(result);
      setError(null);
    } catch (err) {
      setError(err.message || 'Failed to load packet data');
      console.error('Error loading packet data:', err);
    } finally {
      setLoading(false);
    }
  };

  // Load data on mount and when options change
  useEffect(() => {
    loadData();
  }, [JSON.stringify(options)]); // eslint-disable-line react-hooks/exhaustive-deps

  return {
    data,
    loading,
    error,
    refresh: loadData
  };
};

export default usePacketData;