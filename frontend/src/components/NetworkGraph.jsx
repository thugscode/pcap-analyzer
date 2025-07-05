import React, { useEffect, useRef, useState } from 'react';
import { MultiDirectedGraph } from 'graphology';
import Sigma from 'sigma';
import circular from 'graphology-layout/circular';
import forceAtlas2 from 'graphology-layout-forceatlas2';
import api from '../services/api';
import './NetworkGraph.css';

const NetworkGraph = () => {
  const containerRef = useRef(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [graph, setGraph] = useState(null);
  const [renderer, setRenderer] = useState(null);
  const [hoveredNode, setHoveredNode] = useState(null);
  const [tooltipPosition, setTooltipPosition] = useState({ x: 0, y: 0 });

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        console.log('Fetching network topology data...');
        
        // Simple direct call, no Promise.race to see real errors
        const data = await api.getNetworkTopology();
        console.log('Network topology data received:', data);
        
        if (!data || !data.nodes || !data.edges || data.nodes.length === 0) {
          throw new Error('Invalid or empty network topology data');
        }
        
        // Create graph
        const newGraph = new MultiDirectedGraph();
        
        // Add nodes (IP addresses)
        data.nodes.forEach(node => {
          // Calculate additional metrics
          const nodePackets = node.packets || 0;
          const nodeBytes = node.bytes || 0;
          const nodeType = node.type || 'internal';
          
          newGraph.addNode(node.id, {
            label: node.label || node.id,
            size: node.size || 10,
            color: nodeType === 'external' ? '#FF6384' : '#36A2EB',
            nodeType: nodeType, // Use nodeType instead of type to avoid Sigma.js conflicts
            // Add more information for hover tooltip
            packets: nodePackets,
            bytes: nodeBytes,
            hostname: node.hostname || '',
            protocols: node.protocols || [],
            firstSeen: node.firstSeen || '',
            lastSeen: node.lastSeen || '',
            // Add class for hover styles
            classes: [`${nodeType}-node`]
          });
        });
        
        // Add edges (connections between IPs)
        data.edges.forEach(edge => {
          if (newGraph.hasNode(edge.source) && newGraph.hasNode(edge.target)) {
            try {
              newGraph.addEdge(edge.source, edge.target, {
                size: edge.size || 1,
                label: edge.label || '',
                color: edge.color || '#999',
                type: edge.type || 'arrow',
                highlighted: false
              });
            } catch (e) {
              console.error('Error adding edge:', e, edge);
            }
          } else {
            console.warn('Cannot add edge, missing nodes:', edge);
          }
        });
        
        // Replace your layout code with this:
        // Start with simple random positions
        newGraph.forEachNode((node) => {
          const angle = Math.random() * 2 * Math.PI;
          const radius = 50 + Math.random() * 50;
          newGraph.setNodeAttribute(node, "x", Math.cos(angle) * radius);
          newGraph.setNodeAttribute(node, "y", Math.sin(angle) * radius);
        });
        
        // Then apply circular layout for basic structure
        circular.assign(newGraph, {scale: 200});
        
        // Finally apply gentler force directed layout
        const settings = forceAtlas2.inferSettings(newGraph);
        const adjustedSettings = {
          ...settings,
          gravity: 1,
          scalingRatio: 5,
          slowDown: 20,
          linLogMode: false,  // Try without linLogMode
          outboundAttractionDistribution: false,  // Try without this too
          adjustSizes: true
        };
        
        // Run fewer iterations to start
        forceAtlas2.assign(newGraph, { settings: adjustedSettings, iterations: 50 });
        
        setGraph(newGraph);
        setError(null);
      } catch (err) {
        console.error('Failed to load network topology:', err);
        setError(`Failed to load network topology: ${err.message}`);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  // Initialize Sigma when graph is ready
  useEffect(() => {
    if (!graph || !containerRef.current) return;
    
    // If a renderer already exists, destroy it first
    if (renderer) {
      console.log('Destroying old renderer');
      renderer.kill();
    }
    
    // Create new renderer
    console.log('Creating new Sigma renderer');
    const newRenderer = new Sigma(graph, containerRef.current, {
      renderEdgeLabels: true,
      defaultEdgeType: 'arrow',
      defaultEdgeColor: '#999',
      labelSize: 14,
      labelThreshold: 5,
      minCameraRatio: 0.1,
      maxCameraRatio: 5,
      allowInvalidContainer: true, // Add this line to fix the container width error
      labelColor: {
        color: '#333',
        background: 'rgba(255, 255, 255, 0.8)'  // Add background to labels
      },
      nodeReducer: (node, data) => {
        const res = { ...data };
        
        // Adjust size for better visibility
        if (res.size) res.size *= 1.5;
        
        // If node is highlighted, emphasize it
        if (res.highlighted) {
          res.color = '#F1C40F';  // Highlight color
          res.size *= 1.3;        // Make highlighted nodes larger
          res.border = {          // Add border to highlighted nodes
            color: '#E67E22',
            width: 2
          };
        }
        
        return res;
      },
      edgeReducer: (edge, data) => {
        const res = { ...data };
        
        // Make edges more visible
        if (res.size) res.size *= 1.2;
        
        // If edge is highlighted, emphasize it
        if (res.highlighted) {
          res.color = '#F1C40F';  // Highlight color
          res.size *= 1.5;        // Make highlighted edges thicker
        }
        
        return res;
      }
    });
    
    // Add interactivity
    newRenderer.on('clickNode', ({ node }) => {
      console.log('Clicked node:', node, graph.getNodeAttributes(node));
      // Optionally highlight the node's connections
      // Reset previous highlights
      graph.forEachNode((n) => {
        graph.setNodeAttribute(n, 'highlighted', false);
      });
      graph.forEachEdge((e) => {
        graph.setEdgeAttribute(e, 'highlighted', false);
      });
      
      // Highlight the selected node
      graph.setNodeAttribute(node, 'highlighted', true);
      
      // Highlight connected nodes and edges
      graph.forEachNeighbor(node, (neighbor) => {
        graph.setNodeAttribute(neighbor, 'highlighted', true);
        const edges = graph.edges(node, neighbor);
        edges.forEach(edge => {
          graph.setEdgeAttribute(edge, 'highlighted', true);
        });
      });
      
      // Refresh renderer
      newRenderer.refresh();
    });
    
    // Add these lines after setting the renderer:
    newRenderer.on('afterRender', () => {
      console.log('Graph rendered successfully');
    });

    // Add better camera positioning
    setTimeout(() => {
      if (newRenderer && graph) {
        // Center the camera view
        const camera = newRenderer.getCamera();
        camera.setState({
          x: 0.5,
          y: 0.5,
          ratio: 1.2,
          angle: 0
        });
        newRenderer.refresh();
        console.log('Camera position reset');
      }
    }, 500);
    
    setRenderer(newRenderer);
    
    // Cleanup function
    return () => {
      if (newRenderer) {
        console.log('Cleanup: Destroying Sigma renderer');
        newRenderer.kill();
      }
    };
  }, [graph, renderer]);

  // Add this useEffect to monitor container dimensions:
  useEffect(() => {
    if (containerRef.current) {
      const rect = containerRef.current.getBoundingClientRect();
      console.log('Container dimensions:', rect.width, rect.height);
      if (rect.width === 0 || rect.height === 0) {
        console.error('Container has zero width or height!');
      }
    }
  }, [containerRef.current]);

  // Add this inside your NetworkGraph component
  const NodeTooltip = ({ node, position }) => {
    if (!node) return null;
    
    // Position tooltip near the cursor but ensure it stays in viewport
    const style = {
      left: `${position.x + 10}px`,
      top: `${position.y + 10}px`,
    };
    
    // Format data from the node
    return (
      <div className="node-tooltip" style={style}>
        <h4>{node.label || node.id}</h4>
        <div className="node-tooltip-row">
          <span className="node-tooltip-label">IP:</span>
          <span>{node.id}</span>
        </div>
        <div className="node-tooltip-row">
          <span className="node-tooltip-label">Type:</span>
          <span>{node.nodeType === 'external' ? 'External' : 'Internal'}</span>
        </div>
        {node.connections && (
          <div className="node-tooltip-row">
            <span className="node-tooltip-label">Connections:</span>
            <span>{node.connections}</span>
          </div>
        )}
        {node.packets && (
          <div className="node-tooltip-row">
            <span className="node-tooltip-label">Packets:</span>
            <span>{node.packets.toLocaleString()}</span>
          </div>
        )}
        {node.bytes && (
          <div className="node-tooltip-row">
            <span className="node-tooltip-label">Data:</span>
            <span>{formatBytes(node.bytes)}</span>
          </div>
        )}
        {node.protocols && (
          <div className="node-tooltip-row">
            <span className="node-tooltip-label">Protocols:</span>
            <span>{node.protocols.join(', ')}</span>
          </div>
        )}
      </div>
    );
  };

  // Add this helper function
  const formatBytes = (bytes, decimals = 2) => {
    if (!bytes || bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  };

  if (loading) return <div className="loading">Loading network topology data...</div>;
  
  if (error) return (
    <div className="error-container">
      <div className="error-message">{error}</div>
      <button onClick={() => window.location.reload()} className="retry-button">
        Retry
      </button>
    </div>
  );

  return (
    <div className="network-graph">
      <h1>Network Communication Graph</h1>
      <div className="graph-info">
        <p>This graph shows the communication patterns between IP addresses in the captured packets.</p>
        <p><span className="legend internal">●</span> Internal IPs &nbsp; <span className="legend external">●</span> External IPs</p>
      </div>
      
      <div className="graph-container-wrapper" style={{position: 'relative'}}>
        <div ref={containerRef} className="graph-container">
          {graph && renderer && (
            <div className="zoom-controls">
              <button onClick={() => renderer.getCamera().animatedZoom({ duration: 600 })}>+</button>
              <button onClick={() => renderer.getCamera().animatedUnzoom({ duration: 600 })}>-</button>
              <button onClick={() => {
                renderer.getCamera().animate({ x: 0.5, y: 0.5, ratio: 1, angle: 0 }, { duration: 600 });
              }}>⟳</button>
            </div>
          )}
        </div>
        
        {/* Render tooltip only when a node is hovered */}
        {hoveredNode && (
          <NodeTooltip 
            node={hoveredNode}
            position={tooltipPosition}
          />
        )}
      </div>
    </div>
  );
};

export default NetworkGraph;