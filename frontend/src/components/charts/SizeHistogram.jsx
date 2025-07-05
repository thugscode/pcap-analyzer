import React, { useRef, useEffect, useMemo } from 'react';
import * as d3 from 'd3';
import './SizeHistogram.css';

const SizeHistogram = ({ data, width = 600, height = 400 }) => {
  const svgRef = useRef(null);
  
  // Use useMemo for margin to avoid unnecessary recalculations
  const margin = useMemo(() => ({ top: 20, right: 30, bottom: 40, left: 50 }), []);
  
  // Calculate inner dimensions with useMemo
  const dimensions = useMemo(() => {
    return {
      innerWidth: width - margin.left - margin.right,
      innerHeight: height - margin.top - margin.bottom
    };
  }, [width, height, margin.left, margin.right, margin.top, margin.bottom]);

  useEffect(() => {
    if (!data || !data.length) return;

    const { innerWidth, innerHeight } = dimensions;

    // Clear any existing SVG content
    d3.select(svgRef.current).selectAll('*').remove();
    
    // Create the SVG container
    const svg = d3.select(svgRef.current)
      .attr('width', width)
      .attr('height', height);
      
    // Create a group element for the chart
    const chart = svg.append('g')
      .attr('transform', `translate(${margin.left}, ${margin.top})`);
    
    // Create X scale
    const x = d3.scaleBand()
      .domain(data.map(d => d.size))
      .range([0, innerWidth])
      .padding(0.1);
    
    // Create Y scale
    const y = d3.scaleLinear()
      .domain([0, d3.max(data, d => d.count)])
      .nice()
      .range([innerHeight, 0]);
    
    // Add X axis
    chart.append('g')
      .attr('transform', `translate(0, ${innerHeight})`)
      .call(d3.axisBottom(x))
      .selectAll('text')
        .style('text-anchor', 'end')
        .attr('dx', '-.8em')
        .attr('dy', '.15em')
        .attr('transform', 'rotate(-45)');
    
    // Add Y axis
    chart.append('g')
      .call(d3.axisLeft(y));
    
    // Add bars
    chart.selectAll('rect')
      .data(data)
      .join('rect')
        .attr('x', d => x(d.size))
        .attr('y', d => y(d.count))
        .attr('width', x.bandwidth())
        .attr('height', d => innerHeight - y(d.count))
        .attr('fill', '#4CAF50');
    
    // Add X axis label
    chart.append('text')
      .attr('x', innerWidth / 2)
      .attr('y', innerHeight + margin.bottom - 5)
      .style('text-anchor', 'middle')
      .text('Packet Size (bytes)');
    
    // Add Y axis label
    chart.append('text')
      .attr('transform', 'rotate(-90)')
      .attr('x', -innerHeight / 2)
      .attr('y', -margin.left + 15)
      .style('text-anchor', 'middle')
      .text('Count');
      
  }, [data, width, height, margin.top, margin.right, margin.bottom, margin.left, dimensions]);

  return (
    <div className="size-histogram">
      <svg ref={svgRef}></svg>
    </div>
  );
};

export default SizeHistogram;