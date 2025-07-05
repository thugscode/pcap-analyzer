import React, { useEffect, useRef } from 'react';
import Sigma from 'sigma';

const NetworkGraph = ({ data }) => {
    const containerRef = useRef(null);

    useEffect(() => {
        if (data && containerRef.current) {
            const graph = {
                nodes: [],
                edges: []
            };

            const ipSet = new Set();

            data.forEach(packet => {
                const { src_ip, dst_ip } = packet;

                if (!ipSet.has(src_ip)) {
                    graph.nodes.push({ id: src_ip, label: src_ip, size: 1 });
                    ipSet.add(src_ip);
                }

                if (!ipSet.has(dst_ip)) {
                    graph.nodes.push({ id: dst_ip, label: dst_ip, size: 1 });
                    ipSet.add(dst_ip);
                }

                graph.edges.push({ id: `${src_ip}-${dst_ip}`, source: src_ip, target: dst_ip });
            });

            const sigmaInstance = new Sigma(graph, containerRef.current);

            return () => {
                sigmaInstance.kill();
            };
        }
    }, [data]);

    return <div ref={containerRef} style={{ width: '100%', height: '400px' }} />;
};

export default NetworkGraph;