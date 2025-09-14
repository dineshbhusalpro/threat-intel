/**
 * Network Visualization for Threat Intelligence Graph
 * Uses D3.js for interactive force-directed graph rendering
 */

let simulation = null;
let svg = null;
let g = null;
let currentData = null;

// Color scheme for different node types
const nodeColors = {
    'Indicator': '#3B82F6',  // Blue
    'Document': '#10B981',   // Green
    'Campaign': '#F59E0B',   // Yellow
    'ThreatActor': '#EF4444', // Red
    'domain': '#8B5CF6',     // Purple
    'ip_address': '#EC4899', // Pink
    'email': '#14B8A6',      // Teal
    'url': '#F97316',        // Orange
    'default': '#6B7280'     // Gray
};

// Initialize the network graph
function initializeNetworkGraph() {
    const container = d3.select('#network-graph');
    const width = container.node().getBoundingClientRect().width;
    const height = 500;

    // Clear any existing graph
    container.selectAll('*').remove();

    // Create SVG
    svg = container.append('svg')
        .attr('width', width)
        .attr('height', height)
        .style('background', '#111827');

    // Create container for zoom
    g = svg.append('g');

    // Add zoom behavior
    const zoom = d3.zoom()
        .scaleExtent([0.1, 4])
        .on('zoom', (event) => {
            g.attr('transform', event.transform);
        });

    svg.call(zoom);

    // Add arrow markers for directed edges
    svg.append('defs').selectAll('marker')
        .data(['MENTIONED_IN', 'RELATED_TO', 'PART_OF', 'ATTRIBUTED_TO'])
        .enter().append('marker')
        .attr('id', d => `arrow-${d}`)
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 20)
        .attr('refY', 0)
        .attr('markerWidth', 6)
        .attr('markerHeight', 6)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-5L10,0L0,5')
        .attr('fill', '#6B7280');

    // Initialize simulation
    simulation = d3.forceSimulation()
        .force('link', d3.forceLink().id(d => d.id).distance(100))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(30));

    // Load initial empty graph
    updateGraph({ nodes: [], edges: [] });
}

// Load network graph for a specific node
async function loadNetworkGraph() {
    const nodeId = document.getElementById('node-input').value;
    if (!nodeId) {
        alert('Please enter a node ID');
        return;
    }

    try {
        const response = await fetch(`${API_URL}/network/${nodeId}?max_hops=2&limit=50`);
        const data = await response.json();
        
        if (data.graph) {
            currentData = data.graph;
            updateGraph(data.graph);
        }
    } catch (error) {
        console.error('Error loading network graph:', error);
        alert('Error loading network graph');
    }
}

// Update the graph with new data
function updateGraph(data) {
    if (!svg || !g) {
        initializeNetworkGraph();
        return;
    }

    const width = svg.node().getBoundingClientRect().width;
    const height = 500;

    // Clear existing elements
    g.selectAll('.link').remove();
    g.selectAll('.node').remove();

    if (!data.nodes || data.nodes.length === 0) {
        // Show empty state
        g.append('text')
            .attr('x', width / 2)
            .attr('y', height / 2)
            .attr('text-anchor', 'middle')
            .attr('fill', '#6B7280')
            .text('No data to display. Enter a node ID and click "Load Graph"');
        return;
    }

    // Create links
    const link = g.append('g')
        .attr('class', 'links')
        .selectAll('line')
        .data(data.edges || [])
        .enter().append('line')
        .attr('class', 'link')
        .attr('stroke', '#4B5563')
        .attr('stroke-width', d => d.weight || 1)
        .attr('marker-end', d => `url(#arrow-${d.type || 'default'})`);

    // Create node groups
    const node = g.append('g')
        .attr('class', 'nodes')
        .selectAll('g')
        .data(data.nodes)
        .enter().append('g')
        .attr('class', 'node')
        .call(d3.drag()
            .on('start', dragstarted)
            .on('drag', dragged)
            .on('end', dragended));

    // Add circles for nodes
    node.append('circle')
        .attr('r', d => {
            if (d.label === 'Campaign' || d.label === 'ThreatActor') return 15;
            if (d.label === 'Document') return 12;
            return 10;
        })
        .attr('fill', d => nodeColors[d.label] || nodeColors[d.properties?.type] || nodeColors.default)
        .attr('stroke', '#1F2937')
        .attr('stroke-width', 2)
        .on('mouseover', handleMouseOver)
        .on('mouseout', handleMouseOut)
        .on('click', handleNodeClick);

    // Add labels
    node.append('text')
        .text(d => {
            if (d.properties?.value) {
                return d.properties.value.length > 20 
                    ? d.properties.value.substring(0, 20) + '...' 
                    : d.properties.value;
            }
            return d.id.substring(0, 20);
        })
        .attr('x', 0)
        .attr('y', -15)
        .attr('text-anchor', 'middle')
        .attr('fill', '#E5E7EB')
        .style('font-size', '10px')
        .style('pointer-events', 'none');

    // Update simulation
    simulation.nodes(data.nodes);
    simulation.force('link').links(data.edges || []);
    simulation.alpha(1).restart();

    // Update positions on each tick
    simulation.on('tick', () => {
        link
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);

        node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    // Add legend
    addLegend();
}

// Add legend to the graph
function addLegend() {
    const legendData = [
        { label: 'Indicator', color: nodeColors.Indicator },
        { label: 'Document', color: nodeColors.Document },
        { label: 'Campaign', color: nodeColors.Campaign },
        { label: 'Threat Actor', color: nodeColors.ThreatActor }
    ];

    const legend = svg.append('g')
        .attr('class', 'legend')
        .attr('transform', 'translate(20, 20)');

    const legendItems = legend.selectAll('.legend-item')
        .data(legendData)
        .enter().append('g')
        .attr('class', 'legend-item')
        .attr('transform', (d, i) => `translate(0, ${i * 25})`);

    legendItems.append('circle')
        .attr('r', 6)
        .attr('fill', d => d.color);

    legendItems.append('text')
        .attr('x', 15)
        .attr('y', 4)
        .text(d => d.label)
        .style('font-size', '12px')
        .attr('fill', '#9CA3AF');
}

// Drag functions
function dragstarted(event, d) {
    if (!event.active) simulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
}

function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
}

function dragended(event, d) {
    if (!event.active) simulation.alphaTarget(0);
    d.fx = null;
    d.fy = null;
}

// Mouse interaction handlers
function handleMouseOver(event, d) {
    // Highlight connected nodes
    const connectedNodes = new Set();
    
    if (currentData && currentData.edges) {
        currentData.edges.forEach(edge => {
            if (edge.source.id === d.id || edge.source === d.id) {
                connectedNodes.add(edge.target.id || edge.target);
            }
            if (edge.target.id === d.id || edge.target === d.id) {
                connectedNodes.add(edge.source.id || edge.source);
            }
        });
    }

    // Dim non-connected nodes
    d3.selectAll('.node circle')
        .style('opacity', node => {
            if (node.id === d.id) return 1;
            return connectedNodes.has(node.id) ? 0.8 : 0.3;
        });

    // Show tooltip
    const tooltip = d3.select('body').append('div')
        .attr('class', 'tooltip')
        .style('position', 'absolute')
        .style('padding', '10px')
        .style('background', 'rgba(0, 0, 0, 0.8)')
        .style('color', 'white')
        .style('border-radius', '5px')
        .style('pointer-events', 'none')
        .style('font-size', '12px');

    tooltip.html(`
        <strong>${d.label}</strong><br/>
        ID: ${d.id}<br/>
        ${d.properties ? Object.entries(d.properties)
            .filter(([key]) => key !== 'metadata')
            .map(([key, value]) => `${key}: ${value}`)
            .join('<br/>') : ''}
    `)
        .style('left', (event.pageX + 10) + 'px')
        .style('top', (event.pageY - 10) + 'px');
}

function handleMouseOut(event, d) {
    // Reset opacity
    d3.selectAll('.node circle').style('opacity', 1);
    
    // Remove tooltip
    d3.selectAll('.tooltip').remove();
}

function handleNodeClick(event, d) {
    // Load context for clicked node
    if (d.label === 'Indicator' && d.id) {
        loadIndicatorContext(d.id);
    } else {
        // For other node types, load their network
        document.getElementById('node-input').value = d.id;
        loadNetworkGraph();
    }
}

// Load indicator context
async function loadIndicatorContext(indicatorId) {
    try {
        const response = await fetch(`${API_URL}/context/${indicatorId}`);
        const data = await response.json();
        
        // Show in modal
        const modal = document.getElementById('indicator-modal');
        const content = document.getElementById('modal-content');
        
        content.innerHTML = `
            <div class="space-y-4">
                <div>
                    <h4 class="text-lg font-semibold text-blue-400">Indicator Details</h4>
                    <pre class="text-xs bg-gray-900 p-2 rounded mt-2">${JSON.stringify(data.indicator, null, 2)}</pre>
                </div>
                
                ${data.documents && data.documents.length > 0 ? `
                <div>
                    <h4 class="text-lg font-semibold text-green-400">Related Documents</h4>
                    <div class="space-y-2 mt-2">
                        ${data.documents.map(doc => `
                            <div class="bg-gray-900 p-2 rounded">
                                <p class="text-sm font-semibold">${doc.title}</p>
                                <p class="text-xs text-gray-400">${doc.source}</p>
                            </div>
                        `).join('')}
                    </div>
                </div>
                ` : ''}
                
                ${data.campaigns && data.campaigns.length > 0 ? `
                <div>
                    <h4 class="text-lg font-semibold text-yellow-400">Associated Campaigns</h4>
                    <div class="space-y-2 mt-2">
                        ${data.campaigns.map(campaign => `
                            <div class="bg-gray-900 p-2 rounded">
                                <p class="text-sm font-semibold">${campaign.name || campaign.campaign}</p>
                                <p class="text-xs text-gray-400">${campaign.description || ''}</p>
                            </div>
                        `).join('')}
                    </div>
                </div>
                ` : ''}
            </div>
        `;
        
        modal.classList.remove('hidden');
        modal.classList.add('flex');
        
    } catch (error) {
        console.error('Error loading indicator context:', error);
    }
}

// Load indicator distribution chart
async function loadIndicatorDistribution() {
    try {
        const response = await fetch(`${API_URL}/statistics`);
        const data = await response.json();
        
        if (data.relational_database?.indicator_types) {
            drawIndicatorChart(data.relational_database.indicator_types);
        }
    } catch (error) {
        console.error('Error loading indicator distribution:', error);
    }
}

// Draw indicator distribution chart
function drawIndicatorChart(data) {
    const container = d3.select('#indicator-chart');
    const width = container.node().getBoundingClientRect().width;
    const height = 300;
    const margin = { top: 20, right: 20, bottom: 40, left: 60 };

    container.selectAll('*').remove();

    const svg = container.append('svg')
        .attr('width', width)
        .attr('height', height);

    const chartData = Object.entries(data).map(([type, count]) => ({ type, count }));
    
    const x = d3.scaleBand()
        .domain(chartData.map(d => d.type))
        .range([margin.left, width - margin.right])
        .padding(0.1);

    const y = d3.scaleLinear()
        .domain([0, d3.max(chartData, d => d.count)])
        .nice()
        .range([height - margin.bottom, margin.top]);

    // Add bars
    svg.selectAll('.bar')
        .data(chartData)
        .enter().append('rect')
        .attr('class', 'bar')
        .attr('x', d => x(d.type))
        .attr('y', d => y(d.count) - 5)
        .attr('text-anchor', 'middle')
        .text(d => d.count)
        .attr('fill', '#E5E7EB')
        .style('font-size', '12px');
}(d.count)
        .attr('width', x.bandwidth())
        .attr('height', d => height - margin.bottom - y(d.count))
        .attr('fill', d => nodeColors[d.type] || nodeColors.default);

    // Add x-axis
    svg.append('g')
        .attr('transform', `translate(0,${height - margin.bottom})`)
        .call(d3.axisBottom(x))
        .selectAll('text')
        .attr('transform', 'rotate(-45)')
        .style('text-anchor', 'end')
        .attr('fill', '#9CA3AF');

    // Add y-axis
    svg.append('g')
        .attr('transform', `translate(${margin.left},0)`)
        .call(d3.axisLeft(y))
        .selectAll('text')
        .attr('fill', '#9CA3AF');

    // Add value labels on bars
    svg.selectAll('.label')
        .data(chartData)
        .enter().append('text')
        .attr('class', 'label')
        .attr('x', d => x(d.type) + x.bandwidth() / 2)
        .attr('y', d => y)