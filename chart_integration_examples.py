"""
Chart Integration Examples
Demonstrates how to consume the API chart endpoints with different charting libraries
and frameworks.
"""

# ============================================================================
# 1. PYTHON - Using Matplotlib
# ============================================================================

def plot_cpu_timeline_matplotlib():
    """
    Example: Plot CPU timeline using matplotlib.
    
    Requires: pip install matplotlib requests
    """
    import matplotlib.pyplot as plt
    from datetime import datetime
    import requests
    from api_client import MonitoringAPIClient
    
    # Connect to API
    client = MonitoringAPIClient("http://localhost:5001")
    client.login("admin", "admin123")
    
    # Fetch CPU timeline
    response = requests.get(
        f"{client.api_url}/api/charts/cpu-timeline?hours=24",
        headers={"Authorization": f"Bearer {client.token}"}
    )
    data = response.json()['data']
    
    # Parse data
    timestamps = [datetime.fromisoformat(d['timestamp']) for d in data['timeline']]
    cpu_values = [d['system_cpu'] for d in data['timeline']]
    
    # Create plot
    plt.figure(figsize=(12, 5))
    plt.plot(timestamps, cpu_values, linewidth=2, color='#667eea')
    plt.fill_between(timestamps, cpu_values, alpha=0.3, color='#667eea')
    plt.title('CPU Usage Timeline (Last 24 Hours)', fontsize=14, fontweight='bold')
    plt.xlabel('Time')
    plt.ylabel('CPU Usage (%)')
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.show()


def plot_top_processes_matplotlib():
    """
    Example: Plot top processes by CPU using bar chart.
    
    Requires: pip install matplotlib requests
    """
    import matplotlib.pyplot as plt
    import requests
    from api_client import MonitoringAPIClient
    
    # Connect to API
    client = MonitoringAPIClient("http://localhost:5001")
    client.login("admin", "admin123")
    
    # Fetch top processes
    response = requests.get(
        f"{client.api_url}/api/charts/top-processes-cpu?hours=1&limit=10",
        headers={"Authorization": f"Bearer {client.token}"}
    )
    data = response.json()['data']
    
    # Parse data
    names = [p['name'] for p in data['processes']]
    cpu_values = [p['avg_cpu'] for p in data['processes']]
    
    # Create bar chart
    plt.figure(figsize=(10, 6))
    plt.barh(names, cpu_values, color='#667eea')
    plt.xlabel('Average CPU Usage (%)')
    plt.title('Top 10 Processes by CPU', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.show()


# ============================================================================
# 2. JAVASCRIPT/NODE.JS - Using Chart.js with Node
# ============================================================================

def generate_nodejs_chart_example():
    """
    Node.js example using node-canvas and chartjs
    
    Requires: npm install chart.js canvas node-fetch
    """
    code = '''
// nodejs_chart_example.js
const ChartJsImage = require('chartjs-to-image');

async function generateCPUChart() {
  const apiUrl = 'http://localhost:5001';
  const token = 'YOUR_JWT_TOKEN_HERE';
  
  // Fetch CPU data
  const response = await fetch(`${apiUrl}/api/charts/cpu-timeline?hours=24`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  const data = await response.json();
  
  // Create chart
  const chart = new ChartJsImage();
  chart.setChartJs({
    type: 'line',
    data: {
      labels: data.data.timeline.map(d => 
        new Date(d.timestamp).toLocaleTimeString()
      ),
      datasets: [{
        label: 'CPU Usage %',
        data: data.data.timeline.map(d => d.system_cpu),
        borderColor: '#667eea',
        backgroundColor: 'rgba(102, 126, 234, 0.1)',
        tension: 0.4,
        fill: true
      }]
    },
    options: {
      title: 'CPU Timeline',
      scales: {
        yAxes: [{ ticks: { beginAtZero: true, max: 100 } }]
      }
    }
  });
  
  // Save image
  const imageUrl = await chart.toFile('cpu_chart.png');
  console.log('Chart saved:', imageUrl);
}

generateCPUChart();
'''
    return code


# ============================================================================
# 3. REACT - Using Recharts (Component)
# ============================================================================

def generate_react_recharts_component():
    """
    React component using Recharts for chart visualization
    
    Requires: npm install recharts axios
    """
    code = '''
// CPUTimeline.jsx
import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import axios from 'axios';

export default function CPUTimeline() {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [hours, setHours] = useState(24);
  
  useEffect(() => {
    fetchCPUData();
    const interval = setInterval(fetchCPUData, 60000); // Refresh every minute
    return () => clearInterval(interval);
  }, [hours]);
  
  const fetchCPUData = async () => {
    try {
      setLoading(true);
      const response = await axios.get(
        `http://localhost:5001/api/charts/cpu-timeline?hours=${hours}`,
        {
          headers: { 'Authorization': `Bearer ${localStorage.getItem('apiToken')}` }
        }
      );
      
      // Format for Recharts
      const formatted = response.data.data.timeline.map(item => ({
        timestamp: new Date(item.timestamp).toLocaleTimeString(),
        cpu: item.system_cpu,
        processes: item.process_count
      }));
      
      setData(formatted);
    } catch (error) {
      console.error('Error fetching CPU data:', error);
    } finally {
      setLoading(false);
    }
  };
  
  if (loading) return <div>Loading...</div>;
  
  return (
    <div>
      <h2>CPU Usage Timeline</h2>
      <div>
        <label>Time Range:</label>
        <select value={hours} onChange={(e) => setHours(Number(e.target.value))}>
          <option value="1">Last 1 Hour</option>
          <option value="6">Last 6 Hours</option>
          <option value="24">Last 24 Hours</option>
        </select>
      </div>
      
      <ResponsiveContainer width="100%" height={400}>
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="timestamp" />
          <YAxis domain={[0, 100]} />
          <Tooltip />
          <Legend />
          <Line 
            type="monotone" 
            dataKey="cpu" 
            stroke="#667eea" 
            name="CPU %"
            connectNulls
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
'''
    return code


def generate_react_topprocesses_component():
    """
    React component for top processes bar chart with Recharts
    """
    code = '''
// TopProcesses.jsx
import React, { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import axios from 'axios';

export default function TopProcesses() {
  const [data, setData] = useState([]);
  const [metric, setMetric] = useState('cpu'); // 'cpu' or 'memory'
  
  useEffect(() => {
    fetchTopProcesses();
  }, [metric]);
  
  const fetchTopProcesses = async () => {
    try {
      const endpoint = metric === 'cpu' 
        ? '/api/charts/top-processes-cpu'
        : '/api/charts/top-processes-memory';
      
      const response = await axios.get(
        `http://localhost:5001${endpoint}?hours=24&limit=10`,
        {
          headers: { 'Authorization': `Bearer ${localStorage.getItem('apiToken')}` }
        }
      );
      
      // Format for Recharts
      const formatted = response.data.data.processes.map(p => ({
        name: p.name,
        value: metric === 'cpu' ? p.avg_cpu : p.avg_memory_mb
      }));
      
      setData(formatted);
    } catch (error) {
      console.error('Error fetching processes:', error);
    }
  };
  
  return (
    <div>
      <h2>Top Processes</h2>
      <div>
        <button onClick={() => setMetric('cpu')}>By CPU</button>
        <button onClick={() => setMetric('memory')}>By Memory</button>
      </div>
      
      <ResponsiveContainer width="100%" height={400}>
        <BarChart data={data} layout="vertical">
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis type="number" />
          <YAxis dataKey="name" type="category" width={100} />
          <Tooltip />
          <Bar 
            dataKey="value" 
            fill="#667eea"
            name={metric === 'cpu' ? 'Avg CPU %' : 'Avg Memory MB'}
          />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
'''
    return code


# ============================================================================
# 4. VUE.JS - Using Chart.js with Vue
# ============================================================================

def generate_vue_chart_component():
    """
    Vue.js component with Chart.js
    
    Requires: npm install vue-chartjs chart.js axios
    """
    code = '''
<!-- CPUChart.vue -->
<template>
  <div class="cpu-chart">
    <h2>CPU Usage Timeline</h2>
    <div class="controls">
      <label>Hours:</label>
      <select v-model="hours" @change="fetchData">
        <option value="1">1 Hour</option>
        <option value="6">6 Hours</option>
        <option value="24" selected>24 Hours</option>
      </select>
    </div>
    <line-chart :data="chartData" :options="chartOptions"></line-chart>
  </div>
</template>

<script>
import { Line as LineChart } from 'vue-chartjs';
import { Chart as ChartJS, registerables } from 'chart.js';
import axios from 'axios';

ChartJS.register(...registerables);

export default {
  components: { LineChart },
  data() {
    return {
      hours: 24,
      chartData: { labels: [], datasets: [] },
      chartOptions: {
        responsive: true,
        plugins: {
          title: { display: true, text: 'CPU Timeline' }
        },
        scales: {
          y: { beginAtZero: true, max: 100 }
        }
      }
    };
  },
  mounted() {
    this.fetchData();
  },
  methods: {
    async fetchData() {
      try {
        const response = await axios.get(
          `http://localhost:5001/api/charts/cpu-timeline?hours=${this.hours}`,
          {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('apiToken')}` }
          }
        );
        
        const timeline = response.data.data.timeline;
        this.chartData = {
          labels: timeline.map(d => new Date(d.timestamp).toLocaleTimeString()),
          datasets: [{
            label: 'CPU %',
            data: timeline.map(d => d.system_cpu),
            borderColor: '#667eea',
            backgroundColor: 'rgba(102, 126, 234, 0.1)',
            tension: 0.4,
            fill: true
          }]
        };
      } catch (error) {
        console.error('Error fetching data:', error);
      }
    }
  }
};
</script>

<style scoped>
.controls { margin: 20px 0; }
select { padding: 5px 10px; }
</style>
'''
    return code


# ============================================================================
# 5. PYTHON - Using Pandas and Plotly
# ============================================================================

def generate_plotly_example():
    """
    Python example using Plotly for interactive visualizations
    
    Requires: pip install plotly pandas requests
    """
    code = '''
import plotly.graph_objects as go
import pandas as pd
import requests
from api_client import MonitoringAPIClient
from datetime import datetime

def plot_metrics_dashboard():
    """Create interactive dashboard with multiple charts"""
    
    # Setup API client
    client = MonitoringAPIClient("http://localhost:5001")
    client.login("admin", "admin123")
    
    # Fetch all data
    headers = {"Authorization": f"Bearer {client.token}"}
    
    cpu_resp = requests.get(
        f"{client.api_url}/api/charts/cpu-timeline?hours=24",
        headers=headers
    )
    memory_resp = requests.get(
        f"{client.api_url}/api/charts/memory-timeline?hours=24",
        headers=headers
    )
    top_cpu_resp = requests.get(
        f"{client.api_url}/api/charts/top-processes-cpu?hours=24&limit=10",
        headers=headers
    )
    
    cpu_data = cpu_resp.json()['data']
    memory_data = memory_resp.json()['data']
    top_cpu = top_cpu_resp.json()['data']
    
    # Create subplots
    from plotly.subplots import make_subplots
    
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=('CPU Timeline', 'Memory Timeline', 'Top Processes', 'Memory Usage')
    )
    
    # CPU Timeline
    timestamps = [d['timestamp'] for d in cpu_data['timeline']]
    cpu_values = [d['system_cpu'] for d in cpu_data['timeline']]
    fig.add_trace(
        go.Scatter(x=timestamps, y=cpu_values, name='CPU %', 
                  line=dict(color='#667eea')),
        row=1, col=1
    )
    
    # Memory Timeline
    memory_values = [d['system_memory_percent'] for d in memory_data['timeline']]
    fig.add_trace(
        go.Scatter(x=timestamps, y=memory_values, name='Memory %',
                  fill='tozeroy', line=dict(color='#764ba2')),
        row=1, col=2
    )
    
    # Top Processes
    process_names = [p['name'] for p in top_cpu['processes']]
    process_cpu = [p['avg_cpu'] for p in top_cpu['processes']]
    fig.add_trace(
        go.Bar(y=process_names, x=process_cpu, name='CPU %',
              orientation='h'),
        row=2, col=1
    )
    
    # Update layout
    fig.update_layout(height=800, width=1200, showlegend=True)
    fig.show()

# Run the dashboard
plot_metrics_dashboard()
'''
    return code


# ============================================================================
# 6. CURL/REST API Examples
# ============================================================================

def print_curl_examples():
    """
    Examples of calling the chart API endpoints with curl
    """
    examples = '''
# ============================================================================
# REST API Chart Endpoint Examples
# ============================================================================

# 1. Get CPU Timeline (Last 24 hours)
curl -H "Authorization: Bearer YOUR_TOKEN" \\
  http://localhost:5001/api/charts/cpu-timeline?hours=24 | jq

# 2. Get Memory Timeline
curl -H "Authorization: Bearer YOUR_TOKEN" \\
  http://localhost:5001/api/charts/memory-timeline?hours=6 | jq

# 3. Get Top 10 Processes by CPU
curl -H "Authorization: Bearer YOUR_TOKEN" \\
  http://localhost:5001/api/charts/top-processes-cpu?hours=1&limit=10 | jq

# 4. Get Top 10 Processes by Memory
curl -H "Authorization: Bearer YOUR_TOKEN" \\
  http://localhost:5001/api/charts/top-processes-memory?hours=24&limit=5 | jq

# 5. Get CPU Timeline for Specific Process
curl -H "Authorization: Bearer YOUR_TOKEN" \\
  http://localhost:5001/api/charts/process-cpu/chrome.exe?hours=1 | jq

# 6. Get Memory Timeline for Specific Process
curl -H "Authorization: Bearer YOUR_TOKEN" \\
  http://localhost:5001/api/charts/process-memory/python.exe?hours=24 | jq

# 7. Get Summary Statistics
curl -H "Authorization: Bearer YOUR_TOKEN" \\
  http://localhost:5001/api/charts/metrics-summary?hours=24 | jq

# Complete Example: Login, Get Token, Fetch CPU Data
TOKEN=$(curl -X POST http://localhost:5001/api/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"username":"admin","password":"admin123"}' | jq -r '.data.token')

echo "Token: $TOKEN"

curl -H "Authorization: Bearer $TOKEN" \\
  http://localhost:5001/api/charts/cpu-timeline?hours=1 | jq '.data.timeline | .[] | {timestamp, cpu: .system_cpu}'
'''
    return examples


if __name__ == "__main__":
    # Print all examples
    print("=" * 70)
    print("CHART INTEGRATION EXAMPLES")
    print("=" * 70)
    print()
    
    print("1. MATPLOTLIB EXAMPLE")
    print("-" * 70)
    print("See: plot_cpu_timeline_matplotlib()")
    print("See: plot_top_processes_matplotlib()")
    print()
    
    print("2. NODE.JS / CHART.JS EXAMPLE")
    print("-" * 70)
    print(generate_nodejs_chart_example())
    print()
    
    print("3. REACT / RECHARTS EXAMPLES")
    print("-" * 70)
    print(generate_react_recharts_component())
    print()
    print(generate_react_topprocesses_component())
    print()
    
    print("4. VUE.JS EXAMPLE")
    print("-" * 70)
    print(generate_vue_chart_component())
    print()
    
    print("5. PYTHON / PLOTLY EXAMPLE")
    print("-" * 70)
    print(generate_plotly_example())
    print()
    
    print("6. CURL EXAMPLES")
    print("-" * 70)
    print(print_curl_examples())
