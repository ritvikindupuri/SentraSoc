import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, 
  PieChart, Pie, Cell, BarChart, Bar, AreaChart, Area, RadialBarChart, RadialBar,
  ScatterChart, Scatter, Treemap
} from 'recharts';
import './App.css';

const SEVERITY_COLORS = {
  'CRITICAL': '#dc2626',
  'HIGH': '#ea580c', 
  'MEDIUM': '#d97706',
  'LOW': '#65a30d',
  'INFO': '#0891b2'
};

const CATEGORY_COLORS = ['#3b82f6', '#8b5cf6', '#06b6d4', '#10b981', '#f59e0b', '#ef4444'];

function App() {
  const [threats, setThreats] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [connections, setConnections] = useState([]);
  const [activeTab, setActiveTab] = useState('overview');
  const [stats, setStats] = useState({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    resolved: 0
  });
  const [timeRange, setTimeRange] = useState('24h');
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchThreats = async () => {
      try {
        const apiUrl = process.env.REACT_APP_API_URL || '/api';
        const response = await axios.get(`${apiUrl}/events`);
        setThreats(response.data);
        
        // Calculate stats
        const total = response.data.length;
        const high = response.data.filter(t => t.severity === 'HIGH').length;
        const medium = response.data.filter(t => t.severity === 'MEDIUM').length;
        const low = response.data.filter(t => t.severity === 'LOW').length;
        
        setStats({ total, high, medium, low });
      } catch (error) {
        console.error('Error fetching threats:', error);
      }
    };

    fetchThreats();
    const interval = setInterval(fetchThreats, 5000); // Refresh every 5 seconds
    
    return () => clearInterval(interval);
  }, []);

  const severityData = [
    { name: 'High', value: stats.high, color: '#ff6b6b' },
    { name: 'Medium', value: stats.medium, color: '#feca57' },
    { name: 'Low', value: stats.low, color: '#48dbfb' }
  ];

  const timelineData = threats.slice(-20).map((threat, index) => ({
    time: new Date(threat.timestamp).toLocaleTimeString(),
    threats: index + 1
  }));

  return (
    <div className="App">
      <header className="header">
        <div className="header-left">
          <div className="logo">
            <span className="logo-icon">🛡️</span>
            <h1>CyberGuard SOC</h1>
          </div>
          <div className="status-indicator">
            <span className="status-dot active"></span>
            <span>All Systems Operational</span>
          </div>
        </div>
        <div className="header-right">
          <div className="time-range-selector">
            <select value={timeRange} onChange={(e) => setTimeRange(e.target.value)}>
              <option value="1h">Last Hour</option>
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>
          </div>
          <div className="user-info">
            <span>Security Analyst</span>
            <div className="avatar">SA</div>
          </div>
        </div>
      </header>

      <nav className="nav-tabs">
        <button 
          className={`nav-tab ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          Overview
        </button>
        <button 
          className={`nav-tab ${activeTab === 'threats' ? 'active' : ''}`}
          onClick={() => setActiveTab('threats')}
        >
          Threat Detection
        </button>
        <button 
          className={`nav-tab ${activeTab === 'vulnerabilities' ? 'active' : ''}`}
          onClick={() => setActiveTab('vulnerabilities')}
        >
          Vulnerabilities
        </button>
        <button 
          className={`nav-tab ${activeTab === 'network' ? 'active' : ''}`}
          onClick={() => setActiveTab('network')}
        >
          Network Security
        </button>
        <button 
          className={`nav-tab ${activeTab === 'compliance' ? 'active' : ''}`}
          onClick={() => setActiveTab('compliance')}
        >
          Compliance
        </button>
      </nav>

      <main className="main-content">
        {activeTab === 'overview' && (
          <div className="overview-tab">
            <div className="kpi-grid">
              <div className="kpi-card critical">
                <div className="kpi-header">
                  <h3>Critical Threats</h3>
                  <span className="kpi-icon">🚨</span>
                </div>
                <div className="kpi-value">{stats.critical}</div>
                <div className="kpi-change">+2 from yesterday</div>
              </div>
              <div className="kpi-card high">
                <div className="kpi-header">
                  <h3>High Priority</h3>
                  <span className="kpi-icon">⚠️</span>
                </div>
                <div className="kpi-value">{stats.high}</div>
                <div className="kpi-change">-1 from yesterday</div>
              </div>
              <div className="kpi-card medium">
                <div className="kpi-header">
                  <h3>Medium Priority</h3>
                  <span className="kpi-icon">📊</span>
                </div>
                <div className="kpi-value">{stats.medium}</div>
                <div className="kpi-change">+5 from yesterday</div>
              </div>
              <div className="kpi-card resolved">
                <div className="kpi-header">
                  <h3>Resolved Today</h3>
                  <span className="kpi-icon">✅</span>
                </div>
                <div className="kpi-value">{stats.resolved}</div>
                <div className="kpi-change">+12 from yesterday</div>
              </div>
            </div>

            <div className="charts-grid">
              <div className="chart-card">
                <div className="chart-header">
                  <h3>Threat Timeline (24h)</h3>
                  <div className="chart-controls">
                    <button className="chart-btn active">Hourly</button>
                    <button className="chart-btn">Daily</button>
                  </div>
                </div>
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart data={timelineData}>
                    <defs>
                      <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.8}/>
                        <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.1}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis dataKey="time" stroke="#64748b" />
                    <YAxis stroke="#64748b" />
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: '#1e293b', 
                        border: '1px solid #334155',
                        borderRadius: '8px'
                      }} 
                    />
                    <Area 
                      type="monotone" 
                      dataKey="threats" 
                      stroke="#3b82f6" 
                      fillOpacity={1} 
                      fill="url(#colorThreats)" 
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>

              <div className="chart-card">
                <div className="chart-header">
                  <h3>Threat Categories</h3>
                </div>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={severityData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={100}
                      paddingAngle={5}
                      dataKey="value"
                    >
                      {severityData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[entry.name] || '#64748b'} />
                      ))}
                    </Pie>
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: '#1e293b', 
                        border: '1px solid #334155',
                        borderRadius: '8px'
                      }} 
                    />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="recent-alerts">
              <div className="section-header">
                <h3>Recent Security Alerts</h3>
                <button className="view-all-btn">View All</button>
              </div>
              <div className="alerts-list">
                {threats.slice(-5).reverse().map((threat, index) => (
                  <div key={index} className={`alert-item severity-${threat.severity?.toLowerCase()}`}>
                    <div className="alert-icon">
                      {threat.severity === 'CRITICAL' && '🚨'}
                      {threat.severity === 'HIGH' && '⚠️'}
                      {threat.severity === 'MEDIUM' && '📊'}
                      {threat.severity === 'LOW' && 'ℹ️'}
                    </div>
                    <div className="alert-content">
                      <div className="alert-title">{threat.title || threat.description}</div>
                      <div className="alert-meta">
                        <span className="alert-source">{threat.source}</span>
                        <span className="alert-time">{new Date(threat.timestamp).toLocaleTimeString()}</span>
                        {threat.mitre_attack && <span className="alert-mitre">MITRE: {threat.mitre_attack}</span>}
                      </div>
                    </div>
                    <div className="alert-actions">
                      <button className="action-btn investigate">Investigate</button>
                      <button className="action-btn dismiss">Dismiss</button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'threats' && (
          <div className="threats-tab">
            <div className="section-header">
              <h2>Active Threat Detection</h2>
              <div className="filters">
                <select>
                  <option>All Severities</option>
                  <option>Critical</option>
                  <option>High</option>
                  <option>Medium</option>
                  <option>Low</option>
                </select>
                <select>
                  <option>All Sources</option>
                  <option>Network Monitor</option>
                  <option>Vulnerability Scanner</option>
                  <option>Log Analyzer</option>
                </select>
              </div>
            </div>
            
            <div className="threats-table-container">
              <table className="threats-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Timestamp</th>
                    <th>Severity</th>
                    <th>Category</th>
                    <th>Title</th>
                    <th>MITRE ATT&CK</th>
                    <th>Risk Score</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {threats.slice(-15).reverse().map((threat, index) => (
                    <tr key={index} className={`threat-row severity-${threat.severity?.toLowerCase()}`}>
                      <td className="threat-id">{threat.id || `T-${index}`}</td>
                      <td className="threat-time">{new Date(threat.timestamp).toLocaleString()}</td>
                      <td>
                        <span className={`severity-badge ${threat.severity?.toLowerCase()}`}>
                          {threat.severity}
                        </span>
                      </td>
                      <td className="threat-category">{threat.category || 'General'}</td>
                      <td className="threat-title">{threat.title || threat.description}</td>
                      <td className="threat-mitre">{threat.mitre_attack || '-'}</td>
                      <td className="threat-score">{threat.risk_score?.toFixed(1) || '0.0'}</td>
                      <td>
                        <span className={`status-badge ${threat.status?.toLowerCase() || 'open'}`}>
                          {threat.status || 'OPEN'}
                        </span>
                      </td>
                      <td className="threat-actions">
                        <button className="action-btn small">View</button>
                        <button className="action-btn small">Assign</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;