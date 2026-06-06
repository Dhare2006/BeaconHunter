import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

const API_URL = 'http://localhost:8000';

function App() {
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [beaconingIP, setBeaconingIP] = useState('');
  const [message, setMessage] = useState('');
const [message, setMessage] = useState('');

useEffect(() => {
  fetchData();
  const interval = setInterval(fetchData, 5000);
  return () => clearInterval(interval);
}, []);

const fetchData = async () => {
  try {
    const [statsRes, alertsRes, eventsRes] = await Promise.all([
      axios.get(`${API_URL}/stats`),
      axios.get(`${API_URL}/alerts?limit=50`),
      axios.get(`${API_URL}/events?limit=50`)
    ]);
    setStats(statsRes.data);
    setAlerts(alertsRes.data);
    setEvents(eventsRes.data);
    setLoading(false);
  } catch (error) {
    console.error('Error fetching data:', error);
    setMessage('⚠️ Backend not connected');
    setLoading(false);
  }
};

const handleRunDetection = async () => {
  try {
    setMessage('🔍 Running detection...');
    await axios.post(`${API_URL}/detect`);
    await fetchData();
    setMessage('✅ Detection complete!');
    setTimeout(() => setMessage(''), 3000);
  } catch (error) {
    console.error('Error running detection:', error);
    setMessage('❌ Error running detection');
  }
};


  const handleCreateBeaconing = async () => {
    if (!beaconingIP) {
      setMessage('⚠️ Please enter a destination IP');
      return;
    }
    
    const events = [];
    for (let i = 0; i < 8; i++) {
      events.push({
        source_ip: '192.168.1.100',
        destination_ip: beaconingIP,
        protocol: 'HTTPS',
        timestamp: new Date(Date.now() + i * 60000).toISOString(),
        bytes_sent: 1024,
        bytes_received: 2048,
        domain: 'evil-c2.com',
        user_agent: 'Mozilla/5.0'
      });
    }
    
    try {
      setMessage(`🎯 Creating ${events.length} beaconing events...`);
      await axios.post(`${API_URL}/events/batch`, events);
      await axios.post(`${API_URL}/detect`);
      await fetchData();
      setMessage('✅ Beaconing traffic detected! Check alerts below.');
      setBeaconingIP('');
      setTimeout(() => setMessage(''), 5000);
    } catch (error) {
      console.error('Error creating beaconing:', error);
      setMessage('❌ Error creating beaconing traffic');
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      Critical: '#ff4757',
      High: '#ff6b81',
      Medium: '#ffa502',
      Low: '#2ed573'
    };
    return colors[severity] || '#747d8c';
  };

  if (loading) {
    return (
      <div className="loading">
        <div className="spinner"></div>
        <h2>Connecting to BeaconHunter Backend...</h2>
        <p>Make sure the backend server is running on http://localhost:8000</p>
      </div>
    );
  }

  const filteredAlerts = selectedSeverity === 'all' 
    ? alerts 
    : alerts.filter(a => a.severity === selectedSeverity);

  return (
    <div className="app">
      <div className="header">
        <h1>🎯 BeaconHunter SOC Platform</h1>
        <p>Real-time C2 Beaconing Detection & Threat Intelligence</p>
        <div className="status-badge">
          <span className="status-dot"></span>
          System Operational | {new Date().toLocaleTimeString()}
        </div>
      </div>

      {message && (
        <div className="message-banner">
          {message}
        </div>
      )}

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon">📊</div>
          <div className="stat-info">
            <h3>Total Events</h3>
            <div className="stat-value">{stats?.total_events || 0}</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">🚨</div>
          <div className="stat-info">
            <h3>Total Alerts</h3>
            <div className="stat-value">{stats?.total_alerts || 0}</div>
          </div>
        </div>
        <div className="stat-card critical">
          <div className="stat-icon">⚠️</div>
          <div className="stat-info">
            <h3>Critical Alerts</h3>
            <div className="stat-value">{stats?.critical_alerts || 0}</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">🎯</div>
          <div className="stat-info">
            <h3>Beaconing Detections</h3>
            <div className="stat-value">{stats?.beaconing_detections || 0}</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">🌐</div>
          <div className="stat-info">
            <h3>Unique IPs</h3>
            <div className="stat-value">{stats?.unique_ips || 0}</div>
          </div>
        </div>
      </div>

      <div className="action-bar">
        <button className="btn-primary" onClick={handleRunDetection}>
          🔍 Run Detection Now
        </button>
        <button className="btn-secondary" onClick={fetchData}>
          🔄 Refresh Data
        </button>
      </div>

      <div className="beaconing-section">
        <h3>🎯 Create Test C2 Beaconing Traffic</h3>
        <div className="beaconing-form">
          <input
            type="text"
            placeholder="Destination IP (e.g., 45.67.23.11)"
            value={beaconingIP}
            onChange={(e) => setBeaconingIP(e.target.value)}
          />
          <button onClick={handleCreateBeaconing}>Generate Beaconing Traffic</button>
        </div>
        <small>⚠️ This creates simulated C2 beaconing patterns for testing</small>
      </div>

      <div className="alerts-section">
        <div className="section-header">
          <h2>🚨 Security Alerts</h2>
          <select 
            className="severity-filter"
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
          >
            <option value="all">All Severities</option>
            <option value="Critical">Critical Only</option>
            <option value="High">High Only</option>
            <option value="Medium">Medium Only</option>
          </select>
        </div>
        
        {filteredAlerts.length === 0 ? (
          <div className="no-alerts">
            <p>✅ No alerts detected. System is quiet.</p>
            <p>Click "Generate Beaconing Traffic" to test the detection engine.</p>
          </div>
        ) : (
          <div className="table-container">
            <table className="alerts-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Alert Type</th>
                  <th>Source IP</th>
                  <th>Destination IP</th>
                  <th>MITRE Technique</th>
                  <th>Confidence</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {filteredAlerts.map((alert, idx) => (
                  <tr key={idx}>
                    <td>
                      <span className="severity-badge" style={{backgroundColor: getSeverityColor(alert.severity)}}>
                        {alert.severity}
                      </span>
                    </td>
                    <td>{alert.alert_type}</td>
                    <td>{alert.source_ip}</td>
                    <td>{alert.destination_ip}</td>
                    <td><code>{alert.mitre_technique || 'N/A'}</code></td>
                    <td><span className="confidence-badge">{alert.confidence || 'Medium'}</span></td>
                    <td>{new Date(alert.timestamp).toLocaleTimeString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="events-section">
        <h2>📡 Recent Network Events</h2>
        {events.length === 0 ? (
          <div className="no-events">
            <p>No events yet. Generate some traffic to see data.</p>
          </div>
        ) : (
          <div className="table-container">
            <table className="events-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Source IP</th>
                  <th>Destination IP</th>
                  <th>Protocol</th>
                  <th>Domain</th>
                </tr>
              </thead>
              <tbody>
                {events.slice(0, 20).map((event, idx) => (
                  <tr key={idx}>
                    <td>{new Date(event.timestamp).toLocaleTimeString()}</td>
                    <td>{event.source_ip}</td>
                    <td>{event.destination_ip}</td>
                    <td><span className="protocol-badge">{event.protocol}</span></td>
                    <td>{event.domain || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

export default App; 
