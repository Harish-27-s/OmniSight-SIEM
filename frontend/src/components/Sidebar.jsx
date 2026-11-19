import React from 'react'

const ITEMS = [
  { id: 'stream', label: 'Live Stream', icon: '☰' },
  { id: 'incidents', label: 'Incident Queue', icon: '⚡' },
  { id: 'nodes', label: 'Lab Nodes', icon: '▣' },
]

export default function Sidebar({ view, setView }) {
  return (
    <nav className="sidebar">
      <div className="sidebar-section">
        <div className="sidebar-label">Views</div>
        {ITEMS.map((item) => (
          <button
            key={item.id}
            className={`nav-item ${view === item.id ? 'active' : ''}`}
            onClick={() => setView(item.id)}
          >
            <span style={{ width: 16, textAlign: 'center', opacity: 0.7 }}>{item.icon}</span>
            {item.label}
          </button>
        ))}
      </div>
      <div className="sidebar-section">
        <div className="sidebar-label">Quick Filters</div>
        <button className="nav-item" onClick={() => setView('stream')}>
          Auth Failures
        </button>
        <button className="nav-item" onClick={() => setView('stream')}>
          FIM Events
        </button>
        <button className="nav-item" onClick={() => setView('incidents')}>
          Open Alerts
        </button>
      </div>
    </nav>
  )
}
