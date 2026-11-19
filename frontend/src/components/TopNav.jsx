import React from 'react'

export default function TopNav({ health }) {
  const ok = health?.status === 'ok'
  return (
    <header className="topnav">
      <div className="topnav-brand">
        <div className="logo">OS</div>
        <span>Omnisight SIEM</span>
        <span style={{ color: 'var(--text-muted)', fontWeight: 400, fontSize: 12 }}>
          Command Center
        </span>
      </div>
      <div className="topnav-status">
        <span>
          Backend:{' '}
          <strong style={{ color: ok ? 'var(--success)' : 'var(--danger)' }}>
            {ok ? 'Operational' : health?.status || '—'}
          </strong>
        </span>
        <span>
          Agents:{' '}
          <strong style={{ color: 'var(--text-primary)' }}>
            {health?.connected_agents ?? 0}
          </strong>
        </span>
        <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span className="live-dot" /> Live
        </span>
      </div>
    </header>
  )
}
