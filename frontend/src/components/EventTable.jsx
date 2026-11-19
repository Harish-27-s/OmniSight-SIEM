import React, { useRef, useEffect } from 'react'

function severityBadge(s) {
  const cls = {
    critical: 'badge-critical',
    high: 'badge-high',
    medium: 'badge-medium',
    low: 'badge-low',
    info: 'badge-info',
  }[s] || 'badge-info'
  return <span className={`badge ${cls}`}>{s || 'info'}</span>
}

export default function EventTable({ events, filters, setFilters, nodes }) {
  const bodyRef = useRef(null)
  const autoScroll = useRef(true)

  useEffect(() => {
    if (autoScroll.current && bodyRef.current) {
      // Keep near top since we order desc
    }
  }, [events])

  return (
    <>
      <div className="view-header">
        <h1>Live Stream Viewer</h1>
        <div className="actions">
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            {events.length} events · auto-refresh 4s
          </span>
          <button className="btn btn-ghost btn-sm" onClick={() => window.location.reload()}>
            Refresh
          </button>
        </div>
      </div>
      <div className="view-body">
        <div className="filters">
          <select
            value={filters.event_type}
            onChange={(e) => setFilters({ ...filters, event_type: e.target.value })}
          >
            <option value="">All types</option>
            <option value="auth_failure">auth_failure</option>
            <option value="auth_success">auth_success</option>
            <option value="fim_change">fim_change</option>
            <option value="fim_create">fim_create</option>
            <option value="fim_delete">fim_delete</option>
            <option value="privilege_escalation">privilege_escalation</option>
            <option value="slow_query">slow_query</option>
            <option value="log">log</option>
          </select>
          <select
            value={filters.severity}
            onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
          >
            <option value="">All severities</option>
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
            <option value="info">info</option>
          </select>
          <select
            value={filters.node_id}
            onChange={(e) => setFilters({ ...filters, node_id: e.target.value })}
          >
            <option value="">All nodes</option>
            {nodes.map((n) => (
              <option key={n.node_id} value={n.node_id}>{n.node_id}</option>
            ))}
          </select>
        </div>

        <div className="table-wrap" ref={bodyRef} style={{ maxHeight: 'calc(100vh - 180px)', overflow: 'auto' }}>
          <table className="data">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Node</th>
                <th>Source</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Src IP</th>
                <th>User</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 && (
                <tr>
                  <td colSpan={8}>
                    <div className="empty-state">
                      No events yet. Start the agent or run the seed script.
                    </div>
                  </td>
                </tr>
              )}
              {events.map((e) => (
                <tr key={e.event_id || e.id}>
                  <td className="mono" style={{ whiteSpace: 'nowrap' }}>
                    {e.timestamp ? e.timestamp.replace('T', ' ').slice(0, 19) : '—'}
                  </td>
                  <td className="mono">{e.node_id}</td>
                  <td>{e.source}</td>
                  <td className="mono">{e.event_type}</td>
                  <td>{severityBadge(e.severity)}</td>
                  <td className="mono">{e.src_ip || '—'}</td>
                  <td>{e.user || '—'}</td>
                  <td className="raw-cell" title={e.raw}>{e.raw}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}
