import React, { useState } from 'react'

const COMMANDS = [
  { id: 'whoami', label: 'whoami' },
  { id: 'uptime', label: 'uptime' },
  { id: 'hostname', label: 'hostname' },
  { id: 'df', label: 'disk free' },
  { id: 'free', label: 'memory' },
  { id: 'ps_top', label: 'top procs' },
  { id: 'netstat', label: 'listeners' },
  { id: 'echo_test', label: 'ping agent' },
  { id: 'lock_session', label: 'lock session' },
]

export default function NodeManager({ nodes, onCommand }) {
  const [selected, setSelected] = useState(null)

  return (
    <>
      <div className="view-header">
        <h1>Lab Node Manager</h1>
        <div className="actions">
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            {nodes.filter((n) => n.status === 'online').length} online / {nodes.length} total
          </span>
        </div>
      </div>
      <div className="view-body" style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: 16 }}>
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th>Node ID</th>
                <th>Hostname</th>
                <th>IP</th>
                <th>Platform</th>
                <th>Status</th>
                <th>Last Seen</th>
                <th>Agent</th>
              </tr>
            </thead>
            <tbody>
              {nodes.length === 0 && (
                <tr>
                  <td colSpan={7}>
                    <div className="empty-state">
                      No nodes registered. Start an edge agent to populate.
                    </div>
                  </td>
                </tr>
              )}
              {nodes.map((n) => (
                <tr
                  key={n.node_id}
                  onClick={() => setSelected(n)}
                  style={{
                    cursor: 'pointer',
                    background: selected?.node_id === n.node_id ? 'var(--bg-hover)' : undefined,
                  }}
                >
                  <td className="mono">{n.node_id}</td>
                  <td>{n.hostname}</td>
                  <td className="mono">{n.ip || '—'}</td>
                  <td style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                    {(n.platform || '—').slice(0, 28)}
                  </td>
                  <td>
                    <span className={`badge badge-${n.status}`}>{n.status}</span>
                  </td>
                  <td className="mono" style={{ whiteSpace: 'nowrap' }}>
                    {n.last_seen ? n.last_seen.replace('T', ' ').slice(0, 19) : '—'}
                  </td>
                  <td className="mono">{n.agent_version || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="panel">
          <div className="panel-title">Remote Control</div>
          {selected ? (
            <>
              <div style={{ marginBottom: 8 }}>
                <strong className="mono">{selected.node_id}</strong>
                <div style={{ color: 'var(--text-muted)', fontSize: 11, marginTop: 2 }}>
                  {selected.hostname} · {selected.ip}
                </div>
              </div>
              <div className="cmd-grid">
                {COMMANDS.map((c) => (
                  <button
                    key={c.id}
                    className="btn btn-ghost btn-sm"
                    onClick={() => onCommand(selected.node_id, c.id)}
                    disabled={selected.status === 'offline'}
                  >
                    {c.label}
                  </button>
                ))}
              </div>
              <div style={{ marginTop: 14, fontSize: 11, color: 'var(--text-muted)' }}>
                Commands are HMAC-signed and executed only if the agent is online.
                Destructive actions (block_ip, disable_user, kill_process) are demo-safe.
              </div>
            </>
          ) : (
            <p style={{ color: 'var(--text-muted)', fontSize: 12 }}>
              Select a node to dispatch remote diagnostic or remediation commands.
            </p>
          )}
        </div>
      </div>
    </>
  )
}
