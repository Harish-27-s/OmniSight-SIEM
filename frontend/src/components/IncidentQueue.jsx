import React from 'react'

function riskColor(score) {
  if (score >= 80) return 'var(--critical)'
  if (score >= 60) return 'var(--danger)'
  if (score >= 40) return 'var(--warning)'
  return 'var(--success)'
}

export default function IncidentQueue({ alerts, onReport, onRemediate }) {
  return (
    <>
      <div className="view-header">
        <h1>Incident Triage Queue</h1>
        <div className="actions">
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            {alerts.filter((a) => a.status === 'open').length} open
          </span>
        </div>
      </div>
      <div className="view-body">
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th>Created</th>
                <th>Severity</th>
                <th>Risk</th>
                <th>Title</th>
                <th>Node</th>
                <th>Rule</th>
                <th>Status</th>
                <th>AI Brief</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {alerts.length === 0 && (
                <tr>
                  <td colSpan={9}>
                    <div className="empty-state">No alerts. Seed demo data or wait for detections.</div>
                  </td>
                </tr>
              )}
              {alerts.map((a) => (
                <tr key={a.alert_id}>
                  <td className="mono" style={{ whiteSpace: 'nowrap' }}>
                    {a.created_at ? a.created_at.replace('T', ' ').slice(0, 19) : '—'}
                  </td>
                  <td>
                    <span className={`badge badge-${a.severity}`}>{a.severity}</span>
                  </td>
                  <td>
                    <div className="risk-bar">
                      <div className="track">
                        <div
                          className="fill"
                          style={{
                            width: `${Math.min(100, a.risk_score || 0)}%`,
                            background: riskColor(a.risk_score || 0),
                          }}
                        />
                      </div>
                      <span className="val">{Math.round(a.risk_score || 0)}</span>
                    </div>
                  </td>
                  <td style={{ maxWidth: 220, fontWeight: 500 }}>{a.title}</td>
                  <td className="mono">{a.node_id}</td>
                  <td className="mono">{a.rule_name}</td>
                  <td>
                    <span className={`badge badge-${a.status}`}>{a.status}</span>
                  </td>
                  <td
                    style={{
                      maxWidth: 260,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                      color: 'var(--text-secondary)',
                      fontSize: 11,
                    }}
                    title={a.ai_brief}
                  >
                    {a.ai_brief || '—'}
                  </td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    <button className="btn btn-ghost btn-sm" onClick={() => onReport(a)}>
                      PDF
                    </button>{' '}
                    <button
                      className="btn btn-danger btn-sm"
                      onClick={() => onRemediate(a)}
                      title="Dispatch remediation command"
                    >
                      Remediate
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}
