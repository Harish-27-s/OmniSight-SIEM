import React from 'react'

export default function ReportModal({ alert, onClose }) {
  const pdfUrl = `/api/v1/reports/incident/${alert.alert_id}/pdf`
  const jsonUrl = `/api/v1/reports/incident/${alert.alert_id}/json`

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <button className="close" onClick={onClose}>×</button>
        <h2>Export Incident Report</h2>
        <p style={{ color: 'var(--text-secondary)', marginBottom: 14, fontSize: 12 }}>
          <strong>{alert.title}</strong>
          <br />
          Alert ID: <span className="mono">{alert.alert_id}</span> · Risk {Math.round(alert.risk_score || 0)}
        </p>
        {alert.ai_brief && (
          <div className="panel" style={{ marginBottom: 14, fontSize: 12, lineHeight: 1.5 }}>
            <div className="panel-title">AI Threat Brief</div>
            {alert.ai_brief}
          </div>
        )}
        <div style={{ display: 'flex', gap: 10 }}>
          <a href={pdfUrl} target="_blank" rel="noreferrer" className="btn btn-primary">
            Download PDF
          </a>
          <a href={jsonUrl} target="_blank" rel="noreferrer" className="btn btn-ghost">
            View JSON
          </a>
          <button className="btn btn-ghost" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
