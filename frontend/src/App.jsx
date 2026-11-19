import React, { useState, useEffect, useCallback } from 'react'
import TopNav from './components/TopNav'
import Sidebar from './components/Sidebar'
import EventTable from './components/EventTable'
import IncidentQueue from './components/IncidentQueue'
import NodeManager from './components/NodeManager'
import ReportModal from './components/ReportModal'

const API = '/api/v1'

export default function App() {
  const [view, setView] = useState('stream')
  const [events, setEvents] = useState([])
  const [alerts, setAlerts] = useState([])
  const [nodes, setNodes] = useState([])
  const [health, setHealth] = useState({ status: '…', connected_agents: 0 })
  const [reportAlert, setReportAlert] = useState(null)
  const [filters, setFilters] = useState({ event_type: '', severity: '', node_id: '' })

  const fetchEvents = useCallback(async () => {
    try {
      const params = new URLSearchParams({ limit: '150' })
      if (filters.event_type) params.set('event_type', filters.event_type)
      if (filters.severity) params.set('severity', filters.severity)
      if (filters.node_id) params.set('node_id', filters.node_id)
      const r = await fetch(`${API}/events?${params}`)
      if (r.ok) setEvents(await r.json())
    } catch (_) {}
  }, [filters])

  const fetchAlerts = useCallback(async () => {
    try {
      const r = await fetch(`${API}/alerts?limit=50`)
      if (r.ok) setAlerts(await r.json())
    } catch (_) {}
  }, [])

  const fetchNodes = useCallback(async () => {
    try {
      const r = await fetch(`${API}/nodes`)
      if (r.ok) setNodes(await r.json())
    } catch (_) {}
  }, [])

  const fetchHealth = useCallback(async () => {
    try {
      const r = await fetch(`${API}/health`)
      if (r.ok) setHealth(await r.json())
    } catch (_) {
      setHealth({ status: 'unreachable', connected_agents: 0 })
    }
  }, [])

  useEffect(() => {
    fetchEvents()
    fetchAlerts()
    fetchNodes()
    fetchHealth()
    const id = setInterval(() => {
      fetchEvents()
      fetchAlerts()
      fetchNodes()
      fetchHealth()
    }, 4000)
    return () => clearInterval(id)
  }, [fetchEvents, fetchAlerts, fetchNodes, fetchHealth])

  const sendCommand = async (nodeId, command, args = {}) => {
    try {
      const r = await fetch(`${API}/nodes/command`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ node_id: nodeId, command, args }),
      })
      const data = await r.json()
      if (!r.ok) throw new Error(data.detail || 'Command failed')
      alert(`Dispatched ${command} → ${nodeId}\nRequest: ${data.request_id}`)
    } catch (e) {
      alert(`Command error: ${e.message}`)
    }
  }

  return (
    <div className="app-shell">
      <TopNav health={health} />
      <Sidebar view={view} setView={setView} />
      <main className="main">
        {view === 'stream' && (
          <EventTable
            events={events}
            filters={filters}
            setFilters={setFilters}
            nodes={nodes}
          />
        )}
        {view === 'incidents' && (
          <IncidentQueue
            alerts={alerts}
            onReport={(a) => setReportAlert(a)}
            onRemediate={(a) => sendCommand(a.node_id, 'block_ip', { ip: '0.0.0.0' })}
          />
        )}
        {view === 'nodes' && (
          <NodeManager nodes={nodes} onCommand={sendCommand} />
        )}
      </main>
      {reportAlert && (
        <ReportModal alert={reportAlert} onClose={() => setReportAlert(null)} />
      )}
    </div>
  )
}
