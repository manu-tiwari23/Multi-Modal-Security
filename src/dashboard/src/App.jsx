import AccountView from './components/AccountView.jsx'
import ResponseView from './components/ResponseView.jsx'
import PhishingView from './components/PhishingView.jsx'
import ForensicsView from './components/ForensicsView.jsx'
import ReportsView from './components/ReportsView.jsx'
import { useState, useEffect, useRef, useCallback } from 'react'
import { apiFetch } from './api.js'
import IntelligenceView from './components/IntelligenceView.jsx'
import './workspace.css'
import Navigation from './components/Navigation.jsx'
import GlobeOverview from './components/GlobeOverview.jsx'
import OverviewView from './components/OverviewView.jsx'
import CopilotView from './components/CopilotView.jsx'
import AlertsView from './components/AlertsView.jsx'
import HoneypotView from './components/HoneypotView.jsx'
import EventFeed from './components/EventFeed.jsx'
import RulesView from './components/RulesView.jsx'
import SimulatorView from './components/SimulatorView.jsx'

const WS_URL = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/api/events/live`

export default function App({ user }) {
  const [activeTab, setActiveTab] = useState('overview')
  const [copilotOpen, setCopilotOpen] = useState(false)
  const copilotDialog = useRef(null)
  useEffect(() => {
    if (copilotOpen) copilotDialog.current?.showModal()
    else copilotDialog.current?.close()
  }, [copilotOpen])
  const [events, setEvents] = useState([])
  const [liveAlerts, setLiveAlerts] = useState([])
  const [connected, setConnected] = useState(false)
  const [pipelineStats, setPipelineStats] = useState({
    active_alerts: 0,
    active_incidents: 0,
    honeypot_sessions: 0,
    rules_loaded: 5,
  })

  const wsRef = useRef(null)
  const reconnectTimer = useRef(null)

  // Fetch health and pipeline stats
  const fetchStats = useCallback(async () => {
    try {
      const res = await apiFetch('/api/health')
      if (res.ok) {
        const data = await res.json()
        setPipelineStats((prev) => ({
          ...prev,
          active_alerts: data.active_alerts ?? 0,
          active_incidents: data.active_incidents ?? 0,
          honeypot_sessions: data.honeypot_sessions ?? 0,
          rules_loaded: data.rules_loaded ?? 5,
        }))
      }
    } catch {
      // ignore if offline
    }
  }, [])

  // WebSocket connection handler
  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return

    const ws = new WebSocket(WS_URL)
    wsRef.current = ws

    ws.onopen = () => {
      setConnected(true)
      console.log('[MMS] WebSocket connected to gateway')
      fetchStats()
    }

    ws.onmessage = (msg) => {
      try {
        const payload = JSON.parse(msg.data)

        if (payload.type === 'event' && payload.event) {
          setEvents((prev) => [payload.event, ...prev.filter((e) => e.event_id !== payload.event.event_id)].slice(0, 500))
          if (payload.alert) {
            setLiveAlerts((prev) => [payload.alert, ...prev.filter((a) => a.alert_id !== payload.alert.alert_id)])
          }
          if (payload.stats) {
            setPipelineStats(payload.stats)
          }
        } else if (payload.event_id) {
          setEvents((prev) => [payload, ...prev.filter((e) => e.event_id !== payload.event_id)].slice(0, 500))
        }

        fetchStats()
      } catch (err) {
        console.warn('[MMS] Failed to parse WebSocket payload:', err)
      }
    }

    ws.onclose = (event) => {
      setConnected(false)
      if (event.code === 1008) {
        window.dispatchEvent(new Event('mms-session-expired'))
        return
      }
      reconnectTimer.current = setTimeout(connect, 3000)
    }

    ws.onerror = () => {
      ws.close()
    }
  }, [fetchStats])

  // Initial event fetching
  const fetchInitial = useCallback(async () => {
    try {
      const alertResponse = await apiFetch('/api/alerts')
      if (alertResponse.ok) setLiveAlerts((await alertResponse.json()).alerts || [])
      const res = await apiFetch('/api/events?size=100')
      if (res.ok) {
        const data = await res.json()
        setEvents(data.events || [])
      }
    } catch {
      // API not available yet
    }
    fetchStats()
  }, [fetchStats])

  useEffect(() => {
    fetchInitial()
    connect()

    // Poll authoritative snapshots to recover missed live messages and lifecycle changes.
    const pollInterval = setInterval(fetchStats, 5000)
    const recoveryInterval = setInterval(fetchInitial, 15000)

    return () => {
      clearInterval(pollInterval)
      clearInterval(recoveryInterval)
      clearTimeout(reconnectTimer.current)
      if (wsRef.current) { wsRef.current.onclose = null; wsRef.current.close() }
    }
  }, [connect, fetchInitial, fetchStats])

  return (
    <div className="security-workspace">
      <aside className="workspace-sidebar">
        <div className="workspace-brand"><span>◈</span><div>MMS<small>Security operations</small></div></div>
        <Navigation role={user?.role} activeTab={activeTab} setActiveTab={setActiveTab}
          alertCount={pipelineStats.active_alerts} sessionCount={pipelineStats.honeypot_sessions} />
        <div className="workspace-connection"><span className={connected ? 'connection-dot live' : 'connection-dot'} />{connected ? 'Telemetry connected' : 'Telemetry unavailable'}</div>
      </aside>
      <div className="workspace-body">
      <header className="workspace-header"><span>WORKSPACE / {activeTab.toUpperCase()}</span><span>Multi Modal Security</span></header>
      {/* Main Tab Views */}
      <main className="main-content">
        {activeTab === 'overview' && (
          <OverviewView
            connected={connected}
            pipelineStats={pipelineStats}
            events={events}
            liveAlerts={liveAlerts}
            onNavigate={(tab) => setActiveTab(tab)}
            onCopilot={() => setCopilotOpen(true)}
            canUseCopilot={user?.role !== 'viewer'}
            onRefresh={() => {
              fetchStats()
              fetchInitial()
            }}
          />
        )}
        {activeTab === 'phishing' && <PhishingView role={user?.role} />}
        {activeTab === 'forensics' && <ForensicsView user={user} />}
        {activeTab === 'account' && <AccountView user={user} />}
        {activeTab === 'response' && <ResponseView user={user} />}
        {activeTab === 'reports' && <ReportsView />}
        {activeTab === 'intelligence' && <IntelligenceView role={user?.role} />}
        {activeTab === 'alerts' && <AlertsView alerts={liveAlerts} />}
        {activeTab === 'honeypot' && <HoneypotView />}
        {activeTab === 'events' && <EventFeed events={events} />}
        {activeTab === 'rules' && <RulesView />}
        {activeTab === 'simulator' && (
          <SimulatorView
            onSimulationSuccess={() => {
              fetchStats()
              fetchInitial()
            }}
          />
        )}
      </main>
      </div>
      {user?.role !== 'viewer' && <button className="copilot-launcher" onClick={() => setCopilotOpen(true)} aria-haspopup="dialog">✦ Ask Copilot</button>}
      <dialog ref={copilotDialog} className="copilot-dialog" onClose={() => setCopilotOpen(false)} aria-labelledby="copilot-panel-title">
        <div className="copilot-panel-heading"><h2 id="copilot-panel-title">Investigation assistant</h2><button autoFocus onClick={() => setCopilotOpen(false)} aria-label="Close Copilot">✕</button></div>
        {copilotOpen && <CopilotView />}
      </dialog>
    </div>
  )
}
