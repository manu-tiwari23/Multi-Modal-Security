import { useState, useEffect, useRef, useCallback } from 'react'
import Navigation from './components/Navigation.jsx'
import CopilotView from './components/CopilotView.jsx'
import AlertsView from './components/AlertsView.jsx'
import HoneypotView from './components/HoneypotView.jsx'
import EventFeed from './components/EventFeed.jsx'
import RulesView from './components/RulesView.jsx'
import SimulatorView from './components/SimulatorView.jsx'

const WS_URL = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/api/events/live`

export default function App() {
  const [activeTab, setActiveTab] = useState('copilot')
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
      const res = await fetch('/api/health')
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

  // Calculate severity stats
  const stats = events.reduce(
    (acc, e) => {
      acc.total++
      acc[e.severity] = (acc[e.severity] || 0) + 1
      return acc
    },
    { total: 0, low: 0, medium: 0, high: 0, critical: 0 },
  )

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

    ws.onclose = () => {
      setConnected(false)
      reconnectTimer.current = setTimeout(connect, 3000)
    }

    ws.onerror = () => {
      ws.close()
    }
  }, [fetchStats])

  // Initial event fetching
  const fetchInitial = useCallback(async () => {
    try {
      const res = await fetch('/api/events?size=100')
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

    // 2-second periodic stats polling so metrics never freeze
    const pollInterval = setInterval(() => {
      fetchStats()
    }, 2000)

    return () => {
      clearInterval(pollInterval)
      clearTimeout(reconnectTimer.current)
      wsRef.current?.close()
    }
  }, [connect, fetchInitial, fetchStats])

  return (
    <div className="app">
      {/* Top Header */}
      <header className="header">
        <div className="header__brand">
          <div className="header__logo">🛡️</div>
          <div>
            <h1 className="header__title">Multi Modal Security</h1>
            <p className="header__subtitle">
              Integrated SOC • AI Copilot • Honeypot • Forensics • Phishing
            </p>
          </div>
        </div>

        <div className="header__status-box">
          <div className={`status-badge ${connected ? 'status-badge--connected' : 'status-badge--disconnected'}`}>
            <span className="status-badge__dot" />
            {connected ? 'Pipeline Active' : 'Offline / Standalone'}
          </div>
        </div>
      </header>

      {/* Global Security Metrics Bar */}
      <div className="stats-bar">
        <div className="stat-card stat-card--alerts" onClick={() => setActiveTab('alerts')}>
          <div className="stat-card__label">Active Alerts</div>
          <div className="stat-card__value">{pipelineStats.active_alerts || 0}</div>
        </div>
        <div className="stat-card stat-card--incidents" onClick={() => setActiveTab('alerts')}>
          <div className="stat-card__label">Correlated Incidents</div>
          <div className="stat-card__value">{pipelineStats.active_incidents || 0}</div>
        </div>
        <div className="stat-card stat-card--honeypot" onClick={() => setActiveTab('honeypot')}>
          <div className="stat-card__label">Honeypot Sessions</div>
          <div className="stat-card__value">{pipelineStats.honeypot_sessions || 0}</div>
        </div>
        <div className="stat-card stat-card--rules" onClick={() => setActiveTab('rules')}>
          <div className="stat-card__label">Detection Rules</div>
          <div className="stat-card__value">{pipelineStats.rules_loaded || 5}</div>
        </div>
        <div className="stat-card stat-card--total" onClick={() => setActiveTab('events')}>
          <div className="stat-card__label">Total Ingested Events</div>
          <div className="stat-card__value">{events.length || stats.total}</div>
        </div>
      </div>

      {/* Primary Navigation Tabs */}
      <Navigation
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        alertCount={pipelineStats.active_alerts}
        sessionCount={pipelineStats.honeypot_sessions}
      />

      {/* Main Tab Views */}
      <main className="main-content">
        {activeTab === 'copilot' && <CopilotView />}
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
  )
}
