import { useState, useEffect, useRef, useCallback } from 'react'
import EventFeed from './components/EventFeed.jsx'

const WS_URL = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/api/events/live`

export default function App() {
  const [events, setEvents] = useState([])
  const [connected, setConnected] = useState(false)
  const wsRef = useRef(null)
  const reconnectTimer = useRef(null)

  // -- Severity stats
  const stats = events.reduce(
    (acc, e) => {
      acc.total++
      acc[e.severity] = (acc[e.severity] || 0) + 1
      return acc
    },
    { total: 0, low: 0, medium: 0, high: 0, critical: 0 },
  )

  // -- WebSocket connection
  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return

    const ws = new WebSocket(WS_URL)
    wsRef.current = ws

    ws.onopen = () => {
      setConnected(true)
      console.log('[MMS] WebSocket connected')
    }

    ws.onmessage = (msg) => {
      try {
        const event = JSON.parse(msg.data)
        setEvents((prev) => [event, ...prev].slice(0, 500))
      } catch (err) {
        console.warn('[MMS] Failed to parse event:', err)
      }
    }

    ws.onclose = () => {
      setConnected(false)
      console.log('[MMS] WebSocket disconnected — reconnecting in 3s')
      reconnectTimer.current = setTimeout(connect, 3000)
    }

    ws.onerror = (err) => {
      console.error('[MMS] WebSocket error:', err)
      ws.close()
    }
  }, [])

  // -- Fetch initial events from REST API
  const fetchInitial = useCallback(async () => {
    try {
      const res = await fetch('/api/events?size=100')
      if (res.ok) {
        const data = await res.json()
        setEvents(data.events || [])
      }
    } catch {
      // API not available yet — that's fine for initial load
    }
  }, [])

  useEffect(() => {
    fetchInitial()
    connect()

    return () => {
      clearTimeout(reconnectTimer.current)
      wsRef.current?.close()
    }
  }, [connect, fetchInitial])

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div>
          <h1 className="header__title">Multi Modal Security</h1>
          <p className="header__subtitle">Real-time event pipeline — Phase 1</p>
        </div>
        <div className={`status-badge ${connected ? 'status-badge--connected' : 'status-badge--disconnected'}`}>
          <span className="status-badge__dot" />
          {connected ? 'Live' : 'Disconnected'}
        </div>
      </header>

      {/* Stats */}
      <div className="stats-bar">
        <div className="stat-card stat-card--total">
          <div className="stat-card__label">Total Events</div>
          <div className="stat-card__value">{stats.total}</div>
        </div>
        <div className="stat-card stat-card--critical">
          <div className="stat-card__label">Critical</div>
          <div className="stat-card__value">{stats.critical}</div>
        </div>
        <div className="stat-card stat-card--high">
          <div className="stat-card__label">High</div>
          <div className="stat-card__value">{stats.high}</div>
        </div>
        <div className="stat-card stat-card--medium">
          <div className="stat-card__label">Medium</div>
          <div className="stat-card__value">{stats.medium}</div>
        </div>
        <div className="stat-card stat-card--low">
          <div className="stat-card__label">Low</div>
          <div className="stat-card__value">{stats.low}</div>
        </div>
      </div>

      {/* Event Feed */}
      <EventFeed events={events} />
    </div>
  )
}
