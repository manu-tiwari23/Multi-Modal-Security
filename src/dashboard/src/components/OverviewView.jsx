import React, { useState, useMemo } from 'react'
import {
  Activity,
  ArrowUpRight,
  BrainCircuit,
  Bug,
  Clock3,
  Fish,
  PlusCircle,
  RefreshCw,
  RotateCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Zap,
} from 'lucide-react'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import GlobeOverview from './GlobeOverview'
import { apiFetch } from '../api'
import { makeActivityBuckets, makeSeverityData } from '../telemetryData'
import '../globe.css'

export default function OverviewView({
  connected,
  pipelineStats = {},
  events = [],
  liveAlerts = [],
  customNodes = [],
  onCustomNodesChange,
  onNavigate,
  onCopilot,
  canUseCopilot = true,
  onRefresh,
}) {
  const [simulating, setSimulating] = useState(false)
  const [simulationNotice, setSimulationNotice] = useState(null)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const handleAddDemoNode = async () => {
    const idx = customNodes.length
    if (idx >= 50) {
      setSimulationNotice('Demo topology is limited to 50 nodes.')
      return
    }
    const host = `demo-node-${String(idx + 1).padStart(2, '0')}`
    const newNode = {
      id: host,
      host,
      ip: `192.0.2.${10 + idx}`,
      role: 'Synthetic telemetry node',
      status: 'demo',
      simulated: true,
      alerts: [],
      eventsCount: 1,
    }
    onCustomNodesChange?.((previous) => [...previous, newNode])
    try {
      const response = await apiFetch('/api/simulate/attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: 'node_activity', attacker_ip: newNode.ip, node_host: newNode.host }),
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      await onRefresh?.()
      setSimulationNotice(`Added ${newNode.host} (${newNode.ip}) and published its synthetic activity to Telemetry.`)
    } catch {
      setSimulationNotice(`Added ${newNode.host} (${newNode.ip}) to the globe, but its telemetry event could not be published.`)
    }
  }

  const handleResetNodes = () => {
    onCustomNodesChange?.([])
    setSimulationNotice('Removed persistent demo nodes from the globe. Their historical telemetry remains in the event store.')
  }

  // Chart data
  const activityData = useMemo(() => makeActivityBuckets(events), [events])

  const severityData = useMemo(() => makeSeverityData(events), [events])

  const criticalAlertsCount = useMemo(() => {
    return liveAlerts.filter((a) => {
      const s = (a.severity || a.priority || '').toLowerCase()
      return s.includes('critical') || s.includes('p1')
    }).length
  }, [liveAlerts])

  const handleSimulate = async () => {
    if (simulating) return
    setSimulating(true)
    setSimulationNotice(null)
    try {
      const res = await apiFetch('/api/simulate/attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: 'multistage', attacker_ip: '198.51.100.77' }),
      })
      if (res.ok) {
        setSimulationNotice(
          'Synthetic scenario submitted. Review its events and detections in Incidents.'
        )
        if (onRefresh) onRefresh()
      } else {
        setSimulationNotice('⚠️ Simulation dispatch returned error.')
      }
    } catch {
      setSimulationNotice('⚠️ Could not dispatch attack simulation.')
    } finally {
      setSimulating(false)
    }
  }

  const handleManualRefresh = async () => {
    setIsRefreshing(true)
    if (onRefresh) await onRefresh()
    setTimeout(() => setIsRefreshing(false), 500)
  }

  return (
    <div className="ops-dashboard-wrapper">
      {/* Top Operations Header & Actions */}
      <div className="ops-header-bar">
        <div>
          <div className="ops-eyebrow">
            <span className="pulse-led" />
            SECURITY OPERATIONS
          </div>
          <h1 className="ops-title">Overview</h1>
          <p className="ops-subtitle">
            Your recent telemetry, detections, and investigation workspace.
          </p>
        </div>

        <div className="ops-header-controls">
          <button
            className="ops-btn"
            onClick={handleManualRefresh}
            title="Refresh telemetry"
            disabled={isRefreshing}
          >
            <RefreshCw size={13} className={isRefreshing ? 'spin-anim' : ''} />
            <span>{isRefreshing ? 'Refreshing...' : 'Refresh'}</span>
          </button>

          <div className={`ops-status-pill ${connected ? 'connected' : 'disconnected'}`}>
            <span className="status-dot" />
            <span>{connected ? 'GATEWAY LIVE' : 'OFFLINE'}</span>
          </div>
        </div>
      </div>

      {/* Analyst Quick Actions Bar */}
      <div className="analyst-toolbar">
        <span className="toolbar-label">Quick Actions:</span>
        <button
          className="toolbar-btn primary"
          onClick={handleSimulate}
          disabled={simulating || !canUseCopilot}
          title="Generate synthetic events for a test investigation"
        >
          <Bug size={14} className="text-amber-400" />
          <span>{simulating ? 'Simulating Attack...' : 'Run simulation'}</span>
        </button>

        <button
          className="toolbar-btn text-emerald-400 border-emerald-400/30"
          onClick={handleAddDemoNode}
          title="Add a clearly labelled simulated node to preview the globe layout"
        >
          <PlusCircle size={14} className="text-emerald-400" />
          <span>Add demo node ({customNodes.length})</span>
        </button>

        {customNodes.length > 0 && (
          <button
            className="toolbar-btn text-slate-400"
            onClick={handleResetNodes}
            title="Remove simulated visualization nodes"
          >
            <RotateCcw size={13} />
            <span>Clear demo nodes</span>
          </button>
        )}

        <button className="toolbar-btn" onClick={() => onNavigate('phishing')}>
          <Fish size={14} className="text-cyan-400" />
          <span>Scan Phishing Email</span>
        </button>

        <button className="toolbar-btn" onClick={() => onNavigate('intelligence')}>
          <Search size={14} className="text-emerald-400" />
          <span>Threat Intel Lookup</span>
        </button>

        {canUseCopilot && (
          <button className="toolbar-btn" onClick={onCopilot}>
            <BrainCircuit size={14} className="text-purple-400" />
            <span>Ask Security Copilot</span>
          </button>
        )}
      </div>

      {/* Notice Banner */}
      {simulationNotice && (
        <div className="simulation-notice-banner">
          <span>{simulationNotice}</span>
          <button onClick={() => setSimulationNotice(null)} className="notice-dismiss-btn">
            ✕
          </button>
        </div>
      )}

      {/* Metric Cards Grid */}
      <section className="metric-cards-grid">
        {/* Recent events */}
        <div className="ops-metric-card" onClick={() => onNavigate('events')} role="button" tabIndex={0} onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); e.currentTarget.click() } }}>
          <div className="card-top">
            <span className="card-label">Recent events</span>
            <div className="card-icon-wrap text-cyan-400">
              <Activity size={16} />
            </div>
          </div>
          <div className="card-value">
            {events.length.toLocaleString()}
          </div>
          <div className="card-bottom">
            <span>Loaded telemetry sample</span>
            <ArrowUpRight size={14} className="card-arrow" />
          </div>
        </div>

        {/* Active Incidents */}
        <div className="ops-metric-card" onClick={() => onNavigate('response')} role="button" tabIndex={0} onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); e.currentTarget.click() } }}>
          <div className="card-top">
            <span className="card-label">Active Incidents</span>
            <div className="card-icon-wrap text-orange-400">
              <Siren size={16} />
            </div>
          </div>
          <div className="card-value">{pipelineStats.active_incidents ?? 0}</div>
          <div className="card-bottom">
            <span>Correlated attack cases</span>
            <ArrowUpRight size={14} className="card-arrow" />
          </div>
        </div>

        {/* Critical Alerts */}
        <div className="ops-metric-card" onClick={() => onNavigate('alerts')} role="button" tabIndex={0} onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); e.currentTarget.click() } }}>
          <div className="card-top">
            <span className="card-label">Critical Alerts</span>
            <div className="card-icon-wrap text-red-400">
              <ShieldAlert size={16} />
            </div>
          </div>
          <div className="card-value">
            {criticalAlertsCount}
          </div>
          <div className="card-bottom">
            <span>Priority rule triggers</span>
            <ArrowUpRight size={14} className="card-arrow" />
          </div>
        </div>

        {/* Honeypot Sessions */}
        <div className="ops-metric-card" onClick={() => onNavigate('honeypot')} role="button" tabIndex={0} onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); e.currentTarget.click() } }}>
          <div className="card-top">
            <span className="card-label">Honeypot Sessions</span>
            <div className="card-icon-wrap text-amber-400">
              <Bug size={16} />
            </div>
          </div>
          <div className="card-value">{pipelineStats.honeypot_sessions ?? 0}</div>
          <div className="card-bottom">
            <span>Deceptive telemetry traps</span>
            <ArrowUpRight size={14} className="card-arrow" />
          </div>
        </div>
      </section>

      {/* 3D Cyber Threat Network Systems Globe with Dynamic Node Status */}
      <GlobeOverview
        connected={connected}
        alertCount={pipelineStats.active_alerts}
        alerts={liveAlerts}
        events={events}
        customNodes={customNodes}
        onAddDemoNode={handleAddDemoNode}
        onResetNodes={handleResetNodes}
        onInvestigate={() => onNavigate('alerts')}
        onCopilot={onCopilot}
        canUseCopilot={canUseCopilot}
      />

      {/* Modern Analytics & Activity Charts Section */}
      <section className="charts-section-grid">
        {/* Chart 1: Recent activity (AreaChart) */}
        <div className="chart-card">
          <div className="chart-header">
            <div>
              <h2 className="chart-title">Recent activity</h2>
              <p className="chart-subtitle">Loaded events in the last 24 hours · 3-hour buckets</p>
            </div>
            <div className="chart-legend-badge">
              <span className="legend-dot" style={{ background: '#fbbf24' }} /> Events
              <span className="legend-dot" style={{ background: '#fb7185', marginLeft: 8 }} /> Critical
            </div>
          </div>
          <div style={{ width: '100%', height: 240 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={activityData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="eventAreaGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#fbbf24" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#fbbf24" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="critAreaGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#fb7185" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#fb7185" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false} />
                <XAxis dataKey="label" tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    background: '#0d1520',
                    border: '1px solid rgba(255,255,255,0.12)',
                    borderRadius: 10,
                    color: '#f8fafc',
                    fontSize: 12,
                    boxShadow: '0 8px 24px rgba(0,0,0,0.5)',
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="events"
                  name="Events"
                  stroke="#fbbf24"
                  strokeWidth={2}
                  fill="url(#eventAreaGrad)"
                />
                <Area
                  type="monotone"
                  dataKey="critical"
                  name="Critical"
                  stroke="#fb7185"
                  strokeWidth={2}
                  fill="url(#critAreaGrad)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Chart 2: Severity Distribution (BarChart) */}
        <div className="chart-card">
          <div className="chart-header">
            <div>
              <h2 className="chart-title">Severity Breakdown</h2>
              <p className="chart-subtitle">Severity of loaded events</p>
            </div>
            <Clock3 size={15} className="text-slate-500" />
          </div>
          <div style={{ width: '100%', height: 240 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData} layout="vertical" margin={{ top: 5, right: 15, left: 10, bottom: 5 }}>
                <XAxis type="number" hide allowDecimals={false} />
                <YAxis
                  type="category"
                  dataKey="severity"
                  width={68}
                  tick={{ fill: '#94a3b8', fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                  contentStyle={{
                    background: '#0d1520',
                    border: '1px solid rgba(255,255,255,0.12)',
                    borderRadius: 10,
                    color: '#f8fafc',
                    fontSize: 12,
                  }}
                />
                <Bar dataKey="count" name="Count" fill="#38bdf8" radius={[0, 4, 4, 0]} barSize={14} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>

      {/* Incidents & Active Alerts Triage Lists */}
      <section className="activity-feed-section">
        {/* Recent Alerts Feed */}
        <div className="card-list-box">
          <div className="list-box-header">
            <div>
              <div className="list-box-title">Recent Alerts Queue</div>
              <div style={{ fontSize: '11px', color: '#64748b' }}>Active detections awaiting triage</div>
            </div>
            <button className="list-box-link" onClick={() => onNavigate('alerts')}>
              View all alerts ↗
            </button>
          </div>
          <div className="list-box-body">
            {liveAlerts.length === 0 ? (
              <div style={{ padding: '30px 20px', textAlign: 'center', color: '#64748b', fontSize: '12px' }}>
                <ShieldCheck size={28} style={{ margin: '0 auto 8px', color: '#34d399' }} />
                No active alerts in the current snapshot.
              </div>
            ) : (
              liveAlerts.slice(0, 4).map((alert, idx) => (
                <div key={alert.alert_id || idx} className="list-row" onClick={() => onNavigate('alerts')}>
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <div className="list-row-title">{alert.title || 'Security Detection Alert'}</div>
                    <div className="list-row-meta">
                      Host: {alert.primary_entity?.host || alert.primary_entity?.ip || 'Unknown'} · Score: {alert.risk_score ?? '—'}/100
                    </div>
                  </div>
                  <span
                    style={{
                      padding: '3px 8px',
                      borderRadius: 6,
                      fontSize: '10px',
                      fontWeight: 700,
                      background:
                        alert.severity === 'critical' || alert.priority?.includes('P1')
                          ? 'rgba(239, 68, 68, 0.2)'
                          : 'rgba(249, 115, 22, 0.2)',
                      color:
                        alert.severity === 'critical' || alert.priority?.includes('P1')
                          ? '#ff4d4f'
                          : '#fb923c',
                    }}
                  >
                    {(alert.severity || alert.priority || 'UNKNOWN').toUpperCase()}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Security Posture & Honeypot Summary */}
        <div className="card-list-box">
          <div className="list-box-header">
            <div>
              <div className="list-box-title">Deception & Honeypot Status</div>
              <div style={{ fontSize: '11px', color: '#64748b' }}>Open an investigation workflow</div>
            </div>
            <button className="list-box-link" onClick={() => onNavigate('honeypot')}>
              View honeypots ↗
            </button>
          </div>
          <div className="list-box-body">
            <div className="list-row" onClick={() => onNavigate('honeypot')}>
              <div>
                <div className="list-row-title">Honeypot sessions</div>
                <div className="list-row-meta">Review recorded deception activity</div>
              </div>
              <span style={{ color: '#34d399', fontSize: '11px', fontWeight: 600 }}>OPEN</span>
            </div>
            <div className="list-row" onClick={() => onNavigate('forensics')}>
              <div>
                <div className="list-row-title">Digital Forensics Vault</div>
                <div className="list-row-meta">Automated SHA-256 artifact integrity hashing</div>
              </div>
              <span style={{ color: '#38bdf8', fontSize: '11px', fontWeight: 600 }}>OPEN</span>
            </div>
            <div className="list-row" onClick={() => onNavigate('phishing')}>
              <div>
                <div className="list-row-title">Phishing Email & URL Classifier</div>
                <div className="list-row-meta">Multi-vector lexical + header heuristic scanning</div>
              </div>
              <span style={{ color: '#34d399', fontSize: '11px', fontWeight: 600 }}>OPEN</span>
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}

