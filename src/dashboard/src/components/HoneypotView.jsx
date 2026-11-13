import { apiFetch } from '../api.js'
import React, { useState, useEffect, useCallback } from 'react'

export default function HoneypotView() {
  const [sessions, setSessions] = useState([])
  const [clusters, setClusters] = useState({})
  const [stats, setStats] = useState({})
  const [selectedSessionId, setSelectedSessionId] = useState(null)
  const [loading, setLoading] = useState(true)

  const fetchData = useCallback(async () => {
    try {
      const [sessRes, atkRes] = await Promise.all([
        apiFetch('/api/honeypot/sessions'),
        apiFetch('/api/honeypot/attackers'),
      ])
      if (sessRes.ok) {
        const data = await sessRes.json()
        const sessList = data.sessions || []
        setSessions(sessList)
        if (sessList.length > 0 && !selectedSessionId) {
          setSelectedSessionId(sessList[0].session_id)
        }
      }
      if (atkRes.ok) {
        const data = await atkRes.json()
        setClusters(data.clusters || {})
        setStats(data.statistics || {})
      }
    } catch (err) {
      console.error('Failed to fetch honeypot telemetry:', err)
    } finally {
      setLoading(false)
    }
  }, [selectedSessionId])

  useEffect(() => {
    fetchData()

    // 2.5-second polling for live session updates
    const timer = setInterval(fetchData, 2500)
    return () => clearInterval(timer)
  }, [fetchData])

  const selectedSession = sessions.find((s) => s.session_id === selectedSessionId) || sessions[0]

  const formatTime = (ts) => {
    if (!ts) return 'Just now'
    try {
      const d = new Date(ts)
      return d.toLocaleTimeString()
    } catch {
      return ts
    }
  }

  const formatDuration = (s) => {
    if (s.is_active) return 'LIVE'
    const d = s.duration_seconds || 0
    if (d >= 60) {
      const mins = Math.floor(d / 60)
      const secs = Math.floor(d % 60)
      return `${mins}m ${secs}s`
    }
    return `${d.toFixed(0)}s`
  }

  return (
    <div className="view-container">
      {/* Header */}
      <div className="view-header">
        <div>
          <h2 className="view-title">Honeypot Deception & Attacker Intelligence</h2>
          <p className="view-subtitle">
            Sandboxed deception sensors, session captures, and MITRE ATT&CK campaign clustering
          </p>
        </div>
        <button className="btn-refresh" onClick={fetchData} title="Refresh Honeypot Data">
          🔄
        </button>
      </div>

      {/* Honeypot Analytics Metrics Bar */}
      <div className="honeypot-metrics-bar">
        <div className="hp-metric-card">
          <div className="hp-metric-card__val">{sessions.length}</div>
          <div className="hp-metric-card__lbl">Captured Sessions</div>
        </div>
        <div className="hp-metric-card">
          <div className="hp-metric-card__val">{stats.unique_attackers || (sessions.length > 0 ? 1 : 0)}</div>
          <div className="hp-metric-card__lbl">Unique Attackers</div>
        </div>
        <div className="hp-metric-card">
          <div className="hp-metric-card__val">{stats.total_credentials_tried || (sessions.length > 0 ? 1 : 0)}</div>
          <div className="hp-metric-card__lbl">Credentials Tested</div>
        </div>
        <div className="hp-metric-card">
          <div className="hp-metric-card__val">{stats.total_commands_executed || 0}</div>
          <div className="hp-metric-card__lbl">Commands Executed</div>
        </div>
      </div>

      {/* Campaign Archetype Clusters */}
      <div className="clusters-section">
        <h3 className="section-title">🧬 Campaign Archetype Clusters (TTP Analysis)</h3>
        <div className="clusters-grid">
          {Object.entries(clusters).map(([archetype, profiles]) => (
            <div key={archetype} className="cluster-card">
              <div className="cluster-card__header">
                <span className="cluster-card__icon">
                  {archetype.includes('Dropper') ? '🤖' : archetype.includes('Recon') ? '🕵️' : archetype.includes('Multi-Stage') ? '⚡' : '🔑'}
                </span>
                <h4 className="cluster-card__title">{archetype}</h4>
                <span className="cluster-card__count">{profiles.length} IP(s)</span>
              </div>
              <div className="cluster-card__body">
                {profiles.length === 0 ? (
                  <div className="cluster-empty">No active attacker profiles in this cluster</div>
                ) : (
                  profiles.map((p) => (
                    <div key={p.ip} className="attacker-chip">
                      <div className="attacker-chip__ip">
                        <strong>{p.ip}</strong>
                        <span className={`badge-severity badge-severity--${p.threat_level}`}>
                          {p.threat_level}
                        </span>
                      </div>
                      <div className="attacker-chip__details">
                        <span>{p.session_count} session(s)</span> •{' '}
                        <span>{p.total_commands_executed} cmd(s)</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Main Two-Column Layout: Session List & Detailed Inspector */}
      <div className="honeypot-layout">
        {/* Left: Sessions List */}
        <div className="sessions-list-panel">
          <h3 className="panel-title">Captured Deception Sessions</h3>
          {loading && sessions.length === 0 ? (
            <div className="empty-state">Loading honeypot sessions...</div>
          ) : sessions.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state__icon">🍯</div>
              <p>No honeypot interactions yet. Launch a scenario in the Attack Simulator!</p>
            </div>
          ) : (
            <div className="sessions-list">
              {sessions.map((s) => {
                const isSelected = selectedSession?.session_id === s.session_id
                return (
                  <div
                    key={s.session_id}
                    className={`session-item ${isSelected ? 'session-item--selected' : ''}`}
                    onClick={() => setSelectedSessionId(s.session_id)}
                  >
                    <div className="session-item__header">
                      <span className="session-protocol">{s.protocol.toUpperCase()}</span>
                      <strong className="session-ip">{s.source_ip}</strong>
                      <span className={`session-status ${s.is_active ? 'session-status--live' : ''}`}>
                        {formatDuration(s)}
                      </span>
                    </div>

                    <div className="session-item__time-row">
                      <span className="session-time">🕒 {formatTime(s.start_time)}</span>
                    </div>

                    <div className="session-item__summary">
                      {s.authenticated ? (
                        <span className="auth-badge">User: {s.authenticated_user}</span>
                      ) : (
                        <span className="unauth-badge">Failed Auth</span>
                      )}
                      <span className="counter-pill">{s.commands?.length || 0} cmds</span>
                      {s.artifacts?.length > 0 && (
                        <span className="artifact-pill">📦 {s.artifacts.length} payload</span>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Right: Detailed Session Terminal & Artifact Inspector */}
        <div className="session-detail-panel">
          {selectedSession ? (
            <div className="inspector-card">
              <div className="inspector-header">
                <div>
                  <h3 className="inspector-title">
                    Session Inspection — {selectedSession.source_ip}
                  </h3>
                  <p className="inspector-subtitle">
                    Sensor: {selectedSession.target_host} ({selectedSession.protocol.toUpperCase()}) | Started: {formatTime(selectedSession.start_time)} | Duration: {formatDuration(selectedSession)}
                  </p>
                </div>
              </div>

              {/* Credentials Section */}
              {selectedSession.credentials?.length > 0 && (
                <div className="inspector-section">
                  <h4 className="section-label">🔑 Credentials Attempted</h4>
                  <div className="creds-list">
                    {selectedSession.credentials.map((c, i) => (
                      <div key={i} className={`cred-item ${c.success ? 'cred-item--success' : ''}`}>
                        <span>User: <code>{c.username}</code></span>
                        <span>Pass: <code>{c.password}</code></span>
                        <span className={c.success ? 'cred-status--ok' : 'cred-status--fail'}>
                          {c.success ? 'ACCEPTED' : 'REJECTED'}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Terminal Shell Commands */}
              <div className="inspector-section">
                <h4 className="section-label">💻 Simulated Shell Commands</h4>
                {selectedSession.commands?.length === 0 ? (
                  <div className="terminal-empty">No interactive shell commands executed in this session</div>
                ) : (
                  <div className="virtual-terminal">
                    {selectedSession.commands.map((cmd, i) => (
                      <div key={i} className="terminal-entry">
                        <div className="terminal-prompt">
                          <span className="prompt-user">root@{selectedSession.target_host}</span>
                          <span className="prompt-cwd">{cmd.working_dir || '/root'}#</span>
                          <span className="prompt-cmd">{cmd.command}</span>
                          <div className="cmd-tags">
                            {cmd.tags?.map((t) => (
                              <span key={t} className={`cmd-tag cmd-tag--${t}`}>
                                {t}
                              </span>
                            ))}
                          </div>
                        </div>
                        {cmd.output_preview && (
                          <pre className="terminal-output">{cmd.output_preview}</pre>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Captured Dropper / Payload Artifacts */}
              {selectedSession.artifacts?.length > 0 && (
                <div className="inspector-section">
                  <h4 className="section-label">📦 Captured Payload / Dropper Artifacts</h4>
                  <div className="artifacts-list">
                    {selectedSession.artifacts.map((art, i) => (
                      <div key={i} className="artifact-item">
                        <div className="artifact-item__name">
                          <strong>{art.filename_or_url}</strong>
                          <span className="artifact-size">{(art.size_bytes / 1024).toFixed(1)} KB</span>
                        </div>
                        <div className="artifact-item__hash">
                          <span>SHA-256:</span> <code>{art.file_hash}</code>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="empty-state">Select a session from the list to inspect</div>
          )}
        </div>
      </div>
    </div>
  )
}

