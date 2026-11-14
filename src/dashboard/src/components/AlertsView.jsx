import React, { useState, useEffect, useCallback } from 'react'
import { apiFetch } from '../api.js'
import { Shield, ShieldAlert, Terminal, Activity, ChevronDown, ChevronUp, Target, ListTree, ArrowRight, Zap, CheckCircle } from 'lucide-react'

export default function AlertsView({ alerts: liveAlerts, onRespond }) {
  const [alerts, setAlerts] = useState([])
  const [selectedPriority, setSelectedPriority] = useState('ALL')
  const [expandedAlertId, setExpandedAlertId] = useState(null)
  const [categoryMap, setCategoryMap] = useState({}) // alert_id -> 'overview' | 'detection' | 'scoring' | 'response'
  const [loading, setLoading] = useState(true)
  const [copyStatus, setCopyStatus] = useState({})

  async function copyIncidentId(alert) {
    try {
      await navigator.clipboard.writeText(alert.incident_id)
      setCopyStatus(prev => ({ ...prev, [alert.alert_id]: 'Copied!' }))
    } catch {
      setCopyStatus(prev => ({ ...prev, [alert.alert_id]: 'Copy failed. Select the ID and copy manually.' }))
    }
  }

  // Fetch alerts from REST API
  const fetchAlerts = useCallback(async () => {
    try {
      const res = await apiFetch('/api/alerts')
      if (res.ok) {
        const data = await res.json()
        setAlerts(data.alerts || [])
      }
    } catch (err) {
      console.error('Failed to fetch alerts:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchAlerts()
    const timer = setInterval(fetchAlerts, 2500)
    return () => clearInterval(timer)
  }, [fetchAlerts])

  // Merge live alert updates
  useEffect(() => {
    if (!liveAlerts || liveAlerts.length === 0) return
    setAlerts((prev) => {
      const merged = [...prev]
      for (const live of liveAlerts) {
        const idx = merged.findIndex((a) => a.alert_id === live.alert_id)
        if (idx >= 0) {
          merged[idx] = live
        } else {
          merged.unshift(live)
        }
      }
      return merged.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
    })
  }, [liveAlerts])

  const filteredAlerts = alerts.filter((a) => {
    if (selectedPriority === 'ALL') return true
    return a.priority === selectedPriority
  })

  const getScoreColor = (score) => {
    if (score >= 80) return 'var(--severity-critical)'
    if (score >= 50) return 'var(--severity-high)'
    if (score >= 25) return 'var(--severity-medium)'
    return 'var(--severity-low)'
  }

  const getPriorityClass = (priority) => {
    if (priority === 'P1-critical') return 'badge-priority--p1'
    if (priority === 'P2-high') return 'badge-priority--p2'
    if (priority === 'P3-medium') return 'badge-priority--p3'
    return 'badge-priority--p4'
  }

  const formatTimestamp = (ts) => {
    if (!ts) return 'Just now'
    try {
      const d = new Date(ts)
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    } catch {
      return ts
    }
  }

  const getCategory = (id) => categoryMap[id] || 'overview'
  const setCategory = (id, cat) => setCategoryMap((prev) => ({ ...prev, [id]: cat }))

  return (
    <div className="view-container">
      {/* Header & Filter Bar */}
      <div className="view-header">
        <div>
          <h2 className="view-title">SOC Correlated Incidents & Alerts</h2>
          <p className="view-subtitle">
            Simplified incident queue. Click any activity to inspect categorized investigation details.
          </p>
        </div>
        <div className="filter-group">
          {['ALL', 'P1-critical', 'P2-high', 'P3-medium', 'P4-low'].map((prio) => (
            <button
              key={prio}
              className={`filter-btn ${selectedPriority === prio ? 'filter-btn--active' : ''}`}
              onClick={() => setSelectedPriority(prio)}
            >
              {prio}
            </button>
          ))}
          <button className="btn-refresh" onClick={fetchAlerts} title="Refresh Alerts">
            🔄
          </button>
        </div>
      </div>

      {loading && alerts.length === 0 ? (
        <div className="empty-state">Loading correlated alerts...</div>
      ) : filteredAlerts.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state__icon">🛡️</div>
          <h3>No incidents found for selected filter</h3>
          <p>No active alerts are present in the current snapshot.</p>
        </div>
      ) : (
        <div className="alerts-grid">
          {filteredAlerts.map((alert) => {
            const isExpanded = expandedAlertId === alert.alert_id
            const currentCat = getCategory(alert.alert_id)
            const bd = alert.score_breakdown || {}
            const uniqueRules = Array.from(new Set(alert.rule_ids || []))
            const uniqueMitre = Array.from(new Set(alert.mitre_techniques || []))

            return (
              <div
                key={alert.alert_id}
                className={`alert-card ${isExpanded ? 'alert-card--expanded' : 'alert-card--simplified'}`}
              >
                {/* Simplified Card Summary (Always visible & clean) */}
                <div
                  className="alert-card__header"
                  onClick={() => setExpandedAlertId(isExpanded ? null : alert.alert_id)}
                  role="button"
                  tabIndex={0}
                  aria-expanded={isExpanded}
                >
                  <div className="alert-card__title-row">
                    <span className={`badge-priority ${getPriorityClass(alert.priority)}`}>
                      {alert.priority}
                    </span>
                    <span className={`badge-severity badge-severity--${alert.severity}`}>
                      {alert.severity}
                    </span>
                    <h3 className="alert-card__title">{alert.title}</h3>

                    {/* Compact quick-glance chips */}
                    <div className="alert-card__quick-chips">
                      <span className="quick-chip">
                        Host: <strong>{alert.primary_entity?.host || 'Unknown'}</strong>
                      </span>
                      <span className="quick-chip">
                        IP: <strong>{alert.primary_entity?.ip || '—'}</strong>
                      </span>
                      <span className="quick-chip">
                        {alert.event_count || 1} events
                      </span>
                    </div>
                  </div>

                  <div className="alert-card__score-box">
                    <div className="score-meter" style={{ borderColor: getScoreColor(alert.risk_score) }}>
                      <span className="score-meter__val" style={{ color: getScoreColor(alert.risk_score) }}>
                        {alert.risk_score ? alert.risk_score.toFixed(1) : '0.0'}
                      </span>
                      <span className="score-meter__denom">/100</span>
                    </div>
                    <span className="chevron-toggle">
                      {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                    </span>
                  </div>
                </div>

                <div className="incident-id-row">
                  <span>Incident ID</span>
                  <code>{alert.incident_id || 'Unavailable'}</code>
                  <button type="button" disabled={!alert.incident_id} onClick={() => copyIncidentId(alert)} aria-label={`Copy incident ID ${alert.incident_id || ''}`}>Copy ID</button>
                  <span role="status">{copyStatus[alert.alert_id] || ''}</span>
                </div>

                {/* Categorized Details: ONLY rendered when clicked */}
                {isExpanded && (
                  <div className="alert-detail-expanded-pane">
                    {/* Category Selector Tabs */}
                    <div className="incident-category-tabs">
                      <button
                        className={`category-tab-btn ${currentCat === 'overview' ? 'active' : ''}`}
                        onClick={(e) => {
                          e.stopPropagation()
                          setCategory(alert.alert_id, 'overview')
                        }}
                      >
                        📋 Overview & Entities
                      </button>
                      <button
                        className={`category-tab-btn ${currentCat === 'detection' ? 'active' : ''}`}
                        onClick={(e) => {
                          e.stopPropagation()
                          setCategory(alert.alert_id, 'detection')
                        }}
                      >
                        🎯 Detection & MITRE ({uniqueRules.length + uniqueMitre.length})
                      </button>
                      <button
                        className={`category-tab-btn ${currentCat === 'scoring' ? 'active' : ''}`}
                        onClick={(e) => {
                          e.stopPropagation()
                          setCategory(alert.alert_id, 'scoring')
                        }}
                      >
                        📊 Score Breakdown ({alert.risk_score?.toFixed(1) || '0.0'})
                      </button>
                      <button
                        className={`category-tab-btn ${currentCat === 'response' ? 'active' : ''}`}
                        onClick={(e) => {
                          e.stopPropagation()
                          setCategory(alert.alert_id, 'response')
                        }}
                      >
                        ⚡ Response Actions
                      </button>
                    </div>

                    {/* Category 1: Overview & Entities */}
                    {currentCat === 'overview' && (
                      <div className="category-content-panel">
                        <div className="category-section">
                          <h4 className="category-heading">Incident Narrative</h4>
                          <p className="alert-card__desc">{alert.description || 'No extended description provided.'}</p>
                        </div>

                        <div className="category-section">
                          <h4 className="category-heading">Entity & Telemetry Attributes</h4>
                          <div className="entity-attributes-grid">
                            <div className="entity-attribute-box">
                              <span className="attr-label">Attacker Source IP</span>
                              <code className="attr-value">{alert.primary_entity?.ip || '—'}</code>
                            </div>
                            <div className="entity-attribute-box">
                              <span className="attr-label">Target Hostname</span>
                              <code className="attr-value">{alert.primary_entity?.host || 'Unknown'}</code>
                            </div>
                            <div className="entity-attribute-box">
                              <span className="attr-label">Affected User</span>
                              <code className="attr-value">{alert.primary_entity?.user || 'root'}</code>
                            </div>
                            <div className="entity-attribute-box">
                              <span className="attr-label">Correlated Events</span>
                              <span className="attr-value highlight">{alert.event_count || 1} events</span>
                            </div>
                            <div className="entity-attribute-box">
                              <span className="attr-label">First Seen</span>
                              <span className="attr-value">{formatTimestamp(alert.created_at)}</span>
                            </div>
                            <div className="entity-attribute-box">
                              <span className="attr-label">Last Updated</span>
                              <span className="attr-value">{formatTimestamp(alert.updated_at || alert.created_at)}</span>
                            </div>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Category 2: Detection & MITRE */}
                    {currentCat === 'detection' && (
                      <div className="category-content-panel">
                        <div className="category-section">
                          <h4 className="category-heading">Triggered Sigma Detection Rules</h4>
                          {uniqueRules.length === 0 ? (
                            <p className="text-muted">No specific detection rule IDs attached.</p>
                          ) : (
                            <div className="tags-row">
                              {uniqueRules.map((rid) => (
                                <span key={rid} className="tag-pill tag-pill--rule">
                                  📋 {rid}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>

                        <div className="category-section">
                          <h4 className="category-heading">MITRE ATT&CK TTPs & Techniques</h4>
                          {uniqueMitre.length === 0 ? (
                            <p className="text-muted">No specific MITRE techniques mapped.</p>
                          ) : (
                            <div className="tags-row">
                              {uniqueMitre.map((tech) => (
                                <span key={tech} className="tag-pill tag-pill--mitre">
                                  🎯 {tech}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>

                        <div className="category-section">
                          <h4 className="category-heading">Incident Correlation Key</h4>
                          <code className="incident-id-box">{alert.incident_id || 'Unavailable'}</code>
                        </div>
                      </div>
                    )}

                    {/* Category 3: Score Breakdown */}
                    {currentCat === 'scoring' && (
                      <div className="category-content-panel">
                        <div className="score-breakdown-card">
                          <h4 className="breakdown-title">
                            <span>📊 Transparent Auditable Scoring Formula</span>
                          </h4>

                          <div className="breakdown-grid">
                            <div className="breakdown-item">
                              <span className="breakdown-item__name">Base Severity ({bd.base_severity?.label || alert.severity})</span>
                              <span className="breakdown-item__val">+{bd.base_severity?.value?.toFixed(1) || '0.0'}</span>
                            </div>

                            {bd.frequency?.value > 0 && (
                              <div className="breakdown-item">
                                <span className="breakdown-item__name">
                                  Event Frequency ({bd.frequency.event_count} events)
                                </span>
                                <span className="breakdown-item__val">+{bd.frequency.value.toFixed(1)}</span>
                              </div>
                            )}

                            {bd.mitre_techniques?.value > 0 && (
                              <div className="breakdown-item">
                                <span className="breakdown-item__name">
                                  MITRE Breadth ({bd.mitre_techniques.techniques?.join(', ')})
                                </span>
                                <span className="breakdown-item__val">+{bd.mitre_techniques.value.toFixed(1)}</span>
                              </div>
                            )}

                            {bd.critical_user?.value > 0 && (
                              <div className="breakdown-item">
                                <span className="breakdown-item__name">
                                  Critical User Privilege ('{bd.critical_user.user}')
                                </span>
                                <span className="breakdown-item__val">+{bd.critical_user.value.toFixed(1)}</span>
                              </div>
                            )}

                            {bd.critical_host?.value > 0 && (
                              <div className="breakdown-item">
                                <span className="breakdown-item__name">
                                  Critical Target Host ('{bd.critical_host.host}')
                                </span>
                                <span className="breakdown-item__val">+{bd.critical_host.value.toFixed(1)}</span>
                              </div>
                            )}

                            {bd.threat_intel?.value > 0 && (
                              <div className="breakdown-item">
                                <span className="breakdown-item__name">Threat Intel IOC Match</span>
                                <span className="breakdown-item__val">+{bd.threat_intel.value.toFixed(1)}</span>
                              </div>
                            )}

                            {bd.multi_source?.value > 0 && (
                              <div className="breakdown-item breakdown-item--multisource">
                                <span className="breakdown-item__name">
                                  ✨ Multi-Source Correlation ({bd.multi_source.sources?.join(' + ')})
                                </span>
                                <span className="breakdown-item__val">+{bd.multi_source.value.toFixed(1)}</span>
                              </div>
                            )}
                          </div>

                          <div className="breakdown-footer">
                            <span>Final Calculated Risk Score:</span>
                            <strong style={{ color: getScoreColor(alert.risk_score) }}>
                              {alert.risk_score?.toFixed(1)} / 100.0
                            </strong>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Category 4: Response Actions */}
                    {currentCat === 'response' && (
                      <div className="category-content-panel">
                        <div className="category-section">
                          <h4 className="category-heading">Analyst Response Actions</h4>
                          <p className="text-muted">Review an evidence-based plan before approving any action. Execution always requires a separate analyst decision.</p>
                          <button className="globe-btn" style={{ marginTop: 16 }} onClick={() => onRespond(alert.incident_id)}>Open response workflow →</button>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
