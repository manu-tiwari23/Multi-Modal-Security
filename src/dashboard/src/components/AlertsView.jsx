import React, { useState, useEffect, useCallback } from 'react'

export default function AlertsView({ alerts: liveAlerts }) {
  const [alerts, setAlerts] = useState([])
  const [selectedPriority, setSelectedPriority] = useState('ALL')
  const [expandedAlertId, setExpandedAlertId] = useState(null)
  const [loading, setLoading] = useState(true)

  // Fetch alerts from REST API
  const fetchAlerts = useCallback(async () => {
    try {
      const res = await fetch('/api/alerts')
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

    // Poll every 2.5s to catch new alerts seamlessly
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
      return d.toLocaleTimeString()
    } catch {
      return ts
    }
  }

  return (
    <div className="view-container">
      {/* Header & Filter Bar */}
      <div className="view-header">
        <div>
          <h2 className="view-title">SOC Correlated Alerts & Incidents</h2>
          <p className="view-subtitle">
            Deduplicated multi-stage security incidents with explainable risk scoring
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
          <h3>No alerts found for selected filter</h3>
          <p>Go to the Attack Simulator tab and click "Launch Attack Scenario" to generate alerts!</p>
        </div>
      ) : (
        <div className="alerts-grid">
          {filteredAlerts.map((alert) => {
            const isExpanded = expandedAlertId === alert.alert_id
            const bd = alert.score_breakdown || {}
            // Deduplicate rule_ids and mitre_techniques
            const uniqueRules = Array.from(new Set(alert.rule_ids || []))
            const uniqueMitre = Array.from(new Set(alert.mitre_techniques || []))

            return (
              <div
                key={alert.alert_id}
                className={`alert-card ${isExpanded ? 'alert-card--expanded' : ''}`}
              >
                <div
                  className="alert-card__header"
                  onClick={() => setExpandedAlertId(isExpanded ? null : alert.alert_id)}
                >
                  <div className="alert-card__title-row">
                    <span className={`badge-priority ${getPriorityClass(alert.priority)}`}>
                      {alert.priority}
                    </span>
                    <span className={`badge-severity badge-severity--${alert.severity}`}>
                      {alert.severity}
                    </span>
                    <h3 className="alert-card__title">{alert.title}</h3>
                  </div>

                  <div className="alert-card__score-box">
                    <div className="score-meter" style={{ borderColor: getScoreColor(alert.risk_score) }}>
                      <span className="score-meter__val" style={{ color: getScoreColor(alert.risk_score) }}>
                        {alert.risk_score ? alert.risk_score.toFixed(1) : '0.0'}
                      </span>
                      <span className="score-meter__denom">/100</span>
                    </div>
                    <span className="chevron-toggle">{isExpanded ? '▲' : '▼'}</span>
                  </div>
                </div>

                {/* Entity & Metadata Bar */}
                <div className="alert-card__meta-bar">
                  <span className="meta-pill">
                    <span className="meta-pill__label">Attacker IP:</span>
                    <code className="meta-pill__value">{alert.primary_entity?.ip || '—'}</code>
                  </span>
                  {alert.primary_entity?.user && (
                    <span className="meta-pill">
                      <span className="meta-pill__label">User:</span>
                      <code className="meta-pill__value">{alert.primary_entity.user}</code>
                    </span>
                  )}
                  {alert.primary_entity?.host && (
                    <span className="meta-pill">
                      <span className="meta-pill__label">Target Host:</span>
                      <code className="meta-pill__value">{alert.primary_entity.host}</code>
                    </span>
                  )}
                  <span className="meta-pill">
                    <span className="meta-pill__label">Events:</span>
                    <span className="meta-pill__value">{alert.event_count || 1}</span>
                  </span>
                  <span className="meta-pill">
                    <span className="meta-pill__label">Updated:</span>
                    <span className="meta-pill__value">{formatTimestamp(alert.updated_at || alert.created_at)}</span>
                  </span>
                </div>

                {/* Description narrative */}
                <p className="alert-card__desc">{alert.description}</p>

                {/* Unique Tags & MITRE badges */}
                <div className="tags-row">
                  {uniqueRules.map((rid) => (
                    <span key={rid} className="tag-pill tag-pill--rule">
                      📋 {rid}
                    </span>
                  ))}
                  {uniqueMitre.map((tech) => (
                    <span key={tech} className="tag-pill tag-pill--mitre">
                      🎯 {tech}
                    </span>
                  ))}
                </div>

                {/* Expanded Score Breakdown Card */}
                {isExpanded && (
                  <div className="score-breakdown-card">
                    <h4 className="breakdown-title">
                      <span>📊 Transparent Score Breakdown (Auditable Calculation)</span>
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
                      <span>Final Computed Score:</span>
                      <strong style={{ color: getScoreColor(alert.risk_score) }}>
                        {alert.risk_score?.toFixed(1)} / 100.0
                      </strong>
                    </div>
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
