import { apiFetch } from '../api.js'
import React, { useState, useEffect } from 'react'

export default function RulesView() {
  const [rules, setRules] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchRules = async () => {
      try {
        const res = await apiFetch('/api/rules')
        if (res.ok) {
          const data = await res.json()
          setRules(data.rules || [])
        }
      } catch (err) {
        console.error('Failed to fetch rules:', err)
      } finally {
        setLoading(false)
      }
    }
    fetchRules()
  }, [])

  return (
    <div className="view-container">
      <div className="view-header">
        <div>
          <h2 className="view-title">Sigma Detection Rules</h2>
          <p className="view-subtitle">
            Declarative detection rules supporting sliding-window aggregations and MITRE ATT&CK tagging
          </p>
        </div>
      </div>

      {loading ? (
        <div className="empty-state">Loading detection rules...</div>
      ) : (
        <div className="rules-grid">
          {rules.map((rule) => (
            <div key={rule.id} className="rule-card">
              <div className="rule-card__header">
                <div>
                  <span className="rule-card__id">{rule.id}</span>
                  <h3 className="rule-card__title">{rule.title}</h3>
                </div>
                <span className={`badge-severity badge-severity--${rule.severity}`}>
                  {rule.severity}
                </span>
              </div>

              <p className="rule-card__desc">{rule.description}</p>

              {/* Threshold info if aggregation rule */}
              {rule.detection?.threshold && (
                <div className="rule-threshold-box">
                  <span>⏱️ Sliding Window:</span>
                  <strong>{rule.detection.threshold.count} events</strong> within{' '}
                  <strong>{rule.detection.threshold.timeframe}s</strong> grouped by{' '}
                  <code>{rule.detection.threshold.by?.join(', ')}</code>
                </div>
              )}

              {/* Selection Criteria */}
              <div className="rule-criteria">
                <span className="criteria-label">Selection Criteria:</span>
                <pre className="criteria-code">
                  {JSON.stringify(rule.detection?.selection || {}, null, 2)}
                </pre>
              </div>

              {/* MITRE Tags */}
              <div className="tags-row">
                {rule.tags?.map((t) => (
                  <span key={t} className="tag-pill tag-pill--rule">
                    {t}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

