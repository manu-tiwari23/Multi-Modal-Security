import { apiFetch } from '../api.js'
import React, { useState } from 'react'

export default function SimulatorView({ onSimulationSuccess }) {
  const [attackerIp, setAttackerIp] = useState('203.0.113.88')
  const [runningScenario, setRunningScenario] = useState(null)
  const [simulationLogs, setSimulationLogs] = useState([])
  const [lastResult, setLastResult] = useState(null)

  const scenarios = [
    {
      id: 'multistage',
      title: 'Full Multi-Modal Cross Attack',
      icon: '🔥',
      badge: 'Recommended Demo',
      desc: 'Simulates SSH brute force on production, sudo root escalation, and a pivot to the deceptive honeypot. Triggers full pipeline correlation & Multi-Source Risk Bonus (+5.0)!',
      tags: ['SOC Syslog', 'Honeypot Deception', 'Multi-Source', 'Risk Scoring 80+'],
    },
    {
      id: 'ssh_brute_force',
      title: 'SSH Password Brute Force',
      icon: '🔨',
      badge: 'Phase 2 Detection',
      desc: 'Generates 5 rapid failed SSH authentications from the same IP within 60s window. Triggers sliding-window threshold rule SOC-RULE-001 (T1110).',
      tags: ['Threshold Aggregation', 'T1110', 'Sliding Window 60s'],
    },
    {
      id: 'sudo_escalation',
      title: 'Sudo Privilege Escalation',
      icon: '⚡',
      badge: 'Phase 2 Severity Escalation',
      desc: 'Opens an interactive session on prod-web-01 and executes high-risk sudo /bin/bash. Triggers SOC-RULE-002 and escalates incident severity.',
      tags: ['T1548.003', 'Critical User (root)', 'Severity Escalation'],
    },
    {
      id: 'honeypot_pivot',
      title: 'Honeypot Probe & Dropper Ingress',
      icon: '🍯',
      badge: 'Phase 3 Honeypot',
      desc: 'Attacker connects to honeypot-ssh-01, tests credentials, runs recon, and downloads an ELF malware payload via wget. Captures artifacts & session telemetry.',
      tags: ['Virtual Shell', 'T1105 Dropper', 'Artifact Hash', 'TTP Clustering'],
    },
  ]

  const runScenario = async (scenarioId) => {
    setRunningScenario(scenarioId)
    setLastResult(null)
    setSimulationLogs((prev) => [
      `[${new Date().toLocaleTimeString()}] Starting scenario: ${scenarioId} from IP ${attackerIp}...`,
      ...prev,
    ])

    try {
      const res = await apiFetch('/api/simulate/attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: scenarioId, attacker_ip: attackerIp }),
      })

      if (res.ok) {
        const data = await res.json()
        setLastResult(data)
        setSimulationLogs((prev) => [
          `[${new Date().toLocaleTimeString()}] ✓ Ingested ${data.events_ingested} event(s). Active Alerts: ${data.total_active_alerts}.`,
          `[${new Date().toLocaleTimeString()}] 🚨 Scored Alert: "${data.top_alert?.title || 'Correlated Incident'}" (Risk Score: ${data.top_alert?.risk_score?.toFixed(1) || '—'}/100)`,
          ...prev,
        ])
        if (onSimulationSuccess) {
          onSimulationSuccess(data)
        }
      } else {
        setSimulationLogs((prev) => [
          `[${new Date().toLocaleTimeString()}] ❌ Simulation failed: HTTP ${res.status}`,
          ...prev,
        ])
      }
    } catch (err) {
      setSimulationLogs((prev) => [
        `[${new Date().toLocaleTimeString()}] ❌ Network error: ${err.message}`,
        ...prev,
      ])
    } finally {
      setRunningScenario(null)
    }
  }

  return (
    <div className="view-container">
      <div className="view-header">
        <div>
          <h2 className="view-title">Interactive Attack Simulator</h2>
          <p className="view-subtitle">
            Trigger real-time simulated attack scenarios and observe the entire detection & correlation pipeline
          </p>
        </div>

        <div className="sim-ip-box">
          <label className="sim-ip-label">Simulated Attacker IP:</label>
          <input
            type="text"
            className="sim-ip-input"
            value={attackerIp}
            onChange={(e) => setAttackerIp(e.target.value)}
            placeholder="203.0.113.88"
          />
        </div>
      </div>

      {/* Scenarios Grid */}
      <div className="scenarios-grid">
        {scenarios.map((sc) => {
          const isRunning = runningScenario === sc.id
          return (
            <div key={sc.id} className="scenario-card">
              <div className="scenario-card__header">
                <span className="scenario-card__icon">{sc.icon}</span>
                <div>
                  <span className="scenario-badge">{sc.badge}</span>
                  <h3 className="scenario-card__title">{sc.title}</h3>
                </div>
              </div>

              <p className="scenario-card__desc">{sc.desc}</p>

              <div className="scenario-tags">
                {sc.tags.map((t) => (
                  <span key={t} className="scenario-tag">
                    {t}
                  </span>
                ))}
              </div>

              <button
                className={`btn-launch ${isRunning ? 'btn-launch--running' : ''}`}
                disabled={runningScenario !== null}
                onClick={() => runScenario(sc.id)}
              >
                {isRunning ? '⚡ Ingesting Events...' : '🚀 Launch Attack Scenario'}
              </button>
            </div>
          )
        })}
      </div>

      {/* Real-time Simulator Execution Console */}
      <div className="sim-console">
        <div className="sim-console__header">
          <span className="sim-console__title">🖥️ Simulator Telemetry Stream</span>
          <button className="btn-clear" onClick={() => setSimulationLogs([])}>
            Clear
          </button>
        </div>
        <div className="sim-console__body">
          {simulationLogs.length === 0 ? (
            <div className="console-empty">
              Click "Launch Attack Scenario" above to execute a simulated attack and view live telemetry.
            </div>
          ) : (
            simulationLogs.map((log, i) => (
              <div key={i} className="console-line">
                {log}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}

