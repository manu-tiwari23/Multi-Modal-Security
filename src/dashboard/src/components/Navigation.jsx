import React from 'react'

export default function Navigation({ activeTab, setActiveTab, alertCount, sessionCount }) {
  const tabs = [
    { id: 'copilot', label: 'AI Security Copilot', icon: '🤖' },
    { id: 'alerts', label: 'SOC Alerts & Incidents', icon: '🚨', badge: alertCount },
    { id: 'honeypot', label: 'Honeypot & Deception', icon: '🍯', badge: sessionCount },
    { id: 'events', label: 'Live Telemetry', icon: '📡' },
    { id: 'rules', label: 'Sigma Rules', icon: '🎯' },
    { id: 'simulator', label: 'Attack Simulator', icon: '⚡' },
  ]

  return (
    <nav className="nav-tabs" role="tablist">
      {tabs.map((tab) => {
        const isActive = activeTab === tab.id
        return (
          <button
            key={tab.id}
            role="tab"
            aria-selected={isActive}
            className={`nav-tab ${isActive ? 'nav-tab--active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            <span className="nav-tab__icon">{tab.icon}</span>
            <span className="nav-tab__label">{tab.label}</span>
            {tab.badge !== undefined && tab.badge > 0 && (
              <span className={`nav-tab__badge ${tab.id === 'alerts' ? 'nav-tab__badge--alert' : ''}`}>
                {tab.badge}
              </span>
            )}
          </button>
        )
      })}
    </nav>
  )
}
