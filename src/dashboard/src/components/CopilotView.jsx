import React, { useState, useEffect, useRef } from 'react'

export default function CopilotView() {
  const [messages, setMessages] = useState([
    {
      id: 'welcome',
      role: 'assistant',
      content:
        '👋 **Hello Analyst!** I am your **AI Security Copilot**.\n\n' +
        'I am grounded in live MMS telemetry, OpenSearch logs, SOC correlated incidents, honeypot captures, and threat intelligence.\n\n' +
        '**Quick Actions:**\n' +
        '- Ask me to investigate an active incident\n' +
        '- Look up threat intelligence for an IP or hash\n' +
        '- Draft an executive & technical incident report\n' +
        '- Analyze adversary tactics and MITRE ATT&CK techniques',
      citations: [],
      tool_calls: [],
      recommendations: [],
      timestamp: new Date().toLocaleTimeString(),
    },
  ])

  const [inputPrompt, setInputPrompt] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [toolsList, setToolsList] = useState([])
  const [generatedReport, setGeneratedReport] = useState(null)
  const [reportModalOpen, setReportModalOpen] = useState(false)

  const messagesEndRef = useRef(null)

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages, isLoading])

  // Fetch loaded tools on mount
  useEffect(() => {
    fetch('/api/copilot/tools')
      .then((res) => res.json())
      .then((data) => setToolsList(data.tools || []))
      .catch(() => {})
  }, [])

  // Send query to Copilot
  const handleSend = async (customPrompt) => {
    const promptToSend = customPrompt || inputPrompt.trim()
    if (!promptToSend || isLoading) return

    const userMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: promptToSend,
      timestamp: new Date().toLocaleTimeString(),
    }

    setMessages((prev) => [...prev, userMessage])
    if (!customPrompt) setInputPrompt('')
    setIsLoading(true)

    try {
      const res = await fetch('/api/copilot/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: promptToSend }),
      })

      if (res.ok) {
        const data = await res.json()
        const assistantMessage = {
          id: `assistant-${Date.now()}`,
          role: 'assistant',
          content: data.answer || 'Analysis complete.',
          citations: data.citations || [],
          tool_calls: data.tool_calls || [],
          recommendations: data.recommendations || [],
          model: data.model,
          execution_time_ms: data.execution_time_ms,
          timestamp: new Date().toLocaleTimeString(),
        }
        setMessages((prev) => [...prev, assistantMessage])
      } else {
        setMessages((prev) => [
          ...prev,
          {
            id: `err-${Date.now()}`,
            role: 'assistant',
            content: '❌ **Error**: Failed to communicate with AI Copilot service.',
            timestamp: new Date().toLocaleTimeString(),
          },
        ])
      }
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          id: `err-${Date.now()}`,
          role: 'assistant',
          content: `❌ **Connection Error**: ${err.message}`,
          timestamp: new Date().toLocaleTimeString(),
        },
      ])
    } finally {
      setIsLoading(false)
    }
  }

  // Quick prompt buttons
  const quickPrompts = [
    { label: '🚨 Investigate Current Attack', prompt: 'Investigate the latest correlated incident and provide a technical threat breakdown.' },
    { label: '🔍 Check Attacker IP 203.0.113.88', prompt: 'Lookup threat intelligence, reputation, and honeypot activity for IP 203.0.113.88.' },
    { label: '📄 Generate Incident Report', prompt: 'Draft a complete executive and forensic incident report for the active incident.' },
    { label: '🍯 Analyze Honeypot Activity', prompt: 'Analyze recent honeypot deception sessions and summarize observed attacker commands and payloads.' },
  ]

  const handleGenerateReportQuick = async () => {
    setIsLoading(true)
    try {
      // Find active incidents
      const incRes = await fetch('/api/incidents')
      if (incRes.ok) {
        const incData = await incRes.json()
        const activeInc = incData.incidents?.[0]
        if (activeInc) {
          const repRes = await fetch('/api/copilot/reports/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ incident_id: activeInc.incident_id }),
          })
          if (repRes.ok) {
            const repData = await repRes.json()
            setGeneratedReport(repData)
            setReportModalOpen(true)
          }
        } else {
          handleSend('Draft an incident report')
        }
      }
    } catch (err) {
      console.error('Failed to generate quick report:', err)
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="view-container copilot-container">
      {/* Header */}
      <div className="view-header">
        <div>
          <h2 className="view-title">🤖 AI Security Copilot Command Center</h2>
          <p className="view-subtitle">
            Autonomous security reasoning with OpenSearch RAG, OpenAI tool calling, and human-in-the-loop containment
          </p>
        </div>
        <div className="copilot-header-actions">
          <button className="btn-action btn-action--report" onClick={handleGenerateReportQuick}>
            📑 Quick Incident Report
          </button>
          <div className="copilot-badge">
            <span className="copilot-badge__dot" />
            {toolsList.length} Active Tools
          </div>
        </div>
      </div>

      {/* Quick Prompts Bar */}
      <div className="quick-prompts-bar">
        {quickPrompts.map((qp, idx) => (
          <button
            key={idx}
            className="quick-prompt-btn"
            onClick={() => handleSend(qp.prompt)}
            disabled={isLoading}
          >
            {qp.label}
          </button>
        ))}
      </div>

      {/* Chat Messages Log */}
      <div className="chat-messages-container">
        {messages.map((m) => (
          <div key={m.id} className={`chat-message chat-message--${m.role}`}>
            <div className="chat-message__avatar">
              {m.role === 'user' ? '👨‍💻' : '🛡️'}
            </div>

            <div className="chat-message__body">
              <div className="chat-message__meta">
                <strong>{m.role === 'user' ? 'Analyst' : 'MMS AI Copilot'}</strong>
                <span className="chat-message__time">{m.timestamp}</span>
                {m.execution_time_ms ? (
                  <span className="chat-message__latency">⚡ {m.execution_time_ms.toFixed(0)}ms</span>
                ) : null}
              </div>

              {/* Tool Execution Badges */}
              {m.tool_calls && m.tool_calls.length > 0 && (
                <div className="tool-calls-bar">
                  <span className="tool-calls-bar__label">Executed Tools:</span>
                  {m.tool_calls.map((tc, i) => (
                    <span key={i} className="tool-pill">
                      🔧 <code>{tc.tool_name}({Object.keys(tc.arguments || {}).join(', ')})</code>
                    </span>
                  ))}
                </div>
              )}

              {/* Message Content */}
              <div className="chat-message__text">
                <div style={{ whiteSpace: 'pre-wrap' }}>{m.content}</div>
              </div>

              {/* Containment Recommendations Box */}
              {m.recommendations && m.recommendations.length > 0 && (
                <div className="containment-box">
                  <div className="containment-box__header">
                    <span>⚡ Recommended Containment Actions (Analyst Authorization Required)</span>
                  </div>
                  <div className="containment-box__list">
                    {m.recommendations.map((rec, i) => (
                      <div key={i} className="containment-item">
                        <div className="containment-item__action">
                          <span className="action-tag">{rec.action_type.toUpperCase()}</span>
                          <strong>{rec.target}</strong>
                        </div>
                        <p className="containment-item__rationale">{rec.rationale}</p>
                        <div className="containment-item__footer">
                          <button className="btn-approve" onClick={() => alert(`Containment Action '${rec.action_type}' for ${rec.target} submitted for execution approval!`)}>
                            ✅ Authorize Action
                          </button>
                          <span className="approval-status">Requires Level-2 Analyst Sign-off</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Evidence Citations Drawer */}
              {m.citations && m.citations.length > 0 && (
                <div className="citations-tray">
                  <div className="citations-tray__header">
                    <span>📚 Grounding Evidence Citations ({m.citations.length})</span>
                  </div>
                  <div className="citations-grid">
                    {m.citations.map((c, i) => (
                      <div key={i} className="citation-card">
                        <div className="citation-card__title">
                          <span className={`cite-badge cite-badge--${c.type}`}>{c.type.toUpperCase()}</span>
                          <strong>{c.id}</strong>
                        </div>
                        <div className="citation-card__snippet">{c.snippet || c.title}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        ))}

        {isLoading && (
          <div className="chat-message chat-message--assistant">
            <div className="chat-message__avatar">🛡️</div>
            <div className="chat-message__body">
              <div className="typing-indicator">
                <span />
                <span />
                <span />
              </div>
              <span className="typing-label">Copilot is querying logs, analyzing incidents & verifying threat intel...</span>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input Box */}
      <form
        className="copilot-input-form"
        onSubmit={(e) => {
          e.preventDefault()
          handleSend()
        }}
      >
        <input
          type="text"
          className="copilot-input"
          placeholder="Ask Copilot: 'Investigate incident INC-01', 'Lookup IP 203.0.113.88', 'Draft report'..."
          value={inputPrompt}
          onChange={(e) => setInputPrompt(e.target.value)}
          disabled={isLoading}
        />
        <button type="submit" className="copilot-send-btn" disabled={isLoading || !inputPrompt.trim()}>
          🚀 Ask Copilot
        </button>
      </form>

      {/* Report Modal */}
      {reportModalOpen && generatedReport && (
        <div className="modal-overlay" onClick={() => setReportModalOpen(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>📄 Generated Incident & Forensic Report</h3>
              <button className="modal-close-btn" onClick={() => setReportModalOpen(false)}>
                ✕
              </button>
            </div>
            <div className="modal-body">
              <pre className="report-markdown-view">{generatedReport.markdown}</pre>
            </div>
            <div className="modal-footer">
              <button
                className="btn-action"
                onClick={() => {
                  navigator.clipboard.writeText(generatedReport.markdown)
                  alert('Report copied to clipboard!')
                }}
              >
                📋 Copy Markdown
              </button>
              <button className="filter-btn" onClick={() => setReportModalOpen(false)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
