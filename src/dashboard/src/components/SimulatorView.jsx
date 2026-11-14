import { useMemo, useState } from 'react'
import {
  Activity, ArrowRight, Check, Clipboard, Download, FileArchive,
  Clock3, FlaskConical, Globe2, MailWarning, Play, Radar, ShieldCheck,
  TerminalSquare, TriangleAlert,
} from 'lucide-react'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { apiFetch } from '../api.js'
import { makeActivityBuckets, makeSeverityData, makeSourceData } from '../telemetryData.js'

const scenarios = [
  {
    id: 'multistage', title: 'Full platform showcase', icon: Radar, badge: 'Recommended', tone: 'critical',
    desc: 'Runs one connected story across SOC telemetry, privilege escalation, honeypot deception and phishing analysis.',
    tags: ['SOC', 'Honeypot', 'Phishing', 'Correlation'],
    stages: ['SSH failures', 'Root session', 'Honeypot pivot', 'Phishing ingress'],
  },
  {
    id: 'ssh_brute_force', title: 'SSH brute force', icon: TerminalSquare, badge: 'SOC pipeline', tone: 'warning',
    desc: 'Generates five rapid failed authentications to demonstrate threshold detection, scoring and incident creation.',
    tags: ['T1110', '60 sec window', 'Risk scoring'], stages: ['Generate logs', 'Detect threshold', 'Create incident'],
  },
  {
    id: 'sudo_escalation', title: 'Privilege escalation', icon: ShieldCheck, badge: 'Incident response', tone: 'warning',
    desc: 'Creates a root session and elevated command to demonstrate severity escalation and the approval-gated response path.',
    tags: ['T1548.003', 'Root session', 'Approval gate'], stages: ['Open session', 'Escalate severity', 'Plan response'],
  },
  {
    id: 'honeypot_pivot', title: 'Honeypot probe', icon: ShieldCheck, badge: 'Deception', tone: 'warning',
    desc: 'Records a synthetic shell session, reconnaissance commands and an inert payload download inside the deceptive service.',
    tags: ['Session capture', 'T1105', 'Artifact metadata'], stages: ['Connect', 'Capture commands', 'Cluster behavior'],
  },
  {
    id: 'phishing_campaign', title: 'Phishing campaign', icon: MailWarning, badge: 'Email analysis', tone: 'info',
    desc: 'Publishes a safe synthetic spear-phishing message with urgency, lookalike and credential-request signals.',
    tags: ['Email parser', 'URL signals', 'Explanation'], stages: ['Parse email', 'Score signals', 'Publish finding'],
  },
]

const demoArtifacts = [
  {
    key: 'ip', label: 'Reserved attacker IP', type: 'IP address', icon: Globe2,
    value: '203.0.113.88', destination: 'intelligence', action: 'Open intelligence',
    note: 'RFC 5737 documentation address; safe for demonstrations.',
  },
  {
    key: 'domain', label: 'Lookalike-style domain', type: 'Domain', icon: TriangleAlert,
    value: 'account-verification.example.test', destination: 'intelligence', action: 'Open intelligence',
    note: '.test is reserved and cannot resolve on the public internet.',
  },
  {
    key: 'url', label: 'Credential lure URL', type: 'URL', icon: MailWarning,
    value: 'http://secure-login.example.test/verify/account?session=demo', destination: 'phishing', action: 'Open phishing',
    note: 'Safe non-resolving URL containing signals the scanner can explain.',
  },
  {
    key: 'hash', label: 'Demo evidence hash', type: 'SHA-256', icon: FileArchive,
    value: 'f36f9731c93cebe6dd00be680e7049d69261100c9e5ff00fe110752b6fbd9694', destination: 'intelligence', action: 'Open intelligence',
    note: 'SHA-256 of suspicious-invoice.txt for a reproducible file lookup.',
  },
]

const demoFiles = [
  { name: 'phishing-demo.eml', use: 'Email analysis', href: '/demo/phishing-demo.eml' },
  { name: 'auth-telemetry.log', use: 'Forensic evidence', href: '/demo/auth-telemetry.log' },
  { name: 'suspicious-invoice.txt', use: 'Attachment analysis', href: '/demo/suspicious-invoice.txt' },
  { name: 'demo-data-guide.txt', use: 'Presenter guide', href: '/demo/demo-data-guide.txt' },
]

function validDemoIp(value) {
  const parts = value.trim().split('.')
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
}

export default function SimulatorView({ onSimulationSuccess, onNavigate, events = [], liveAlerts = [] }) {
  const [attackerIp, setAttackerIp] = useState('203.0.113.88')
  const [runningScenario, setRunningScenario] = useState(null)
  const [simulationLogs, setSimulationLogs] = useState([])
  const [lastResult, setLastResult] = useState(null)
  const [copied, setCopied] = useState('')
  const [error, setError] = useState('')
  const activityData = useMemo(() => makeActivityBuckets(events), [events])
  const severityData = useMemo(() => makeSeverityData(events), [events])
  const sourceData = useMemo(() => makeSourceData(events), [events])
  const recentDemoEvents = useMemo(() => events.filter((event) => (
    event.raw?.simulated || event.enrichment?.simulation_scenario || ['phishing', 'honeypot'].includes(event.source)
  )).slice(0, 6), [events])

  async function copyArtifact(artifact) {
    try {
      await navigator.clipboard.writeText(artifact.value)
      setCopied(artifact.key)
      window.setTimeout(() => setCopied(''), 1800)
    } catch {
      setError('Clipboard access is unavailable. Select the indicator text and copy it manually.')
    }
  }

  function openArtifact(artifact) {
    sessionStorage.setItem('mms-demo-artifact', JSON.stringify({
      destination: artifact.destination,
      type: artifact.type,
      value: artifact.value,
    }))
    onNavigate?.(artifact.destination)
  }

  async function runScenario(scenarioId) {
    if (!validDemoIp(attackerIp)) {
      setError('Enter a valid IPv4 address. Use 203.0.113.88 for a safe documentation-only demo.')
      return
    }
    setError('')
    setRunningScenario(scenarioId)
    setLastResult(null)
    const scenario = scenarios.find((item) => item.id === scenarioId)
    setSimulationLogs((prev) => [
      { status: 'running', text: `Dispatching ${scenario?.title || scenarioId} from ${attackerIp}` }, ...prev,
    ])
    try {
      const response = await apiFetch('/api/simulate/attack', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: scenarioId, attacker_ip: attackerIp }),
      })
      if (!response.ok) throw new Error(`request returned HTTP ${response.status}`)
      const data = await response.json()
      setLastResult(data)
      setSimulationLogs((prev) => [
        { status: 'success', text: `${data.events_ingested} pipeline result(s) ingested • ${data.total_active_alerts} active alert(s)` },
        { status: 'success', text: `${data.top_alert?.title || 'Pipeline completed'} • risk ${data.top_alert?.risk_score?.toFixed?.(1) || '—'}/100` },
        ...prev.filter((line) => line.status !== 'running'),
      ])
      await onSimulationSuccess?.(data)
    } catch (requestError) {
      setSimulationLogs((prev) => [
        { status: 'error', text: `Simulation failed: ${requestError.message}` }, ...prev.filter((line) => line.status !== 'running'),
      ])
    } finally {
      setRunningScenario(null)
    }
  }

  async function openPhishingEmailDemo() {
    setError('')
    try {
      const response = await fetch('/demo/phishing-demo.eml')
      if (!response.ok) throw new Error('Unable to load the demo email. Please retry.')
      openArtifact({ destination: 'phishing', type: 'email', value: await response.text() })
    } catch (error) {
      setError(error.message)
    }
  }

  return (
    <div className="view-container simulation-lab">
      <section className="simulation-hero" aria-labelledby="simulation-title">
        <div>
          <div className="simulation-kicker"><FlaskConical size={14} /> Safe demonstration workspace</div>
          <h1 id="simulation-title">Simulation Lab</h1>
          <p>Launch controlled synthetic activity, watch it cross the real analysis pipeline, then open each workspace to tell the complete investigation story.</p>
          <div className="simulation-safety"><ShieldCheck size={16} /> Reserved indicators and inert files only. No external target is contacted.</div>
        </div>
        <div className="simulation-source-card">
          <label htmlFor="sim-attacker-ip">Synthetic source IP</label>
          <div className="simulation-source-input">
            <input id="sim-attacker-ip" value={attackerIp} onChange={(event) => setAttackerIp(event.target.value)} spellCheck={false} />
            <button type="button" onClick={() => setAttackerIp('203.0.113.88')}>Reset</button>
          </div>
          <small>Use an RFC 5737 address when presenting.</small>
        </div>
      </section>

      {error && <div className="simulation-error" role="alert">{error}</div>}

      <section className="simulation-journey" aria-label="Demonstration journey">
        {['Generate synthetic activity', 'Detect and correlate', 'Investigate evidence', 'Approve response'].map((step, index) => (
          <div key={step}><span>{index + 1}</span><strong>{step}</strong>{index < 3 && <ArrowRight size={15} />}</div>
        ))}
      </section>

      <section className="simulation-section" aria-labelledby="scenarios-heading">
        <div className="simulation-section-heading">
          <div><span>01</span><div><h2 id="scenarios-heading">Choose a scenario</h2><p>Each run uses the same detection and correlation pipeline as normal telemetry.</p></div></div>
          {runningScenario && <div className="simulation-running"><Activity size={15} /> Running scenario</div>}
        </div>
        <div className="scenarios-grid">
          {scenarios.map((scenario) => {
            const ScenarioIcon = scenario.icon
            const isRunning = runningScenario === scenario.id
            return (
              <article key={scenario.id} className={`scenario-card scenario-card--${scenario.tone}`}>
                <div className="scenario-card__header">
                  <span className="scenario-card__icon"><ScenarioIcon size={22} /></span>
                  <div><span className="scenario-badge">{scenario.badge}</span><h3 className="scenario-card__title">{scenario.title}</h3></div>
                </div>
                <p className="scenario-card__desc">{scenario.desc}</p>
                <div className="scenario-flow">{scenario.stages.map((stage, index) => <span key={stage}>{index + 1}. {stage}</span>)}</div>
                <div className="scenario-tags">{scenario.tags.map((tag) => <span key={tag} className="scenario-tag">{tag}</span>)}</div>
                <button className={`btn-launch ${isRunning ? 'btn-launch--running' : ''}`} disabled={runningScenario !== null} onClick={() => runScenario(scenario.id)}>
                  {isRunning ? <><Activity size={16} /> Ingesting events</> : <><Play size={16} /> Launch scenario</>}
                </button>
              </article>
            )
          })}
        </div>
      </section>

      <section className="simulation-section" aria-labelledby="phishing-demo-heading">
        <div className="simulation-section-heading"><div><MailWarning size={22} /><div><h2 id="phishing-demo-heading">Phishing demo</h2><p>Inspect a synthetic account-verification email, analyze its lure URL, or publish a campaign into telemetry.</p></div></div></div>
        <article className="demo-downloads">
          <h3>URGENT: Verify your account within 24 hours</h3>
          <p className="tool-hint">From: security-alerts@account-verification.example.test</p>
          <p>Your account requires immediate verification. Sign in using the verification link.</p>
          <p className="tool-hint">Look for urgency, credential requests and suspicious link signals. This sample uses reserved .test domains.</p>
          <div className="demo-artifact__actions">
            <button type="button" onClick={openPhishingEmailDemo}>Open demo email <ArrowRight size={14} /></button>
            <button type="button" onClick={() => openArtifact(demoArtifacts.find(item => item.key === 'url'))}>Analyze demo URL <ArrowRight size={14} /></button>
            <button type="button" disabled={runningScenario !== null} onClick={() => runScenario('phishing_campaign')}>{runningScenario === 'phishing_campaign' ? 'Running phishing demo…' : 'Run phishing campaign'}</button>
          </div>
        </article>
      </section>

      <section className="simulation-section demo-kit" aria-labelledby="demo-kit-heading">
        <div className="simulation-section-heading"><div><span>02</span><div><h2 id="demo-kit-heading">Demo data kit</h2><p>Copy indicators or download safe files to demonstrate intelligence, phishing and forensics.</p></div></div></div>
        <div className="demo-kit-grid">
          <div className="demo-indicators">
            {demoArtifacts.map((artifact) => {
              const ArtifactIcon = artifact.icon
              return <article className="demo-artifact" key={artifact.key}>
                <div className="demo-artifact__icon"><ArtifactIcon size={18} /></div>
                <div className="demo-artifact__body"><div><span>{artifact.type}</span><strong>{artifact.label}</strong></div><code>{artifact.value}</code><small>{artifact.note}</small></div>
                <div className="demo-artifact__actions">
                  <button type="button" onClick={() => copyArtifact(artifact)}>{copied === artifact.key ? <Check size={15} /> : <Clipboard size={15} />} {copied === artifact.key ? 'Copied' : 'Copy'}</button>
                  <button type="button" onClick={() => openArtifact(artifact)}>{artifact.action} <ArrowRight size={14} /></button>
                </div>
              </article>
            })}
          </div>
          <aside className="demo-downloads">
            <div className="demo-downloads__heading"><Download size={19} /><div><h3>Safe sample files</h3><p>Download, then upload through the matching workflow.</p></div></div>
            {demoFiles.map((file) => <a key={file.name} href={file.href} download><FileArchive size={17} /><span><strong>{file.name}</strong><small>{file.use}</small></span><Download size={15} /></a>)}
          </aside>
        </div>
      </section>

      <section className="simulation-section simulation-analytics" aria-labelledby="simulation-analytics-heading">
        <div className="simulation-section-heading">
          <div><span>03</span><div><h2 id="simulation-analytics-heading">Simulation telemetry</h2><p>Recent activity and severity update from the same live event snapshot used by the dashboard.</p></div></div>
          <div className="simulation-running"><Activity size={15} /> {events.length} events · {liveAlerts.length} alerts</div>
        </div>
        <div className="simulation-source-summary" aria-label="Telemetry sources">
          {sourceData.map((item) => <div key={item.source} className={item.source === 'phishing' ? 'is-phishing' : ''}><span>{item.label}</span><strong>{item.count}</strong></div>)}
        </div>
        <div className="charts-section-grid simulation-chart-grid">
          <div className="chart-card">
            <div className="chart-header"><div><h2 className="chart-title">Recent activity</h2><p className="chart-subtitle">Loaded events in the last 24 hours · includes phishing</p></div><span className="chart-legend-badge"><span className="legend-dot" style={{ background: '#6ee7d2' }} /> Events</span></div>
            <div className="simulation-chart-canvas">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={activityData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs><linearGradient id="simEventAreaGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#6ee7d2" stopOpacity={0.34} /><stop offset="95%" stopColor="#6ee7d2" stopOpacity={0} /></linearGradient></defs>
                  <CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false} />
                  <XAxis dataKey="label" tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <YAxis allowDecimals={false} tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: '#0d1520', border: '1px solid rgba(255,255,255,0.12)', borderRadius: 10, color: '#f8fafc', fontSize: 12 }} />
                  <Area type="monotone" dataKey="events" name="Events" stroke="#6ee7d2" strokeWidth={2} fill="url(#simEventAreaGrad)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
          <div className="chart-card">
            <div className="chart-header"><div><h2 className="chart-title">Severity Breakdown</h2><p className="chart-subtitle">Severity of all loaded simulation and analysis events</p></div><Clock3 size={15} className="text-slate-500" /></div>
            <div className="simulation-chart-canvas">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severityData} layout="vertical" margin={{ top: 5, right: 15, left: 10, bottom: 5 }}>
                  <XAxis type="number" hide allowDecimals={false} />
                  <YAxis type="category" dataKey="severity" width={68} tick={{ fill: '#94a3b8', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <Tooltip cursor={{ fill: 'rgba(255,255,255,0.03)' }} contentStyle={{ background: '#0d1520', border: '1px solid rgba(255,255,255,0.12)', borderRadius: 10, color: '#f8fafc', fontSize: 12 }} />
                  <Bar dataKey="count" name="Count" fill="#38bdf8" radius={[0, 4, 4, 0]} barSize={14} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
        <div className="simulation-recent-events">
          <div className="simulation-recent-events__heading"><strong>Latest demonstration activity</strong><button onClick={() => onNavigate?.('events')}>Open Telemetry <ArrowRight size={14} /></button></div>
          {recentDemoEvents.length === 0 ? <p>No simulation or phishing telemetry is loaded yet. Launch a scenario or add a demo node.</p> : recentDemoEvents.map((event) => <article key={event.event_id}>
            <span className={`simulation-event-source source-${event.source}`}>{event.source}</span>
            <div><strong>{event.event_type?.replaceAll('_', ' ') || 'security event'}</strong><small>{event.entity?.host || 'No host'} · {event.entity?.ip || 'No IP'} · {new Date(event.timestamp).toLocaleTimeString()}</small></div>
            <span className={`simulation-event-severity severity-${event.severity}`}>{event.severity}</span>
          </article>)}
        </div>
      </section>

      <section className="simulation-section simulation-output" aria-labelledby="output-heading">
        <div className="simulation-section-heading"><div><span>04</span><div><h2 id="output-heading">Live run output</h2><p>Results are synthetic but the processing path and resulting workspace records are real.</p></div></div>{simulationLogs.length > 0 && <button className="btn-clear" onClick={() => { setSimulationLogs([]); setLastResult(null) }}>Clear output</button>}</div>
        {lastResult && <div className="simulation-result-strip">
          <div><span>Scenario</span><strong>{scenarios.find((item) => item.id === lastResult.scenario)?.title || lastResult.scenario}</strong></div>
          <div><span>Pipeline results</span><strong>{lastResult.events_ingested}</strong></div>
          <div><span>Active alerts</span><strong>{lastResult.total_active_alerts}</strong></div>
          <div><span>Top risk</span><strong>{lastResult.top_alert?.risk_score?.toFixed?.(1) || '—'}</strong></div>
          <button onClick={() => onNavigate?.('alerts')}>Open incidents <ArrowRight size={15} /></button>
        </div>}
        <div className="sim-console">
          <div className="sim-console__header"><span className="sim-console__title"><Activity size={15} /> Pipeline activity</span><span>synthetic telemetry</span></div>
          <div className="sim-console__body" aria-live="polite">
            {simulationLogs.length === 0 ? <div className="console-empty">No scenario has run in this session. Choose “Full platform showcase” for the broadest demonstration.</div> : simulationLogs.map((line, index) => <div key={`${line.text}-${index}`} className={`console-line console-line--${line.status}`}><span>{line.status === 'success' ? '✓' : line.status === 'error' ? '!' : '•'}</span>{line.text}</div>)}
          </div>
        </div>
      </section>
    </div>
  )
}
