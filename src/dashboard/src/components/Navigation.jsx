const tabs = [
  ['overview', 'Overview', '◉'], ['alerts', 'Incidents', '◎'],
  ['intelligence', 'Intelligence', '◇'], ['honeypot', 'Honeypot', '⬡'],
  ['phishing', 'Phishing', '⌁'], ['forensics', 'Forensics', '▧'], ['reports', 'Reports', '▤'],
  ['events', 'Telemetry', '≋'], ['rules', 'Detection rules', '⌘'],
  ['response', 'Response', '↗'], ['account', 'Account & access', '⚙'],
  ['simulator', 'Simulation lab', '↯'],
]

export default function Navigation({ activeTab, setActiveTab, alertCount, role }) {
  return <nav className="workspace-nav" aria-label="Workspace">
    {tabs.filter(([id]) => role !== 'viewer' || id !== 'simulator').map(([id, label, icon]) =>
      <button key={id} aria-current={activeTab === id ? 'page' : undefined} onClick={() => setActiveTab(id)}>
        <span aria-hidden="true">{icon}</span>{label}
        {id === 'alerts' && alertCount > 0 && <small>{alertCount}</small>}
      </button>)}
  </nav>
}
