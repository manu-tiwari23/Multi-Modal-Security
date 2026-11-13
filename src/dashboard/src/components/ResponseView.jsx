import { useEffect, useState } from 'react'
import { requestJSON } from '../workflows.js'

function ResponseActionCard({ entry, editable, busy, onAction }) {
  const [reason, setReason] = useState('')
  const [confirmExecute, setConfirmExecute] = useState(false)
  const { approval, action, result } = entry
  return <article className="tool-card">
    <p className="eyebrow">{approval.status} · {action?.execution_status?.replaceAll('_', ' ') || 'action unavailable'}</p>
    <h2>{approval.action_title}</h2><p>{approval.action_description}</p>
    <dl className="findings-fields">{Object.entries(approval.target_entity).map(([key, value]) => <div key={key}><dt>Target {key}</dt><dd>{value}</dd></div>)}</dl>
    <p className="tool-hint">Requested {new Date(approval.requested_at).toLocaleString()}{approval.expires_at && ` · Approval expires ${new Date(approval.expires_at).toLocaleString()}`}</p>
    {approval.decided_by && <p className="tool-hint">{approval.status} by {approval.decided_by} · {approval.decision_reason || 'No reason recorded'}</p>}
    {editable && approval.status === 'pending' && <form onSubmit={event => { event.preventDefault(); onAction(`/api/ir/approvals/${encodeURIComponent(approval.request_id)}/approve`, { reason }) }}>
      <label htmlFor={`reason-${approval.request_id}`}>Decision reason</label><textarea id={`reason-${approval.request_id}`} value={reason} onChange={e => setReason(e.target.value)} required maxLength={2000} disabled={busy} rows={2} />
      <p className="tool-hint">Approval authorizes this exact action and target. Execution is a separate step.</p>
      <button disabled={busy || !reason.trim()}>Approve action</button><button type="button" className="secondary-action" disabled={busy || !reason.trim()} onClick={() => onAction(`/api/ir/approvals/${encodeURIComponent(approval.request_id)}/reject`, { reason })}>Reject action</button>
    </form>}
    {editable && approval.status === 'approved' && action?.execution_status === 'approved' && <div>
      {!confirmExecute ? <button disabled={busy} onClick={() => setConfirmExecute(true)}>Review execution</button> : <div className="tool-notice"><p>Execute the approved action above against its listed target?</p><button disabled={busy} onClick={() => { setConfirmExecute(false); onAction(`/api/ir/execute/${encodeURIComponent(action.action_id)}`, {}) }}>Execute approved action</button><button className="secondary-action" disabled={busy} onClick={() => setConfirmExecute(false)}>Cancel</button></div>}
    </div>}
    {result && <div className={result.success ? 'tool-notice' : 'tool-error'}><p>{result.success ? 'Execution completed' : 'Execution failed'} · {result.backend}</p><p>{result.message}</p><small>{new Date(result.executed_at).toLocaleString()}</small></div>}
  </article>
}

export default function ResponseView({ user }) {
  const [incidents, setIncidents] = useState([])
  const [identifier, setIdentifier] = useState('')
  const [workflow, setWorkflow] = useState(null)
  const [phase, setPhase] = useState('')
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const editable = user?.role !== 'viewer'
  useEffect(() => {
    let active = true
    requestJSON('/api/incidents').then(data => { if (active) setIncidents(data.incidents) }).catch(e => { if (active) setError(e.message) })
    return () => { active = false }
  }, [])
  async function load(id) {
    const data = await requestJSON(`/api/ir/incidents/${encodeURIComponent(id)}/workflow`)
    setWorkflow(data); setPhase(data.allowed_transitions[0] || '')
  }
  async function perform(work) {
    setBusy(true); setError('')
    try { await work() } catch (e) { setError(e.message) }
    finally { setBusy(false) }
  }
  async function mutate(path, body) {
    await perform(async () => { await requestJSON(path, body); await load(workflow.incident_id) })
  }
  return <section className="tool-page">
    <header><p className="eyebrow">INCIDENT RESPONSE</p><h1>Review. Approve. Respond.</h1><p>Inspect recommended actions and record analyst decisions before execution.</p></header>
    <form className="tool-card" onSubmit={event => { event.preventDefault(); perform(async () => { setWorkflow(null); await load(identifier.trim()) }) }}>
      <label htmlFor="response-incident">Incident ID</label><input id="response-incident" list="response-incidents" value={identifier} onChange={e => setIdentifier(e.target.value)} required maxLength={120} disabled={busy} />
      <datalist id="response-incidents">{incidents.map(incident => <option key={incident.incident_id} value={incident.incident_id}>{incident.title || incident.severity}</option>)}</datalist>
      <p className="tool-hint">Select an active incident or enter its ID from the incident view.</p><button disabled={busy || !identifier.trim()}>Load response workflow</button>
    </form>
    {error && <p role="alert" className="tool-error">{error}</p>}
    {busy && <p role="status" className="tool-hint">Updating response workflow…</p>}
    {workflow && <>
      <p className="tool-notice"><strong>Execution mode: {workflow.execution_mode}</strong><br />{workflow.execution_notice}{workflow.storage_mode === 'memory' && <><br />Response state is currently process-local and does not survive a backend restart.</>}</p>
      {workflow.configuration_matches === false && <p className="tool-error">The current execution configuration differs from the reviewed plan. Execution is blocked. Restore the reviewed configuration or create a separately reviewed incident plan.</p>}
      <section className="tool-card"><p className="eyebrow">{workflow.incident_id}</p><h2>{workflow.state ? `Phase: ${workflow.state.phase}` : 'No response plan yet'}</h2>
        <button disabled={busy} onClick={() => perform(() => load(workflow.incident_id))}>Refresh workflow</button>
        {editable && !workflow.state && <button className="secondary-action" disabled={busy} onClick={() => mutate(`/api/ir/recommend/${encodeURIComponent(workflow.incident_id)}`, {})}>Generate response plan</button>}
        {editable && workflow.state && <form onSubmit={event => { event.preventDefault(); mutate(`/api/ir/incidents/${encodeURIComponent(workflow.incident_id)}/transition`, { to_phase: phase, reason }) }}>
          <label htmlFor="response-phase">Move to phase</label><select id="response-phase" value={phase} onChange={e => setPhase(e.target.value)} disabled={busy}>{workflow.allowed_transitions.map(item => <option key={item} value={item}>{item}</option>)}</select>
          <label htmlFor="phase-reason">Reason</label><textarea id="phase-reason" value={reason} onChange={e => setReason(e.target.value)} required maxLength={2000} rows={2} disabled={busy} /><button disabled={busy || !phase || !reason.trim()}>Record phase transition</button>
        </form>}
        {workflow.state && <details className="custody-trail"><summary>Lifecycle history</summary><ol>{workflow.state.transitions.map((transition, index) => <li key={index}><strong>{transition.from_phase} → {transition.to_phase}</strong><p>{transition.transitioned_by} · {new Date(transition.transitioned_at).toLocaleString()}</p><p>{transition.reason}</p></li>)}</ol></details>}
      </section>
      {workflow.state && !workflow.actions.length && <p className="tool-notice">No response actions were recommended for the available incident evidence.</p>}
      {workflow.actions.map(entry => <ResponseActionCard key={entry.approval.request_id} entry={entry} editable={editable && workflow.configuration_matches !== false} busy={busy} onAction={mutate} />)}
    </>}
  </section>
}
