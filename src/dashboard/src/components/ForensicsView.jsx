import { useEffect, useState } from 'react'
import { downloadFile, fileBase64, requestJSON } from '../workflows.js'

const analysisKinds = [['file', 'File analysis and carving'], ['metadata', 'Document / image metadata'], ['browser', 'Browser SQLite snapshot'], ['browser_bundle', 'Browser ZIP bundle with WAL'], ['browser_cache_har', 'Browser cache HAR export'], ['usb_setupapi', 'Windows SetupAPI log'], ['usb_registry', 'USB registry text export'], ['usb_syslog', 'Linux USB log']]
function Findings({ value }) {
  if (value === null || value === undefined) return <span>Unknown</span>
  if (typeof value !== 'object') return <span>{String(value)}</span>
  if (Array.isArray(value)) return value.length ? <ol className="findings-list">{value.map((item, index) => <li key={index}><Findings value={item} /></li>)}</ol> : <span>None recorded</span>
  return <dl className="findings-fields">{Object.entries(value).map(([key, item]) => <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{typeof item === 'object' && item !== null ? <details><summary>View {Array.isArray(item) ? `${item.length} records` : 'details'}</summary><Findings value={item} /></details> : <Findings value={item} />}</dd></div>)}</dl>
}

export default function ForensicsView({ user }) {
  const [caseId, setCaseId] = useState('')
  const [loadedCase, setLoadedCase] = useState('')
  const [items, setItems] = useState([])
  const [selected, setSelected] = useState(null)
  const [file, setFile] = useState(null)
  const [host, setHost] = useState('')
  const [deletionMetadata, setDeletionMetadata] = useState('')
  const [deletionContent, setDeletionContent] = useState('')
  const [kind, setKind] = useState('file')
  const [analysis, setAnalysis] = useState(null)
  const [status, setStatus] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const editable = user?.role !== 'viewer'
  async function refresh(scope = loadedCase) {
    const data = await requestJSON(`/api/forensics/evidence${scope ? `?case_id=${encodeURIComponent(scope)}` : ''}`)
    setItems(data.evidence)
  }
  useEffect(() => {
    let active = true
    setBusy(true)
    requestJSON('/api/forensics/evidence').then(data => { if (active) setItems(data.evidence) }).catch(e => { if (active) setError(e.message) }).finally(() => { if (active) setBusy(false) })
    return () => { active = false }
  }, [])
  async function action(work) {
    setBusy(true); setError(''); setStatus(null)
    try { await work() } catch (e) { setError(e.message) }
    finally { setBusy(false) }
  }
  async function selectEvidence(item) {
    await action(async () => {
      setAnalysis(null); setSelected(null)
      setSelected(await requestJSON(`/api/forensics/evidence/${encodeURIComponent(item.evidence_id)}`))
    })
  }
  async function upload(event) {
    event.preventDefault()
    await action(async () => {
      const evidence = await requestJSON('/api/forensics/evidence', { filename: file?.name, content_base64: await fileBase64(file), case_id: caseId.trim(), source_host: host.trim() || null })
      setLoadedCase(caseId.trim()); await refresh(caseId.trim()); setSelected(evidence); setAnalysis(null)
      setStatus({ message: 'Evidence stored. Hashes and acquisition identity recorded.', evidence_id: evidence.evidence_id })
    })
  }
  const evidencePath = selected ? `/api/forensics/evidence/${encodeURIComponent(selected.evidence_id)}` : ''
  return <section className="tool-page">
    <header><p className="eyebrow">DIGITAL FORENSICS</p><h1>Follow the evidence</h1><p>Preserve originals, verify integrity and investigate recorded artifacts.</p></header>
    <form className="tool-card" onSubmit={event => { event.preventDefault(); action(async () => { await refresh(caseId.trim()); setLoadedCase(caseId.trim()); setSelected(null); setAnalysis(null) }) }}>
      <label htmlFor="evidence-case">Case ID · leave empty to list all evidence</label><input id="evidence-case" value={caseId} onChange={e => setCaseId(e.target.value)} maxLength={120} pattern="[A-Za-z0-9_-]+" disabled={busy} />
      <button disabled={busy}>Load evidence</button>
      {editable && loadedCase && <button type="button" className="secondary-action" disabled={busy} onClick={() => action(async () => { setStatus(await requestJSON(`/api/forensics/cases/${encodeURIComponent(loadedCase)}/verify`, {})); await refresh() })}>Verify loaded case</button>}
    </form>
    {editable && <details className="tool-card"><summary>Add evidence to a case</summary><form onSubmit={upload}>
      <p className="tool-hint">Use the case ID above. Acquired by {user.username}; identity is bound to your session. This interface accepts files up to 10 MiB; server limits may be lower.</p>
      <label htmlFor="evidence-file">Evidence file</label><input id="evidence-file" type="file" required disabled={busy} onChange={e => setFile(e.target.files[0] || null)} />
      <label htmlFor="evidence-host">Source host (optional)</label><input id="evidence-host" value={host} maxLength={250} disabled={busy} onChange={e => setHost(e.target.value)} />
      <button disabled={busy || !/^[A-Za-z0-9_-]{1,120}$/.test(caseId.trim()) || !file}>Store evidence</button>
    </form></details>}
    {editable && <details className="tool-card"><summary>Recover a deleted-file pair</summary>
      <form onSubmit={event => { event.preventDefault(); action(async () => {
        const result = await requestJSON('/api/forensics/recover-deleted', { metadata_evidence_id: deletionMetadata, content_evidence_id: deletionContent })
        await refresh(); setSelected(result.evidence); setAnalysis(null); setStatus(result.recovery)
      }) }}>
        <p className="tool-hint">Upload both partners into the same case first. Select a Windows $I / $R pair, or a .trashinfo file and its matching stored content. Both are hash-verified; recovery creates a new evidence item linked to the originals.</p>
        <label htmlFor="deleted-metadata">Deletion metadata</label><select id="deleted-metadata" required value={deletionMetadata} disabled={busy} onChange={e => setDeletionMetadata(e.target.value)}><option value="">Select metadata</option>{items.filter(item => item.filename.startsWith('$I') || item.filename.endsWith('.trashinfo')).map(item => <option value={item.evidence_id} key={item.evidence_id}>{item.filename} · {item.case_id} · {item.evidence_id.slice(0, 8)}</option>)}</select>
        <label htmlFor="deleted-content">Matching content</label><select id="deleted-content" required value={deletionContent} disabled={busy} onChange={e => setDeletionContent(e.target.value)}><option value="">Select content</option>{items.filter(item => item.evidence_id !== deletionMetadata).map(item => <option value={item.evidence_id} key={item.evidence_id}>{item.filename} · {item.case_id} · {item.evidence_id.slice(0, 8)}</option>)}</select>
        <button disabled={busy || !deletionMetadata || !deletionContent}>Preserve recovered file</button>
      </form>
    </details>}
    {error && <p className="tool-error" role="alert">{error}</p>}
    <p role="status" className="tool-hint">{busy ? 'Working…' : `${items.length} evidence items · ${loadedCase || 'all cases'}`}</p>
    <div className="evidence-layout">
      <div className="evidence-list" aria-label="Stored evidence">{items.map(item => <button key={item.evidence_id} disabled={busy} aria-pressed={selected?.evidence_id === item.evidence_id} onClick={() => selectEvidence(item)}><strong>{item.filename}</strong><small>{item.case_id} · {item.file_size_bytes.toLocaleString()} bytes</small>{item.is_tampered && <span className="tool-error">Integrity investigation required</span>}</button>)}{!busy && !items.length && <p className="tool-hint">No evidence found. Load another case or add an evidence file.</p>}</div>
      {selected && <article className="tool-card evidence-detail">
        <p className="eyebrow">EVIDENCE RECORD</p><h2>{selected.filename}</h2><p className="hash-text">ID: {selected.evidence_id}</p><p className="hash-text">SHA-256: {selected.sha256}</p><p className="hash-text">MD5: {selected.md5}</p>
        <p className="tool-hint">{selected.file_size_bytes.toLocaleString()} bytes · {selected.mime_type}<br />Acquired by {selected.acquired_by} · {new Date(selected.intake_timestamp).toLocaleString()}</p>
        {selected.is_tampered && <p className="tool-error">Evidence is flagged for integrity investigation. Analysis and export are blocked.</p>}
        <div className="action-row">
          <button disabled={busy || selected.is_tampered} onClick={() => action(() => downloadFile(`${evidencePath}/download`, selected.filename))}>Download verified copy</button>
          {editable && <button disabled={busy} onClick={() => action(async () => { setStatus(await requestJSON(`${evidencePath}/verify`, {})); setSelected(await requestJSON(evidencePath)); await refresh() })}>Verify integrity</button>}
        </div>
        {editable && <form onSubmit={event => { event.preventDefault(); action(async () => { setAnalysis(null); const data = await requestJSON(`${evidencePath}/analyze?kind=${kind}`, {}); setAnalysis(data); setSelected(data.evidence) }) }}>
          <label htmlFor="evidence-analysis">Analysis type</label><select id="evidence-analysis" value={kind} disabled={busy} onChange={e => setKind(e.target.value)}>{analysisKinds.map(([id, name]) => <option key={id} value={id}>{name}</option>)}</select>
          <p className="tool-hint">A browser ZIP accepts root History, Cookies, places.sqlite, cookies.sqlite, matching -wal files and cache.har. Cache analysis supports HAR export metadata, not raw binary cache files. USB registry analysis accepts text exports.</p>
          <button disabled={busy || selected.is_tampered}>Analyze verified copy</button>
        </form>}
        <details className="custody-trail"><summary>Chain of custody · {selected.custody_history.length} records</summary><ol>{selected.custody_history.map(entry => <li key={entry.custody_id}><strong>{entry.action} · {entry.status}</strong><p>{entry.actor} · {new Date(entry.timestamp).toLocaleString()}</p><p>{entry.notes}</p><details><summary>Verification hashes</summary><p className="hash-text">Expected: {entry.expected_hash}<br />Actual: {entry.actual_hash}</p></details></li>)}</ol></details>
      </article>}
    </div>
    {status && <div className="tool-card" role="status"><Findings value={status} /></div>}
    {analysis && <article className="tool-card"><p className="eyebrow">{analysis.analysis_kind.replaceAll('_', ' ')} FINDINGS</p><Findings value={analysis.analysis} />
      {editable && analysis.analysis.carved_files?.map((artifact, index) => <div key={index} className="provider-result"><p>{artifact.recovered_name} · bytes {artifact.offset_start}–{artifact.offset_end}</p><button disabled={busy} onClick={() => action(async () => { const child = await requestJSON(`/api/forensics/evidence/${encodeURIComponent(analysis.evidence.evidence_id)}/carve/${index}`, {}); setStatus({ message: 'Derived evidence stored with parent provenance.', evidence_id: child.evidence_id }); await refresh(); setSelected(await requestJSON(evidencePath)) })}>Preserve recovered artifact</button></div>)}
    </article>}
  </section>
}
