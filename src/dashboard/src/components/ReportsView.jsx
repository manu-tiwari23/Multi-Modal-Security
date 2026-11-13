import { useState } from 'react'
import { downloadFile } from '../workflows.js'

export default function ReportsView() {
  const [kind, setKind] = useState('threats')
  const [identifier, setIdentifier] = useState('')
  const [format, setFormat] = useState('html')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  async function download(event) {
    event.preventDefault(); setBusy(true); setMessage(''); setError('')
    try {
      await downloadFile(`/api/reports/${kind}${kind === 'threats' ? '' : `/${encodeURIComponent(identifier.trim())}`}?format=${format}`, `mms-${kind}.${format === 'markdown' ? 'md' : format}`)
      setMessage('Report generated. The download has been started.')
    } catch (e) { setError(e.message) }
    finally { setBusy(false) }
  }
  return <section className="tool-page">
    <header><p className="eyebrow">REPORTING</p><h1>Export an evidence snapshot</h1><p>Generate incident, forensic case or retained threat activity reports without an AI request.</p></header>
    <form className="tool-card" onSubmit={download}>
      <label htmlFor="report-kind">Report</label><select id="report-kind" value={kind} onChange={e => { setKind(e.target.value); setIdentifier(''); setMessage(''); setError('') }} disabled={busy}><option value="threats">Threat activity</option><option value="incidents">Incident</option><option value="forensics">Forensic case</option></select>
      {kind !== 'threats' && <><label htmlFor="report-id">{kind === 'incidents' ? 'Incident ID' : 'Case ID'}</label><input id="report-id" required maxLength={120} value={identifier} onChange={e => setIdentifier(e.target.value)} disabled={busy} /></>}
      <label htmlFor="report-format">Format</label><select id="report-format" value={format} onChange={e => setFormat(e.target.value)} disabled={busy}><option value="html">HTML · printable</option><option value="markdown">Markdown</option><option value="json">JSON</option></select>
      <p className="tool-hint">Forensic reports verify stored evidence and record analysis in the custody trail. Missing or tampered evidence blocks report generation. Reports reflect available records and state their coverage limits.</p>
      <button disabled={busy || (kind !== 'threats' && !identifier.trim())}>{busy ? 'Generating report…' : 'Download report'}</button>
    </form>
    {error && <p role="alert" className="tool-error">{error}</p>}
    {message && <p role="status" className="tool-notice">{message}</p>}
  </section>
}
