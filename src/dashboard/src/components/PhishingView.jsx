import { useState } from 'react'
import { fileBase64, requestJSON } from '../workflows.js'

function Verdict({ verdict }) {
  return <article className="tool-card">
    <p className="eyebrow">{verdict.analysis_type} ANALYSIS</p>
    <h2>{verdict.severity === 'safe' ? 'No indicators detected' : `${verdict.severity} risk`} · {verdict.score}/100</h2>
    <p className="tool-hint">{verdict.target_url || verdict.target_filename || 'Email'} · {new Date(verdict.analyzed_at).toLocaleString()}</p>
    <p>{verdict.explanation}</p>
    <p className="tool-hint">This is an indicator score, not a probability or guarantee of safety.</p>
    {verdict.attachment_sha256 && <p className="hash-text">SHA-256: {verdict.attachment_sha256}</p>}
    {verdict.signals.map(signal => <div className="provider-result" key={signal.signal_id}>
      <h3>{signal.name} <small>+{signal.score_contribution} · {signal.severity}</small></h3>
      <p>{signal.description}</p>
      {signal.evidence && <pre className="evidence-text">{signal.evidence}</pre>}
      {signal.mitre_technique && <small>{signal.mitre_technique}</small>}
    </div>)}
    {!verdict.signals.length && <p className="tool-hint">No configured detection signals fired.</p>}
  </article>
}

export default function PhishingView({ role }) {
  const [mode, setMode] = useState('url')
  const [text, setText] = useState('')
  const [file, setFile] = useState(null)
  const [publish, setPublish] = useState(false)
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function scan(event) {
    event.preventDefault(); setBusy(true); setError(''); setResult(null)
    try {
      const body = { publish_to_pipeline: publish }
      if (mode === 'url') body.url = text.trim()
      if (mode === 'email' || mode === 'composite') body.raw_email = text
      if (mode === 'attachment' || (mode === 'composite' && file)) {
        const attachment = { filename: file?.name, content_base64: await fileBase64(file), content_type: file.type || 'application/octet-stream' }
        if (mode === 'composite') body.attachments = [attachment]
        else Object.assign(body, attachment)
      }
      setResult(await requestJSON(`/api/phishing/scan/${mode}`, body))
    } catch (e) { setError(e.message) }
    finally { setBusy(false) }
  }
  return <section className="tool-page">
    <header><p className="eyebrow">PHISHING DETECTION</p><h1>Inspect suspicious content</h1><p>Review detection signals from URLs, raw emails and static attachment analysis.</p></header>
    {role === 'viewer' ? <p className="tool-notice">An analyst role is required to run scans.</p> : <form className="tool-card" onSubmit={scan}>
      <label htmlFor="scan-mode">Analysis</label>
      <select id="scan-mode" value={mode} disabled={busy} onChange={e => { setMode(e.target.value); setText(''); setFile(null); setResult(null); setError('') }}>
        <option value="url">URL</option><option value="email">Raw email</option><option value="attachment">Attachment</option><option value="composite">Email + links + attachment</option>
      </select>
      {mode !== 'attachment' && <><label htmlFor="scan-content">{mode === 'url' ? 'URL to inspect' : 'Raw email, including headers'}</label>
        <textarea id="scan-content" rows={mode === 'url' ? 2 : 9} value={text} onChange={e => setText(e.target.value)} required maxLength={mode === 'url' ? 8192 : 1000000} spellCheck={false} disabled={busy} /></>}
      {(mode === 'attachment' || mode === 'composite') && <><label htmlFor="scan-file">{mode === 'composite' ? 'Optional attachment' : 'Attachment'} · up to 10 MiB</label>
        <input key={mode} id="scan-file" type="file" required={mode === 'attachment'} disabled={busy} onChange={e => setFile(e.target.files[0] || null)} /></>}
      <label className="checkbox-line"><input type="checkbox" checked={publish} onChange={e => setPublish(e.target.checked)} disabled={busy} />Publish findings to the security pipeline</label>
      <p className="tool-hint">Attachments are inspected statically. Uploaded samples are not executed. Email link analysis covers up to ten extracted links.</p>
      <button disabled={busy}>{busy ? 'Analyzing…' : 'Analyze content'}</button>
    </form>}
    {error && <p role="alert" className="tool-error">{error}</p>}
    <div aria-live="polite" aria-busy={busy}>{result && <>
      {result.structured_explanation?.headline && <p className="tool-notice">{result.structured_explanation.headline}</p>}
      {result.verdict ? <Verdict verdict={result.verdict} /> : [result.email_verdict, ...(result.url_verdicts || []), ...(result.attachment_verdicts || [])].filter(Boolean).map(v => <Verdict verdict={v} key={v.verdict_id} />)}
      <p className="tool-hint">{result.pipeline ? 'Findings submitted to the security pipeline.' : 'Analysis only. Findings were not published to the pipeline.'}</p>
    </>}</div>
  </section>
}
