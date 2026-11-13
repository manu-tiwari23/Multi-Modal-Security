import { useEffect, useState } from 'react'
import { apiFetch } from '../api.js'

export default function IntelligenceView({ role }) {
  const [value, setValue] = useState('')
  const [external, setExternal] = useState(false)
  const [providers, setProviders] = useState(null)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    const controller = new AbortController()
    apiFetch('/api/threat-intel/status', { signal: controller.signal }).then(async response => {
      if (!response.ok) throw new Error('Provider status unavailable.')
      setProviders((await response.json()).providers)
    }).catch(e => { if (e.name !== 'AbortError') setError(e.message) })
    return () => controller.abort()
  }, [])
  async function lookup(event) {
    event.preventDefault()
    setBusy(true); setError(''); setResult(null)
    try {
      const response = await apiFetch('/api/threat-intel/lookup', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value: value.trim(), allow_external: external }),
      })
      const data = await response.json()
      if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : `Lookup failed (${response.status}). Check the indicator and retry.`)
      setResult(data)
    } catch (e) { setError(e.message || 'Lookup unavailable. Please retry.') }
    finally { setBusy(false) }
  }
  return <section className="tool-page">
    <header><p className="eyebrow">THREAT INTELLIGENCE</p><h1>Investigate an indicator</h1><p>Check an IP address, domain, URL or file hash against retained intelligence.</p></header>
    <div className="provider-status">{providers === null ? 'Loading provider status…' : providers.map(p => <span key={p.name}>{p.name} · {p.configured ? 'configured' : 'not configured'}</span>)}</div>
    {role === 'viewer' ? <p className="tool-notice">An analyst role is required to run indicator lookups.</p> :
      <form className="tool-card" onSubmit={lookup}>
        <label htmlFor="intel-value">Indicator</label>
        <input id="intel-value" value={value} onChange={e => setValue(e.target.value)} required maxLength={4096} placeholder="IP, domain, URL or hash" disabled={busy} autoComplete="off" spellCheck={false} />
        <label className="checkbox-line"><input type="checkbox" checked={external} onChange={e => setExternal(e.target.checked)} disabled={busy} />Allow external provider lookup</label>
        <p className="tool-hint">External lookups disclose this indicator to configured providers and may add it to their datasets. URLs are not visited and file contents are not uploaded. Leave unchecked to use local cached results.</p>
        <button disabled={busy || !value.trim()}>{busy ? 'Checking indicator…' : 'Look up indicator'}</button>
      </form>}
    {error && <p role="alert" className="tool-error">{error}</p>}
    <div aria-live="polite" aria-busy={busy}>
      {result && <article className="tool-card intelligence-result">
        <p className="eyebrow">{result.indicator.type} · {result.cached ? 'CACHED RESULT' : 'LOOKUP RESULT'}</p>
        <h2>{result.indicator.value}</h2>
        <p className="result-verdict">{result.classification.replaceAll('_', ' ')} · {result.score === null ? 'Score unavailable' : `Provider score ${result.score}/100`}</p>
        <p className="tool-hint">Checked {new Date(result.checked_at).toLocaleString()}{result.expires_at && ` · Expires ${new Date(result.expires_at).toLocaleString()}`} · Cache: {result.cache_status}</p>
        {result.providers.map(p => <div className="provider-result" key={p.provider}><h3>{p.provider} <small>{p.status.replaceAll('_', ' ')}</small></h3><p>{p.explanation}</p><p className="tool-hint">Observed {new Date(p.observed_at).toLocaleString()}</p></div>)}
        <ul className="tool-limitations">{result.limitations.map((text, i) => <li key={i}>{text}</li>)}</ul>
      </article>}
    </div>
  </section>
}
