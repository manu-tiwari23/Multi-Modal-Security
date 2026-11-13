import { useEffect, useState } from 'react'
import { apiFetch, setSessionProof } from '../api.js'
import App from '../App.jsx'
import '../auth.css'

export default function AuthGate() {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [setup, setSetup] = useState(false)
  const [name, setName] = useState('')
  const [password, setPassword] = useState('')

  useEffect(() => {
    let active = true
    const expired = () => {
      setSessionProof(null)
      setUser(null)
      setError('Your session ended. Sign in to continue.')
    }
    window.addEventListener('mms-session-expired', expired)
    async function restore() {
      try {
        const response = await fetch('/api/auth/session', { credentials: 'same-origin', cache: 'no-store' })
        if (!active) return
        if (response.ok) {
          const data = await response.json()
          setSessionProof(data.csrf_token)
          setUser(data.user)
        } else if (response.status === 401) {
          const status = await fetch('/api/auth/status', { cache: 'no-store' })
          if (status.ok && active) setSetup((await status.json()).setup_required)
          else if (active) setError('The sign-in service is unavailable. Check the backend and database, then retry.')
        } else setError('The sign-in service is unavailable. Check the backend and database, then retry.')
      } catch {
        if (active) setError('Cannot reach the sign-in service. Check your connection and retry.')
      } finally {
        if (active) setLoading(false)
      }
    }
    restore()
    return () => { active = false; window.removeEventListener('mms-session-expired', expired) }
  }, [])

  async function signIn(event) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      const response = await apiFetch('/api/auth/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: name, password }),
      })
      const data = await response.json()
      if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Check the username and password.')
      setSessionProof(data.csrf_token)
      setUser(data.user)
      setPassword('')
    } catch (failure) {
      setError(failure.message || 'Sign-in failed. Please retry.')
    } finally { setBusy(false) }
  }

  async function signOut() {
    setBusy(true)
    try {
      const response = await apiFetch('/api/auth/logout', { method: 'POST' })
      if (!response.ok && response.status !== 401) throw new Error('Sign-out could not be confirmed. Please retry.')
      setSessionProof(null)
      setUser(null)
      setError('')
    } catch (failure) { setError(failure.message) }
    finally { setBusy(false) }
  }

  if (loading) return <main className="auth-page"><p role="status">Checking your session…</p></main>
  if (user) return <>
    <div className="account-bar">
      <span>Signed in as <strong>{user.username}</strong> <span className="account-role">{user.role}</span></span>
      {error && <span role="alert">{error}</span>}
      <button onClick={signOut} disabled={busy}>{busy ? 'Signing out…' : 'Sign out'}</button>
    </div>
    <App user={user} />
  </>
  return <main className="auth-page">
    <section className="auth-card" aria-labelledby="auth-title">
      <p className="auth-wordmark">MMS / SECURITY OPERATIONS</p>
      <h1 id="auth-title">Your investigation starts here.</h1>
      <p className="auth-description">Sign in to review evidence, investigate incidents, and coordinate an approved response.</p>
      {setup && <div className="auth-setup"><strong>First-time setup</strong><p>Create an administrator from the project terminal, then sign in below.</p><code>python -m src.auth.cli create admin --role admin</code></div>}
      <form onSubmit={signIn}>
        <label htmlFor="auth-username">Username</label>
        <input id="auth-username" autoComplete="username" required maxLength={64} value={name} onChange={e => setName(e.target.value)} />
        <label htmlFor="auth-password">Password</label>
        <input id="auth-password" type="password" autoComplete="current-password" required maxLength={128} value={password} onChange={e => setPassword(e.target.value)} />
        {error && <p className="auth-error" role="alert">{error}</p>}
        <button type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
      </form>
      <p className="auth-footnote">Access is recorded. Response actions require an analyst’s approval.</p>
    </section>
  </main>
}
