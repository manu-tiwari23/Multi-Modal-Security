import { useEffect, useState } from 'react'
import { requestJSON } from '../workflows.js'

export default function AccountView({ user }) {
  const [accounts, setAccounts] = useState([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [current, setCurrent] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [username, setUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [role, setRole] = useState('viewer')
  const [target, setTarget] = useState('')
  const [reset, setReset] = useState('')
  const admin = user.role === 'admin'
  async function refresh() { setAccounts((await requestJSON('/api/auth/users')).users) }
  useEffect(() => {
    if (!admin) return
    let active = true
    requestJSON('/api/auth/users').then(data => { if (active) setAccounts(data.users) }).catch(e => { if (active) setError(e.message) })
    return () => { active = false }
  }, [admin])
  async function act(work) {
    setBusy(true); setError(''); setMessage('')
    try { await work() } catch (e) { setError(e.message) }
    finally { setBusy(false) }
  }
  const signedOut = () => window.dispatchEvent(new Event('mms-session-expired'))
  return <section className="tool-page">
    <header><p className="eyebrow">ACCESS & ACCOUNT</p><h1>Your workspace access</h1><p>Signed in as {user.username} · {user.role}</p></header>
    {error && <p className="tool-error" role="alert">{error}</p>}{message && <p className="tool-notice" role="status">{message}</p>}
    <form className="tool-card" onSubmit={e => { e.preventDefault(); act(async () => {
      if (password !== confirm) throw new Error('New passwords do not match.')
      await requestJSON('/api/auth/password', { current_password: current, password })
      setCurrent(''); setPassword(''); setConfirm(''); signedOut()
    }) }}>
      <h2>Change your password</h2><p className="tool-hint">Use 15–128 characters. Changing your password ends all your sessions, including this one.</p>
      <label htmlFor="current-password">Current password</label><input id="current-password" type="password" autoComplete="current-password" required maxLength={128} value={current} disabled={busy} onChange={e => setCurrent(e.target.value)} />
      <label htmlFor="own-password">New password</label><input id="own-password" type="password" autoComplete="new-password" required minLength={15} maxLength={128} value={password} disabled={busy} onChange={e => setPassword(e.target.value)} />
      <label htmlFor="confirm-password">Confirm new password</label><input id="confirm-password" type="password" autoComplete="new-password" required minLength={15} maxLength={128} value={confirm} disabled={busy} onChange={e => setConfirm(e.target.value)} />
      <button disabled={busy}>Change password and sign out</button>
    </form>
    {admin && <>
      <form className="tool-card" onSubmit={e => { e.preventDefault(); act(async () => {
        await requestJSON('/api/auth/users', { username, password: newPassword, role }); setUsername(''); setNewPassword(''); await refresh(); setMessage('Account created.')
      }) }}><h2>Create an account</h2>
        <label htmlFor="new-username">Username</label><input id="new-username" required minLength={3} maxLength={64} autoComplete="off" value={username} disabled={busy} onChange={e => setUsername(e.target.value)} />
        <label htmlFor="new-account-password">Initial password</label><input id="new-account-password" type="password" autoComplete="new-password" required minLength={15} maxLength={128} value={newPassword} disabled={busy} onChange={e => setNewPassword(e.target.value)} />
        <label htmlFor="new-role">Role</label><select id="new-role" value={role} disabled={busy} onChange={e => setRole(e.target.value)}><option value="viewer">Viewer · read access</option><option value="analyst">Analyst · investigations and approvals</option><option value="admin">Administrator · analyst access and accounts</option></select>
        <button disabled={busy}>Create account</button>
      </form>
      <section className="tool-card"><h2>Manage accounts</h2><p className="tool-hint">Role, password and access changes revoke the account’s sessions. The last enabled administrator cannot be removed.</p>
        <button disabled={busy} onClick={() => act(refresh)}>Refresh accounts</button>
        {accounts.map(account => <div className="provider-result" key={account.username}>
          <h3>{account.username} <small>{account.disabled ? 'disabled' : 'enabled'} · {account.role}</small></h3>
          <form className="action-row" onSubmit={e => { e.preventDefault(); const selectedRole = new FormData(e.currentTarget).get('role'); act(async () => {
            await requestJSON(`/api/auth/users/${encodeURIComponent(account.username)}`, { role: selectedRole }, 'PATCH')
            if (account.username === user.username) { signedOut(); return }
            await refresh(); setMessage(`Role updated for ${account.username}.`)
          }) }}>
            <select name="role" aria-label={`Role for ${account.username}`} key={account.role} defaultValue={account.role} disabled={busy}><option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="admin">Administrator</option></select>
            <button disabled={busy}>Save role</button>
            <button type="button" disabled={busy} onClick={() => act(async () => {
              await requestJSON(`/api/auth/users/${encodeURIComponent(account.username)}`, { disabled: !account.disabled }, 'PATCH')
              if (account.username === user.username) { signedOut(); return }
              await refresh(); setMessage(`Access updated for ${account.username}.`)
            })}>{account.disabled ? 'Enable access' : 'Disable access'}</button>
            <button type="button" disabled={busy} onClick={() => { setTarget(account.username); setReset('') }}>Reset password</button>
          </form>
        </div>)}
      </section>
      {target && <form className="tool-card" onSubmit={e => { e.preventDefault(); act(async () => {
        await requestJSON(`/api/auth/users/${encodeURIComponent(target)}/password`, { password: reset }); setReset(''); setTarget('')
        if (target === user.username) signedOut(); else setMessage(`Password reset for ${target}. Existing sessions revoked.`)
      }) }}><h2>Reset password for {target}</h2><label htmlFor="reset-password">New password</label><input id="reset-password" type="password" autoComplete="new-password" required minLength={15} maxLength={128} value={reset} disabled={busy} onChange={e => setReset(e.target.value)} /><button disabled={busy}>Reset password</button><button type="button" className="secondary-action" disabled={busy} onClick={() => { setTarget(''); setReset('') }}>Cancel</button></form>}
    </>}
  </section>
}
