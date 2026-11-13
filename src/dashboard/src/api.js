// Session cookies stay HttpOnly. Only the CSRF proof is kept in module memory.
let csrf = null

export function setSessionProof(value) {
  csrf = value || null
}

export async function apiFetch(path, options = {}) {
  if (!path.startsWith('/api/')) throw new Error('Expected a local API path')
  const headers = new Headers(options.headers)
  const method = (options.method || 'GET').toUpperCase()
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && path !== '/api/auth/login') {
    if (!csrf) {
      const session = await fetch('/api/auth/session', { credentials: 'same-origin', cache: 'no-store' })
      if (session.ok) csrf = (await session.json()).csrf_token
    }
    if (csrf) headers.set('X-MMS-CSRF', csrf)
  }
  const response = await fetch(path, { ...options, headers, credentials: 'same-origin', cache: 'no-store' })
  if (response.status === 401 && path !== '/api/auth/login') {
    csrf = null
    window.dispatchEvent(new Event('mms-session-expired'))
  }
  return response
}
