import { apiFetch } from './api.js'

export async function requestJSON(path, body, method = 'POST') {
  const response = await apiFetch(path, body === undefined ? {} : {
    method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  })
  if (response.status === 204) return null
  const data = await response.json()
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : `Request failed (${response.status}). Check the supplied values and retry.`)
  return data
}

export async function fileBase64(file, maxBytes = 10 * 1024 * 1024) {
  if (!file) throw new Error('Choose a file first.')
  if (file.size > maxBytes) throw new Error(`Choose a file smaller than ${maxBytes / 1024 / 1024} MiB.`)
  const bytes = new Uint8Array(await file.arrayBuffer())
  let binary = ''
  for (let offset = 0; offset < bytes.length; offset += 8192) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192))
  }
  return btoa(binary)
}

export async function downloadFile(path, filename) {
  const response = await apiFetch(path)
  if (!response.ok) {
    const data = await response.json().catch(() => ({}))
    throw new Error(typeof data.detail === 'string' ? data.detail : `Download failed (${response.status}).`)
  }
  const url = URL.createObjectURL(await response.blob())
  const link = document.createElement('a')
  link.href = url; link.download = filename; document.body.appendChild(link); link.click(); link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 30000)
}
