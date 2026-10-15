// Talks to the Sentinel control plane and hands a successful session off to the dashboard at /app.
const TOKEN_KEY = 'sentinel-token'

async function post(path: string, body: unknown): Promise<any> {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body),
  })
  const text = await res.text()
  let data: any = null
  try { data = text ? JSON.parse(text) : null } catch { data = { detail: text } }
  if (!res.ok) {
    const message = (data && (typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail))) || `Request failed (${res.status})`
    throw new Error(message)
  }
  return data
}

export function storeSession(result: { access_token: string }) {
  try { window.localStorage.setItem(TOKEN_KEY, result.access_token) } catch { /* ignore */ }
}

export function enterApp() {
  window.location.href = '/app'
}

export async function login(email: string, password: string) {
  const data = await post('/v1/auth/login', { email, password })
  storeSession(data)
  return data
}

export async function signupIndividual(payload: { name: string; email: string; password: string; team?: string }) {
  const data = await post('/v1/auth/signup/individual', payload)
  storeSession(data)
  return data
}

export async function signupOrganization(payload: unknown) {
  const data = await post('/v1/auth/signup/organization', payload)
  storeSession(data)
  return data
}
