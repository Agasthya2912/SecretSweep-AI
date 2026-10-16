// Runtime-configurable API base URL / key (editable from the Settings page),
// falling back to build-time Vite env vars. Stored in localStorage so a
// change on Settings takes effect immediately without a rebuild.
const STORAGE_KEYS = {
  apiKey: 'secretsweep.apiKey',
  baseUrl: 'secretsweep.baseUrl',
}

export function getApiKey() {
  return localStorage.getItem(STORAGE_KEYS.apiKey) ?? import.meta.env.VITE_API_KEY ?? ''
}

export function setApiKey(key) {
  if (key) localStorage.setItem(STORAGE_KEYS.apiKey, key)
  else localStorage.removeItem(STORAGE_KEYS.apiKey)
}

export function getBaseUrl() {
  return localStorage.getItem(STORAGE_KEYS.baseUrl) ?? import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'
}

export function setBaseUrl(url) {
  if (url) localStorage.setItem(STORAGE_KEYS.baseUrl, url)
  else localStorage.removeItem(STORAGE_KEYS.baseUrl)
}
