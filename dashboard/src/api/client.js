import axios from 'axios'
import { getApiKey, getBaseUrl, setApiKey } from '../lib/apiConfig'
import { showToast } from '../lib/toast'

export const apiClient = axios.create({
  headers: { 'Content-Type': 'application/json' },
})

apiClient.interceptors.request.use((config) => {
  // Read fresh on every request so a change on the Settings page applies
  // immediately, without recreating the axios instance.
  config.baseURL = `${getBaseUrl()}/api`
  const apiKey = getApiKey()
  if (apiKey) {
    config.headers['X-API-Key'] = apiKey
  }

  if (import.meta.env.DEV) {
    // eslint-disable-next-line no-console
    console.log(`[api] ${config.method?.toUpperCase()} ${config.baseURL}${config.url}`)
  }

  return config
})

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status

    if (status === 401) {
      setApiKey('')
      showToast('API key missing or invalid — set it in Settings.', 'error')
      if (window.location.pathname !== '/settings') {
        window.location.href = '/settings'
      }
    } else if (status >= 500 || !error.response) {
      const message = error.response?.data?.error || error.message || 'Unexpected server error'
      showToast(message, 'error')
    }

    return Promise.reject(error)
  }
)
