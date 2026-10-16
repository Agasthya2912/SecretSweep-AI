import { useState } from 'react'
import { Eye, EyeOff, CheckCircle, XCircle, Info, Trash2 } from 'lucide-react'
import clsx from 'clsx'
import { checkHealth, clearScanHistory } from '../api/endpoints'
import { usePageTitle } from '../lib/usePageTitle'
import { getApiKey, setApiKey, getBaseUrl, setBaseUrl } from '../lib/apiConfig'
import { getPageSize, setPageSize, getDateFormat, setDateFormat } from '../lib/preferences'
import { clearRecentScans } from '../lib/recentScans'
import { showToast } from '../lib/toast'
import Card from '../components/ui/Card'

export default function Settings() {
  usePageTitle('Settings')

  const [baseUrl, setBaseUrlState] = useState(getBaseUrl())
  const [apiKey, setApiKeyState] = useState(getApiKey())
  const [showKey, setShowKey] = useState(false)
  const [testResult, setTestResult] = useState(null)
  const [testing, setTesting] = useState(false)

  const [pageSize, setPageSizeState] = useState(getPageSize())
  const [dateFormat, setDateFormatState] = useState(getDateFormat())

  const [clearing, setClearing] = useState(false)

  const saveConnection = () => {
    setBaseUrl(baseUrl.trim())
    setApiKey(apiKey.trim())
  }

  const testConnection = async () => {
    saveConnection()
    setTesting(true)
    setTestResult(null)
    try {
      const health = await checkHealth()
      setTestResult({ ok: true, health })
    } catch (err) {
      setTestResult({ ok: false, message: err.response?.data?.error || err.message || 'Connection failed' })
    } finally {
      setTesting(false)
    }
  }

  const handleClearHistory = async () => {
    if (!window.confirm('Delete every scan, finding, and developer risk record? This cannot be undone.')) {
      return
    }
    setClearing(true)
    try {
      await clearScanHistory()
      clearRecentScans()
      showToast('Scan history cleared', 'success')
    } catch (err) {
      showToast(err.response?.data?.error || err.message || 'Failed to clear scan history', 'error')
    } finally {
      setClearing(false)
    }
  }

  return (
    <div className="max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Settings</h1>
        <p className="text-sm text-gray-500 dark:text-gray-400">Configure the API connection and dashboard preferences.</p>
      </div>

      <Card className="space-y-4">
        <h2 className="font-semibold text-gray-900 dark:text-gray-100">API Configuration</h2>

        <div>
          <label className="mb-1 block text-sm font-medium text-gray-700 dark:text-gray-300">API Base URL</label>
          <input
            value={baseUrl}
            onChange={(e) => setBaseUrlState(e.target.value)}
            onBlur={saveConnection}
            placeholder="http://localhost:8000"
            className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm dark:border-gray-700 dark:bg-gray-800"
          />
        </div>

        <div>
          <label className="mb-1 block text-sm font-medium text-gray-700 dark:text-gray-300">API Key</label>
          <div className="relative">
            <input
              type={showKey ? 'text' : 'password'}
              value={apiKey}
              onChange={(e) => setApiKeyState(e.target.value)}
              onBlur={saveConnection}
              placeholder="X-API-Key value"
              className="w-full rounded-lg border border-gray-300 px-3 py-2 pr-10 text-sm dark:border-gray-700 dark:bg-gray-800"
            />
            <button
              type="button"
              onClick={() => setShowKey((v) => !v)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
              aria-label={showKey ? 'Hide API key' : 'Show API key'}
            >
              {showKey ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          </div>
        </div>

        <button
          onClick={testConnection}
          disabled={testing}
          className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
        >
          {testing ? 'Testing...' : 'Test Connection'}
        </button>

        {testResult && (
          <div
            className={clsx(
              'flex items-start gap-2 rounded-lg border p-3 text-sm',
              testResult.ok
                ? 'border-green-200 bg-green-50 text-green-700 dark:border-green-900 dark:bg-green-950 dark:text-green-300'
                : 'border-red-200 bg-red-50 text-red-700 dark:border-red-900 dark:bg-red-950 dark:text-red-300'
            )}
          >
            {testResult.ok ? (
              <CheckCircle size={18} className="mt-0.5 shrink-0" />
            ) : (
              <XCircle size={18} className="mt-0.5 shrink-0" />
            )}
            <div>
              {testResult.ok ? (
                <>
                  <p className="font-medium">Connected successfully</p>
                  <p className="text-xs opacity-80">
                    status: {testResult.health.status} · database: {testResult.health.database} · redis:{' '}
                    {testResult.health.redis}
                  </p>
                </>
              ) : (
                <p>{testResult.message}</p>
              )}
            </div>
          </div>
        )}
      </Card>

      <Card className="space-y-4">
        <h2 className="font-semibold text-gray-900 dark:text-gray-100">Display Preferences</h2>

        <div>
          <label className="mb-1 block text-sm font-medium text-gray-700 dark:text-gray-300">Items per page</label>
          <div className="flex gap-2">
            {[10, 20, 50].map((size) => (
              <button
                key={size}
                onClick={() => {
                  setPageSizeState(size)
                  setPageSize(size)
                }}
                className={clsx(
                  'rounded-lg border px-3 py-1.5 text-sm',
                  pageSize === size
                    ? 'border-blue-600 bg-blue-50 text-blue-700 dark:bg-blue-950 dark:text-blue-300'
                    : 'border-gray-300 text-gray-600 hover:bg-gray-50 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800'
                )}
              >
                {size}
              </button>
            ))}
          </div>
        </div>

        <div>
          <label className="mb-1 block text-sm font-medium text-gray-700 dark:text-gray-300">Date format</label>
          <div className="flex gap-2">
            {[
              { value: 'relative', label: 'Relative ("2 hours ago")' },
              { value: 'absolute', label: 'Absolute' },
            ].map((option) => (
              <button
                key={option.value}
                onClick={() => {
                  setDateFormatState(option.value)
                  setDateFormat(option.value)
                }}
                className={clsx(
                  'rounded-lg border px-3 py-1.5 text-sm',
                  dateFormat === option.value
                    ? 'border-blue-600 bg-blue-50 text-blue-700 dark:bg-blue-950 dark:text-blue-300'
                    : 'border-gray-300 text-gray-600 hover:bg-gray-50 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800'
                )}
              >
                {option.label}
              </button>
            ))}
          </div>
        </div>
      </Card>

      <Card className="space-y-3">
        <h2 className="flex items-center gap-1.5 font-semibold text-gray-900 dark:text-gray-100">
          <Trash2 size={16} />
          Danger Zone
        </h2>
        <p className="text-sm text-gray-500 dark:text-gray-400">
          Permanently delete every scan job, detected secret, and developer risk record — including the
          credential data-flow graph in Neo4j. This cannot be undone.
        </p>
        <button
          onClick={handleClearHistory}
          disabled={clearing}
          className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
        >
          {clearing ? 'Clearing...' : 'Clear All Scan History'}
        </button>
      </Card>

      <Card className="space-y-2">
        <h2 className="flex items-center gap-1.5 font-semibold text-gray-900 dark:text-gray-100">
          <Info size={16} />
          About
        </h2>
        <dl className="grid grid-cols-2 gap-2 text-sm">
          <dt className="text-gray-500 dark:text-gray-400">SecretSweep AI version</dt>
          <dd className="text-gray-800 dark:text-gray-200">1.0.0</dd>
          <dt className="text-gray-500 dark:text-gray-400">Pipeline layers</dt>
          <dd className="text-gray-800 dark:text-gray-200">6</dd>
          <dt className="text-gray-500 dark:text-gray-400">Detection patterns</dt>
          <dd className="text-gray-800 dark:text-gray-200">31</dd>
        </dl>
      </Card>
    </div>
  )
}
