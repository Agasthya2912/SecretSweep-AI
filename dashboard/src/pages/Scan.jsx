import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Copy, AlertTriangle, ArrowRight, History } from 'lucide-react'
import clsx from 'clsx'
import { formatDistanceToNow } from 'date-fns'
import { triggerScan, getScanStatus } from '../api/endpoints'
import { usePageTitle } from '../lib/usePageTitle'
import { showToast } from '../lib/toast'
import { loadRecentScans, saveRecentScan } from '../lib/recentScans'
import Card from '../components/ui/Card'
import LoadingSpinner from '../components/ui/LoadingSpinner'

const POLL_INTERVAL_MS = 3000

const STATUS_STYLES = {
  pending: 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300',
  running: 'bg-blue-100 text-blue-700 dark:bg-blue-950 dark:text-blue-300',
  completed: 'bg-green-100 text-green-700 dark:bg-green-950 dark:text-green-300',
  failed: 'bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300',
}

function StatusBadge({ status }) {
  const style = STATUS_STYLES[status] || STATUS_STYLES.pending
  return (
    <span className={clsx('inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold uppercase', style)}>
      {status}
    </span>
  )
}

export default function Scan() {
  usePageTitle('New Scan')
  const navigate = useNavigate()

  const [repoUrl, setRepoUrl] = useState('')
  const [visibility, setVisibility] = useState('unknown')
  const [activeValidation, setActiveValidation] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  const [scanJob, setScanJob] = useState(null)
  const [recentScans, setRecentScans] = useState(loadRecentScans)
  const pollRef = useRef(null)

  const stopPolling = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current)
      pollRef.current = null
    }
  }

  const pollStatus = (scanJobId) => {
    stopPolling()
    const tick = async () => {
      try {
        const status = await getScanStatus(scanJobId)
        setScanJob(status)
        if (status.status === 'completed' || status.status === 'failed') {
          stopPolling()
        }
      } catch {
        stopPolling()
      }
    }
    tick()
    pollRef.current = setInterval(tick, POLL_INTERVAL_MS)
  }

  useEffect(() => stopPolling, [])

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!repoUrl.trim()) return
    setSubmitting(true)
    try {
      const response = await triggerScan(repoUrl.trim(), {
        enableActiveValidation: activeValidation,
        repoVisibility: visibility,
      })
      showToast('Scan queued', 'success')
      setRecentScans(saveRecentScan({ id: response.scan_job_id, repoUrl: repoUrl.trim(), triggeredAt: new Date().toISOString() }))
      pollStatus(response.scan_job_id)
    } catch (err) {
      showToast(err.response?.data?.error || err.message || 'Failed to start scan', 'error')
    } finally {
      setSubmitting(false)
    }
  }

  const copyId = async (id) => {
    try {
      await navigator.clipboard.writeText(id)
      showToast('Scan job ID copied', 'success')
    } catch {
      showToast('Could not copy to clipboard', 'error')
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">New Scan</h1>
        <p className="text-sm text-gray-500 dark:text-gray-400">Run the full 6-layer pipeline against a repository.</p>
      </div>

      <Card>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700 dark:text-gray-300">
              Repository URL
            </label>
            <input
              required
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="https://github.com/org/repo"
              className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm dark:border-gray-700 dark:bg-gray-800"
            />
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700 dark:text-gray-300">
              Repository Visibility
            </label>
            <div className="flex gap-2">
              {['public', 'private', 'unknown'].map((option) => (
                <button
                  key={option}
                  type="button"
                  onClick={() => setVisibility(option)}
                  className={clsx(
                    'rounded-lg border px-3 py-1.5 text-sm capitalize',
                    visibility === option
                      ? 'border-blue-600 bg-blue-50 text-blue-700 dark:bg-blue-950 dark:text-blue-300'
                      : 'border-gray-300 text-gray-600 hover:bg-gray-50 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800'
                  )}
                >
                  {option}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="flex items-start gap-2 text-sm text-gray-700 dark:text-gray-300">
              <input
                type="checkbox"
                checked={activeValidation}
                onChange={(e) => setActiveValidation(e.target.checked)}
                className="mt-0.5"
              />
              Enable active validation
            </label>
            {activeValidation && (
              <p className="mt-1 flex items-start gap-1.5 text-xs text-orange-600 dark:text-orange-400">
                <AlertTriangle size={14} className="mt-0.5 shrink-0" />
                Makes real API calls to validate if secrets are still active.
              </p>
            )}
          </div>

          <button
            type="submit"
            disabled={submitting}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
          >
            {submitting ? 'Starting...' : 'Start Scan'}
          </button>
        </form>
      </Card>

      {scanJob && (
        <Card className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="font-semibold text-gray-900 dark:text-gray-100">Scan Status</h2>
            <StatusBadge status={scanJob.status} />
          </div>

          <div className="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400">
            <span>Job ID:</span>
            <span className="font-mono">{scanJob.scan_job_id}</span>
            <button
              onClick={() => copyId(scanJob.scan_job_id)}
              className="rounded-md p-1 hover:bg-gray-100 dark:hover:bg-gray-800"
              aria-label="Copy scan job ID"
            >
              <Copy size={12} />
            </button>
          </div>

          {(scanJob.status === 'pending' || scanJob.status === 'running') && (
            <div className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
              <LoadingSpinner size={16} className="py-0" />
              Polling for updates every 3 seconds...
            </div>
          )}

          {scanJob.status === 'completed' && (
            <div className="space-y-2">
              <div className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-3">
                <div>
                  <p className="text-xs text-gray-500 dark:text-gray-400">Commits Scanned</p>
                  <p className="font-semibold text-gray-900 dark:text-gray-100">{scanJob.total_commits_scanned}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-500 dark:text-gray-400">Secrets Found</p>
                  <p className="font-semibold text-gray-900 dark:text-gray-100">{scanJob.secrets_found}</p>
                </div>
                {scanJob.completed_at && (
                  <div>
                    <p className="text-xs text-gray-500 dark:text-gray-400">Finished</p>
                    <p className="font-semibold text-gray-900 dark:text-gray-100">
                      {formatDistanceToNow(new Date(scanJob.completed_at), { addSuffix: true })}
                    </p>
                  </div>
                )}
              </div>
              <button
                onClick={() => navigate('/secrets')}
                className="flex items-center gap-1.5 rounded-lg bg-gray-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-gray-700 dark:bg-gray-100 dark:text-gray-900 dark:hover:bg-white"
              >
                View Results
                <ArrowRight size={14} />
              </button>
            </div>
          )}

          {scanJob.status === 'failed' && (
            <p className="text-sm text-red-600 dark:text-red-400">{scanJob.error_message || 'Scan failed.'}</p>
          )}
        </Card>
      )}

      <Card>
        <h2 className="mb-3 flex items-center gap-1.5 font-semibold text-gray-900 dark:text-gray-100">
          <History size={16} />
          Recent Scans
        </h2>
        {recentScans.length === 0 ? (
          <p className="text-sm text-gray-500 dark:text-gray-400">
            Scans you trigger from this browser will show up here.
          </p>
        ) : (
          <ul className="divide-y divide-gray-100 dark:divide-gray-800">
            {recentScans.map((scan) => (
              <li key={scan.id}>
                <button
                  onClick={() => pollStatus(scan.id)}
                  className="flex w-full items-center justify-between gap-2 py-2 text-left text-sm hover:bg-gray-50 dark:hover:bg-gray-800/50"
                >
                  <span className="truncate font-mono text-xs text-gray-600 dark:text-gray-400">{scan.repoUrl}</span>
                  <span className="shrink-0 text-xs text-gray-400">
                    {formatDistanceToNow(new Date(scan.triggeredAt), { addSuffix: true })}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  )
}
