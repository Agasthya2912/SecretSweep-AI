import { useEffect, useState } from 'react'
import { Users, TrendingUp, TrendingDown, Minus, Star, X, FileText } from 'lucide-react'
import clsx from 'clsx'
import { getDevelopers, getDeveloperReport } from '../api/endpoints'
import { usePageTitle } from '../lib/usePageTitle'
import Card from '../components/ui/Card'
import Badge from '../components/ui/Badge'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import ErrorMessage from '../components/ui/ErrorMessage'
import EmptyState from '../components/ui/EmptyState'

const RISK_LEVELS = ['All', 'HIGH', 'MEDIUM', 'LOW']

const PROGRESS_COLOR = { HIGH: 'bg-red-500', MEDIUM: 'bg-orange-500', LOW: 'bg-green-500' }

const TREND_META = {
  WORSENING: { icon: TrendingUp, className: 'text-red-600 dark:text-red-400' },
  IMPROVING: { icon: TrendingDown, className: 'text-green-600 dark:text-green-400' },
  STABLE: { icon: Minus, className: 'text-gray-400' },
  NEW: { icon: Star, className: 'text-blue-500' },
}

function TrendIndicator({ trend }) {
  const meta = TREND_META[trend] || TREND_META.NEW
  const Icon = meta.icon
  return (
    <span className={clsx('flex items-center gap-1 text-xs font-medium', meta.className)}>
      <Icon size={14} />
      {trend}
    </span>
  )
}

function ReportPanel({ developer, onClose }) {
  const [report, setReport] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    getDeveloperReport(developer.developer_email)
      .then((text) => {
        if (!cancelled) setReport(text)
      })
      .catch(() => {
        if (!cancelled) setReport('Could not load text report.')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [developer.developer_email])

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/40">
      <div className="h-full w-full max-w-lg overflow-y-auto bg-white p-6 shadow-2xl dark:bg-gray-900">
        <div className="mb-4 flex items-start justify-between">
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100">{developer.developer_name}</h2>
            <p className="text-sm text-gray-500 dark:text-gray-400">{developer.developer_email}</p>
          </div>
          <button
            onClick={onClose}
            className="rounded-md p-1.5 text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-800"
            aria-label="Close"
          >
            <X size={18} />
          </button>
        </div>

        <div className="mb-4 flex items-center gap-2">
          <Badge label={developer.risk_label} variant="risk" />
          <TrendIndicator trend={developer.risk_trend} />
          <span className="text-sm text-gray-500 dark:text-gray-400">Score: {developer.risk_score}/100</span>
        </div>

        <div className="mb-4 grid grid-cols-2 gap-3 text-sm">
          <div>
            <p className="text-xs text-gray-500 dark:text-gray-400">Repos Affected</p>
            <p className="text-gray-800 dark:text-gray-200">{developer.repos_affected.length}</p>
            <ul className="mt-1 space-y-0.5">
              {developer.repos_affected.map((repo) => (
                <li key={repo} className="truncate font-mono text-xs text-gray-500 dark:text-gray-400">
                  {repo}
                </li>
              ))}
            </ul>
          </div>
          <div>
            <p className="text-xs text-gray-500 dark:text-gray-400">Secret Types Leaked</p>
            <ul className="mt-1 space-y-0.5">
              {developer.secret_types_leaked.map((type) => (
                <li key={type} className="text-xs text-gray-700 dark:text-gray-300">
                  {type}
                </li>
              ))}
            </ul>
          </div>
        </div>

        <div>
          <p className="mb-1 flex items-center gap-1.5 text-xs font-semibold text-gray-500 dark:text-gray-400">
            <FileText size={14} />
            Full Text Report
          </p>
          {loading ? (
            <LoadingSpinner />
          ) : (
            <pre className="whitespace-pre-wrap rounded-lg bg-gray-50 p-3 font-mono text-xs text-gray-700 dark:bg-gray-800 dark:text-gray-300">
              {report}
            </pre>
          )}
        </div>
      </div>
    </div>
  )
}

export default function Developers() {
  usePageTitle('Developers')

  const [riskLabel, setRiskLabel] = useState('All')
  const [developers, setDevelopers] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [selected, setSelected] = useState(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    const filters = {}
    if (riskLabel !== 'All') filters.risk_label = riskLabel

    getDevelopers(filters)
      .then((data) => {
        if (!cancelled) {
          setDevelopers(data.developers || [])
          setError(null)
        }
      })
      .catch((err) => {
        if (!cancelled) setError(err.response?.data?.error || err.message || 'Failed to load developers')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [riskLabel])

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Developers</h1>
        <p className="text-sm text-gray-500 dark:text-gray-400">Risk profiles for every developer who has leaked a secret.</p>
      </div>

      <Card className="flex items-end gap-3">
        <div>
          <label className="mb-1 block text-xs font-medium text-gray-500 dark:text-gray-400">Risk Level</label>
          <select
            value={riskLabel}
            onChange={(e) => setRiskLabel(e.target.value)}
            className="rounded-lg border border-gray-300 px-3 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
          >
            {RISK_LEVELS.map((level) => (
              <option key={level} value={level}>
                {level}
              </option>
            ))}
          </select>
        </div>
      </Card>

      {loading ? (
        <LoadingSpinner />
      ) : error ? (
        <ErrorMessage message={error} />
      ) : developers.length === 0 ? (
        <EmptyState icon={Users} message="No developer profiles yet" />
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {developers.map((dev) => (
            <Card key={dev.developer_email} className="flex flex-col gap-3">
              <div>
                <p className="truncate font-semibold text-gray-900 dark:text-gray-100">{dev.developer_name}</p>
                <p className="truncate text-xs text-gray-500 dark:text-gray-400">{dev.developer_email}</p>
              </div>

              <div className="flex items-center justify-between">
                <Badge label={dev.risk_label} variant="risk" />
                <TrendIndicator trend={dev.risk_trend} />
              </div>

              <div>
                <div className="mb-1 flex justify-between text-xs text-gray-500 dark:text-gray-400">
                  <span>Risk score</span>
                  <span>{dev.risk_score}/100</span>
                </div>
                <div className="h-2 w-full overflow-hidden rounded-full bg-gray-100 dark:bg-gray-800">
                  <div
                    className={clsx('h-full rounded-full', PROGRESS_COLOR[dev.risk_label] || 'bg-gray-400')}
                    style={{ width: `${Math.min(100, Math.max(0, dev.risk_score))}%` }}
                  />
                </div>
              </div>

              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-600 dark:text-gray-400">Total leaks</span>
                <span className="font-semibold text-gray-900 dark:text-gray-100">{dev.total_leaks}</span>
              </div>

              <div className="flex gap-3 text-xs text-gray-500 dark:text-gray-400">
                <span>C:{dev.critical_leaks}</span>
                <span>H:{dev.high_leaks}</span>
                <span>M:{dev.medium_leaks}</span>
                <span>L:{dev.low_leaks}</span>
              </div>

              <button
                onClick={() => setSelected(dev)}
                className="mt-1 rounded-lg border border-gray-300 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800"
              >
                View Report
              </button>
            </Card>
          ))}
        </div>
      )}

      {selected && <ReportPanel developer={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}
