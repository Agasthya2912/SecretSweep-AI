import { Fragment, useEffect, useState } from 'react'
import { Shield, Copy, ChevronDown, ChevronRight, X } from 'lucide-react'
import { getSecrets } from '../api/endpoints'
import { usePageTitle } from '../lib/usePageTitle'
import { showToast } from '../lib/toast'
import { getPageSize } from '../lib/preferences'
import { formatDate } from '../lib/formatDate'
import Card from '../components/ui/Card'
import Badge from '../components/ui/Badge'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import ErrorMessage from '../components/ui/ErrorMessage'
import EmptyState from '../components/ui/EmptyState'

const SEVERITIES = ['All', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export default function Secrets() {
  usePageTitle('Secrets')
  const pageSize = getPageSize()

  const [severity, setSeverity] = useState('All')
  const [search, setSearch] = useState('')
  const [repoUrl, setRepoUrl] = useState('')
  const [page, setPage] = useState(1)
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [expandedId, setExpandedId] = useState(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    const filters = { page, page_size: pageSize }
    if (severity !== 'All') filters.severity = severity
    if (repoUrl.trim()) filters.repo_url = repoUrl.trim()

    getSecrets(filters)
      .then((result) => {
        if (!cancelled) {
          setData(result)
          setError(null)
        }
      })
      .catch((err) => {
        if (!cancelled) setError(err.response?.data?.error || err.message || 'Failed to load secrets')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [severity, repoUrl, page])

  const clearFilters = () => {
    setSeverity('All')
    setSearch('')
    setRepoUrl('')
    setPage(1)
  }

  const copyHash = async (hash) => {
    try {
      await navigator.clipboard.writeText(hash)
      showToast('Secret hash copied to clipboard', 'success')
    } catch {
      showToast('Could not copy to clipboard', 'error')
    }
  }

  const secrets = (data?.secrets || []).filter((s) => {
    if (!search.trim()) return true
    const needle = search.trim().toLowerCase()
    return s.file_path.toLowerCase().includes(needle) || s.pattern_name.toLowerCase().includes(needle)
  })

  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / pageSize))

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Secrets</h1>
        <p className="text-sm text-gray-500 dark:text-gray-400">{total} total findings</p>
      </div>

      <Card className="flex flex-wrap items-end gap-3">
        <div>
          <label className="mb-1 block text-xs font-medium text-gray-500 dark:text-gray-400">Severity</label>
          <select
            value={severity}
            onChange={(e) => {
              setSeverity(e.target.value)
              setPage(1)
            }}
            className="rounded-lg border border-gray-300 px-3 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
          >
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="mb-1 block text-xs font-medium text-gray-500 dark:text-gray-400">
            Search (file / pattern)
          </label>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="config.py, AWS Access Key..."
            className="w-56 rounded-lg border border-gray-300 px-3 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
          />
        </div>

        <div>
          <label className="mb-1 block text-xs font-medium text-gray-500 dark:text-gray-400">Repo URL</label>
          <input
            value={repoUrl}
            onChange={(e) => {
              setRepoUrl(e.target.value)
              setPage(1)
            }}
            placeholder="https://github.com/org/repo"
            className="w-56 rounded-lg border border-gray-300 px-3 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
          />
        </div>

        <button
          onClick={clearFilters}
          className="flex items-center gap-1 rounded-lg border border-gray-300 px-3 py-1.5 text-sm text-gray-600 hover:bg-gray-50 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800"
        >
          <X size={14} />
          Clear filters
        </button>
      </Card>

      <Card className="p-0">
        {loading ? (
          <LoadingSpinner />
        ) : error ? (
          <div className="p-5">
            <ErrorMessage message={error} />
          </div>
        ) : secrets.length === 0 ? (
          <EmptyState icon={Shield} message="No secrets found" />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-200 text-left text-xs uppercase text-gray-500 dark:border-gray-800 dark:text-gray-400">
                    <th className="w-8 py-3 pl-4" />
                    <th className="py-3 pr-4">Severity</th>
                    <th className="py-3 pr-4">Pattern</th>
                    <th className="py-3 pr-4">Credential</th>
                    <th className="py-3 pr-4">File Path</th>
                    <th className="py-3 pr-4">Commit</th>
                    <th className="py-3 pr-4">Author</th>
                    <th className="py-3 pr-4">Score</th>
                    <th className="py-3 pr-4">Detected At</th>
                  </tr>
                </thead>
                <tbody>
                  {secrets.map((secret) => {
                    const expanded = expandedId === secret.id
                    return (
                      <Fragment key={secret.id}>
                        <tr
                          onClick={() => setExpandedId(expanded ? null : secret.id)}
                          className="cursor-pointer border-b border-gray-100 last:border-0 hover:bg-gray-50 dark:border-gray-800 dark:hover:bg-gray-800/50"
                        >
                          <td className="py-3 pl-4 text-gray-400">
                            {expanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                          </td>
                          <td className="py-3 pr-4">
                            <Badge label={secret.severity_label} variant="severity" />
                          </td>
                          <td className="py-3 pr-4 text-gray-700 dark:text-gray-300">{secret.pattern_name}</td>
                          <td className="py-3 pr-4 font-mono text-xs text-gray-600 dark:text-gray-400">
                            {secret.masked_value || '—'}
                          </td>
                          <td className="max-w-xs truncate py-3 pr-4 font-mono text-xs text-gray-600 dark:text-gray-400">
                            {secret.file_path}
                          </td>
                          <td className="py-3 pr-4 font-mono text-xs text-gray-600 dark:text-gray-400">
                            {secret.commit_hash.slice(0, 8)}
                          </td>
                          <td className="py-3 pr-4 text-gray-600 dark:text-gray-400">{secret.author_email}</td>
                          <td className="py-3 pr-4 font-medium text-gray-900 dark:text-gray-100">
                            {secret.severity_score.toFixed(1)}
                          </td>
                          <td className="py-3 pr-4 text-gray-500 dark:text-gray-400">
                            {formatDate(secret.detected_at)}
                          </td>
                        </tr>
                        {expanded && (
                          <tr className="border-b border-gray-100 bg-gray-50 dark:border-gray-800 dark:bg-gray-800/30">
                            <td colSpan={9} className="px-4 py-4">
                              <div className="grid grid-cols-1 gap-3 text-xs sm:grid-cols-2">
                                <div>
                                  <p className="font-semibold text-gray-500 dark:text-gray-400">Full File Path</p>
                                  <p className="font-mono text-gray-800 dark:text-gray-200">{secret.file_path}</p>
                                </div>
                                <div>
                                  <p className="font-semibold text-gray-500 dark:text-gray-400">Full Commit Hash</p>
                                  <p className="font-mono text-gray-800 dark:text-gray-200">{secret.commit_hash}</p>
                                </div>
                                <div>
                                  <p className="font-semibold text-gray-500 dark:text-gray-400">Status</p>
                                  <p className="text-gray-800 dark:text-gray-200">
                                    {secret.is_active ? 'Active' : 'Not confirmed active'}
                                  </p>
                                </div>
                                <div>
                                  <p className="font-semibold text-gray-500 dark:text-gray-400">Secret Hash</p>
                                  <div className="flex items-center gap-2">
                                    <p className="truncate font-mono text-gray-800 dark:text-gray-200">
                                      {secret.secret_hash}
                                    </p>
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation()
                                        copyHash(secret.secret_hash)
                                      }}
                                      className="flex shrink-0 items-center gap-1 rounded-md border border-gray-300 px-2 py-1 text-gray-600 hover:bg-white dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-700"
                                    >
                                      <Copy size={12} />
                                      Copy hash
                                    </button>
                                  </div>
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    )
                  })}
                </tbody>
              </table>
            </div>

            <div className="flex items-center justify-between border-t border-gray-200 px-4 py-3 text-sm dark:border-gray-800">
              <span className="text-gray-500 dark:text-gray-400">
                Page {page} of {totalPages}
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page <= 1}
                  className="rounded-lg border border-gray-300 px-3 py-1.5 disabled:opacity-40 dark:border-gray-700"
                >
                  Previous
                </button>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page >= totalPages}
                  className="rounded-lg border border-gray-300 px-3 py-1.5 disabled:opacity-40 dark:border-gray-700"
                >
                  Next
                </button>
              </div>
            </div>
          </>
        )}
      </Card>
    </div>
  )
}
