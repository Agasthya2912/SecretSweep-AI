import { useCallback, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { KeyRound, ShieldAlert, Users, GitBranch, Network } from 'lucide-react'
import {
  PieChart,
  Pie,
  Cell,
  Legend,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
} from 'recharts'
import { format } from 'date-fns'
import { getSummary, getTimeline, getSecrets } from '../api/endpoints'
import { usePageTitle } from '../lib/usePageTitle'
import Card from '../components/ui/Card'
import StatCard from '../components/ui/StatCard'
import Badge from '../components/ui/Badge'
import LoadingSpinner from '../components/ui/LoadingSpinner'
import ErrorMessage from '../components/ui/ErrorMessage'
import EmptyState from '../components/ui/EmptyState'
import CDFGGraph from '../components/CDFGGraph'

const SEVERITY_COLORS = { CRITICAL: '#DC2626', HIGH: '#EA580C', MEDIUM: '#CA8A04', LOW: '#16A34A' }
const AUTO_REFRESH_MS = 30_000

export default function Overview() {
  usePageTitle('Dashboard')
  const navigate = useNavigate()

  const [summary, setSummary] = useState(null)
  const [timeline, setTimeline] = useState([])
  const [recentSecrets, setRecentSecrets] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [scanJobId, setScanJobId] = useState('')
  const [graphScanJobId, setGraphScanJobId] = useState('')

  const load = useCallback(async () => {
    try {
      const [summaryData, timelineData, secretsData] = await Promise.all([
        getSummary(),
        getTimeline(),
        getSecrets({ page: 1, page_size: 10 }),
      ])
      setSummary(summaryData)
      setTimeline(timelineData)
      setRecentSecrets(secretsData.secrets || [])
      setError(null)
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Failed to load dashboard data')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    const interval = setInterval(load, AUTO_REFRESH_MS)
    return () => clearInterval(interval)
  }, [load])

  if (loading) return <LoadingSpinner />
  if (error) return <ErrorMessage message={error} />

  const pieData = [
    { name: 'CRITICAL', value: summary.critical_count },
    { name: 'HIGH', value: summary.high_count },
    { name: 'MEDIUM', value: summary.medium_count },
    { name: 'LOW', value: summary.low_count },
  ].filter((d) => d.value > 0)

  const lineData = timeline.map((event) => ({
    date: event.date ? format(new Date(event.date), 'MMM d') : '',
    secrets: event.count ?? 0,
  }))

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Dashboard</h1>
        <p className="text-sm text-gray-500 dark:text-gray-400">
          Overview across every repository scanned by SecretSweep AI.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          label="Total Secrets Found"
          value={summary.total_secrets_found}
          color={summary.total_secrets_found > 0 ? 'red' : 'gray'}
          icon={KeyRound}
        />
        <StatCard
          label="Critical Findings"
          value={summary.critical_count}
          color="red"
          icon={ShieldAlert}
          trend={
            summary.critical_count === 0
              ? 'Needs public visibility + active-key validation on scan'
              : undefined
          }
        />
        <StatCard label="High Risk Developers" value={summary.high_risk_developers} color="orange" icon={Users} />
        <StatCard label="Repos Scanned" value={summary.total_repos_scanned} color="blue" icon={GitBranch} />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <h2 className="mb-4 font-semibold text-gray-900 dark:text-gray-100">Severity Breakdown</h2>
          {pieData.length === 0 ? (
            <EmptyState icon={ShieldAlert} message="No findings yet" />
          ) : (
            <ResponsiveContainer width="100%" height={280}>
              <PieChart>
                <Pie
                  data={pieData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={90}
                  label={({ name, value }) => `${name}: ${value}`}
                >
                  {pieData.map((entry) => (
                    <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name]} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend verticalAlign="bottom" height={36} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </Card>

        <Card>
          <h2 className="mb-4 font-semibold text-gray-900 dark:text-gray-100">Scan Timeline</h2>
          {lineData.length === 0 ? (
            <EmptyState icon={GitBranch} message="No scans yet" />
          ) : (
            <ResponsiveContainer width="100%" height={280}>
              <LineChart data={lineData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                <XAxis dataKey="date" tick={{ fontSize: 12 }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 12 }} />
                <Tooltip />
                <Line
                  type="monotone"
                  dataKey="secrets"
                  stroke="#2563EB"
                  strokeWidth={2}
                  dot={{ r: 4, fill: '#2563EB' }}
                  name="Secrets found"
                />
              </LineChart>
            </ResponsiveContainer>
          )}
        </Card>
      </div>

      <Card>
        <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
          <h2 className="font-semibold text-gray-900 dark:text-gray-100">Credential Data Flow Graph</h2>
          <form
            className="flex items-center gap-2"
            onSubmit={(e) => {
              e.preventDefault()
              setGraphScanJobId(scanJobId.trim())
            }}
          >
            <input
              value={scanJobId}
              onChange={(e) => setScanJobId(e.target.value)}
              placeholder="Paste a scan job ID..."
              className="w-56 rounded-lg border border-gray-300 px-3 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
            />
            <button
              type="submit"
              className="flex items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700"
            >
              <Network size={14} />
              View Graph
            </button>
          </form>
        </div>
        {graphScanJobId ? (
          <CDFGGraph scanJobId={graphScanJobId} />
        ) : (
          <EmptyState icon={Network} message="No scan selected" hint="Enter a scan job ID above to view its credential flow graph" />
        )}
      </Card>

      <Card>
        <h2 className="mb-4 font-semibold text-gray-900 dark:text-gray-100">Recent Findings</h2>
        {recentSecrets.length === 0 ? (
          <EmptyState icon={KeyRound} message="No secrets found" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 text-left text-xs uppercase text-gray-500 dark:border-gray-800 dark:text-gray-400">
                  <th className="pb-2 pr-4">Severity</th>
                  <th className="pb-2 pr-4">Pattern</th>
                  <th className="pb-2 pr-4">File</th>
                  <th className="pb-2 pr-4">Author</th>
                  <th className="pb-2">Score</th>
                </tr>
              </thead>
              <tbody>
                {recentSecrets.map((secret) => (
                  <tr
                    key={secret.id}
                    onClick={() => navigate('/secrets')}
                    className="cursor-pointer border-b border-gray-100 last:border-0 hover:bg-gray-50 dark:border-gray-800 dark:hover:bg-gray-800/50"
                  >
                    <td className="py-2.5 pr-4">
                      <Badge label={secret.severity_label} variant="severity" />
                    </td>
                    <td className="py-2.5 pr-4 text-gray-700 dark:text-gray-300">{secret.pattern_name}</td>
                    <td className="max-w-xs truncate py-2.5 pr-4 font-mono text-xs text-gray-600 dark:text-gray-400">
                      {secret.file_path}
                    </td>
                    <td className="py-2.5 pr-4 text-gray-600 dark:text-gray-400">{secret.author_email}</td>
                    <td className="py-2.5 font-medium text-gray-900 dark:text-gray-100">
                      {secret.severity_score.toFixed(1)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}
