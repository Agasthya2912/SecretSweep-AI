import { format } from 'date-fns'
import { ListTree, CircleDot, Eye, Trash2, ShieldCheck } from 'lucide-react'
import clsx from 'clsx'
import Badge from './ui/Badge'
import EmptyState from './ui/EmptyState'

const MS_PER_DAY = 86_400_000

// Every secret node carries defined_in/used_in/deleted_in out-edges (to file nodes) and
// a found_in edge (to a commit); this derives the lifecycle view purely from that D3
// payload — no extra API call needed, since Neo4j already has everything (see
// cdfg/graph_queries.py's _neo4j_extra_node_fields / _d3_extra_node_fields).
export function buildLifecycles(graph) {
  if (!graph) return []
  const nodeById = new Map(graph.nodes.map((n) => [n.id, n]))
  const touchTypes = new Set(['defined_in', 'used_in', 'deleted_in'])

  return graph.nodes
    .filter((n) => n.type === 'secret')
    .map((secret) => {
      const outEdges = graph.links.filter((l) => l.source === secret.id && touchTypes.has(l.type))

      const filesInvolved = [
        ...new Set(outEdges.map((l) => nodeById.get(l.target)?.label).filter(Boolean)),
      ]

      const timeline = outEdges
        .filter((l) => l.timestamp)
        .map((l) => ({ type: l.type, timestamp: l.timestamp, file: nodeById.get(l.target)?.label }))
        .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))

      const definedAt = timeline.find((e) => e.type === 'defined_in')?.timestamp || secret.first_seen_date
      const usedEvents = timeline.filter((e) => e.type === 'used_in')
      const deletedEvents = timeline.filter((e) => e.type === 'deleted_in')
      const lastDeletedAt = deletedEvents.length
        ? deletedEvents[deletedEvents.length - 1].timestamp
        : null

      let exposureDays = 0
      if (definedAt) {
        const start = new Date(definedAt).getTime()
        const end = secret.is_active || !lastDeletedAt ? Date.now() : new Date(lastDeletedAt).getTime()
        exposureDays = Math.max(0, Math.floor((end - start) / MS_PER_DAY))
      }

      return {
        id: secret.id,
        patternName: secret.pattern_name || secret.label,
        severity: secret.severity,
        author: secret.author,
        isActive: secret.is_active,
        exposureDays,
        filesInvolved,
        definedAt,
        usedCount: usedEvents.length,
        lastUsedAt: usedEvents.length ? usedEvents[usedEvents.length - 1].timestamp : null,
        lastDeletedAt,
      }
    })
    .sort((a, b) => b.exposureDays - a.exposureDays)
}

function safeDate(value) {
  if (!value) return null
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? null : d
}

function Step({ label, date, active, icon: Icon, tone }) {
  return (
    <div className={clsx('flex flex-1 items-center gap-2', !active && 'opacity-35')}>
      <div
        className={clsx(
          'flex h-7 w-7 shrink-0 items-center justify-center rounded-full',
          active ? tone : 'bg-gray-200 dark:bg-gray-800'
        )}
      >
        <Icon size={14} className={active ? 'text-white' : 'text-gray-400'} />
      </div>
      <div className="min-w-0">
        <p className="text-xs font-medium text-gray-800 dark:text-gray-200">{label}</p>
        <p className="truncate text-[11px] text-gray-500 dark:text-gray-400">
          {date ? format(date, 'MMM d, yyyy') : active ? '—' : 'n/a'}
        </p>
      </div>
    </div>
  )
}

function LifecycleCard({ lifecycle }) {
  const definedDate = safeDate(lifecycle.definedAt)
  const usedDate = safeDate(lifecycle.lastUsedAt)
  const deletedDate = safeDate(lifecycle.lastDeletedAt)

  return (
    <div className="rounded-lg border border-gray-200 p-4 dark:border-gray-800">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-gray-900 dark:text-gray-100">{lifecycle.patternName}</span>
          <Badge label={lifecycle.severity} variant="severity" />
          {lifecycle.isActive === false && (
            <span className="inline-flex items-center rounded-full bg-gray-100 px-2 py-0.5 text-xs text-gray-600 dark:bg-gray-800 dark:text-gray-400">
              Deleted
            </span>
          )}
        </div>
        <span className="text-xs text-gray-500 dark:text-gray-400">
          Exposed {lifecycle.exposureDays} {lifecycle.exposureDays === 1 ? 'day' : 'days'}
        </span>
      </div>

      <div className="mb-3 flex items-center">
        <Step label="Defined" date={definedDate} active icon={CircleDot} tone="bg-red-600" />
        <div className="h-px flex-1 bg-gray-200 dark:bg-gray-800" />
        <Step
          label={lifecycle.usedCount > 0 ? `Used (${lifecycle.usedCount}×)` : 'Used'}
          date={usedDate}
          active={lifecycle.usedCount > 0}
          icon={Eye}
          tone="bg-blue-600"
        />
        <div className="h-px flex-1 bg-gray-200 dark:bg-gray-800" />
        <Step
          label={lifecycle.isActive === false ? 'Deleted' : 'Still active'}
          date={lifecycle.isActive === false ? deletedDate : null}
          active
          icon={lifecycle.isActive === false ? Trash2 : ShieldCheck}
          tone={lifecycle.isActive === false ? 'bg-gray-500' : 'bg-green-600'}
        />
      </div>

      <dl className="grid grid-cols-1 gap-x-4 gap-y-1.5 text-xs sm:grid-cols-2">
        <div>
          <dt className="text-gray-500 dark:text-gray-400">Author</dt>
          <dd className="truncate text-gray-800 dark:text-gray-200">{lifecycle.author || 'unknown'}</dd>
        </div>
        <div>
          <dt className="text-gray-500 dark:text-gray-400">Files involved</dt>
          <dd className="truncate text-gray-800 dark:text-gray-200" title={lifecycle.filesInvolved.join(', ')}>
            {lifecycle.filesInvolved.join(', ') || '—'}
          </dd>
        </div>
      </dl>
    </div>
  )
}

export default function SecretLifecycleList({ lifecycles }) {
  if (lifecycles.length === 0) {
    return <EmptyState icon={ListTree} message="No confirmed secrets in this scan" />
  }

  return (
    <div className="space-y-3">
      {lifecycles.map((lifecycle) => (
        <LifecycleCard key={lifecycle.id} lifecycle={lifecycle} />
      ))}
    </div>
  )
}
