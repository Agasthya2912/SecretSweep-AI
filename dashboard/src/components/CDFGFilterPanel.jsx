import clsx from 'clsx'

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

const SEVERITY_DOT = {
  CRITICAL: 'bg-red-600',
  HIGH: 'bg-orange-500',
  MEDIUM: 'bg-yellow-500',
  LOW: 'bg-green-600',
}

export function emptyFilters() {
  return { severities: new Set(), filePath: '', developer: '', onlyDeleted: false, onlyPropagation: false }
}

export function hasActiveFilter(filters) {
  return (
    filters.severities.size > 0 || !!filters.filePath || !!filters.developer || filters.onlyDeleted || filters.onlyPropagation
  )
}

// Distinct file paths / developer emails present in this graph's secret nodes — the
// dropdowns only ever offer choices that could actually narrow the result.
export function buildFilterOptions(graph) {
  if (!graph) return { filePaths: [], developers: [] }
  const filePaths = [...new Set(graph.nodes.filter((n) => n.type === 'file').map((n) => n.file_path || n.label))]
    .filter(Boolean)
    .sort()
  const developers = [...new Set(graph.nodes.filter((n) => n.type === 'secret').map((n) => n.author))]
    .filter(Boolean)
    .sort()
  return { filePaths, developers }
}

function toggleInSet(set, value) {
  const next = new Set(set)
  if (next.has(value)) next.delete(value)
  else next.add(value)
  return next
}

export default function CDFGFilterPanel({ options, filters, onChange, matchCount, totalCount }) {
  const set = (patch) => onChange({ ...filters, ...patch })

  return (
    <div className="w-full shrink-0 space-y-4 rounded-lg border border-gray-200 p-3 text-sm dark:border-gray-800 md:w-56">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold text-gray-900 dark:text-gray-100">Filters</h3>
        {hasActiveFilter(filters) && (
          <button
            onClick={() => onChange(emptyFilters())}
            className="text-xs text-blue-600 hover:underline dark:text-blue-400"
          >
            Reset
          </button>
        )}
      </div>

      <p className="text-xs text-gray-500 dark:text-gray-400">
        Showing {matchCount} of {totalCount} nodes
      </p>

      <div>
        <p className="mb-1.5 text-xs font-medium uppercase text-gray-500 dark:text-gray-400">Severity</p>
        <div className="space-y-1">
          {SEVERITIES.map((sev) => (
            <label key={sev} className="flex items-center gap-2 text-gray-700 dark:text-gray-300">
              <input
                type="checkbox"
                checked={filters.severities.has(sev)}
                onChange={() => set({ severities: toggleInSet(filters.severities, sev) })}
              />
              <span className={clsx('inline-block h-2 w-2 rounded-full', SEVERITY_DOT[sev])} />
              {sev}
            </label>
          ))}
        </div>
      </div>

      <div>
        <label className="mb-1.5 block text-xs font-medium uppercase text-gray-500 dark:text-gray-400">
          File path
        </label>
        <select
          value={filters.filePath}
          onChange={(e) => set({ filePath: e.target.value })}
          className="w-full rounded-md border border-gray-300 px-2 py-1 text-xs dark:border-gray-700 dark:bg-gray-800"
        >
          <option value="">All files</option>
          {options.filePaths.map((path) => (
            <option key={path} value={path}>
              {path}
            </option>
          ))}
        </select>
      </div>

      <div>
        <label className="mb-1.5 block text-xs font-medium uppercase text-gray-500 dark:text-gray-400">
          Developer
        </label>
        <select
          value={filters.developer}
          onChange={(e) => set({ developer: e.target.value })}
          className="w-full rounded-md border border-gray-300 px-2 py-1 text-xs dark:border-gray-700 dark:bg-gray-800"
        >
          <option value="">All developers</option>
          {options.developers.map((email) => (
            <option key={email} value={email}>
              {email}
            </option>
          ))}
        </select>
      </div>

      <div className="space-y-1.5">
        <label className="flex items-center gap-2 text-gray-700 dark:text-gray-300">
          <input
            type="checkbox"
            checked={filters.onlyDeleted}
            onChange={(e) => set({ onlyDeleted: e.target.checked })}
          />
          Show only deleted secrets
        </label>
        <label className="flex items-center gap-2 text-gray-700 dark:text-gray-300">
          <input
            type="checkbox"
            checked={filters.onlyPropagation}
            onChange={(e) => set({ onlyPropagation: e.target.checked })}
          />
          Show only cross-file propagation
        </label>
      </div>
    </div>
  )
}
