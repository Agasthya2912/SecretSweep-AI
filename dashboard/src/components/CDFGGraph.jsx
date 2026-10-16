import { useEffect, useMemo, useRef, useState } from 'react'
import * as d3 from 'd3'
import { Network, ListTree } from 'lucide-react'
import clsx from 'clsx'
import { getGraph } from '../api/endpoints'
import LoadingSpinner from './ui/LoadingSpinner'
import ErrorMessage from './ui/ErrorMessage'
import EmptyState from './ui/EmptyState'
import CDFGFilterPanel, { buildFilterOptions, emptyFilters, hasActiveFilter } from './CDFGFilterPanel'
import SecretLifecycleList, { buildLifecycles } from './SecretLifecycleList'

const NODE_STYLE = {
  secret: { color: '#DC2626', shape: 'circle' },
  commit: { color: '#2563EB', shape: 'square' },
  file: { color: '#16A34A', shape: 'diamond' },
  developer: { color: '#EA580C', shape: 'circle' },
}

const EDGE_STYLE = {
  defined_in: { color: '#DC2626', dash: null },
  deleted_in: { color: '#9CA3AF', dash: '4,3' },
  used_in: { color: '#2563EB', dash: null },
  propagates_to: { color: '#EA580C', dash: null },
}

const HEIGHT = 420

// Edge types that connect a secret directly to a file it touched — the basis for both
// the file-path filter (does this secret have such an edge to the chosen file?) and the
// cross-file-propagation toggle (does it touch 2+ distinct files this way?).
const SECRET_FILE_EDGE_TYPES = new Set(['defined_in', 'used_in', 'deleted_in'])

function shapePath(shape, size) {
  if (shape === 'square') return d3.symbol().type(d3.symbolSquare).size(size * 12)()
  if (shape === 'diamond') return d3.symbol().type(d3.symbolDiamond).size(size * 14)()
  return d3.symbol().type(d3.symbolCircle).size(size * 12)()
}

// Reduces the full graph to just the nodes/edges relevant to the active filters: a
// secret node "matches" if it passes every active filter; kept commit/file nodes are
// whatever a matching secret is actually connected to (so filtering to a handful of
// secrets also drops the now-irrelevant commits/files, not just other secrets).
function filterGraph(graph, filters) {
  if (!graph) return { nodes: [], links: [] }
  if (!hasActiveFilter(filters)) return graph

  const fileTargetsBySecret = new Map()
  graph.links.forEach((l) => {
    if (SECRET_FILE_EDGE_TYPES.has(l.type)) {
      const set = fileTargetsBySecret.get(l.source) || new Set()
      set.add(l.target)
      fileTargetsBySecret.set(l.source, set)
    }
  })

  const filePathToId = new Map(
    graph.nodes.filter((n) => n.type === 'file').map((n) => [n.file_path || n.label, n.id])
  )
  const filterFileId = filters.filePath ? filePathToId.get(filters.filePath) : null

  const secretMatches = (node) => {
    if (filters.severities.size > 0 && !filters.severities.has((node.severity || '').toUpperCase())) return false
    if (filters.developer && node.author !== filters.developer) return false
    if (filters.onlyDeleted && node.is_active !== false) return false
    const touchedFiles = fileTargetsBySecret.get(node.id)
    if (filters.onlyPropagation && (touchedFiles?.size || 0) < 2) return false
    if (filterFileId && !touchedFiles?.has(filterFileId)) return false
    return true
  }

  const passingSecretIds = new Set(
    graph.nodes.filter((n) => n.type === 'secret' && secretMatches(n)).map((n) => n.id)
  )

  const keptNodeIds = new Set(passingSecretIds)
  graph.links.forEach((l) => {
    if (passingSecretIds.has(l.source)) keptNodeIds.add(l.target)
    if (passingSecretIds.has(l.target)) keptNodeIds.add(l.source)
  })

  return {
    nodes: graph.nodes.filter((n) => keptNodeIds.has(n.id)),
    links: graph.links.filter((l) => keptNodeIds.has(l.source) && keptNodeIds.has(l.target)),
  }
}

function CDFGCanvas({ graph }) {
  const containerRef = useRef(null)
  const svgRef = useRef(null)
  const tooltipRef = useRef(null)

  useEffect(() => {
    if (!graph || !graph.nodes?.length || !svgRef.current || !containerRef.current) return undefined

    const width = containerRef.current.clientWidth || 800
    const nodes = graph.nodes.map((n) => ({ ...n }))
    const links = graph.links.map((l) => ({ ...l }))

    const svg = d3.select(svgRef.current).attr('width', width).attr('height', HEIGHT)
    svg.selectAll('*').remove()

    const root = svg.append('g')

    svg.call(
      d3.zoom().scaleExtent([0.3, 4]).on('zoom', (event) => {
        root.attr('transform', event.transform)
      })
    )

    const simulation = d3
      .forceSimulation(nodes)
      .force('link', d3.forceLink(links).id((d) => d.id).distance(90))
      .force('charge', d3.forceManyBody().strength(-220))
      .force('center', d3.forceCenter(width / 2, HEIGHT / 2))
      .force('collide', d3.forceCollide(28))

    const linkSelection = root
      .append('g')
      .selectAll('line')
      .data(links)
      .join('line')
      .attr('stroke', (d) => EDGE_STYLE[d.type]?.color || '#9CA3AF')
      .attr('stroke-dasharray', (d) => EDGE_STYLE[d.type]?.dash || null)
      .attr('stroke-width', 1.5)
      .attr('opacity', 0.7)

    const nodeGroup = root
      .append('g')
      .selectAll('g')
      .data(nodes)
      .join('g')
      .style('cursor', 'grab')
      .call(
        d3
          .drag()
          .on('start', (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart()
            d.fx = d.x
            d.fy = d.y
          })
          .on('drag', (event, d) => {
            d.fx = event.x
            d.fy = event.y
          })
          .on('end', (event, d) => {
            if (!event.active) simulation.alphaTarget(0)
            d.fx = null
            d.fy = null
          })
      )

    nodeGroup
      .append('path')
      .attr('d', (d) => shapePath(NODE_STYLE[d.type]?.shape || 'circle', 12))
      .attr('fill', (d) => d.color || NODE_STYLE[d.type]?.color || '#6B7280')
      .attr('stroke', '#fff')
      .attr('stroke-width', 1.5)

    nodeGroup
      .append('text')
      .text((d) => d.label)
      .attr('x', 12)
      .attr('y', 4)
      .attr('font-size', 10)
      .attr('fill', 'currentColor')
      .attr('class', 'text-gray-700 dark:text-gray-300')

    const tooltip = d3.select(tooltipRef.current)

    nodeGroup
      .on('mouseenter', (event, d) => {
        const detail = d.type === 'secret' && d.severity ? `<br/>severity: ${d.severity}` : ''
        tooltip
          .style('opacity', 1)
          .html(`<strong>${d.label}</strong><br/>type: ${d.type}${detail}`)
          .style('left', `${event.offsetX + 12}px`)
          .style('top', `${event.offsetY + 12}px`)
      })
      .on('mousemove', (event) => {
        tooltip.style('left', `${event.offsetX + 12}px`).style('top', `${event.offsetY + 12}px`)
      })
      .on('mouseleave', () => tooltip.style('opacity', 0))
      .on('click', (event, clicked) => {
        const connected = new Set([clicked.id])
        links.forEach((l) => {
          const sourceId = l.source.id ?? l.source
          const targetId = l.target.id ?? l.target
          if (sourceId === clicked.id) connected.add(targetId)
          if (targetId === clicked.id) connected.add(sourceId)
        })
        nodeGroup.style('opacity', (d) => (connected.has(d.id) ? 1 : 0.15))
        linkSelection.style('opacity', (l) => {
          const sourceId = l.source.id ?? l.source
          const targetId = l.target.id ?? l.target
          return sourceId === clicked.id || targetId === clicked.id ? 0.9 : 0.05
        })
      })

    svg.on('click', (event) => {
      if (event.target === svgRef.current) {
        nodeGroup.style('opacity', 1)
        linkSelection.style('opacity', 0.7)
      }
    })

    simulation.on('tick', () => {
      linkSelection
        .attr('x1', (d) => d.source.x)
        .attr('y1', (d) => d.source.y)
        .attr('x2', (d) => d.target.x)
        .attr('y2', (d) => d.target.y)
      nodeGroup.attr('transform', (d) => `translate(${d.x},${d.y})`)
    })

    return () => simulation.stop()
  }, [graph])

  if (!graph || graph.nodes.length === 0) {
    return <EmptyState icon={Network} message="No nodes match the current filters" />
  }

  return (
    <div ref={containerRef} className="relative">
      <svg ref={svgRef} className="w-full" />
      <div
        ref={tooltipRef}
        className="pointer-events-none absolute z-10 rounded-md bg-gray-900 px-2 py-1 text-xs text-white opacity-0 shadow-lg transition-opacity"
      />
      <div className="absolute bottom-2 left-2 space-y-1 rounded-lg bg-white/90 p-2 text-xs shadow dark:bg-gray-900/90">
        {Object.entries(NODE_STYLE).map(([type, style]) => (
          <div key={type} className="flex items-center gap-1.5">
            <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ backgroundColor: style.color }} />
            <span className="capitalize text-gray-600 dark:text-gray-400">{type}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

const TABS = [
  { id: 'graph', label: 'Graph', icon: Network },
  { id: 'lifecycle', label: 'Secret Lifecycle', icon: ListTree },
]

export default function CDFGGraph({ scanJobId }) {
  const [graph, setGraph] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [tab, setTab] = useState('graph')
  const [filters, setFilters] = useState(emptyFilters)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    setFilters(emptyFilters())
    getGraph(scanJobId)
      .then((data) => {
        if (!cancelled) setGraph(data)
      })
      .catch((err) => {
        if (!cancelled) setError(err.response?.data?.error || err.message || 'Failed to load graph')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [scanJobId])

  const filterOptions = useMemo(() => buildFilterOptions(graph), [graph])
  const filteredGraph = useMemo(() => filterGraph(graph, filters), [graph, filters])
  const lifecycles = useMemo(() => buildLifecycles(graph), [graph])

  if (loading) return <LoadingSpinner />
  if (error) return <ErrorMessage message={error} />
  if (!graph || graph.nodes.length === 0) {
    return <EmptyState icon={Network} message="No graph data available" />
  }

  return (
    <div className="space-y-3">
      <div className="flex gap-1 border-b border-gray-200 dark:border-gray-800">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={clsx(
              'flex items-center gap-1.5 border-b-2 px-3 py-2 text-sm font-medium',
              tab === id
                ? 'border-blue-600 text-blue-600 dark:text-blue-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200'
            )}
          >
            <Icon size={14} />
            {label}
          </button>
        ))}
      </div>

      {tab === 'graph' ? (
        <div className="flex flex-col gap-4 md:flex-row">
          <CDFGFilterPanel
            options={filterOptions}
            filters={filters}
            onChange={setFilters}
            matchCount={filteredGraph.nodes.length}
            totalCount={graph.nodes.length}
          />
          <div className="min-w-0 flex-1">
            <CDFGCanvas graph={filteredGraph} />
          </div>
        </div>
      ) : (
        <SecretLifecycleList lifecycles={lifecycles} />
      )}
    </div>
  )
}
