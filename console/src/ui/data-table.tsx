import * as React from 'react'
import {
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
  type VisibilityState,
  type GroupingState,
} from '@tanstack/react-table'
import { useVirtualizer } from '@tanstack/react-virtual'
import { cn } from '../lib/cn'

/**
 * Where a column's value comes from. Not cosmetic:
 *
 *  - `column`   — a real database column. Empty means empty.
 *  - `metadata` — a key inside the metadata JSONB. Can be **legitimately**
 *                 absent, which is not the same as a null column, so the UI
 *                 must not render it as a gap in the data.
 *  - `derived`  — computed by this console (severity, for instance). Cannot be
 *                 exported, because the export comes from the server and the
 *                 server does not know about it.
 */
export type Provenance = 'column' | 'metadata' | 'derived'

declare module '@tanstack/react-table' {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  interface ColumnMeta<TData extends unknown, TValue> {
    provenance?: Provenance
    /** Fixed width in px. Rows never reflow, so widths are explicit. */
    width?: number
    mono?: boolean
  }
}

const PROVENANCE_NOTE: Record<Provenance, string> = {
  column: '',
  metadata: 'From metadata — may be legitimately absent',
  derived: 'Derived in the console — not included in exports',
}

export interface DataTableProps<T> {
  columns: ColumnDef<T, any>[]
  data: T[]
  state?: {
    sorting?: SortingState
    columnVisibility?: VisibilityState
    grouping?: GroupingState
  }
  onSortingChange?: (s: SortingState) => void
  /** Required over ~200 rows. */
  virtual?: boolean
  isLoading?: boolean
  emptyState?: React.ReactNode
  onRowActivate?: (row: T) => void
  onSelectionChange?: (rows: T[]) => void
  getRowId?: (row: T, index: number) => string
  className?: string
}

const ROW_HEIGHT = 34

function SkeletonRows({ cols, n = 12 }: { cols: number; n?: number }) {
  return (
    <>
      {Array.from({ length: n }).map((_, r) => (
        <tr key={r} className="border-b border-line-subtle">
          {Array.from({ length: cols }).map((__, c) => (
            <td key={c} className="px-2" style={{ height: ROW_HEIGHT }}>
              <span
                className="block h-2 animate-pulse rounded-full bg-sunk"
                style={{ width: `${40 + ((r * 7 + c * 13) % 45)}%` }}
              />
            </td>
          ))}
        </tr>
      ))}
    </>
  )
}

export function DataTable<T>({
  columns,
  data,
  state,
  onSortingChange,
  virtual,
  isLoading,
  emptyState,
  onRowActivate,
  onSelectionChange,
  getRowId,
  className,
}: DataTableProps<T>) {
  const [sorting, setSorting] = React.useState<SortingState>(state?.sorting ?? [])
  const [cursor, setCursor] = React.useState(0)
  const [selected, setSelected] = React.useState<Set<string>>(new Set())
  const scrollRef = React.useRef<HTMLDivElement>(null)

  // Sorting is owned by the URL when the caller passes it; mirror it in.
  React.useEffect(() => {
    if (state?.sorting) setSorting(state.sorting)
  }, [state?.sorting])

  const table = useReactTable({
    data,
    columns,
    state: {
      sorting,
      columnVisibility: state?.columnVisibility ?? {},
      grouping: state?.grouping ?? [],
    },
    onSortingChange: (updater) => {
      const next = typeof updater === 'function' ? updater(sorting) : updater
      setSorting(next)
      onSortingChange?.(next)
    },
    getRowId,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    manualPagination: true,
  })

  const rows = table.getRowModel().rows

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 12,
    enabled: !!virtual,
  })

  const move = React.useCallback(
    (delta: number) => {
      setCursor((c) => {
        const next = Math.min(rows.length - 1, Math.max(0, c + delta))
        if (virtual) virtualizer.scrollToIndex(next, { align: 'auto' })
        return next
      })
    },
    [rows.length, virtual, virtualizer],
  )

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.metaKey || e.ctrlKey || e.altKey) return
    const k = e.key.toLowerCase()
    if (k === 'j' || e.key === 'ArrowDown') {
      e.preventDefault()
      move(1)
    } else if (k === 'k' || e.key === 'ArrowUp') {
      e.preventDefault()
      move(-1)
    } else if (e.key === 'Enter') {
      e.preventDefault()
      const r = rows[cursor]
      if (r) onRowActivate?.(r.original)
    } else if (k === 'x') {
      e.preventDefault()
      const r = rows[cursor]
      if (!r) return
      setSelected((prev) => {
        const next = new Set(prev)
        if (next.has(r.id)) next.delete(r.id)
        else next.add(r.id)
        onSelectionChange?.(rows.filter((row) => next.has(row.id)).map((row) => row.original))
        return next
      })
    }
  }

  const colCount = table.getVisibleLeafColumns().length
  const showEmpty = !isLoading && rows.length === 0

  const body = virtual ? (
    (() => {
      const items = virtualizer.getVirtualItems()
      const padTop = items.length ? items[0].start : 0
      const padBottom = items.length
        ? virtualizer.getTotalSize() - items[items.length - 1].end
        : 0
      return (
        <>
          {padTop > 0 && <tr style={{ height: padTop }} aria-hidden="true" />}
          {items.map((vi) => {
            const row = rows[vi.index]
            return (
              <Row
                key={row.id}
                row={row}
                active={vi.index === cursor}
                selected={selected.has(row.id)}
                onActivate={onRowActivate}
              />
            )
          })}
          {padBottom > 0 && <tr style={{ height: padBottom }} aria-hidden="true" />}
        </>
      )
    })()
  ) : (
    <>
      {rows.map((row, i) => (
        <Row
          key={row.id}
          row={row}
          active={i === cursor}
          selected={selected.has(row.id)}
          onActivate={onRowActivate}
        />
      ))}
    </>
  )

  return (
    <div
      ref={scrollRef}
      // Rows scroll horizontally; they never reflow into stacked cards. A
      // findings row only means something as a row.
      className={cn('relative max-h-[70vh] overflow-auto focus:outline-none', className)}
      tabIndex={0}
      role="grid"
      aria-rowcount={rows.length}
      onKeyDown={onKeyDown}
    >
      <table className="w-full border-collapse text-t4">
        <thead className="sticky top-0 z-10 bg-surface">
          {table.getHeaderGroups().map((hg) => (
            <tr key={hg.id} className="border-b border-line">
              {hg.headers.map((h) => {
                const prov = h.column.columnDef.meta?.provenance ?? 'column'
                const sorted = h.column.getIsSorted()
                return (
                  <th
                    key={h.id}
                    style={{ width: h.column.columnDef.meta?.width }}
                    className="whitespace-nowrap px-2 py-1.5 text-left text-t5 font-medium uppercase tracking-wide text-ink-muted"
                  >
                    <button
                      type="button"
                      disabled={!h.column.getCanSort()}
                      onClick={h.column.getToggleSortingHandler()}
                      title={PROVENANCE_NOTE[prov] || undefined}
                      className="inline-flex items-center gap-1 disabled:cursor-default hover:text-ink"
                    >
                      {flexRender(h.column.columnDef.header, h.getContext())}
                      {prov !== 'column' && (
                        <span
                          aria-hidden="true"
                          className={cn(
                            'size-1 rounded-full',
                            prov === 'derived' ? 'bg-ink-faint' : 'bg-line-bold',
                          )}
                        />
                      )}
                      {sorted && <span aria-hidden="true">{sorted === 'asc' ? '↑' : '↓'}</span>}
                    </button>
                  </th>
                )
              })}
            </tr>
          ))}
        </thead>
        <tbody>
          {isLoading ? <SkeletonRows cols={colCount} /> : showEmpty ? null : body}
        </tbody>
      </table>
      {showEmpty && emptyState}
    </div>
  )
}

function Row<T>({
  row,
  active,
  selected,
  onActivate,
}: {
  row: import('@tanstack/react-table').Row<T>
  active: boolean
  selected: boolean
  onActivate?: (row: T) => void
}) {
  return (
    <tr
      role="row"
      aria-selected={selected}
      onClick={() => onActivate?.(row.original)}
      className={cn(
        'border-b border-line-subtle',
        onActivate && 'cursor-pointer',
        active ? 'bg-hover' : 'hover:bg-hover',
        selected && 'bg-brand-soft',
      )}
      style={{ height: ROW_HEIGHT }}
    >
      {row.getVisibleCells().map((cell) => (
        <td
          key={cell.id}
          className={cn(
            'truncate px-2',
            cell.column.columnDef.meta?.mono && 'font-mono text-t5',
          )}
          style={{ width: cell.column.columnDef.meta?.width }}
        >
          {flexRender(cell.column.columnDef.cell, cell.getContext())}
        </td>
      ))}
    </tr>
  )
}
