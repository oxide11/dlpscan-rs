import * as React from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { useMutation } from '@tanstack/react-query'
import { api, type ScanMatch } from '../../lib/api'
import { Page, PageHeader, Card } from '../../ui/layout'
import { Textarea, Field } from '../../ui/field'
import { Button } from '../../ui/button'
import { Severity } from '../../ui/severity'
import { derive } from '../../lib/severity'
import { Badge } from '../../ui/badge'
import { MonoValue, Kbd, MOD_KEY } from '../../ui/mono'
import { EmptyState } from '../../ui/empty'
import { useCommandSource } from '../../ui/command-palette'

export const Route = createFileRoute('/_c2/scan')({ component: ScanRoute })

/** Renders text with matched spans highlighted inline. */
function HighlightedText({ text, matches }: { text: string; matches: ScanMatch[] }) {
  if (!matches.length) return <code className="font-mono text-t5 whitespace-pre-wrap break-all">{text}</code>

  // Build sorted, non-overlapping span list
  const spans = [...matches]
    .map((m) => ({ start: m.span[0], end: m.span[1], category: m.category, sub: m.sub_category }))
    .sort((a, b) => a.start - b.start)

  const merged: typeof spans = []
  for (const s of spans) {
    const prev = merged[merged.length - 1]
    if (prev && s.start < prev.end) {
      prev.end = Math.max(prev.end, s.end)
    } else {
      merged.push({ ...s })
    }
  }

  const parts: React.ReactNode[] = []
  let cursor = 0
  for (let i = 0; i < merged.length; i++) {
    const { start, end } = merged[i]
    if (cursor < start) parts.push(<span key={`p${i}`}>{text.slice(cursor, start)}</span>)
    parts.push(
      <mark
        key={`m${i}`}
        className="rounded bg-attn/20 px-0.5 text-attn-fg ring-1 ring-attn/30"
        title={merged[i].sub || merged[i].category}
      >
        {text.slice(start, end)}
      </mark>,
    )
    cursor = end
  }
  if (cursor < text.length) parts.push(<span key="tail">{text.slice(cursor)}</span>)

  return (
    <code className="font-mono text-t5 whitespace-pre-wrap break-all leading-relaxed">{parts}</code>
  )
}

/** "What would it do with *this*?" */
function ScanRoute() {
  const [text, setText] = React.useState('')
  const [dragOver, setDragOver] = React.useState(false)

  const scan = useMutation({ mutationFn: (t: string) => api.scan(t) })
  const scanFile = useMutation({ mutationFn: (f: File) => api.scanFile(f) })

  const run = React.useCallback(() => {
    if (text.trim()) scan.mutate(text)
  }, [text, scan])

  useCommandSource(() => [{ id: 'scan:run', group: 'Scan', label: 'Run scan', run }])

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
      e.preventDefault()
      run()
    }
  }

  function handleFileDrop(e: React.DragEvent) {
    e.preventDefault()
    setDragOver(false)
    const file = e.dataTransfer.files[0]
    if (file) scanFile.mutate(file)
  }

  function handleFileInput(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (file) scanFile.mutate(file)
    e.target.value = ''
  }

  const textMatches = scan.data ?? []
  const fileMatches = scanFile.data ?? []

  return (
    <Page>
      <PageHeader
        title="Scan"
        description="Runs the real pipeline against text you paste — the same ten stages, the same patterns, the same validators. Nothing is persisted unless the engine is configured to persist scans."
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card
          title="Input"
          actions={
            <Button variant="primary" size="sm" loading={scan.isPending} onClick={run}>
              Scan
            </Button>
          }
          footer={
            <span className="flex items-center gap-1.5">
              <Kbd>{MOD_KEY}</Kbd>
              <Kbd>Enter</Kbd>
              to run
            </span>
          }
        >
          <Field label="Text to scan" hint="Up to 30 MB — the engine rejects larger inputs.">
            <Textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              onKeyDown={onKeyDown}
              placeholder="Paste a message, a log line, a spreadsheet cell…"
              className="min-h-64"
              mono
            />
          </Field>
        </Card>

        <Card
          title="Result"
          actions={
            textMatches.length > 0 ? <Badge tone="count">{textMatches.length}</Badge> : undefined
          }
          bodyClassName={textMatches.length ? 'p-0' : undefined}
        >
          {scan.isError ? (
            <p className="text-t4 text-attn">
              {scan.error instanceof Error ? scan.error.message : 'The scan failed.'}
            </p>
          ) : scan.isPending ? (
            <p className="text-t4 text-ink-muted">Scanning…</p>
          ) : !scan.isSuccess ? (
            <p className="text-t4 text-ink-muted">Nothing scanned yet.</p>
          ) : textMatches.length === 0 ? (
            <EmptyState
              title="No findings"
              detail="Every pattern ran and stayed quiet. This is a real zero — the scan completed."
            />
          ) : (
            <>
              <div className="border-b border-line-subtle px-3 py-2">
                <HighlightedText text={text} matches={textMatches} />
              </div>
              <ul className="divide-y divide-line-subtle">
                {textMatches.map((m: ScanMatch, i) => {
                  const d = derive({
                    confidence: m.confidence,
                    category: m.category,
                    hasContext: m.has_context,
                  })
                  return (
                    <li key={i} className="flex flex-col gap-1 px-3 py-2">
                      <div className="flex items-center gap-2">
                        <Severity level={d.level} variant="bare" derivation={d} />
                        <span className="text-t4 font-medium">{m.sub_category}</span>
                        <span className="text-t5 text-ink-muted">{m.category}</span>
                        <span className="ml-auto font-mono text-t5 text-ink-muted">
                          {m.confidence.toFixed(2)}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 text-t5 text-ink-muted">
                        <MonoValue value={m.text} truncate="end" copy />
                        <span>
                          at {m.span[0]}–{m.span[1]}
                        </span>
                        {m.has_context && <Badge tone="muted">keyword nearby</Badge>}
                      </div>
                      {m.metadata?.bin_brand && (
                        <div className="flex flex-wrap items-center gap-1 text-t5">
                          <Badge tone="muted">{m.metadata.bin_brand}</Badge>
                          {m.metadata.bin_card_type && <Badge tone="muted">{m.metadata.bin_card_type}</Badge>}
                          {m.metadata.bin_country && <Badge tone="muted">{m.metadata.bin_country}</Badge>}
                          {m.metadata.bin_issuer && <Badge tone="muted">{m.metadata.bin_issuer}</Badge>}
                        </div>
                      )}
                    </li>
                  )
                })}
              </ul>
            </>
          )}
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        {/* File upload */}
        <Card
          title="File scan"
          actions={
            fileMatches.length > 0 ? (
              <Badge tone="count">{fileMatches.length}</Badge>
            ) : undefined
          }
        >
          <div
            onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleFileDrop}
            className={[
              'flex flex-col items-center justify-center gap-3 rounded-lg border-2 border-dashed px-6 py-10 transition-colors',
              dragOver
                ? 'border-accent bg-accent/5'
                : 'border-line-subtle hover:border-line',
            ].join(' ')}
          >
            <p className="text-t4 text-ink-muted text-center">
              Drop a file here, or{' '}
              <label className="cursor-pointer text-accent underline underline-offset-2">
                browse
                <input
                  type="file"
                  className="sr-only"
                  onChange={handleFileInput}
                  disabled={scanFile.isPending}
                />
              </label>
            </p>
            <p className="text-t5 text-ink-faint text-center">
              PDF, Office, ZIP, plain text — up to 100 MB. Routed through siphon-fs.
            </p>
            {scanFile.isPending && (
              <p className="text-t5 text-ink-muted">Uploading and scanning…</p>
            )}
            {scanFile.isError && (
              <p className="text-t5 text-attn">
                {scanFile.error instanceof Error ? scanFile.error.message : 'File scan failed.'}
              </p>
            )}
          </div>

          {fileMatches.length > 0 && (
            <ul className="mt-3 divide-y divide-line-subtle">
              {fileMatches.map((m: ScanMatch, i) => {
                const d = derive({
                  confidence: m.confidence,
                  category: m.category,
                  hasContext: m.has_context,
                })
                return (
                  <li key={i} className="flex flex-col gap-1 py-2">
                    <div className="flex items-center gap-2">
                      <Severity level={d.level} variant="bare" derivation={d} />
                      <span className="text-t4 font-medium">{m.sub_category}</span>
                      <span className="text-t5 text-ink-muted">{m.category}</span>
                      <span className="ml-auto font-mono text-t5 text-ink-muted">
                        {m.confidence.toFixed(2)}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 text-t5 text-ink-muted">
                      <MonoValue value={m.text} truncate="end" copy />
                      <span>
                        at {m.span[0]}–{m.span[1]}
                      </span>
                      {m.has_context && <Badge tone="muted">keyword nearby</Badge>}
                    </div>
                    {m.metadata?.bin_brand && (
                      <div className="flex flex-wrap items-center gap-1 text-t5">
                        <Badge tone="muted">{m.metadata.bin_brand}</Badge>
                        {m.metadata.bin_card_type && <Badge tone="muted">{m.metadata.bin_card_type}</Badge>}
                        {m.metadata.bin_country && <Badge tone="muted">{m.metadata.bin_country}</Badge>}
                        {m.metadata.bin_issuer && <Badge tone="muted">{m.metadata.bin_issuer}</Badge>}
                      </div>
                    )}
                  </li>
                )
              })}
            </ul>
          )}
        </Card>
      </div>
    </Page>
  )
}
