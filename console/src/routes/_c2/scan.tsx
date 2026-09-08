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

/** "What would it do with *this*?" */
function ScanRoute() {
  const [text, setText] = React.useState('')
  const scan = useMutation({ mutationFn: (t: string) => api.scan(t) })

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

  const matches = scan.data ?? []

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
            matches.length > 0 ? <Badge tone="count">{matches.length}</Badge> : undefined
          }
          bodyClassName={matches.length ? 'p-0' : undefined}
        >
          {scan.isError ? (
            <p className="text-t4 text-attn">
              {scan.error instanceof Error ? scan.error.message : 'The scan failed.'}
            </p>
          ) : scan.isPending ? (
            <p className="text-t4 text-ink-muted">Scanning…</p>
          ) : !scan.isSuccess ? (
            <p className="text-t4 text-ink-muted">Nothing scanned yet.</p>
          ) : matches.length === 0 ? (
            <EmptyState
              title="No findings"
              detail="Every pattern ran and stayed quiet. This is a real zero — the scan completed."
            />
          ) : (
            <ul className="divide-y divide-line-subtle">
              {matches.map((m: ScanMatch, i) => {
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
