import { createFileRoute } from '@tanstack/react-router'
import { Page, PageHeader, Card } from '../../ui/layout'
import { EmptyState } from '../../ui/empty'

export const Route = createFileRoute('/ir/correlate')({ component: CorrelateRoute })

/** "What else is connected?" */
function CorrelateRoute() {
  return (
    <Page>
      <PageHeader title="Correlate" description="Linking one finding to everything that shares a document, a source or an indicator." />
      <Card>
        <EmptyState title="Not built yet" detail="Absorbs Timeline, Pivots and IOC Lookup. The LSH document-similarity vault and /v1/lsh/history are the backing for pivots; timeline needs an event query the engine does not expose yet." />
      </Card>
    </Page>
  )
}
