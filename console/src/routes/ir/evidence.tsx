import { createFileRoute } from '@tanstack/react-router'
import { Page, PageHeader, Card } from '../../ui/layout'
import { EmptyState } from '../../ui/empty'

export const Route = createFileRoute('/ir/evidence')({ component: EvidenceRoute })

/** "Can I hand this over?" */
function EvidenceRoute() {
  return (
    <Page>
      <PageHeader title="Evidence" description="Case packaging with chain of custody, for handing an investigation to someone else." />
      <Card>
        <EmptyState title="Not built yet" detail="Absorbs Chain of Custody, Exhibits and Export Bundle. The HMAC-chained audit log is the custody record; what is missing is a per-case export that carries the chain segment alongside the findings so a recipient can verify it." />
      </Card>
    </Page>
  )
}
