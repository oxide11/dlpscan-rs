import { createFileRoute } from '@tanstack/react-router'
import { Page, PageHeader, Card } from '../../ui/layout'
import { EmptyState } from '../../ui/empty'

export const Route = createFileRoute('/ir/handoffs')({ component: HandoffsRoute })

/** "What did I escalate?" */
function HandoffsRoute() {
  return (
    <Page>
      <PageHeader title="Handoffs" description="Tickets and SOAR escalations raised from a case, and what came back." />
      <Card>
        <EmptyState title="Not built yet" detail="Absorbs the Handoffs surface. Needs an integration write path \u2014 the engine has SIEM forwarders behind a feature gate but nothing that opens a ticket and tracks its state." />
      </Card>
    </Page>
  )
}
