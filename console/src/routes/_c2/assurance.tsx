import { createFileRoute } from '@tanstack/react-router'
import { Page, PageHeader, Card } from '../../ui/layout'
import { EmptyState } from '../../ui/empty'

export const Route = createFileRoute('/_c2/assurance')({ component: AssuranceRoute })

/** "Can I prove any of this?" */
function AssuranceRoute() {
  return (
    <Page>
      <PageHeader title="Assurance" description="The evidence surface: precision baselines, adversarial runs, the labelled corpus, and the HMAC audit chain." />
      <Card>
        <EmptyState
          title="Not built yet"
          detail="Absorbs Compliance, Adversarial tests, Test corpus and Audit chain. /v1/baselines/* and /v1/evadex/* are live; the audit chain view needs the verify step, not just the list."
        />
      </Card>
    </Page>
  )
}
