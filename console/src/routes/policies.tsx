import { createFileRoute } from '@tanstack/react-router'
import { Page, PageHeader, Card } from '../ui/layout'
import { EmptyState } from '../ui/empty'

export const Route = createFileRoute('/policies')({ component: PoliciesRoute })

/** "What are we telling it to do?" */
function PoliciesRoute() {
  return (
    <Page>
      <PageHeader title="Policies" description="Loaded rulesets and the lists that tune them. Every change here is a draft until a diff is confirmed \u2014 nothing commits from this screen." />
      <Card>
        <EmptyState
          title="Not built yet"
          detail="Absorbs the Policies list and Lists \u0026 Profiles. Needs the diff-before-apply flow wired to /v1/overrides/diff before any mutation lands here."
        />
      </Card>
    </Page>
  )
}
