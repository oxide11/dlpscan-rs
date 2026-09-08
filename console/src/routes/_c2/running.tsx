import { createFileRoute } from '@tanstack/react-router'
import { Page, PageHeader, Card } from '../../ui/layout'
import { EmptyState } from '../../ui/empty'

export const Route = createFileRoute('/_c2/running')({ component: RunningRoute })

/** "What is actually running right now?" */
function RunningRoute() {
  return (
    <Page>
      <PageHeader title="Running" description="What each pod has loaded, and where that drifts from what the policies say it should have." />
      <Card>
        <EmptyState
          title="Not built yet"
          detail="Absorbs Overrides drift, Pods and pod logs. Findings rings are per-pod, so this surface has to fan out across replicas rather than query one."
        />
      </Card>
    </Page>
  )
}
