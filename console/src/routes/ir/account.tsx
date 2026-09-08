import { createFileRoute } from '@tanstack/react-router'
import { Page, PageHeader, Card } from '../../ui/layout'
import { EmptyState } from '../../ui/empty'

export const Route = createFileRoute('/ir/account')({ component: AccountRoute })

/** "My profile and preferences" */
function AccountRoute() {
  return (
    <Page>
      <PageHeader title="Account" description="Per-operator settings. System configuration lives in C2." />
      <Card>
        <EmptyState title="Not built yet" detail="Shows identity and role from GET /v1/me today via the shell. A durable per-user preference store needs an API; only the theme is persisted, in this browser." />
      </Card>
    </Page>
  )
}
