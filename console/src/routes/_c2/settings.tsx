import { createFileRoute } from '@tanstack/react-router'
import { Page, PageHeader, Card } from '../../ui/layout'
import { EmptyState } from '../../ui/empty'

export const Route = createFileRoute('/_c2/settings')({ component: SettingsRoute })

/** "How is it wired?" */
function SettingsRoute() {
  return (
    <Page>
      <PageHeader title="Settings" description="Set-once configuration: integrations, RBAC, plugins, fingerprints." />
      <Card>
        <EmptyState
          title="Not built yet"
          detail="Absorbs Config, RBAC, Integrations, Plugins and Fingerprints. Read-only first \u2014 the engine has no config-write API today."
        />
      </Card>
    </Page>
  )
}
