import { createFileRoute } from '@tanstack/react-router'
import { Page, PageHeader, Card } from '../../ui/layout'
import { EmptyState } from '../../ui/empty'

export const Route = createFileRoute('/ir/analyze')({ component: AnalyzeRoute })

/** "What is this thing?" */
function AnalyzeRoute() {
  return (
    <Page>
      <PageHeader title="Analyze" description="Investigative tools for a single artefact pulled out of a case." />
      <Card>
        <EmptyState title="Not built yet" detail="Absorbs Crypto Workbench, File Extractor and Forensics as tabs. siphon-fs already does extraction and the forensics feature already reads Office/PDF metadata \u2014 this surface needs those wired, not written." />
      </Card>
    </Page>
  )
}
