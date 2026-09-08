import * as React from 'react'
import * as RDialog from '@radix-ui/react-dialog'
import * as RTabs from '@radix-ui/react-tabs'
import * as RTooltip from '@radix-ui/react-tooltip'
import * as RMenu from '@radix-ui/react-dropdown-menu'
import { cn } from '../lib/cn'
import { Button } from './button'

/* Radix, not local, for all of these: focus trap, portal, dismiss layer and
   roving tabindex are where the real accessibility bugs hide. */

const OVERLAY = 'fixed inset-0 z-50 bg-black/40 data-[state=open]:animate-in'

/**
 * The only place a change commits.
 *
 * States the **consequence**, not the action: "3 patterns stop matching on 4
 * pods" rather than "Apply overrides".
 */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  consequence,
  children,
  confirmLabel = 'Apply',
  destructive,
  loading,
  onConfirm,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  title: string
  /** Plain words. What will be different after this. */
  consequence: React.ReactNode
  children?: React.ReactNode
  confirmLabel?: string
  destructive?: boolean
  loading?: boolean
  onConfirm: () => void
}) {
  return (
    <RDialog.Root open={open} onOpenChange={onOpenChange}>
      <RDialog.Portal>
        <RDialog.Overlay className={OVERLAY} />
        <RDialog.Content className="fixed left-1/2 top-1/2 z-50 flex max-h-[85vh] w-[min(680px,92vw)] -translate-x-1/2 -translate-y-1/2 flex-col rounded-3 border border-line bg-surface shadow-modal">
          <div className="border-b border-line-subtle px-4 py-3">
            <RDialog.Title className="text-t2 font-semibold text-ink">{title}</RDialog.Title>
            <RDialog.Description className="mt-1 text-t4 text-ink-soft">
              {consequence}
            </RDialog.Description>
          </div>
          {children && <div className="min-h-0 flex-1 overflow-auto p-4">{children}</div>}
          <div className="flex items-center justify-end gap-2 border-t border-line-subtle px-4 py-3">
            <RDialog.Close asChild>
              <Button variant="ghost">Cancel</Button>
            </RDialog.Close>
            <Button
              variant={destructive ? 'danger' : 'primary'}
              loading={loading}
              onClick={onConfirm}
            >
              {confirmLabel}
            </Button>
          </div>
        </RDialog.Content>
      </RDialog.Portal>
    </RDialog.Root>
  )
}

/** Right drawer for detail read *beside* a list. If it deserves a URL it is a route. */
export function Sheet({
  open,
  onOpenChange,
  title,
  children,
  footer,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  title: React.ReactNode
  children: React.ReactNode
  footer?: React.ReactNode
}) {
  return (
    <RDialog.Root open={open} onOpenChange={onOpenChange}>
      <RDialog.Portal>
        <RDialog.Overlay className={OVERLAY} />
        <RDialog.Content className="fixed right-0 top-0 z-50 flex h-full w-[min(560px,94vw)] flex-col border-l border-line bg-surface shadow-modal">
          <div className="flex items-center justify-between gap-3 border-b border-line-subtle px-4 py-3">
            <RDialog.Title className="min-w-0 truncate text-t2 font-semibold text-ink">
              {title}
            </RDialog.Title>
            <RDialog.Close asChild>
              <Button variant="ghost" size="sm" aria-label="Close">
                ✕
              </Button>
            </RDialog.Close>
          </div>
          <div className="min-h-0 flex-1 overflow-auto p-4">{children}</div>
          {footer && <div className="border-t border-line-subtle px-4 py-3">{footer}</div>}
        </RDialog.Content>
      </RDialog.Portal>
    </RDialog.Root>
  )
}

/** Selection is a search param — the caller owns `value`. */
export function Tabs({
  value,
  onValueChange,
  tabs,
  children,
}: {
  value: string
  onValueChange: (v: string) => void
  tabs: { value: string; label: React.ReactNode }[]
  children: React.ReactNode
}) {
  return (
    <RTabs.Root value={value} onValueChange={onValueChange}>
      <RTabs.List className="flex items-center gap-0.5 border-b border-line">
        {tabs.map((t) => (
          <RTabs.Trigger
            key={t.value}
            value={t.value}
            className="-mb-px border-b-2 border-transparent px-2.5 py-1.5 text-t4 text-ink-muted hover:text-ink data-[state=active]:border-brand data-[state=active]:text-ink"
          >
            {t.label}
          </RTabs.Trigger>
        ))}
      </RTabs.List>
      {children}
    </RTabs.Root>
  )
}

export const TabPanel = RTabs.Content

/**
 * A tooltip may **not** carry information required to complete a task — it is
 * unreachable by touch and by many keyboard paths. If it matters, it is a hint
 * or a provenance note, not a tooltip.
 */
export function Tooltip({ label, children }: { label: React.ReactNode; children: React.ReactNode }) {
  return (
    <RTooltip.Root>
      <RTooltip.Trigger asChild>{children}</RTooltip.Trigger>
      <RTooltip.Portal>
        <RTooltip.Content
          sideOffset={4}
          className="z-50 max-w-xs rounded-1 border border-line bg-surface px-2 py-1 text-t5 text-ink-soft shadow-menu"
        >
          {label}
        </RTooltip.Content>
      </RTooltip.Portal>
    </RTooltip.Root>
  )
}

export const TooltipProvider = RTooltip.Provider

export function Menu({
  trigger,
  items,
}: {
  trigger: React.ReactNode
  items: { label: string; onSelect: () => void; destructive?: boolean; disabled?: boolean }[]
}) {
  return (
    <RMenu.Root>
      <RMenu.Trigger asChild>{trigger}</RMenu.Trigger>
      <RMenu.Portal>
        <RMenu.Content
          sideOffset={4}
          align="end"
          className="z-50 min-w-40 rounded-2 border border-line bg-surface p-1 shadow-menu"
        >
          {items.map((it) => (
            <RMenu.Item
              key={it.label}
              disabled={it.disabled}
              onSelect={it.onSelect}
              className={cn(
                'cursor-pointer rounded-1 px-2 py-1 text-t4 outline-none data-[highlighted]:bg-hover data-[disabled]:opacity-40',
                it.destructive ? 'text-attn' : 'text-ink',
              )}
            >
              {it.label}
            </RMenu.Item>
          ))}
        </RMenu.Content>
      </RMenu.Portal>
    </RMenu.Root>
  )
}
