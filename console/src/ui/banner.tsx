import * as React from 'react'
import { cn } from '../lib/cn'
import { Button } from './button'

/**
 * Mounted in `AppShell` above every route.
 *
 * The `lockout` kind is **advisory and the copy says so**. The engine has no
 * lock API, so a held lock coordinates admins but cannot stop a direct
 * `/v1/overrides` call — which Kubernetes then resolves last-write-wins. A
 * banner that implied otherwise would be worse than none.
 */
export type BannerKind = 'lockout' | 'progress' | 'notice'

export interface BannerSpec {
  id: string
  kind: BannerKind
  message: React.ReactNode
  /** Only notices dismiss. A lockout or progress state is not the reader's to clear. */
  onDismiss?: () => void
  action?: React.ReactNode
}

const KIND: Record<BannerKind, string> = {
  lockout: 'border-attn/30 bg-attn-soft text-attn',
  progress: 'border-line bg-subtle text-ink-soft',
  notice: 'border-line bg-subtle text-ink-soft',
}

export function Banner({ spec }: { spec: BannerSpec }) {
  const { kind, message, onDismiss, action } = spec
  return (
    <div
      role={kind === 'lockout' ? 'alert' : 'status'}
      className={cn('flex items-center gap-3 border-b px-4 py-1.5 text-t4', KIND[kind])}
    >
      {kind === 'progress' && (
        <svg className="size-3 shrink-0 animate-spin" viewBox="0 0 16 16" aria-hidden="true">
          <circle cx="8" cy="8" r="6.5" fill="none" stroke="currentColor" strokeOpacity="0.25" strokeWidth="2" />
          <path d="M8 1.5A6.5 6.5 0 0 1 14.5 8" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
        </svg>
      )}
      <div className="min-w-0 flex-1">{message}</div>
      {action}
      {kind === 'notice' && onDismiss && (
        <Button variant="ghost" size="sm" onClick={onDismiss} aria-label="Dismiss">
          ✕
        </Button>
      )}
    </div>
  )
}

export function BannerStack({ banners }: { banners: BannerSpec[] }) {
  if (banners.length === 0) return null
  return (
    <div className="flex flex-col">
      {banners.map((b) => (
        <Banner key={b.id} spec={b} />
      ))}
    </div>
  )
}

/** A lock older than this is flagged possibly-abandoned rather than silently expired. */
export const LOCK_STALE_MINUTES = 15

export function lockoutBanner(holder: string, heldMinutes: number): BannerSpec {
  const stale = heldMinutes >= LOCK_STALE_MINUTES
  return {
    id: 'lockout',
    kind: 'lockout',
    message: (
      <>
        <strong className="font-semibold">{holder}</strong> is editing enforcement
        {stale && <> — held {heldMinutes} min, possibly abandoned</>}. This lock is advisory: it
        coordinates admins but does not block a direct API call, and Kubernetes resolves a
        conflict last-write-wins.
      </>
    ),
  }
}
