import * as React from 'react'
import * as RToast from '@radix-ui/react-toast'

/**
 * Confirms an async mutation landed. **Never for errors that need action** —
 * a dismissible error is a lost error, so those render inline where the fix is.
 */
type Toast = { id: number; message: React.ReactNode }

const ToastCtx = React.createContext<(message: React.ReactNode) => void>(() => {})

export const useToast = () => React.useContext(ToastCtx)

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = React.useState<Toast[]>([])
  const next = React.useRef(0)

  const push = React.useCallback((message: React.ReactNode) => {
    const id = next.current++
    setToasts((t) => [...t, { id, message }])
  }, [])

  return (
    <ToastCtx.Provider value={push}>
      <RToast.Provider swipeDirection="right" duration={4000}>
        {children}
        {toasts.map((t) => (
          <RToast.Root
            key={t.id}
            onOpenChange={(open) => {
              if (!open) setToasts((prev) => prev.filter((x) => x.id !== t.id))
            }}
            className="flex items-center gap-3 rounded-2 border border-line bg-surface px-3 py-2 text-t4 text-ink shadow-menu"
          >
            <RToast.Description>{t.message}</RToast.Description>
          </RToast.Root>
        ))}
        <RToast.Viewport className="fixed bottom-4 right-4 z-50 flex w-80 flex-col gap-2 outline-none" />
      </RToast.Provider>
    </ToastCtx.Provider>
  )
}
