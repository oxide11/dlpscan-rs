import * as React from 'react'
import * as RCheckbox from '@radix-ui/react-checkbox'
import * as RSwitch from '@radix-ui/react-switch'
import { cn } from '../lib/cn'

/**
 * `Field` generates the id and wires `aria-describedby` / `aria-invalid` onto
 * its child. Do not pass your own id — the whole point is that the wiring
 * cannot be forgotten.
 */
export type FieldProps = {
  label: string
  hint?: string
  error?: string
  children: React.ReactElement<{
    id?: string
    'aria-describedby'?: string
    'aria-invalid'?: boolean
  }>
  className?: string
}

export function Field({ label, hint, error, children, className }: FieldProps) {
  const id = React.useId()
  const hintId = hint ? `${id}-hint` : undefined
  const errId = error ? `${id}-err` : undefined
  const describedBy = [hintId, errId].filter(Boolean).join(' ') || undefined

  return (
    <div className={cn('flex flex-col gap-1', className)}>
      <label htmlFor={id} className="text-t5 font-medium text-ink-soft">
        {label}
      </label>
      {React.cloneElement(children, {
        id,
        'aria-describedby': describedBy,
        'aria-invalid': error ? true : undefined,
      })}
      {hint && !error && (
        <p id={hintId} className="text-t5 text-ink-muted">
          {hint}
        </p>
      )}
      {error && (
        <p id={errId} className="text-t5 text-attn">
          {error}
        </p>
      )}
    </div>
  )
}

const CONTROL =
  'h-[30px] w-full rounded-1 border border-line bg-surface px-2 text-t3 text-ink ' +
  'placeholder:text-ink-faint transition-colors hover:border-line-strong ' +
  'aria-[invalid=true]:border-attn disabled:opacity-50'

export type InputProps = React.InputHTMLAttributes<HTMLInputElement> & { mono?: boolean }

export const Input = React.forwardRef<HTMLInputElement, InputProps>(function Input(
  { mono, className, ...rest },
  ref,
) {
  return <input ref={ref} className={cn(CONTROL, mono && 'font-mono text-t4', className)} {...rest} />
})

export type TextareaProps = React.TextareaHTMLAttributes<HTMLTextAreaElement> & { mono?: boolean }

export const Textarea = React.forwardRef<HTMLTextAreaElement, TextareaProps>(function Textarea(
  { mono, className, ...rest },
  ref,
) {
  return (
    <textarea
      ref={ref}
      className={cn(CONTROL, 'h-auto min-h-24 py-1.5 leading-relaxed', mono && 'font-mono text-t4', className)}
      {...rest}
    />
  )
})

export type SelectProps = React.SelectHTMLAttributes<HTMLSelectElement>

export const Select = React.forwardRef<HTMLSelectElement, SelectProps>(function Select(
  { className, children, ...rest },
  ref,
) {
  return (
    <select ref={ref} className={cn(CONTROL, 'cursor-pointer pr-6', className)} {...rest}>
      {children}
    </select>
  )
})

export function Checkbox({
  label,
  className,
  ...rest
}: RCheckbox.CheckboxProps & { label?: string }) {
  const id = React.useId()
  return (
    <div className={cn('inline-flex items-center gap-2', className)}>
      <RCheckbox.Root
        id={id}
        className="size-4 shrink-0 rounded-[3px] border border-line-strong bg-surface data-[state=checked]:border-brand data-[state=checked]:bg-brand"
        {...rest}
      >
        <RCheckbox.Indicator className="flex items-center justify-center text-onbrand">
          <svg className="size-3" viewBox="0 0 16 16" aria-hidden="true">
            <path d="M3.5 8.5l3 3 6-6.5" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </RCheckbox.Indicator>
      </RCheckbox.Root>
      {label && (
        <label htmlFor={id} className="text-t3 text-ink cursor-pointer select-none">
          {label}
        </label>
      )}
    </div>
  )
}

export function Switch({ label, className, ...rest }: RSwitch.SwitchProps & { label?: string }) {
  const id = React.useId()
  return (
    <div className={cn('inline-flex items-center gap-2', className)}>
      <RSwitch.Root
        id={id}
        className="h-4 w-7 shrink-0 rounded-full border border-line-strong bg-sunk transition-colors data-[state=checked]:border-brand data-[state=checked]:bg-brand"
        {...rest}
      >
        <RSwitch.Thumb className="block size-3 translate-x-0.5 rounded-full bg-surface transition-transform data-[state=checked]:translate-x-[14px]" />
      </RSwitch.Root>
      {label && (
        <label htmlFor={id} className="text-t3 text-ink cursor-pointer select-none">
          {label}
        </label>
      )}
    </div>
  )
}
