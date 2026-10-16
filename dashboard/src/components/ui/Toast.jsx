import { useEffect, useState } from 'react'
import { CheckCircle, AlertCircle, Info, X } from 'lucide-react'
import clsx from 'clsx'
import { subscribeToasts } from '../../lib/toast'

const TYPE_STYLES = {
  success: 'border-green-200 bg-green-50 text-green-800 dark:border-green-900 dark:bg-green-950 dark:text-green-300',
  error: 'border-red-200 bg-red-50 text-red-800 dark:border-red-900 dark:bg-red-950 dark:text-red-300',
  info: 'border-blue-200 bg-blue-50 text-blue-800 dark:border-blue-900 dark:bg-blue-950 dark:text-blue-300',
}

const TYPE_ICONS = { success: CheckCircle, error: AlertCircle, info: Info }

const AUTO_DISMISS_MS = 5000

export default function ToastContainer() {
  const [toasts, setToasts] = useState([])

  useEffect(() => {
    return subscribeToasts((toast) => {
      setToasts((current) => [...current, toast])
      setTimeout(() => {
        setToasts((current) => current.filter((t) => t.id !== toast.id))
      }, AUTO_DISMISS_MS)
    })
  }, [])

  const dismiss = (id) => setToasts((current) => current.filter((t) => t.id !== id))

  if (toasts.length === 0) return null

  return (
    <div className="fixed right-4 top-4 z-50 flex w-80 flex-col gap-2">
      {toasts.map((toast) => {
        const Icon = TYPE_ICONS[toast.type] || Info
        return (
          <div
            key={toast.id}
            className={clsx(
              'flex items-start gap-2 rounded-lg border p-3 text-sm shadow-lg',
              TYPE_STYLES[toast.type] || TYPE_STYLES.info
            )}
          >
            <Icon size={18} className="mt-0.5 shrink-0" />
            <p className="flex-1">{toast.message}</p>
            <button
              onClick={() => dismiss(toast.id)}
              className="shrink-0 opacity-60 hover:opacity-100"
              aria-label="Dismiss"
            >
              <X size={16} />
            </button>
          </div>
        )
      })}
    </div>
  )
}
