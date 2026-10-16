import { AlertCircle } from 'lucide-react'

export default function ErrorMessage({ message = 'Something went wrong.' }) {
  return (
    <div className="flex items-start gap-3 rounded-lg border border-red-200 bg-red-50 p-4 text-red-700 dark:border-red-900 dark:bg-red-950 dark:text-red-300">
      <AlertCircle size={20} className="mt-0.5 shrink-0" />
      <p className="text-sm">{message}</p>
    </div>
  )
}
