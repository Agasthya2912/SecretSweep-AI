import clsx from 'clsx'

export default function LoadingSpinner({ className, size = 32 }) {
  return (
    <div className={clsx('flex items-center justify-center py-12', className)}>
      <div
        className="animate-spin rounded-full border-2 border-gray-200 border-t-blue-600 dark:border-gray-700 dark:border-t-blue-400"
        style={{ width: size, height: size }}
        role="status"
        aria-label="Loading"
      />
    </div>
  )
}
