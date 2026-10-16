export default function EmptyState({ icon: Icon, message, hint }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-16 text-center">
      {Icon && <Icon size={40} className="text-gray-300 dark:text-gray-700" />}
      <p className="text-sm font-medium text-gray-500 dark:text-gray-400">{message}</p>
      {hint && <p className="text-xs text-gray-400 dark:text-gray-600">{hint}</p>}
    </div>
  )
}
