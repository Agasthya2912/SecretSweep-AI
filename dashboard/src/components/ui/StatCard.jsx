import clsx from 'clsx'
import Card from './Card'

const COLOR_STYLES = {
  red: 'text-red-600 dark:text-red-400',
  orange: 'text-orange-600 dark:text-orange-400',
  blue: 'text-blue-600 dark:text-blue-400',
  green: 'text-green-600 dark:text-green-400',
  gray: 'text-gray-700 dark:text-gray-300',
}

export default function StatCard({ label, value, color = 'gray', icon: Icon, trend }) {
  return (
    <Card className="flex items-start justify-between">
      <div>
        <p className="text-sm font-medium text-gray-500 dark:text-gray-400">{label}</p>
        <p className={clsx('mt-2 text-3xl font-bold tabular-nums', COLOR_STYLES[color])}>{value}</p>
        {trend && <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">{trend}</p>}
      </div>
      {Icon && (
        <div className={clsx('rounded-lg bg-gray-50 p-2 dark:bg-gray-800', COLOR_STYLES[color])}>
          <Icon size={20} />
        </div>
      )}
    </Card>
  )
}
