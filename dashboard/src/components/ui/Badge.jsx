import clsx from 'clsx'

// Two independent color scales sharing the same HIGH/MEDIUM/LOW-shaped labels:
// severity (secret findings) and risk (developer profiles) intentionally use
// different colors for "HIGH" — a HIGH-severity secret and a HIGH-risk developer
// are not the same kind of alarm, so conflating their colors would mislead.
const SEVERITY_STYLES = {
  CRITICAL: 'bg-red-100 text-red-700 ring-red-600/20 dark:bg-red-950 dark:text-red-300',
  HIGH: 'bg-orange-100 text-orange-700 ring-orange-600/20 dark:bg-orange-950 dark:text-orange-300',
  MEDIUM: 'bg-yellow-100 text-yellow-800 ring-yellow-600/20 dark:bg-yellow-950 dark:text-yellow-300',
  LOW: 'bg-green-100 text-green-700 ring-green-600/20 dark:bg-green-950 dark:text-green-300',
}

const RISK_STYLES = {
  HIGH: 'bg-red-100 text-red-700 ring-red-600/20 dark:bg-red-950 dark:text-red-300',
  MEDIUM: 'bg-orange-100 text-orange-700 ring-orange-600/20 dark:bg-orange-950 dark:text-orange-300',
  LOW: 'bg-green-100 text-green-700 ring-green-600/20 dark:bg-green-950 dark:text-green-300',
}

/**
 * variant: "severity" (CRITICAL/HIGH/MEDIUM/LOW) or "risk" (HIGH/MEDIUM/LOW).
 */
export default function Badge({ label, variant = 'severity', className }) {
  const styles = variant === 'risk' ? RISK_STYLES : SEVERITY_STYLES
  const value = (label || '').toUpperCase()
  const style = styles[value] || 'bg-gray-100 text-gray-700 ring-gray-600/20 dark:bg-gray-800 dark:text-gray-300'

  return (
    <span
      className={clsx(
        'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold ring-1 ring-inset',
        style,
        className
      )}
    >
      {value || 'UNKNOWN'}
    </span>
  )
}
