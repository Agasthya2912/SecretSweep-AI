import clsx from 'clsx'

export default function Card({ children, className, ...props }) {
  return (
    <div
      className={clsx(
        'rounded-xl border border-gray-200 bg-white p-5 shadow-sm dark:border-gray-800 dark:bg-gray-900',
        className
      )}
      {...props}
    >
      {children}
    </div>
  )
}
