import { format, formatDistanceToNow } from 'date-fns'
import { getDateFormat } from './preferences'

export function formatDate(value) {
  if (!value) return '—'
  const date = new Date(value)
  return getDateFormat() === 'absolute' ? format(date, 'MMM d, yyyy HH:mm') : formatDistanceToNow(date, { addSuffix: true })
}
