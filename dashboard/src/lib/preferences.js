const STORAGE_KEYS = {
  pageSize: 'secretsweep.pageSize',
  dateFormat: 'secretsweep.dateFormat', // 'relative' | 'absolute'
}

export function getPageSize() {
  const stored = Number(localStorage.getItem(STORAGE_KEYS.pageSize))
  return [10, 20, 50].includes(stored) ? stored : 20
}

export function setPageSize(size) {
  localStorage.setItem(STORAGE_KEYS.pageSize, String(size))
}

export function getDateFormat() {
  return localStorage.getItem(STORAGE_KEYS.dateFormat) === 'absolute' ? 'absolute' : 'relative'
}

export function setDateFormat(format) {
  localStorage.setItem(STORAGE_KEYS.dateFormat, format)
}
