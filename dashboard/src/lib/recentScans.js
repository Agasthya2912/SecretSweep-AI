// Client-side "Recent Scans" list shown on the Scan page — pure localStorage, not
// server-backed (there's no GET /api/scan list endpoint). Lifted out of Scan.jsx so
// Settings.jsx's "clear everything" action can reset it too without importing a page.

const RECENT_SCANS_KEY = 'secretsweep.recentScans'
const MAX_RECENT_SCANS = 5

export function loadRecentScans() {
  try {
    return JSON.parse(localStorage.getItem(RECENT_SCANS_KEY)) || []
  } catch {
    return []
  }
}

export function saveRecentScan(entry) {
  const current = loadRecentScans().filter((s) => s.id !== entry.id)
  const updated = [entry, ...current].slice(0, MAX_RECENT_SCANS)
  localStorage.setItem(RECENT_SCANS_KEY, JSON.stringify(updated))
  return updated
}

export function clearRecentScans() {
  localStorage.removeItem(RECENT_SCANS_KEY)
}
