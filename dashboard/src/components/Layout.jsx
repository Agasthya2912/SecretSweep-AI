import { useEffect, useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { LayoutDashboard, KeyRound, Users, ScanLine, Settings, ShieldCheck, Menu, X } from 'lucide-react'
import clsx from 'clsx'
import { checkHealth } from '../api/endpoints'
import ToastContainer from './ui/Toast'

const NAV_ITEMS = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/secrets', label: 'Secrets', icon: KeyRound },
  { to: '/developers', label: 'Developers', icon: Users },
  { to: '/scan', label: 'New Scan', icon: ScanLine },
  { to: '/settings', label: 'Settings', icon: Settings },
]

const HEALTH_CHECK_INTERVAL_MS = 10_000

function ConnectionStatus() {
  const [connected, setConnected] = useState(null)

  useEffect(() => {
    let cancelled = false

    async function poll() {
      try {
        await checkHealth()
        if (!cancelled) setConnected(true)
      } catch {
        if (!cancelled) setConnected(false)
      }
    }

    poll()
    const interval = setInterval(poll, HEALTH_CHECK_INTERVAL_MS)
    return () => {
      cancelled = true
      clearInterval(interval)
    }
  }, [])

  return (
    <div className="flex items-center gap-2 px-3 py-2 text-xs text-gray-500 dark:text-gray-400">
      <span
        className={clsx(
          'h-2 w-2 shrink-0 rounded-full',
          connected === null ? 'bg-gray-300' : connected ? 'bg-green-500' : 'bg-red-500'
        )}
      />
      <span>{connected === null ? 'Checking...' : connected ? 'API Connected' : 'API Disconnected'}</span>
    </div>
  )
}

function SidebarContent({ onNavigate }) {
  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 px-4 py-5">
        <ShieldCheck className="text-blue-600 dark:text-blue-400" size={26} />
        <span className="text-lg font-semibold tracking-tight text-gray-900 dark:text-gray-100">
          SecretSweep AI
        </span>
      </div>

      <nav className="flex-1 space-y-1 px-3">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            onClick={onNavigate}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                isActive
                  ? 'bg-blue-50 text-blue-700 dark:bg-blue-950 dark:text-blue-300'
                  : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900 dark:text-gray-400 dark:hover:bg-gray-800 dark:hover:text-gray-100'
              )
            }
          >
            <item.icon size={18} />
            {item.label}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-gray-200 dark:border-gray-800">
        <ConnectionStatus />
      </div>
    </div>
  )
}

export default function Layout() {
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <div className="flex min-h-screen bg-gray-50 dark:bg-gray-950">
      {/* Desktop sidebar */}
      <aside className="hidden w-64 shrink-0 border-r border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-900 md:block">
        <SidebarContent />
      </aside>

      {/* Mobile off-canvas sidebar */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 md:hidden">
          <div className="absolute inset-0 bg-black/40" onClick={() => setMobileOpen(false)} />
          <aside className="absolute inset-y-0 left-0 w-64 bg-white shadow-xl dark:bg-gray-900">
            <SidebarContent onNavigate={() => setMobileOpen(false)} />
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center gap-3 border-b border-gray-200 bg-white px-4 py-3 dark:border-gray-800 dark:bg-gray-900 md:hidden">
          <button
            onClick={() => setMobileOpen((open) => !open)}
            className="rounded-md p-1.5 text-gray-600 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-800"
            aria-label="Toggle navigation"
          >
            {mobileOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
          <span className="font-semibold text-gray-900 dark:text-gray-100">SecretSweep AI</span>
        </header>

        <main className="flex-1 px-4 py-6 sm:px-6 lg:px-8">
          <Outlet />
        </main>
      </div>

      <ToastContainer />
    </div>
  )
}
