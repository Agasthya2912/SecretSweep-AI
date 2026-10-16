import { useEffect } from 'react'

export function usePageTitle(pageName) {
  useEffect(() => {
    document.title = `SecretSweep AI — ${pageName}`
  }, [pageName])
}
