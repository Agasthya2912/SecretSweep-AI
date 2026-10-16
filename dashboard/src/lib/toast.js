// Tiny pub/sub so code outside React (e.g. the axios interceptor in api/client.js)
// can trigger a toast without needing access to component state.
const bus = new EventTarget()
let nextId = 1

export function showToast(message, type = 'info') {
  const id = nextId++
  bus.dispatchEvent(new CustomEvent('toast', { detail: { id, message, type } }))
  return id
}

export function subscribeToasts(handler) {
  const listener = (event) => handler(event.detail)
  bus.addEventListener('toast', listener)
  return () => bus.removeEventListener('toast', listener)
}
