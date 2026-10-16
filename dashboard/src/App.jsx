import { Navigate, Route, Routes } from 'react-router-dom'
import Layout from './components/Layout'
import ErrorBoundary from './components/ErrorBoundary'
import Overview from './pages/Overview'
import Secrets from './pages/Secrets'
import Developers from './pages/Developers'
import Scan from './pages/Scan'
import Settings from './pages/Settings'

function withBoundary(element) {
  return <ErrorBoundary>{element}</ErrorBoundary>
}

function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={withBoundary(<Overview />)} />
        <Route path="secrets" element={withBoundary(<Secrets />)} />
        <Route path="developers" element={withBoundary(<Developers />)} />
        <Route path="scan" element={withBoundary(<Scan />)} />
        <Route path="settings" element={withBoundary(<Settings />)} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Route>
    </Routes>
  )
}

export default App
