import { Route, Routes } from 'react-router-dom'
import { Empty } from './components/common'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Findings from './pages/Findings'
import Hosts from './pages/Hosts'
import Modules from './pages/Modules'
import NewScan from './pages/NewScan'
import ScanDetail from './pages/ScanDetail'
import Scans from './pages/Scans'

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="scans" element={<Scans />} />
        <Route path="scans/new" element={<NewScan />} />
        <Route path="scans/:id" element={<ScanDetail />} />
        <Route path="findings" element={<Findings />} />
        <Route path="hosts" element={<Hosts />} />
        <Route path="modules" element={<Modules />} />
        <Route path="*" element={<Empty title="Page not found" />} />
      </Route>
    </Routes>
  )
}
