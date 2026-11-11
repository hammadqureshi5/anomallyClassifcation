import { useMemo, useState } from 'react'
import { api } from '../api'
import { Empty, ErrorBanner, Loading, NewScanCta, Panel, useApi } from '../components/common'
import HostsTable from '../components/HostsTable'

export default function Hosts() {
  const hosts = useApi(() => api.hosts(), [])
  const [q, setQ] = useState('')
  const filtered = useMemo(() => hosts.data?.filter((h) => h.host.toLowerCase().includes(q.trim().toLowerCase())) ?? [], [hosts.data, q])

  if (hosts.loading && !hosts.data) return <Loading />

  return (
    <div className="stack">
      {hosts.error && <ErrorBanner message={hosts.error} onRetry={hosts.reload} />}
      <div className="filters">
        <input className="input grow" placeholder="Filter hosts…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter hosts" />
      </div>
      <Panel title={`${filtered.length.toLocaleString()} host${filtered.length === 1 ? '' : 's'}`} flush>
        {hosts.data && hosts.data.length === 0 ? (
          <Empty title="No hosts yet" action={<NewScanCta />}>
            Hosts appear here once a scan produces findings that reference an IP address or file.
          </Empty>
        ) : (
          <HostsTable hosts={filtered} />
        )}
      </Panel>
    </div>
  )
}
