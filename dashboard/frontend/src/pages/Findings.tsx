import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { FINDING_STATUSES, SEVERITIES, api } from '../api'
import type { Finding } from '../api'
import { Empty, ErrorBanner, Loading, Panel, STATUS_LABEL, StatusPill, fmtDate, fmtNum, useApi } from '../components/common'
import FindingDrawer, { MitreChip, assetText } from '../components/FindingDrawer'
import { SEV_LABEL, SeverityBadge } from '../components/severity'

const PAGE = 50
const FILTER_KEYS = ['severity', 'module_id', 'status', 'scan_id', 'host', 'q'] as const

export default function Findings() {
  const [params, setParams] = useSearchParams()
  const filters = Object.fromEntries(FILTER_KEYS.map((k) => [k, params.get(k) ?? ''])) as Record<(typeof FILTER_KEYS)[number], string>
  const page = Math.max(0, Number(params.get('page') ?? 0) || 0)
  const openId = params.get('open')

  const [hostText, setHostText] = useState(filters.host)
  const [qText, setQText] = useState(filters.q)
  const [selected, setSelected] = useState<Finding | null>(null)

  const modules = useApi(() => api.modules(), [])
  const scans = useApi(() => api.scans(), [])
  const key = params.toString()
  const findings = useApi(() => api.findings({ ...filters, limit: PAGE, offset: page * PAGE }), [key])

  const update = (patch: Record<string, string>) => {
    const next = new URLSearchParams(params)
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v)
      else next.delete(k)
    }
    if (!('page' in patch)) next.delete('page')
    setParams(next, { replace: true })
  }

  // Debounce free-text filters into the URL.
  useEffect(() => {
    const t = window.setTimeout(() => {
      if (hostText !== filters.host || qText !== filters.q) update({ host: hostText, q: qText })
    }, 350)
    return () => window.clearTimeout(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hostText, qText])

  // Open a finding passed via ?open=<id> (e.g. from the dashboard).
  useEffect(() => {
    if (!openId || !findings.data) return
    const f = findings.data.items.find((x) => String(x.id) === openId)
    if (f) setSelected(f)
  }, [openId, findings.data])

  const closeDrawer = () => {
    setSelected(null)
    if (openId) update({ open: '' })
  }

  const onUpdated = (f: Finding) => {
    setSelected(f)
    findings.setData((d) => (d ? { ...d, items: d.items.map((x) => (x.id === f.id ? f : x)) } : d))
  }

  const total = findings.data?.total ?? 0
  const pages = Math.max(1, Math.ceil(total / PAGE))
  const activeFilters = FILTER_KEYS.filter((k) => filters[k])
  const moduleName = (id: string) => modules.data?.find((m) => m.id === id)?.name ?? id

  return (
    <div className="stack">
      {findings.error && <ErrorBanner message={findings.error} onRetry={findings.reload} />}
      <div className="filters">
        <select className="input" value={filters.severity} onChange={(e) => update({ severity: e.target.value })} aria-label="Severity">
          <option value="">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {SEV_LABEL[s]}
            </option>
          ))}
        </select>
        <select className="input" value={filters.module_id} onChange={(e) => update({ module_id: e.target.value })} aria-label="Module">
          <option value="">All modules</option>
          {modules.data
            ?.filter((m) => m.status === 'active')
            .map((m) => (
              <option key={m.id} value={m.id}>
                {m.name}
              </option>
            ))}
        </select>
        <select className="input" value={filters.status} onChange={(e) => update({ status: e.target.value })} aria-label="Status">
          <option value="">All statuses</option>
          {FINDING_STATUSES.map((s) => (
            <option key={s} value={s}>
              {STATUS_LABEL[s]}
            </option>
          ))}
        </select>
        <select className="input" value={filters.scan_id} onChange={(e) => update({ scan_id: e.target.value })} aria-label="Scan">
          <option value="">All scans</option>
          {scans.data?.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name}
            </option>
          ))}
          {filters.scan_id && !scans.data?.some((s) => s.id === filters.scan_id) && <option value={filters.scan_id}>{filters.scan_id}</option>}
        </select>
        <input className="input" placeholder="Host / IP…" value={hostText} onChange={(e) => setHostText(e.target.value)} aria-label="Host" />
        <input className="input grow" placeholder="Search title…" value={qText} onChange={(e) => setQText(e.target.value)} aria-label="Search" />
        {activeFilters.length > 0 && (
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => {
              setHostText('')
              setQText('')
              setParams(new URLSearchParams(), { replace: true })
            }}
          >
            Clear filters
          </button>
        )}
      </div>

      <Panel
        title={`${total.toLocaleString()} finding${total === 1 ? '' : 's'}`}
        actions={
          total > PAGE && (
            <div className="pager">
              <button className="btn btn-ghost btn-sm" disabled={page === 0} onClick={() => update({ page: String(page - 1) })}>
                ‹ Prev
              </button>
              <span className="muted small">
                Page {page + 1} of {pages}
              </span>
              <button className="btn btn-ghost btn-sm" disabled={page + 1 >= pages} onClick={() => update({ page: String(page + 1) })}>
                Next ›
              </button>
            </div>
          )
        }
        flush
      >
        {findings.loading && !findings.data ? (
          <Loading />
        ) : findings.data && findings.data.items.length === 0 ? (
          <Empty title={activeFilters.length ? 'No findings match these filters' : 'No findings yet'}>
            {activeFilters.length ? 'Try clearing some filters.' : 'Run a scan to generate findings.'}
          </Empty>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th className="w-sev">Severity</th>
                  <th>Finding</th>
                  <th>Asset</th>
                  <th>Module</th>
                  <th>ATT&amp;CK</th>
                  <th className="num">Score</th>
                  <th>Status</th>
                  <th>Detected</th>
                </tr>
              </thead>
              <tbody>
                {findings.data?.items.map((f) => (
                  <tr key={f.id} className={`clickable ${selected?.id === f.id ? 'selected' : ''}`} onClick={() => setSelected(f)}>
                    <td className="w-sev">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="cell-title">{f.title}</td>
                    <td className="mono small nowrap">{assetText(f)}</td>
                    <td className="small">{moduleName(f.module_id)}</td>
                    <td>{f.mitre ? <MitreChip mitre={f.mitre} /> : <span className="muted">—</span>}</td>
                    <td className="num mono">{f.score != null ? fmtNum(f.score, 3) : f.confidence != null ? `${fmtNum(f.confidence * 100, 0)}%` : '—'}</td>
                    <td>
                      <StatusPill status={f.status} />
                    </td>
                    <td className="small nowrap">{fmtDate(f.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {selected && <FindingDrawer finding={selected} onClose={closeDrawer} onUpdated={onUpdated} />}
    </div>
  )
}
