import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import type { Scan } from '../api'
import { Empty, ErrorBanner, Loading, NewScanCta, Panel, ProgressBar, ScanStatusPill, fmtDate, fmtDuration, useApi } from '../components/common'
import { SeverityCountBar } from '../components/severity'

export const isActive = (s: Scan) => s.status === 'queued' || s.status === 'running'

export default function Scans() {
  const navigate = useNavigate()
  const scans = useApi(() => api.scans(), [], { pollMs: 2000, shouldPoll: (d) => d.some(isActive) })

  const remove = async (e: React.MouseEvent, scan: Scan) => {
    e.stopPropagation()
    if (!window.confirm(`Delete scan "${scan.name}" and all of its findings?`)) return
    try {
      await api.deleteScan(scan.id)
      scans.setData((prev) => prev?.filter((s) => s.id !== scan.id) ?? null)
    } catch (err) {
      window.alert(err instanceof Error ? err.message : String(err))
    }
  }

  if (scans.loading && !scans.data) return <Loading />

  return (
    <div className="stack">
      {scans.error && <ErrorBanner message={scans.error} onRetry={scans.reload} />}
      <Panel title={`My scans${scans.data ? ` (${scans.data.length})` : ''}`} flush>
        {scans.data && scans.data.length === 0 ? (
          <Empty title="No scans yet" action={<NewScanCta />}>
            A scan runs one analysis module over a dataset (CSV of network flows or PE feature vectors) and records every finding.
          </Empty>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Module</th>
                  <th>Input</th>
                  <th>Status</th>
                  <th className="w-sevbar">Findings</th>
                  <th>Created</th>
                  <th>Duration</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {scans.data?.map((s) => (
                  <tr key={s.id} className="clickable" onClick={() => navigate(`/scans/${s.id}`)}>
                    <td>
                      <div className="cell-title">{s.name}</div>
                      <div className="muted small mono">{s.id}</div>
                    </td>
                    <td>{s.module_name}</td>
                    <td className="mono small ellipsis" title={s.input_name}>
                      {s.input_name}
                    </td>
                    <td className="w-status">
                      {isActive(s) ? (
                        <div className="status-progress">
                          <ScanStatusPill status={s.status} />
                          <ProgressBar value={s.progress} label={`${Math.round(s.progress * 100)}%`} />
                        </div>
                      ) : (
                        <ScanStatusPill status={s.status} />
                      )}
                    </td>
                    <td>{s.status === 'failed' ? <span className="muted small">{s.error ?? 'failed'}</span> : <SeverityCountBar counts={s.counts} showZero={s.status === 'completed'} />}</td>
                    <td className="nowrap small">{fmtDate(s.created_at)}</td>
                    <td className="nowrap small mono">{fmtDuration(s.started_at, s.finished_at)}</td>
                    <td className="actions">
                      <button className="btn btn-ghost btn-sm" onClick={(e) => remove(e, s)} title="Delete scan" aria-label={`Delete ${s.name}`}>
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  )
}
