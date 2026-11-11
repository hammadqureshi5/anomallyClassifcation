import { Fragment, useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api'
import type { Finding, FindingGroup } from '../api'
import { Empty, ErrorBanner, Loading, Panel, ProgressBar, ScanStatusPill, StatusPill, fmtDate, fmtDuration, fmtNum, useApi } from '../components/common'
import { SeverityDonut } from '../components/charts'
import FindingDrawer, { assetText } from '../components/FindingDrawer'
import HostsTable from '../components/HostsTable'
import { SeverityBadge, totalCounts } from '../components/severity'
import { isActive } from './Scans'

type Tab = 'findings' | 'hosts' | 'log'

function GroupRow({ scanId, g, onOpen }: { scanId: string; g: FindingGroup; onOpen: (f: Finding) => void }) {
  const [open, setOpen] = useState(false)
  const items = useApi(
    () => (open ? api.findings({ scan_id: scanId, q: g.title, module_id: g.module_id, severity: g.severity, limit: 100 }) : Promise.resolve(null)),
    [open, scanId, g.title],
  )
  const list = items.data?.items.filter((f) => f.title === g.title) ?? []
  return (
    <>
      <tr className="clickable" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
        <td className="w-caret">{open ? '▾' : '▸'}</td>
        <td className="w-sev">
          <SeverityBadge severity={g.severity} />
        </td>
        <td className="cell-title">{g.title}</td>
        <td className="muted">{g.module_id}</td>
        <td className="num mono">{g.hosts.toLocaleString()}</td>
        <td className="num mono">
          <span className="count-pill">{g.count.toLocaleString()}</span>
        </td>
      </tr>
      {open && (
        <tr className="subrow">
          <td />
          <td colSpan={5}>
            {items.loading ? (
              <Loading />
            ) : (
              <table className="table table-compact">
                <thead>
                  <tr>
                    <th>Asset</th>
                    <th className="num">Score</th>
                    <th className="num">Confidence</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {list.map((f) => (
                    <tr key={f.id} className="clickable" onClick={() => onOpen(f)}>
                      <td className="mono">{assetText(f)}</td>
                      <td className="num mono">{fmtNum(f.score, 3)}</td>
                      <td className="num mono">{f.confidence == null ? '—' : `${fmtNum(f.confidence * 100, 1)}%`}</td>
                      <td>
                        <StatusPill status={f.status} />
                      </td>
                    </tr>
                  ))}
                  {items.data && items.data.total > list.length && (
                    <tr>
                      <td colSpan={4} className="muted small">
                        Showing first {list.length}.{' '}
                        <Link to={`/findings?scan_id=${encodeURIComponent(scanId)}&q=${encodeURIComponent(g.title)}`}>View all in Findings →</Link>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            )}
          </td>
        </tr>
      )}
    </>
  )
}


function Console({ lines, live }: { lines: string[]; live: boolean }) {
  const ref = useRef<HTMLPreElement>(null)
  useEffect(() => {
    const el = ref.current
    if (el) el.scrollTop = el.scrollHeight
  }, [lines.length])
  return (
    <pre className="console" ref={ref}>
      {lines.length === 0 && <span className="muted">No log output yet.</span>}
      {lines.map((l, i) => {
        const cls = /error|fail|traceback/i.test(l) ? 'c-err' : /warn/i.test(l) ? 'c-warn' : /done|complete|finished|\[\+\]/i.test(l) ? 'c-ok' : ''
        return (
          <div key={i} className={cls}>
            <span className="c-prompt">acds&gt;</span> {l}
          </div>
        )
      })}
      {live && <span className="cursor" aria-hidden>▌</span>}
    </pre>
  )
}

export default function ScanDetail() {
  const { id = '' } = useParams()
  const [tab, setTab] = useState<Tab>('findings')
  const [selected, setSelected] = useState<Finding | null>(null)
  const scan = useApi(() => api.scan(id), [id], { pollMs: 1500, shouldPoll: isActive })
  const status = scan.data?.status
  const groups = useApi(() => api.findingGroups(id), [id, status])
  const hosts = useApi(() => (tab === 'hosts' ? api.scanHosts(id) : Promise.resolve(null)), [id, tab, status])

  if (scan.loading && !scan.data) return <Loading />
  if (scan.error && !scan.data)
    return (
      <div className="stack">
        <ErrorBanner message={scan.error} onRetry={scan.reload} />
        <Link to="/scans">← Back to scans</Link>
      </div>
    )
  const s = scan.data!
  const live = isActive(s)
  const total = totalCounts(s.counts)

  return (
    <div className="stack">
      {scan.error && <ErrorBanner message={scan.error} onRetry={scan.reload} />}
      <div className="crumbs">
        <Link to="/scans">Scans</Link> / <span>{s.name}</span>
      </div>
      <div className="scan-header panel">
        <div className="scan-header-main">
          <div className="scan-title-row">
            <h2>{s.name}</h2>
            <ScanStatusPill status={s.status} />
          </div>
          {live && <ProgressBar value={s.progress} label={`${Math.round(s.progress * 100)}%`} />}
          {s.status === 'failed' && s.error && (
            <div className="banner banner-error">
              <span className="banner-icon" aria-hidden>!</span>
              <div>
                <strong>Scan failed.</strong> <span className="mono small">{s.error}</span>
              </div>
            </div>
          )}
          <dl className="scan-facts">
            <div>
              <dt>Module</dt>
              <dd>{s.module_name}</dd>
            </div>
            <div>
              <dt>Input</dt>
              <dd className="mono ellipsis" title={s.input_name}>
                {s.input_name}
              </dd>
            </div>
            <div>
              <dt>Rows scanned</dt>
              <dd className="mono">{fmtNum(s.rows_scanned)}</dd>
            </div>
            <div>
              <dt>Started</dt>
              <dd>{fmtDate(s.started_at ?? s.created_at)}</dd>
            </div>
            <div>
              <dt>Duration</dt>
              <dd className="mono">{fmtDuration(s.started_at, s.finished_at)}</dd>
            </div>
            <div>
              <dt>Findings</dt>
              <dd className="mono">{total.toLocaleString()}</dd>
            </div>
          </dl>
          <div className="btn-row">
            <Link className="btn btn-ghost btn-sm" to={`/findings?scan_id=${encodeURIComponent(s.id)}`}>
              Open in Findings
            </Link>
            <Link className="btn btn-ghost btn-sm" to={`/scans/new?module=${encodeURIComponent(s.module_id)}`}>
              Re-run with this module
            </Link>
          </div>
        </div>
        <div className="scan-header-chart">
          <SeverityDonut counts={s.counts} size={140} />
        </div>
      </div>

      <div className="tabs" role="tablist">
        {(
          [
            ['findings', `Findings (${groups.data?.length ?? 0} types)`],
            ['hosts', 'Hosts'],
            ['log', 'Log'],
          ] as [Tab, string][]
        ).map(([k, label]) => (
          <button key={k} role="tab" aria-selected={tab === k} className={`tab ${tab === k ? 'active' : ''}`} onClick={() => setTab(k)}>
            {label}
          </button>
        ))}
      </div>

      {tab === 'findings' && (
        <Panel flush>
          {groups.data && groups.data.length > 0 ? (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th className="w-caret" />
                    <th className="w-sev">Sev</th>
                    <th>Name</th>
                    <th>Module</th>
                    <th className="num">Hosts</th>
                    <th className="num">Count</th>
                  </tr>
                </thead>
                <tbody>
                  {groups.data.map((g) => (
                    <Fragment key={`${g.module_id}|${g.severity}|${g.title}`}>
                      <GroupRow scanId={s.id} g={g} onOpen={setSelected} />
                    </Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          ) : live ? (
            <Loading label="Scan in progress — findings will appear when it completes…" />
          ) : (
            <Empty title={s.status === 'failed' ? 'No findings — the scan failed' : 'No findings'}>
              {s.status === 'completed' && 'Nothing in this input crossed the module’s alert threshold.'}
            </Empty>
          )}
        </Panel>
      )}

      {tab === 'hosts' && <Panel flush>{hosts.loading && !hosts.data ? <Loading /> : <HostsTable hosts={hosts.data ?? []} scanId={s.id} />}</Panel>}

      {tab === 'log' && <Console lines={s.log ?? []} live={live} />}

      {selected && (
        <FindingDrawer
          finding={selected}
          onClose={() => setSelected(null)}
          onUpdated={(f) => {
            setSelected(f)
          }}
        />
      )}
    </div>
  )
}
