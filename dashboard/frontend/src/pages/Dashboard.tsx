import { Link, useNavigate } from 'react-router-dom'
import { api } from '../api'
import type { Module, Stats } from '../api'
import { Empty, ErrorBanner, Loading, NewScanCta, Panel, StatusPill, fmtRelative, useApi } from '../components/common'
import { HBarChart, SeverityDonut, SeverityTimeline } from '../components/charts'
import { assetText } from '../components/FindingDrawer'
import { SeverityBadge, SeverityCountBar } from '../components/severity'

function Kpi({ label, value, hint, tone }: { label: string; value: number; hint?: string; tone?: 'alert' | 'live' }) {
  return (
    <div className={`kpi ${tone ? `kpi-${tone}` : ''}`}>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">{value.toLocaleString()}</div>
      {hint && <div className="kpi-hint">{hint}</div>}
    </div>
  )
}

function ModuleStrip({ modules }: { modules: Module[] }) {
  return (
    <div className="module-strip">
      {modules.map((m) => (
        <Link
          to="/modules"
          key={m.id}
          className={`module-dot status-${m.status} ${m.status === 'active' ? (m.ready ? 'ready' : 'not-ready') : ''}`}
          title={`${m.name} — ${m.status === 'active' ? (m.ready ? 'ready' : m.ready_reason) : m.status.replace('_', ' ')}`}
        >
          <span className="module-dot-num">{m.number}</span>
          <span className="module-dot-name">{m.name}</span>
          <span className="module-dot-state">
            {m.status === 'active' ? (m.ready ? 'Ready' : 'Not configured') : m.status === 'in_progress' ? 'In progress' : 'Planned'}
          </span>
        </Link>
      ))}
    </div>
  )
}

function FeedbackSummary({ fb }: { fb: Stats['feedback'] }) {
  const total = fb.open + fb.confirmed + fb.false_positive + fb.resolved
  const reviewed = total - fb.open
  const rows: [keyof Stats['feedback'], string][] = [
    ['confirmed', 'Confirmed threats'],
    ['false_positive', 'False positives'],
    ['resolved', 'Resolved'],
    ['open', 'Awaiting review'],
  ]
  return (
    <div className="feedback">
      <div className="feedback-head">
        <span className="kpi-value sm">{total ? Math.round((reviewed / total) * 100) : 0}%</span>
        <span className="muted">of findings reviewed by an analyst</span>
      </div>
      <ul className="feedback-list">
        {rows.map(([k, label]) => (
          <li key={k}>
            <StatusPill status={k} />
            <span className="feedback-label">{label}</span>
            <span className="mono">{fb[k].toLocaleString()}</span>
          </li>
        ))}
      </ul>
      {fb.confirmed + fb.false_positive > 0 && (
        <div className="muted small">
          Analyst-measured precision: {Math.round((fb.confirmed / (fb.confirmed + fb.false_positive)) * 100)}% (confirmed ÷ confirmed + false positive)
        </div>
      )}
    </div>
  )
}

export default function Dashboard() {
  const navigate = useNavigate()
  const stats = useApi(() => api.stats(), [], { pollMs: 5000 })
  const modules = useApi(() => api.modules(), [])

  if (stats.loading && !stats.data) return <Loading />
  const s = stats.data

  return (
    <div className="stack">
      {stats.error && <ErrorBanner message={stats.error} onRetry={stats.reload} />}
      {modules.data && (
        <Panel title="Analysis modules" actions={<Link to="/modules">All modules →</Link>}>
          <ModuleStrip modules={modules.data} />
        </Panel>
      )}
      {s && s.scans_total === 0 ? (
        <Panel>
          <Empty title="No scans yet" action={<NewScanCta />}>
            Run your first scan: pick an analysis module (anomaly detection, threat classification, malware classification), give it a CSV or a
            built-in sample, and the findings will show up here.
          </Empty>
        </Panel>
      ) : (
        s && (
          <>
            <div className="kpis">
              <Kpi label="Total scans" value={s.scans_total} />
              <Kpi label="Running now" value={s.scans_running} tone={s.scans_running ? 'live' : undefined} />
              <Kpi label="Total findings" value={s.findings_total} />
              <Kpi label="Open critical + high" value={s.open_critical_high} tone={s.open_critical_high ? 'alert' : undefined} hint="need analyst attention" />
            </div>

            <div className="grid-3">
              <Panel title="Severity distribution">
                <SeverityDonut counts={s.by_severity} />
              </Panel>
              <Panel title="Findings by module">
                {s.by_module.length ? (
                  <HBarChart
                    data={s.by_module.map((m) => ({ label: m.name, value: m.count, key: m.module_id }))}
                    onSelect={(id) => navigate(`/findings?module_id=${encodeURIComponent(id)}`)}
                  />
                ) : (
                  <Empty title="No findings yet" />
                )}
              </Panel>
              <Panel title="Analyst feedback">
                <FeedbackSummary fb={s.feedback} />
              </Panel>
            </div>

            <Panel title="Findings over time" actions={<span className="muted small">per day, stacked by severity</span>}>
              {s.timeline.length ? <SeverityTimeline data={s.timeline} /> : <Empty title="No findings yet" />}
            </Panel>

            <div className="grid-2">
              <Panel title="Top affected hosts" actions={<Link to="/hosts">All hosts →</Link>} flush>
                {s.top_hosts.length ? (
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Host</th>
                        <th className="w-sevbar">Severity</th>
                        <th className="num">Findings</th>
                      </tr>
                    </thead>
                    <tbody>
                      {s.top_hosts.map((h) => (
                        <tr key={h.host} className="clickable" onClick={() => navigate(`/findings?host=${encodeURIComponent(h.host)}`)}>
                          <td className="mono">{h.host}</td>
                          <td>
                            <SeverityCountBar counts={h.counts} />
                          </td>
                          <td className="num mono">{h.findings.toLocaleString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <Empty title="No hosts yet" />
                )}
              </Panel>
              <Panel title="Recent findings" actions={<Link to="/findings">All findings →</Link>} flush>
                {s.recent_findings.length ? (
                  <table className="table">
                    <tbody>
                      {s.recent_findings.map((f) => (
                        <tr key={f.id} className="clickable" onClick={() => navigate(`/findings?scan_id=${encodeURIComponent(f.scan_id)}&open=${f.id}`)}>
                          <td className="w-sev">
                            <SeverityBadge severity={f.severity} />
                          </td>
                          <td>
                            <div className="cell-title">{f.title}</div>
                            <div className="muted small mono">{assetText(f)}</div>
                          </td>
                          <td className="muted small nowrap">{fmtRelative(f.created_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <Empty title="No findings yet" />
                )}
              </Panel>
            </div>
          </>
        )
      )}
    </div>
  )
}
