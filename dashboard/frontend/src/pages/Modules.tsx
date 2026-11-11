import { Link } from 'react-router-dom'
import { api } from '../api'
import type { Module, ModuleStatus } from '../api'
import { ErrorBanner, Loading, useApi } from '../components/common'

const GROUPS: { status: ModuleStatus; title: string; blurb: string }[] = [
  { status: 'active', title: 'Active', blurb: 'Implemented, trained and evaluated — can be run as scans.' },
  { status: 'in_progress', title: 'In progress', blurb: 'Development has started.' },
  { status: 'planned', title: 'Planned', blurb: 'Scheduled for the second half of the project.' },
]

function ModuleCard({ m }: { m: Module }) {
  return (
    <article className={`module-card status-${m.status}`}>
      <header className="module-card-head">
        <span className="template-num">M{m.number}</span>
        {m.status === 'active' ? (
          <span className={`badge ${m.ready ? 'badge-ok' : 'badge-warn'}`} title={m.ready_reason}>
            {m.ready ? '● Ready' : '▲ Not configured'}
          </span>
        ) : (
          <span className="badge badge-muted">{m.status === 'in_progress' ? 'In progress' : 'Planned'}</span>
        )}
      </header>
      <h3>{m.name}</h3>
      <div className="muted small">
        {m.category} · {m.owner}
      </div>
      <p className="module-desc">{m.description}</p>
      {m.status === 'active' && !m.ready && <div className="template-reason small">{m.ready_reason}</div>}
      {m.metrics.length > 0 && (
        <dl className="metrics">
          {m.metrics.map((x) => (
            <div key={x.label} className="metric">
              <dt>{x.label}</dt>
              <dd>{x.value}</dd>
            </div>
          ))}
        </dl>
      )}
      <footer className="module-card-foot">
        {m.input && <span className="muted small">Input: {m.input.label}</span>}
        <span className="grow" />
        {m.repo && (
          <a href={m.repo} target="_blank" rel="noreferrer" className="small">
            Repository ↗
          </a>
        )}
        {m.status === 'active' && m.ready && m.input && (
          <Link className="btn btn-primary btn-sm" to={`/scans/new?module=${encodeURIComponent(m.id)}`}>
            Scan
          </Link>
        )}
      </footer>
    </article>
  )
}

export default function Modules() {
  const modules = useApi(() => api.modules(), [])
  if (modules.loading && !modules.data) return <Loading />
  const list = modules.data ?? []

  return (
    <div className="stack">
      {modules.error && <ErrorBanner message={modules.error} onRetry={modules.reload} />}
      <p className="lede">
        ACDS is built from twelve independent analysis modules (see the project proposal). Each one runs in its own environment and reports findings in a
        shared format, so new modules can be plugged in without changing the others.
      </p>
      {GROUPS.map((g) => {
        const items = list.filter((m) => m.status === g.status).sort((a, b) => a.number - b.number)
        if (!items.length) return null
        return (
          <section key={g.status} className="module-group">
            <div className="module-group-head">
              <h2>
                {g.title} <span className="muted">({items.length})</span>
              </h2>
              <span className="muted small">{g.blurb}</span>
            </div>
            <div className="module-grid">
              {items.map((m) => (
                <ModuleCard key={m.id} m={m} />
              ))}
            </div>
          </section>
        )
      })}
    </div>
  )
}
