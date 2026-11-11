import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import type { Finding, FindingStatus } from '../api'
import { StatusPill, fmtDate, fmtNum, fmtValue } from './common'
import { SeverityBadge } from './severity'

export function mitreUrl(id: string): string | null {
  if (!/^T\d{4}(\.\d{3})?$/.test(id)) return null
  return `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`
}

export function MitreChip({ mitre }: { mitre: NonNullable<Finding['mitre']> }) {
  const url = mitreUrl(mitre.technique_id)
  const body = (
    <>
      <b>{mitre.technique_id}</b> {mitre.technique_name}
    </>
  )
  return url ? (
    <a className="mitre-chip" href={url} target="_blank" rel="noreferrer" title={`MITRE ATT&CK · ${mitre.tactic}`}>
      {body} ↗
    </a>
  ) : (
    <span className="mitre-chip" title={mitre.tactic}>
      {body}
    </span>
  )
}

export function assetText(f: Finding): string {
  const a = f.asset ?? {}
  if (a.file) return a.file
  const dst = a.dst_ip ? `${a.dst_ip}${a.dst_port != null ? `:${a.dst_port}` : ''}` : a.dst_port != null ? `port ${a.dst_port}` : ''
  if (a.src_ip && dst) return `${a.src_ip} → ${dst}`
  return a.src_ip ?? (dst || f.host || '—')
}

const ACTIONS: { status: FindingStatus; label: string; cls: string }[] = [
  { status: 'confirmed', label: 'Confirm threat', cls: 'btn-danger' },
  { status: 'false_positive', label: 'False positive', cls: 'btn-ghost' },
  { status: 'resolved', label: 'Resolved', cls: 'btn-ghost' },
  { status: 'open', label: 'Reopen', cls: 'btn-ghost' },
]

export default function FindingDrawer({
  finding,
  onClose,
  onUpdated,
}: {
  finding: Finding
  onClose: () => void
  onUpdated: (f: Finding) => void
}) {
  const [note, setNote] = useState(finding.feedback_note ?? '')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setNote(finding.feedback_note ?? '')
    setError(null)
  }, [finding.id, finding.feedback_note])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const save = async (status?: FindingStatus) => {
    setSaving(true)
    setError(null)
    try {
      const updated = await api.updateFinding(finding.id, { status, feedback_note: note })
      onUpdated(updated)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setSaving(false)
    }
  }

  const maxZ = Math.max(1, ...finding.top_features.map((t) => Math.abs(t.z_score ?? 0)))

  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="Finding details">
        <header className="drawer-head">
          <div className="drawer-meta">
            <SeverityBadge severity={finding.severity} />
            <StatusPill status={finding.status} />
            <span className="muted mono">#{finding.id}</span>
          </div>
          <button className="btn btn-ghost btn-sm" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </header>
        <div className="drawer-body">
          <h3 className="drawer-title">{finding.title}</h3>
          {finding.description && <p className="drawer-desc">{finding.description}</p>}

          <dl className="kv">
            <dt>Asset</dt>
            <dd className="mono">{assetText(finding)}</dd>
            <dt>Module</dt>
            <dd>{finding.module_id}</dd>
            <dt>Scan</dt>
            <dd>
              <Link to={`/scans/${finding.scan_id}`}>{finding.scan_id}</Link>
            </dd>
            {finding.score !== null && (
              <>
                <dt>Score</dt>
                <dd className="mono">{fmtNum(finding.score, 4)}</dd>
              </>
            )}
            {finding.confidence !== null && (
              <>
                <dt>Confidence</dt>
                <dd className="mono">{fmtNum(finding.confidence * 100, 1)}%</dd>
              </>
            )}
            <dt>Detected</dt>
            <dd>{fmtDate(finding.created_at)}</dd>
          </dl>

          {finding.mitre && (
            <section className="drawer-section">
              <h4>MITRE ATT&amp;CK</h4>
              <MitreChip mitre={finding.mitre} />
              <div className="muted small">Tactic: {finding.mitre.tactic}</div>
            </section>
          )}

          {finding.top_features.length > 0 && (
            <section className="drawer-section">
              <h4>Why it was flagged</h4>
              <table className="table table-compact">
                <thead>
                  <tr>
                    <th>Feature</th>
                    <th className="num">Value</th>
                    <th className="num">z-score</th>
                    <th>Deviation</th>
                  </tr>
                </thead>
                <tbody>
                  {finding.top_features.map((t) => (
                    <tr key={t.feature}>
                      <td className="mono">{t.feature}</td>
                      <td className="num mono">{fmtValue(t.value)}</td>
                      <td className="num mono">{t.z_score == null ? '—' : t.z_score.toFixed(2)}</td>
                      <td>
                        <div className="zbar" title={`${t.direction ?? ''} than normal`}>
                          <div className="zbar-fill" style={{ width: `${(Math.abs(t.z_score ?? 0) / maxZ) * 100}%` }} />
                          <span className="zbar-dir">{t.direction === 'high' ? '▲ high' : t.direction === 'low' ? '▼ low' : ''}</span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          )}

          {finding.evidence.length > 0 && (
            <section className="drawer-section">
              <h4>Evidence</h4>
              <dl className="kv">
                {finding.evidence.map((e) => (
                  <div key={e.label} className="kv-row">
                    <dt>{e.label}</dt>
                    <dd className="mono">{fmtValue(e.value)}</dd>
                  </div>
                ))}
              </dl>
            </section>
          )}

          {finding.recommendation && (
            <section className="drawer-section">
              <h4>Recommended response</h4>
              <div className="callout">{finding.recommendation}</div>
              <div className="muted small">Recommendation only — ACDS never executes countermeasures automatically.</div>
            </section>
          )}

          <section className="drawer-section">
            <h4>Analyst feedback</h4>
            <textarea
              className="input"
              rows={3}
              placeholder="Add a note for the team (why is this a real threat / false positive?)"
              value={note}
              onChange={(e) => setNote(e.target.value)}
            />
            {error && <div className="form-error">{error}</div>}
            <div className="btn-row">
              {ACTIONS.filter((a) => a.status !== finding.status).map((a) => (
                <button key={a.status} className={`btn btn-sm ${a.cls}`} disabled={saving} onClick={() => save(a.status)}>
                  {a.label}
                </button>
              ))}
              <button className="btn btn-sm btn-ghost" disabled={saving || note === (finding.feedback_note ?? '')} onClick={() => save()}>
                Save note
              </button>
            </div>
          </section>
        </div>
      </aside>
    </>
  )
}
