import { useEffect, useMemo, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { api } from '../api'
import type { Module } from '../api'
import { ErrorBanner, Loading, Panel, useApi } from '../components/common'

function TemplateCard({ m, selected, onSelect }: { m: Module; selected: boolean; onSelect: () => void }) {
  const selectable = m.status === 'active' && m.input !== null
  return (
    <button
      type="button"
      className={`template ${selected ? 'selected' : ''} ${selectable ? '' : 'disabled'}`}
      onClick={selectable ? onSelect : undefined}
      disabled={!selectable}
      aria-pressed={selected}
    >
      <div className="template-top">
        <span className="template-num">M{m.number}</span>
        {selectable ? (
          <span className={`badge ${m.ready ? 'badge-ok' : 'badge-warn'}`}>{m.ready ? '● Ready' : '▲ Not configured'}</span>
        ) : (
          <span className="badge badge-muted">{m.status === 'in_progress' ? 'In progress' : 'Planned'}</span>
        )}
      </div>
      <div className="template-name">{m.name}</div>
      <div className="template-desc">{m.description}</div>
      {selectable && m.input && <div className="template-input muted small">Input: {m.input.label}</div>}
      {selectable && !m.ready && <div className="template-reason small">{m.ready_reason}</div>}
      <div className="template-owner muted small">{m.owner}</div>
    </button>
  )
}

export default function NewScan() {
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const modules = useApi(() => api.modules(), [])
  const samples = useApi(() => api.samples(), [])

  const [moduleId, setModuleId] = useState<string | null>(params.get('module'))
  const [name, setName] = useState('')
  const [source, setSource] = useState<'sample' | 'upload'>('sample')
  const [sampleId, setSampleId] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [options, setOptions] = useState<Record<string, string>>({})
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const active = useMemo(() => modules.data?.filter((m) => m.status === 'active' && m.input !== null) ?? [], [modules.data])
  const upcoming = useMemo(() => modules.data?.filter((m) => m.status !== 'active') ?? [], [modules.data])
  const module = modules.data?.find((m) => m.id === moduleId) ?? null
  const moduleSamples = useMemo(() => samples.data?.filter((s) => moduleId && s.module_ids.includes(moduleId)) ?? [], [samples.data, moduleId])

  // Reset step-2 fields whenever the template changes.
  useEffect(() => {
    if (!module) return
    setOptions(Object.fromEntries(module.options.map((o) => [o.key, o.default])))
    setName(`${module.name} — ${new Date().toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}`)
    setFile(null)
    setError(null)
  }, [module])

  useEffect(() => {
    setSampleId(moduleSamples[0]?.id ?? '')
    setSource(moduleSamples.length ? 'sample' : 'upload')
  }, [moduleSamples])

  const canSubmit = module && module.ready && name.trim() && (source === 'sample' ? !!sampleId : !!file) && !submitting

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!module || !canSubmit) return
    setSubmitting(true)
    setError(null)
    const form = new FormData()
    form.set('name', name.trim())
    form.set('module_id', module.id)
    if (source === 'sample') form.set('sample_id', sampleId)
    else if (file) form.set('file', file)
    form.set('options', JSON.stringify(options))
    try {
      const scan = await api.createScan(form)
      navigate(`/scans/${scan.id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      setSubmitting(false)
    }
  }

  if (modules.loading && !modules.data) return <Loading />

  return (
    <div className="stack">
      {modules.error && <ErrorBanner message={modules.error} onRetry={modules.reload} />}
      <Panel title={<><span className="step">1</span> Choose a scan template</>}>
        <div className="templates">
          {active.map((m) => (
            <TemplateCard key={m.id} m={m} selected={m.id === moduleId} onSelect={() => setModuleId(m.id)} />
          ))}
        </div>
        {upcoming.length > 0 && (
          <>
            <div className="subhead">Coming soon</div>
            <div className="templates">
              {upcoming.map((m) => (
                <TemplateCard key={m.id} m={m} selected={false} onSelect={() => {}} />
              ))}
            </div>
          </>
        )}
      </Panel>

      {module && (
        <Panel title={<><span className="step">2</span> Configure — {module.name}</>}>
          {!module.ready && (
            <div className="banner banner-warn">
              <span className="banner-icon" aria-hidden>▲</span>
              <div>
                <strong>This module isn’t configured on the server yet.</strong> <span className="muted">{module.ready_reason}</span>
              </div>
            </div>
          )}
          <form className="form" onSubmit={submit}>
            <label className="field">
              <span className="field-label">Scan name</span>
              <input className="input" value={name} onChange={(e) => setName(e.target.value)} required />
            </label>

            <fieldset className="field">
              <legend className="field-label">Input data{module.input ? ` — ${module.input.label}` : ''}</legend>
              <div className="radio-row">
                <label className={`radio ${moduleSamples.length ? '' : 'disabled'}`}>
                  <input type="radio" name="source" checked={source === 'sample'} disabled={!moduleSamples.length} onChange={() => setSource('sample')} />
                  Built-in sample
                </label>
                <label className="radio">
                  <input type="radio" name="source" checked={source === 'upload'} onChange={() => setSource('upload')} />
                  Upload CSV
                </label>
              </div>
              {source === 'sample' ? (
                moduleSamples.length ? (
                  <div className="sample-list">
                    {moduleSamples.map((s) => (
                      <label key={s.id} className={`sample ${sampleId === s.id ? 'selected' : ''}`}>
                        <input type="radio" name="sample" checked={sampleId === s.id} onChange={() => setSampleId(s.id)} />
                        <div>
                          <div className="cell-title">{s.name}</div>
                          <div className="muted small">
                            {s.description}
                            {s.rows != null && ` · ${s.rows.toLocaleString()} rows`}
                          </div>
                        </div>
                      </label>
                    ))}
                  </div>
                ) : (
                  <div className="muted small">No built-in samples for this module — upload a CSV.</div>
                )
              ) : (
                <label className="dropzone">
                  <input type="file" accept={module.input?.accept || '.csv'} onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
                  {file ? (
                    <span>
                      <b>{file.name}</b> <span className="muted">({(file.size / 1024 / 1024).toFixed(2)} MB)</span>
                    </span>
                  ) : (
                    <span className="muted">Choose a {module.input?.accept || '.csv'} file…</span>
                  )}
                </label>
              )}
            </fieldset>

            {module.options.map((o) => (
              <label key={o.key} className="field">
                <span className="field-label">{o.label}</span>
                <select className="input" value={options[o.key] ?? o.default} onChange={(e) => setOptions((p) => ({ ...p, [o.key]: e.target.value }))}>
                  {o.choices.map((c) => (
                    <option key={c.value} value={c.value}>
                      {c.label}
                    </option>
                  ))}
                </select>
              </label>
            ))}

            {error && <div className="form-error">{error}</div>}
            <div className="btn-row">
              <button className="btn btn-primary" type="submit" disabled={!canSubmit}>
                {submitting ? 'Launching…' : 'Launch scan'}
              </button>
              <button className="btn btn-ghost" type="button" onClick={() => navigate('/scans')}>
                Cancel
              </button>
            </div>
          </form>
        </Panel>
      )}
    </div>
  )
}
