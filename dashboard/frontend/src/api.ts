// Typed client for the ACDS backend (FastAPI, served under /api).

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const
export type Severity = (typeof SEVERITIES)[number]
export type SeverityCounts = Record<Severity, number>

export const FINDING_STATUSES = ['open', 'confirmed', 'false_positive', 'resolved'] as const
export type FindingStatus = (typeof FINDING_STATUSES)[number]

export type ModuleStatus = 'active' | 'in_progress' | 'planned'
export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed'

export interface ModuleOption {
  key: string
  label: string
  type: 'select'
  choices: { value: string; label: string }[]
  default: string
}

export interface Module {
  id: string
  number: number
  name: string
  owner: string
  category: string
  status: ModuleStatus
  ready: boolean
  ready_reason: string
  description: string
  repo: string | null
  input: { kind: string; label: string; accept: string } | null
  options: ModuleOption[]
  metrics: { label: string; value: string }[]
}

export interface Sample {
  id: string
  name: string
  description: string
  module_ids: string[]
  rows: number | null
}

export interface Scan {
  id: string
  name: string
  module_id: string
  module_name: string
  status: ScanStatus
  progress: number
  created_at: string
  started_at: string | null
  finished_at: string | null
  input_name: string
  rows_scanned: number | null
  counts: SeverityCounts
  error: string | null
  log?: string[]
}

export interface Host {
  host: string
  findings: number
  counts: SeverityCounts
  max_severity: Severity
  modules: string[]
  last_seen: string
}

export interface Mitre {
  technique_id: string
  technique_name: string
  tactic: string
}

export interface TopFeature {
  feature: string
  value: number | string | null
  z_score: number | null
  direction: string | null
}

export interface Finding {
  id: number
  scan_id: string
  module_id: string
  severity: Severity
  title: string
  description: string
  host: string | null
  asset: { src_ip?: string; dst_ip?: string; dst_port?: number; file?: string }
  score: number | null
  confidence: number | null
  mitre: Mitre | null
  evidence: { label: string; value: string | number }[]
  top_features: TopFeature[]
  recommendation: string | null
  status: FindingStatus
  feedback_note: string | null
  created_at: string
}

export interface FindingGroup {
  title: string
  module_id: string
  severity: Severity
  count: number
  hosts: number
}

export interface Stats {
  scans_total: number
  scans_running: number
  findings_total: number
  open_critical_high: number
  by_severity: SeverityCounts
  by_module: { module_id: string; name: string; count: number }[]
  top_hosts: Host[]
  timeline: ({ date: string } & SeverityCounts)[]
  feedback: Record<FindingStatus, number>
  recent_findings: Finding[]
}

export interface FindingQuery {
  scan_id?: string
  severity?: string
  module_id?: string
  status?: string
  host?: string
  q?: string
  limit?: number
  offset?: number
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, init)
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`
    try {
      const body = await res.json()
      if (body?.detail) detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
    } catch {
      /* non-JSON error body */
    }
    throw new Error(detail)
  }
  return res.json() as Promise<T>
}

function query(params: object): string {
  const qs = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') qs.set(k, String(v))
  }
  const s = qs.toString()
  return s ? `?${s}` : ''
}

export const api = {
  modules: () => request<Module[]>('/modules'),
  samples: () => request<Sample[]>('/samples'),
  stats: () => request<Stats>('/stats'),
  scans: () => request<Scan[]>('/scans'),
  scan: (id: string) => request<Scan>(`/scans/${encodeURIComponent(id)}`),
  scanHosts: (id: string) => request<Host[]>(`/scans/${encodeURIComponent(id)}/hosts`),
  deleteScan: (id: string) => request<{ ok: boolean }>(`/scans/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  createScan: (form: FormData) => request<Scan>('/scans', { method: 'POST', body: form }),
  hosts: () => request<Host[]>('/hosts'),
  findings: (q: FindingQuery) => request<{ total: number; items: Finding[] }>(`/findings${query(q)}`),
  findingGroups: (scanId: string) => request<FindingGroup[]>(`/findings/groups${query({ scan_id: scanId })}`),
  updateFinding: (id: number, body: { status?: FindingStatus; feedback_note?: string }) =>
    request<Finding>(`/findings/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
}
