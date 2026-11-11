import { SEVERITIES } from '../api'
import type { Severity, SeverityCounts } from '../api'

export const SEV_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
}

export function SeverityBadge({ severity, compact = false }: { severity: Severity; compact?: boolean }) {
  return (
    <span className={`sev-badge sev-${severity}`} title={SEV_LABEL[severity]}>
      {compact ? SEV_LABEL[severity].slice(0, 1) : SEV_LABEL[severity]}
    </span>
  )
}

export function emptyCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
}

export function totalCounts(c: SeverityCounts | null | undefined): number {
  if (!c) return 0
  return SEVERITIES.reduce((s, k) => s + (c[k] ?? 0), 0)
}

/**
 * Nessus-style horizontal stacked severity bar. Each segment carries its count as
 * text (identity is never colour alone); a 2px gap separates segments.
 */
export function SeverityCountBar({ counts, showZero = false }: { counts: SeverityCounts; showZero?: boolean }) {
  const total = totalCounts(counts)
  if (total === 0) {
    return <div className="sevbar sevbar-empty">{showZero ? 'No findings' : '—'}</div>
  }
  const parts = SEVERITIES.filter((s) => counts[s] > 0)
  return (
    <div
      className="sevbar"
      role="img"
      aria-label={parts.map((s) => `${SEV_LABEL[s]} ${counts[s]}`).join(', ')}
    >
      {parts.map((s) => (
        <div
          key={s}
          className={`sevbar-seg sev-bg-${s}`}
          style={{ flexGrow: Math.max(counts[s], total * 0.06) }}
          title={`${SEV_LABEL[s]}: ${counts[s].toLocaleString()}`}
        >
          <span>{counts[s].toLocaleString()}</span>
        </div>
      ))}
    </div>
  )
}

/** Compact per-severity numeric chips (C 3 · H 12 …) for dense tables. */
export function SeverityChips({ counts }: { counts: SeverityCounts }) {
  return (
    <div className="sevchips">
      {SEVERITIES.map((s) => (
        <span key={s} className={`sevchip ${counts[s] ? `sev-${s}` : 'zero'}`} title={SEV_LABEL[s]}>
          <b>{SEV_LABEL[s].slice(0, 1)}</b>
          {counts[s].toLocaleString()}
        </span>
      ))}
    </div>
  )
}
