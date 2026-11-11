// Hand-rolled SVG charts. Thin marks, 2px surface gaps between fills, recessive grid,
// a hover tooltip on every mark, and text in ink tokens (never the series colour).
import { useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { SEVERITIES } from '../api'
import type { Severity, SeverityCounts } from '../api'
import { SEV_LABEL } from './severity'

const SEV_VAR = (s: Severity) => `var(--sev-${s})`

interface Tip {
  x: number
  y: number
  content: ReactNode
}

function useTip() {
  const ref = useRef<HTMLDivElement>(null)
  const [tip, setTip] = useState<Tip | null>(null)
  const show = (e: React.MouseEvent, content: ReactNode) => {
    const box = ref.current?.getBoundingClientRect()
    if (!box) return
    setTip({ x: e.clientX - box.left, y: e.clientY - box.top, content })
  }
  const hide = () => setTip(null)
  const node = tip ? (
    <div
      className="chart-tip"
      style={{
        left: tip.x,
        top: tip.y,
        transform: `translate(${tip.x > (ref.current?.clientWidth ?? 0) / 2 ? 'calc(-100% - 12px)' : '12px'}, -50%)`,
      }}
    >
      {tip.content}
    </div>
  ) : null
  return { ref, show, hide, node }
}

function TipRow({ swatch, label, value }: { swatch?: string; label: string; value: ReactNode }) {
  return (
    <div className="tip-row">
      {swatch && <span className="tip-swatch" style={{ background: swatch }} />}
      <span className="tip-label">{label}</span>
      <span className="tip-value">{value}</span>
    </div>
  )
}

export function SeverityLegend({ counts }: { counts?: SeverityCounts }) {
  const total = counts ? SEVERITIES.reduce((s, k) => s + counts[k], 0) : 0
  return (
    <ul className="legend">
      {SEVERITIES.map((s) => (
        <li key={s}>
          <span className="legend-swatch" style={{ background: SEV_VAR(s) }} />
          <span className="legend-label">{SEV_LABEL[s]}</span>
          {counts && (
            <span className="legend-value">
              {counts[s].toLocaleString()}
              <span className="muted"> {total ? Math.round((counts[s] / total) * 100) : 0}%</span>
            </span>
          )}
        </li>
      ))}
    </ul>
  )
}

/** Part-to-whole of five ordered severities: donut with the total in the hole. */
export function SeverityDonut({ counts, size = 168 }: { counts: SeverityCounts; size?: number }) {
  const { ref, show, hide, node } = useTip()
  const total = SEVERITIES.reduce((s, k) => s + counts[k], 0)
  const r = size / 2
  const thickness = 22
  const rInner = r - thickness
  let angle = -Math.PI / 2

  const arcs = SEVERITIES.filter((s) => counts[s] > 0).map((s) => {
    const sweep = (counts[s] / total) * Math.PI * 2
    const a0 = angle
    const a1 = angle + sweep
    angle = a1
    const large = sweep > Math.PI ? 1 : 0
    const p = (a: number, rad: number) => [r + rad * Math.cos(a), r + rad * Math.sin(a)]
    const [x0, y0] = p(a0, r)
    const [x1, y1] = p(a1, r)
    const [x2, y2] = p(a1, rInner)
    const [x3, y3] = p(a0, rInner)
    const d = `M ${x0} ${y0} A ${r} ${r} 0 ${large} 1 ${x1} ${y1} L ${x2} ${y2} A ${rInner} ${rInner} 0 ${large} 0 ${x3} ${y3} Z`
    return { s, d }
  })

  return (
    <div className="donut-wrap">
      <div className="chart-rel" ref={ref} style={{ width: size, height: size }}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label="Findings by severity">
          {arcs.length <= 1 ? (
            <circle
              cx={r}
              cy={r}
              r={r - thickness / 2}
              fill="none"
              stroke={arcs.length ? SEV_VAR(arcs[0].s) : 'var(--grid)'}
              strokeWidth={thickness}
              className="mark"
              onMouseMove={(e) =>
                arcs.length &&
                show(e, <TipRow swatch={SEV_VAR(arcs[0].s)} label={SEV_LABEL[arcs[0].s]} value={`${total.toLocaleString()} (100%)`} />)
              }
              onMouseLeave={hide}
            />
          ) : (
            arcs.map(({ s, d }) => (
              <path
                key={s}
                d={d}
                fill={SEV_VAR(s)}
                stroke="var(--surface-1)"
                strokeWidth={2}
                className="mark"
                onMouseMove={(e) =>
                  show(
                    e,
                    <TipRow
                      swatch={SEV_VAR(s)}
                      label={SEV_LABEL[s]}
                      value={`${counts[s].toLocaleString()} (${Math.round((counts[s] / total) * 100)}%)`}
                    />,
                  )
                }
                onMouseLeave={hide}
              />
            ))
          )}
          <text x={r} y={r - 2} textAnchor="middle" className="donut-total">
            {total.toLocaleString()}
          </text>
          <text x={r} y={r + 16} textAnchor="middle" className="donut-caption">
            findings
          </text>
        </svg>
        {node}
      </div>
      <SeverityLegend counts={counts} />
    </div>
  )
}

/** Single-series horizontal bars (magnitude by category). */
export function HBarChart({
  data,
  color = 'var(--series-1)',
  unit = 'findings',
  onSelect,
}: {
  data: { label: string; value: number; key?: string }[]
  color?: string
  unit?: string
  onSelect?: (key: string) => void
}) {
  const { ref, show, hide, node } = useTip()
  const max = Math.max(1, ...data.map((d) => d.value))
  return (
    <div className="chart-rel hbar" ref={ref}>
      {data.map((d) => (
        <div
          key={d.key ?? d.label}
          className={`hbar-row ${onSelect ? 'clickable' : ''}`}
          onMouseMove={(e) => show(e, <TipRow swatch={color} label={d.label} value={`${d.value.toLocaleString()} ${unit}`} />)}
          onMouseLeave={hide}
          onClick={() => onSelect?.(d.key ?? d.label)}
        >
          <div className="hbar-label" title={d.label}>
            {d.label}
          </div>
          <div className="hbar-track">
            <div className="hbar-fill" style={{ width: `${(d.value / max) * 100}%`, background: color }} />
          </div>
          <div className="hbar-value">{d.value.toLocaleString()}</div>
        </div>
      ))}
      {node}
    </div>
  )
}

/** Rect with only its top (data-end) corners rounded. */
function columnPath(x: number, y: number, w: number, h: number, radius: number): string {
  const r = Math.min(radius, w / 2, h)
  if (r <= 0) return `M ${x} ${y} h ${w} v ${h} h ${-w} Z`
  return `M ${x} ${y + h} V ${y + r} Q ${x} ${y} ${x + r} ${y} H ${x + w - r} Q ${x + w} ${y} ${x + w} ${y + r} V ${y + h} Z`
}

function niceMax(v: number): number {
  if (v <= 5) return 5
  const p = 10 ** Math.floor(Math.log10(v))
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p
  return 10 * p
}

/** Stacked columns of findings per day, one segment per severity. */
export function SeverityTimeline({ data, height = 190 }: { data: ({ date: string } & SeverityCounts)[]; height?: number }) {
  const { ref, show, hide, node } = useTip()
  const width = 640
  const pad = { top: 8, right: 8, bottom: 22, left: 36 }
  const innerW = width - pad.left - pad.right
  const innerH = height - pad.top - pad.bottom
  const totals = data.map((d) => SEVERITIES.reduce((s, k) => s + d[k], 0))
  const yMax = niceMax(Math.max(1, ...totals))
  const ticks = [0, yMax / 2, yMax]
  const slot = innerW / Math.max(1, data.length)
  const barW = Math.min(28, Math.max(4, slot * 0.6))
  const y = (v: number) => pad.top + innerH - (v / yMax) * innerH
  const labelEvery = Math.ceil(data.length / 8)

  return (
    <div className="chart-rel" ref={ref}>
      <svg viewBox={`0 0 ${width} ${height}`} className="chart-svg" role="img" aria-label="Findings per day by severity">
        {ticks.map((t) => (
          <g key={t}>
            <line x1={pad.left} x2={width - pad.right} y1={y(t)} y2={y(t)} className="grid-line" />
            <text x={pad.left - 6} y={y(t) + 4} textAnchor="end" className="axis-text">
              {new Intl.NumberFormat(undefined, { notation: 'compact' }).format(t)}
            </text>
          </g>
        ))}
        {data.map((d, i) => {
          const cx = pad.left + slot * i + slot / 2
          let acc = 0
          const segs = SEVERITIES.slice()
            .reverse() // info at the baseline, critical on top
            .filter((s) => d[s] > 0)
          return (
            <g
              key={d.date}
              onMouseMove={(e) =>
                show(
                  e,
                  <div>
                    <div className="tip-title">{d.date}</div>
                    {SEVERITIES.map((s) => (
                      <TipRow key={s} swatch={SEV_VAR(s)} label={SEV_LABEL[s]} value={d[s].toLocaleString()} />
                    ))}
                    <TipRow label="Total" value={totals[i].toLocaleString()} />
                  </div>,
                )
              }
              onMouseLeave={hide}
            >
              {/* oversized hit target */}
              <rect x={cx - slot / 2} y={pad.top} width={slot} height={innerH} fill="transparent" />
              {segs.map((s, j) => {
                const y0 = y(acc)
                acc += d[s]
                const y1 = y(acc)
                const isTop = j === segs.length - 1
                const h = Math.max(0, y0 - y1 - (isTop ? 0 : 2))
                return (
                  <path key={s} d={columnPath(cx - barW / 2, y1 + (isTop ? 0 : 2), barW, h, isTop ? 4 : 0)} fill={SEV_VAR(s)} className="mark" />
                )
              })}
              {i % labelEvery === 0 && (
                <text x={cx} y={height - 6} textAnchor="middle" className="axis-text">
                  {d.date.slice(5)}
                </text>
              )}
            </g>
          )
        })}
        <line x1={pad.left} x2={width - pad.right} y1={y(0)} y2={y(0)} className="axis-line" />
      </svg>
      {node}
    </div>
  )
}
