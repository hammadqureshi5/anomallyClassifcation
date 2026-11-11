import { useNavigate } from 'react-router-dom'
import type { Host } from '../api'
import { Empty, fmtDate } from './common'
import { SeverityCountBar } from './severity'

export default function HostsTable({ hosts, scanId }: { hosts: Host[]; scanId?: string }) {
  const navigate = useNavigate()
  if (!hosts.length) return <Empty title="No hosts with findings" />
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>Host</th>
            <th className="w-sevbar">Vulnerabilities</th>
            <th className="num">Findings</th>
            <th>Modules</th>
            <th>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {hosts.map((h) => (
            <tr
              key={h.host}
              className="clickable"
              onClick={() => navigate(`/findings?host=${encodeURIComponent(h.host)}${scanId ? `&scan_id=${encodeURIComponent(scanId)}` : ''}`)}
            >
              <td className="mono">{h.host}</td>
              <td>
                <SeverityCountBar counts={h.counts} />
              </td>
              <td className="num mono">{h.findings.toLocaleString()}</td>
              <td className="small">{h.modules.join(', ')}</td>
              <td className="small nowrap">{fmtDate(h.last_seen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
