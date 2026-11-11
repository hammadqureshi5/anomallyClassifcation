import { useEffect, useState } from 'react'
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom'

const NAV = [
  { to: '/', label: 'Dashboard', icon: 'M3 13h8V3H3zm0 8h8v-6H3zm10 0h8V11h-8zm0-18v6h8V3z' },
  { to: '/scans', label: 'Scans', icon: 'M12 2a10 10 0 1 0 10 10h-2a8 8 0 1 1-8-8zm0 4a6 6 0 1 0 6 6h-2a4 4 0 1 1-4-4zm0 4a2 2 0 1 0 2 2l7-7-1.4-1.4L12.6 10z' },
  { to: '/findings', label: 'Findings', icon: 'M12 2 1 21h22zm0 4.5 7.5 12.5h-15zM11 10v4h2v-4zm0 6v2h2v-2z' },
  { to: '/hosts', label: 'Hosts', icon: 'M4 4h16v10H4zm2 2v6h12V6zM2 18h20v2H2z' },
  { to: '/modules', label: 'Modules', icon: 'M4 4h7v7H4zm9 0h7v7h-7zM4 13h7v7H4zm9 3.5a3.5 3.5 0 1 0 7 0 3.5 3.5 0 0 0-7 0' },
]

const TITLES: [RegExp, string][] = [
  [/^\/$/, 'Dashboard'],
  [/^\/scans\/new/, 'New Scan'],
  [/^\/scans\/.+/, 'Scan Results'],
  [/^\/scans/, 'Scans'],
  [/^\/findings/, 'Findings'],
  [/^\/hosts/, 'Hosts'],
  [/^\/modules/, 'Modules'],
]

export default function Layout() {
  const { pathname } = useLocation()
  const [open, setOpen] = useState(false)
  const title = TITLES.find(([re]) => re.test(pathname))?.[1] ?? 'ACDS'

  useEffect(() => {
    setOpen(false)
    document.title = `${title} · ACDS Console`
  }, [pathname, title])

  return (
    <div className={`shell ${open ? 'nav-open' : ''}`}>
      <aside className="sidebar">
        <Link to="/" className="brand">
          <svg viewBox="0 0 32 32" width="30" height="30" aria-hidden>
            <path d="M16 2 4 7v8c0 7.2 5.1 13.4 12 15 6.9-1.6 12-7.8 12-15V7z" fill="var(--surface-2)" stroke="var(--accent)" strokeWidth="2" />
            <path d="m11 16 4 4 7-8" fill="none" stroke="var(--accent)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <div>
            <div className="brand-name">
              AC<span>DS</span>
            </div>
            <div className="brand-sub">Autonomous Cyber Defense</div>
          </div>
        </Link>
        <nav className="nav">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.to === '/'} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
              <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden>
                <path d={n.icon} fill="currentColor" />
              </svg>
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div>AI-Based Autonomous Cyber Defense</div>
          <div className="muted">SZABIST · FYP 2026 · research prototype</div>
        </div>
      </aside>
      <div className="scrim" onClick={() => setOpen(false)} />
      <div className="main">
        <header className="topbar">
          <button className="btn btn-ghost nav-toggle" aria-label="Toggle navigation" onClick={() => setOpen((o) => !o)}>
            <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden>
              <path d="M3 6h18v2H3zm0 5h18v2H3zm0 5h18v2H3z" fill="currentColor" />
            </svg>
          </button>
          <h1>{title}</h1>
          <div className="topbar-actions">
            {!pathname.startsWith('/scans/new') && (
              <Link to="/scans/new" className="btn btn-primary">
                + New Scan
              </Link>
            )}
          </div>
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
