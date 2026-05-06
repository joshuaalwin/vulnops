import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from 'recharts';
import {
  ShieldCheck, AlertTriangle, CircleDot, Flame, Search,
  ArrowUpRight, ChevronRight,
} from 'lucide-react';
import StatsCard from '../components/StatsCard';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import './AnalyticsDashboard.css';

const SEVERITY_FILTERS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const STATUS_FILTERS = [
  { key: 'OPEN', label: 'Open' },
  { key: 'IN_PROGRESS', label: 'In Progress' },
  { key: 'MITIGATED', label: 'Mitigated' },
  { key: 'RESOLVED', label: 'Resolved' },
];

const SEVERITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
  INFO: '#3b82f6',
};

const STATUS_COLORS = {
  OPEN: '#818cf8',
  IN_PROGRESS: '#f59e0b',
  MITIGATED: '#38bdf8',
  RESOLVED: '#22c55e',
};

const STATUS_LABELS = {
  OPEN: 'Open',
  IN_PROGRESS: 'In Progress',
  MITIGATED: 'Mitigated',
  RESOLVED: 'Resolved',
};

function CustomTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  const { name, value } = payload[0];
  return (
    <div className="chart-tooltip">
      <span className="chart-tooltip-label">{name}</span>
      <span className="chart-tooltip-value">{value}</span>
    </div>
  );
}

function AnalyticsDashboard() {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchValue, setSearchValue] = useState('');

  function submitSearch(e) {
    e.preventDefault();
    const q = searchValue.trim();
    if (!q) return;
    navigate(`/vulnerabilities?q=${encodeURIComponent(q)}`);
  }

  useEffect(() => {
    fetch('/api/stats')
      .then((r) => {
        if (!r.ok) throw new Error('Failed to fetch stats');
        return r.json();
      })
      .then(setStats)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="dash-loading">Loading dashboard...</div>;
  if (error) return <div className="dash-error">{error}</div>;

  const severityData = Object.entries(SEVERITY_COLORS)
    .map(([severity]) => ({
      name: severity,
      value: stats.by_severity[severity] || 0,
    }))
    .filter((d) => d.value > 0);

  const statusData = Object.entries(STATUS_LABELS).map(([key, label]) => ({
    name: label,
    key,
    value: stats.by_status[key] || 0,
  }));

  const totalKev = stats.summary.kev || 0;

  return (
    <div className="analytics-shell">
      <aside className="analytics-sidebar">
        <form className="rail-search" onSubmit={submitSearch}>
          <Search size={14} strokeWidth={2} className="rail-search-icon" />
          <input
            type="text"
            className="rail-search-input"
            placeholder="Search CVE, title, product…"
            value={searchValue}
            onChange={(e) => setSearchValue(e.target.value)}
          />
          <kbd className="rail-search-kbd">↵</kbd>
        </form>

        <div className="rail-section">
          <p className="rail-label">Quick Actions</p>
          <Link
            to="/vulnerabilities?kev=1"
            className="rail-quick rail-quick-kev"
          >
            <span className="rail-quick-icon"><Flame size={16} strokeWidth={2} /></span>
            <span className="rail-quick-text">
              <span className="rail-quick-title">KEV Only</span>
              <span className="rail-quick-sub">{totalKev} actively exploited</span>
            </span>
            <ChevronRight size={14} className="rail-quick-arrow" />
          </Link>
          <Link
            to="/vulnerabilities?severity=CRITICAL"
            className="rail-quick rail-quick-critical"
          >
            <span className="rail-quick-icon"><AlertTriangle size={16} strokeWidth={2} /></span>
            <span className="rail-quick-text">
              <span className="rail-quick-title">Critical</span>
              <span className="rail-quick-sub">{stats.summary.critical} need triage</span>
            </span>
            <ChevronRight size={14} className="rail-quick-arrow" />
          </Link>
          <Link
            to="/vulnerabilities?status=OPEN"
            className="rail-quick rail-quick-open"
          >
            <span className="rail-quick-icon"><CircleDot size={16} strokeWidth={2} /></span>
            <span className="rail-quick-text">
              <span className="rail-quick-title">Open Backlog</span>
              <span className="rail-quick-sub">{stats.summary.open} awaiting action</span>
            </span>
            <ChevronRight size={14} className="rail-quick-arrow" />
          </Link>
        </div>

        <div className="rail-section">
          <p className="rail-label">Severity</p>
          <div className="rail-list">
            {SEVERITY_FILTERS.map((s) => {
              const count = stats.by_severity[s] || 0;
              return (
                <Link
                  key={s}
                  to={`/vulnerabilities?severity=${s}`}
                  className={`rail-row rail-sev-${s.toLowerCase()}`}
                >
                  <span className="rail-row-label">{s}</span>
                  <span className="rail-row-count">{count}</span>
                </Link>
              );
            })}
          </div>
        </div>

        <div className="rail-section">
          <p className="rail-label">Status</p>
          <div className="rail-list">
            {STATUS_FILTERS.map(({ key, label }) => {
              const count = stats.by_status[key] || 0;
              return (
                <Link
                  key={key}
                  to={`/vulnerabilities?status=${key}`}
                  className={`rail-row rail-status-${key.toLowerCase().replace('_', '-')}`}
                >
                  <span className="rail-row-label">{label}</span>
                  <span className="rail-row-count">{count}</span>
                </Link>
              );
            })}
          </div>
        </div>

        {stats.latest_kev && stats.latest_kev.length > 0 && (
          <div className="rail-section">
            <p className="rail-label">Latest KEV</p>
            <div className="rail-feed">
              {stats.latest_kev.map((v) => (
                <Link key={v.id} to={`/vuln/${v.id}`} className="rail-feed-row">
                  <span className="rail-feed-cve">{v.cve_id}</span>
                  <span className="rail-feed-title">{v.title}</span>
                </Link>
              ))}
            </div>
          </div>
        )}
      </aside>

      <main className="analytics-dashboard">
      <div className="dash-header">
        <div className="dash-header-text">
          <div className="dash-eyebrow">
            <span className="dash-eyebrow-dot" />
            Security Posture · Live
          </div>
          <h1 className="dash-title">Security Dashboard</h1>
          <p className="dash-subtitle">Vulnerability intelligence overview</p>
        </div>
        <Link to="/vulnerabilities" className="dash-view-all">
          View all vulnerabilities
          <ArrowUpRight size={14} strokeWidth={2} />
        </Link>
      </div>

      <div className="stats-grid">
        <StatsCard
          label="Total CVEs"
          value={stats.summary.total}
          color="var(--accent)"
          icon={<ShieldCheck />}
        />
        <StatsCard
          label="Critical"
          value={stats.summary.critical}
          color="var(--critical)"
          icon={<AlertTriangle />}
        />
        <StatsCard
          label="Open"
          value={stats.summary.open}
          color="var(--status-open)"
          icon={<CircleDot />}
        />
        <StatsCard
          label="In CISA KEV"
          value={stats.summary.kev}
          color="#f43f5e"
          icon={<Flame />}
        />
      </div>

      <div className="charts-grid">
        <div className="chart-card">
          <h3 className="chart-title">Severity Distribution</h3>
          {severityData.length === 0 ? (
            <p className="chart-empty">No vulnerabilities yet</p>
          ) : (
            <ResponsiveContainer width="100%" height={280}>
              <PieChart>
                <Pie
                  data={severityData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={3}
                  stroke="none"
                >
                  {severityData.map((entry) => (
                    <Cell
                      key={entry.name}
                      fill={SEVERITY_COLORS[entry.name]}
                    />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
                <Legend
                  verticalAlign="bottom"
                  formatter={(value) => (
                    <span style={{ color: '#e2e8f4', fontSize: '0.75rem' }}>
                      {value}
                    </span>
                  )}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="chart-card">
          <h3 className="chart-title">Status Breakdown</h3>
          {stats.summary.total === 0 ? (
            <p className="chart-empty">No vulnerabilities yet</p>
          ) : (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={statusData} barSize={36}>
                <CartesianGrid stroke="#252d3d" vertical={false} />
                <XAxis
                  dataKey="name"
                  tick={{ fill: '#64748b', fontSize: 12 }}
                  axisLine={{ stroke: '#252d3d' }}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: '#64748b', fontSize: 12 }}
                  axisLine={false}
                  tickLine={false}
                  allowDecimals={false}
                />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {statusData.map((entry) => (
                    <Cell
                      key={entry.key}
                      fill={STATUS_COLORS[entry.key]}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      <div className="bottom-grid">
        <div className="chart-card">
          <h3 className="chart-title">Highest EPSS Risk</h3>
          {stats.top_epss.length === 0 ? (
            <p className="chart-empty">No EPSS data available</p>
          ) : (
            <div className="epss-list">
              {stats.top_epss.map((v) => (
                <Link key={v.id} to={`/vuln/${v.id}`} className="epss-row">
                  <span className="epss-cve">{v.cve_id}</span>
                  <span className="epss-title">{v.title}</span>
                  <SeverityBadge severity={v.severity} />
                  <span className="epss-score">
                    {(parseFloat(v.epss_score) * 100).toFixed(1)}%
                  </span>
                </Link>
              ))}
            </div>
          )}
        </div>

        <div className="chart-card">
          <h3 className="chart-title">Recently Added</h3>
          {stats.recent.length === 0 ? (
            <p className="chart-empty">No vulnerabilities yet</p>
          ) : (
            <div className="recent-list">
              {stats.recent.map((v) => (
                <Link key={v.id} to={`/vuln/${v.id}`} className="recent-row">
                  <div className="recent-main">
                    <span className="recent-cve">{v.cve_id}</span>
                    <span className="recent-title">{v.title}</span>
                  </div>
                  <div className="recent-meta">
                    <SeverityBadge severity={v.severity} />
                    <StatusBadge status={v.status} />
                    <span className="recent-date">
                      {new Date(v.created_at).toLocaleDateString('en-US', {
                        month: 'short',
                        day: 'numeric',
                      })}
                    </span>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>

        {stats.top_products.length > 0 && (
          <div className="chart-card">
            <h3 className="chart-title">Top Affected Products</h3>
            <div className="products-list">
              {stats.top_products.map((p, i) => (
                <div key={p.product} className="product-row">
                  <span className="product-rank">#{i + 1}</span>
                  <span className="product-name">{p.product}</span>
                  <span className="product-count">{p.count}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
      </main>
    </div>
  );
}

export default AnalyticsDashboard;
