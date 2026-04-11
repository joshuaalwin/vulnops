import { useEffect, useState } from 'react';
import VulnCard from '../components/VulnCard';
import VulnTableHeader from '../components/VulnTableHeader';
import './Dashboard.css';

const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const STATUSES = ['ALL', 'OPEN', 'IN_PROGRESS', 'MITIGATED', 'RESOLVED'];

function Dashboard() {
  const [vulns, setVulns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [search, setSearch] = useState('');

  useEffect(() => {
    fetch('/api/vulns')
      .then((r) => r.json())
      .then((data) => setVulns(data))
      .catch(() => setError('Failed to load vulnerabilities'))
      .finally(() => setLoading(false));
  }, []);

  const filtered = vulns.filter((v) => {
    if (severityFilter !== 'ALL' && v.severity !== severityFilter) return false;
    if (statusFilter !== 'ALL' && v.status !== statusFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        v.cve_id.toLowerCase().includes(q) ||
        v.title.toLowerCase().includes(q) ||
        v.affected_product.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const bySeverity = (s) => vulns.filter((v) => v.severity === s).length;
  const byStatus = (s) => vulns.filter((v) => v.status === s).length;

  return (
    <div className="dashboard">

      {/* ── Left panel ── */}
      <aside className="dashboard-sidebar">
        <div className="sidebar-header">
          <h1 className="sidebar-title">CVE Registry</h1>
          <p className="sidebar-subtitle">Vulnerability tracking across your infrastructure</p>
        </div>

        <div className="sidebar-section">
          <p className="sidebar-section-label">By Severity</p>
          <div className="sidebar-stats">
            {['CRITICAL','HIGH','MEDIUM','LOW'].map((s) => (
              <button
                key={s}
                className={`stat-row ${severityFilter === s ? 'active' : ''} stat-${s.toLowerCase()}`}
                onClick={() => setSeverityFilter(severityFilter === s ? 'ALL' : s)}
              >
                <span className="stat-row-label">{s}</span>
                <span className="stat-row-num">{bySeverity(s)}</span>
              </button>
            ))}
          </div>
        </div>

        <div className="sidebar-section">
          <p className="sidebar-section-label">By Status</p>
          <div className="sidebar-stats">
            {[
              { key: 'OPEN', label: 'Open' },
              { key: 'IN_PROGRESS', label: 'In Progress' },
              { key: 'MITIGATED', label: 'Mitigated' },
              { key: 'RESOLVED', label: 'Resolved' },
            ].map(({ key, label }) => (
              <button
                key={key}
                className={`stat-row ${statusFilter === key ? 'active' : ''} status-${key.toLowerCase().replace('_','-')}`}
                onClick={() => setStatusFilter(statusFilter === key ? 'ALL' : key)}
              >
                <span className="stat-row-label">{label}</span>
                <span className="stat-row-num">{byStatus(key)}</span>
              </button>
            ))}
          </div>
        </div>

        {(severityFilter !== 'ALL' || statusFilter !== 'ALL' || search) && (
          <button
            className="clear-filters"
            onClick={() => { setSeverityFilter('ALL'); setStatusFilter('ALL'); setSearch(''); }}
          >
            Clear filters
          </button>
        )}

        <div className="sidebar-total">
          <span>{vulns.length} total vulnerabilities</span>
        </div>
      </aside>

      {/* ── Right panel ── */}
      <main className="dashboard-main">
        <div className="main-toolbar">
          <input
            type="text"
            className="search-input"
            placeholder="Search CVE ID, title, product..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <select
            className="filter-select"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>{s === 'ALL' ? 'All Severities' : s}</option>
            ))}
          </select>
          <select
            className="filter-select"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            {STATUSES.map((s) => (
              <option key={s} value={s}>{s === 'ALL' ? 'All Statuses' : s.replace('_', ' ')}</option>
            ))}
          </select>
        </div>

        <p className="result-count">
          {filtered.length} {filtered.length === 1 ? 'vulnerability' : 'vulnerabilities'}
          {(severityFilter !== 'ALL' || statusFilter !== 'ALL' || search) && ' matching filters'}
        </p>

        {loading && <p className="loading-msg">Loading...</p>}
        {error && <p className="error-msg">{error}</p>}

        {!loading && !error && filtered.length === 0 && (
          <p className="empty-msg">No vulnerabilities match your filters.</p>
        )}

        {!loading && !error && filtered.length > 0 && (
          <div className="vuln-table">
            <VulnTableHeader />
            {filtered.map((v, i) => (
              <div key={v.id} style={{ animationDelay: `${i * 0.03}s` }} className="vuln-list-item">
                <VulnCard vuln={v} />
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
  );
}

export default Dashboard;
