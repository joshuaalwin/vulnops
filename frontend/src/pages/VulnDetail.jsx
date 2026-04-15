import { useEffect, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import NoteSection from '../components/NoteSection';
import './VulnDetail.css';

function VulnDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [vuln, setVuln] = useState(null);
  const [notes, setNotes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    fetch(`/api/vulns/${id}`)
      .then((r) => {
        if (!r.ok) throw new Error('Vulnerability not found');
        return r.json();
      })
      .then((data) => {
        const { notes: n, ...rest } = data;
        setVuln(rest);
        setNotes(n);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [id]);

  async function handleDelete() {
    if (!window.confirm(`Delete ${vuln.cve_id}? This cannot be undone.`)) return;
    setDeleting(true);
    try {
      const res = await fetch(`/api/vulns/${id}`, { method: 'DELETE' });
      if (!res.ok) throw new Error('Delete failed');
      navigate('/');
    } catch {
      setDeleting(false);
      alert('Failed to delete vulnerability');
    }
  }

  if (loading) return <p className="loading-msg">Loading...</p>;
  if (error) return <p className="error-msg">{error}</p>;

  const updatedDate = new Date(vuln.updated_at).toLocaleDateString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
  });

  return (
    <div className="vuln-detail">
      <div className="detail-breadcrumb">
        <Link to="/">Dashboard</Link> / <span>{vuln.cve_id}</span>
      </div>

      <div className="detail-header">
        <div className="detail-header-left">
          <span className="detail-cve-id">{vuln.cve_id}</span>
          <h1 className="detail-title">{vuln.title}</h1>
          <div className="detail-badges">
            <SeverityBadge severity={vuln.severity} />
            <StatusBadge status={vuln.status} />
            {vuln.cvss_score && (
              <span className="cvss-score">CVSS {parseFloat(vuln.cvss_score).toFixed(1)}</span>
            )}
            {vuln.nvd_enriched && (
              <span className="nvd-badge" title="Data sourced from NVD">NVD Verified</span>
            )}
          </div>
        </div>
        <div className="detail-actions">
          <Link to={`/edit/${vuln.id}`} className="btn-edit">Edit</Link>
          <button className="btn-delete" onClick={handleDelete} disabled={deleting}>
            {deleting ? 'Deleting...' : 'Delete'}
          </button>
        </div>
      </div>

      <div className="detail-grid">
        <div className="detail-main">
          <section className="detail-section">
            <h2>Description</h2>
            <p>{vuln.description}</p>
          </section>
          <NoteSection
            vulnId={vuln.id}
            notes={notes}
            onNoteAdded={(note) => setNotes([note, ...notes])}
          />
        </div>

        <div className="detail-meta-panel">
          <div className="meta-item">
            <span className="meta-label">Affected Product</span>
            <span className="meta-value">{vuln.affected_product}</span>
          </div>
          {vuln.affected_version && (
            <div className="meta-item">
              <span className="meta-label">Affected Version</span>
              <span className="meta-value">{vuln.affected_version}</span>
            </div>
          )}
          <div className="meta-item">
            <span className="meta-label">Reporter</span>
            <span className="meta-value">{vuln.reporter}</span>
          </div>
          <div className="meta-item">
            <span className="meta-label">Last Updated</span>
            <span className="meta-value">{updatedDate}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default VulnDetail;
