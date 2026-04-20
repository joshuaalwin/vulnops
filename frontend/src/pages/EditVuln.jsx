import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import VulnForm from '../components/VulnForm';
import './FormPage.css';

function EditVuln() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [values, setValues] = useState(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    fetch(`/api/vulns/${id}`)
      .then((r) => r.json())
      .then((data) => {
        setValues({
          cve_id: data.cve_id,
          title: data.title,
          description: data.description,
          severity: data.severity,
          cvss_score: data.cvss_score != null ? String(data.cvss_score) : '',
          affected_product: data.affected_product,
          affected_version: data.affected_version || '',
          status: data.status,
          reporter: data.reporter,
        });
      })
      .catch(() => setError('Failed to load vulnerability'))
      .finally(() => setLoading(false));
  }, [id]);

  function handleChange(field, value) {
    setValues((prev) => ({ ...prev, [field]: value }));
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setSubmitting(true);
    setError('');
    try {
      const res = await fetch(`/api/vulns/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...values,
          cvss_score: values.cvss_score ? parseFloat(values.cvss_score) : null,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to update vulnerability');
      navigate(`/vuln/${id}`);
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) return <p style={{ color: 'var(--text-muted)' }}>Loading...</p>;
  if (error && !values) return <p style={{ color: 'var(--critical)' }}>{error}</p>;

  return (
    <div className="form-page">
      <aside className="form-context">
        <div>
          <h1 className="form-context-title">Edit Vulnerability</h1>
          <p className="form-context-subtitle">
            Update the details for <strong>{values?.cve_id}</strong>. Changes are saved immediately and reflected across the registry.
          </p>
        </div>

        <div className="form-context-section">
          <h3>Severity Guide</h3>
          <div className="severity-guide">
            {[
              { cls: 'critical', label: 'Critical', desc: 'CVSS 9.0 – 10.0' },
              { cls: 'high',     label: 'High',     desc: 'CVSS 7.0 – 8.9' },
              { cls: 'medium',   label: 'Medium',   desc: 'CVSS 4.0 – 6.9' },
              { cls: 'low',      label: 'Low',      desc: 'CVSS 0.1 – 3.9' },
              { cls: 'info',     label: 'Info',     desc: 'No CVSS score' },
            ].map(({ cls, label, desc }) => (
              <div key={cls} className="severity-guide-item">
                <span className={`severity-guide-dot ${cls}`} />
                <span><strong>{label}</strong> — {desc}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="form-context-section">
          <h3>Tips</h3>
          <div className="form-tips">
            <div className="form-tip">
              <span className="form-tip-icon">→</span>
              Update the status as remediation progresses
            </div>
            <div className="form-tip">
              <span className="form-tip-icon">→</span>
              Recalculate CVSS if the attack surface changes
            </div>
            <div className="form-tip">
              <span className="form-tip-icon">→</span>
              Use notes for audit trail instead of editing the description
            </div>
          </div>
        </div>
      </aside>

      <main className="form-main">
        <VulnForm
          values={values}
          onChange={handleChange}
          onSubmit={handleSubmit}
          submitting={submitting}
          error={error}
          submitLabel="Save Changes"
        />
      </main>
    </div>
  );
}

export default EditVuln;
