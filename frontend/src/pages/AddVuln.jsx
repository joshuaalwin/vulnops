import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import VulnForm from '../components/VulnForm';
import './FormPage.css';

const INITIAL = {
  cve_id: '',
  title: '',
  description: '',
  severity: '',
  cvss_score: '',
  affected_product: '',
  affected_version: '',
  status: 'OPEN',
  reporter: '',
};

function AddVuln() {
  const navigate = useNavigate();
  const [values, setValues] = useState(INITIAL);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  function handleChange(field, value) {
    setValues((prev) => ({ ...prev, [field]: value }));
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setSubmitting(true);
    setError('');
    try {
      const res = await fetch('/api/vulns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...values,
          cvss_score: values.cvss_score ? parseFloat(values.cvss_score) : null,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to create vulnerability');
      navigate(`/vuln/${data.id}`);
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="form-page">

      {/* ── Left context panel ── */}
      <aside className="form-context">
        <div>
          <h1 className="form-context-title">Report a Vulnerability</h1>
          <p className="form-context-subtitle">
            Submit a new CVE entry to the registry. All reported vulnerabilities
            are reviewed and tracked through to resolution.
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
              Use the official CVE ID from NVD or MITRE if available
            </div>
            <div className="form-tip">
              <span className="form-tip-icon">→</span>
              Include exploitation conditions in the description
            </div>
            <div className="form-tip">
              <span className="form-tip-icon">→</span>
              Status will be set by a reviewer after submission
            </div>
          </div>
        </div>
      </aside>

      {/* ── Right form panel ── */}
      <main className="form-main">
        <VulnForm
          values={values}
          onChange={handleChange}
          onSubmit={handleSubmit}
          submitting={submitting}
          error={error}
          submitLabel="Submit Vulnerability Report"
        />
      </main>

    </div>
  );
}

export default AddVuln;
