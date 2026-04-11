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
      <div className="form-card">
        <div className="form-card-header">
          <h1 className="form-page-title">Report Vulnerability</h1>
          <p className="form-page-subtitle">Add a new CVE entry to the registry</p>
        </div>
      <VulnForm
        values={values}
        onChange={handleChange}
        onSubmit={handleSubmit}
        submitting={submitting}
        error={error}
        submitLabel="Report Vulnerability"
      />
      </div>
    </div>
  );
}

export default AddVuln;
