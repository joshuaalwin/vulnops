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
      <h1 className="form-page-title">Edit Vulnerability</h1>
      <p className="form-page-subtitle">{values?.cve_id}</p>
      <VulnForm
        values={values}
        onChange={handleChange}
        onSubmit={handleSubmit}
        submitting={submitting}
        error={error}
        submitLabel="Save Changes"
      />
    </div>
  );
}

export default EditVuln;
