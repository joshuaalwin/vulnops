import { useState } from 'react';
import './VulnForm.css';
import CVSSCalculator from './CVSSCalculator';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const CVE_ID_RE = /^CVE-\d{4}-\d{4,}$/i;

function parseVector(vectorString) {
  if (!vectorString) return {};
  const vals = {};
  vectorString.split('/').slice(1).forEach((part) => {
    const [key, val] = part.split(':');
    if (key && val) vals[key] = val;
  });
  return vals;
}

function VulnForm({ values, onChange, onSubmit, submitting, error, submitLabel }) {
  const [lookupState, setLookupState] = useState({ loading: false, msg: '', ok: false });
  const [nvdVals, setNvdVals] = useState({});

  function handleCVSSScore(score, severityLabel) {
    onChange('cvss_score', score !== null ? score : '');
    if (severityLabel && severityLabel !== 'NONE') {
      onChange('severity', severityLabel);
    }
  }

  async function handleLookup() {
    if (!CVE_ID_RE.test(values.cve_id)) {
      setLookupState({ loading: false, msg: 'Enter a valid CVE ID first (e.g. CVE-2021-44228)', ok: false });
      return;
    }
    setLookupState({ loading: true, msg: '', ok: false });
    try {
      const res = await fetch(`/api/nvd/${values.cve_id.toUpperCase()}`);
      const data = await res.json();
      if (!res.ok) {
        setLookupState({ loading: false, msg: data.error, ok: false });
        return;
      }
      if (data.description) onChange('description', data.description);
      if (data.cvss_score !== null) onChange('cvss_score', data.cvss_score);
      if (data.severity) onChange('severity', data.severity);
      setNvdVals(parseVector(data.vector_string));
      setLookupState({ loading: false, msg: 'Data sourced from NVD. Review all fields before submitting.', ok: true });
    } catch {
      setLookupState({ loading: false, msg: 'NVD lookup failed — fill in manually', ok: false });
    }
  }

  return (
    <form className="vuln-form" onSubmit={onSubmit}>

      {/* ── LEFT COLUMN ── */}

      <div className="form-group form-left">
        <label>CVE ID <span className="required">*</span></label>
        <div className="cve-id-row">
          <input
            type="text"
            value={values.cve_id}
            onChange={(e) => { onChange('cve_id', e.target.value); setLookupState({ loading: false, msg: '', ok: false }); }}
            placeholder="CVE-2024-12345"
            required
          />
          <button type="button" className="btn-lookup" onClick={handleLookup} disabled={lookupState.loading}>
            {lookupState.loading ? 'Looking up…' : 'NVD Lookup'}
          </button>
        </div>
        {lookupState.msg && (
          <span className={`lookup-msg${lookupState.ok ? ' lookup-ok' : ' lookup-err'}`}>
            {lookupState.msg}
          </span>
        )}
      </div>

      <div className="form-group form-left">
        <label>Title <span className="required">*</span></label>
        <input
          type="text"
          value={values.title}
          onChange={(e) => onChange('title', e.target.value)}
          placeholder="Short descriptive title"
          required
        />
      </div>

      <div className="form-group form-left">
        <label>Description <span className="required">*</span></label>
        <textarea
          value={values.description}
          onChange={(e) => onChange('description', e.target.value)}
          placeholder="Describe the vulnerability, its impact, and exploitation conditions..."
          rows={5}
          required
        />
      </div>

      <div className="form-group form-left">
        <label>Severity <span className="required">*</span></label>
        <div className="severity-pills">
          {SEVERITIES.map((s) => (
            <button
              key={s}
              type="button"
              className={`severity-pill${values.severity === s ? ` active-${s.toLowerCase()}` : ''}`}
              onClick={() => onChange('severity', s)}
            >
              {s.charAt(0) + s.slice(1).toLowerCase()}
            </button>
          ))}
        </div>
        <input
          type="text"
          value={values.severity}
          required
          readOnly
          style={{ position: 'absolute', opacity: 0, pointerEvents: 'none', height: 0 }}
          tabIndex={-1}
        />
      </div>

      <div className="form-row form-left">
        <div className="form-group">
          <label>Affected Product <span className="required">*</span></label>
          <input
            type="text"
            value={values.affected_product}
            onChange={(e) => onChange('affected_product', e.target.value)}
            placeholder="e.g. OpenSSL, Apache HTTP Server"
            required
          />
        </div>
        <div className="form-group">
          <label className="label-optional">Affected Version</label>
          <input
            type="text"
            value={values.affected_version}
            onChange={(e) => onChange('affected_version', e.target.value)}
            placeholder="e.g. < 3.0.7"
          />
        </div>
      </div>

      <div className="form-group form-left">
        <label className="label-optional">Reporter</label>
        <input
          type="text"
          value={values.reporter}
          onChange={(e) => onChange('reporter', e.target.value)}
          placeholder="Your name"
        />
      </div>

      {/* ── RIGHT COLUMN — CVSS sticky ── */}
      <div className="form-cvss-col">
        <label>CVSS v3.1 Score</label>
        <CVSSCalculator onScore={handleCVSSScore} initialVals={nvdVals} />
        {values.cvss_score !== '' && (
          <span className="cvss-manual-score">
            Calculated: <strong>{parseFloat(values.cvss_score).toFixed(1)}</strong>
          </span>
        )}
      </div>

      {/* ── Full-width bottom ── */}
      {error && <p className="form-error">{error}</p>}

      <button type="submit" className="btn-submit" disabled={submitting}>
        {submitting ? 'Saving...' : submitLabel}
      </button>

    </form>
  );
}

export default VulnForm;
