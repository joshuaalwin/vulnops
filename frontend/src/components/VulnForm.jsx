import './VulnForm.css';
import CVSSCalculator from './CVSSCalculator';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

function VulnForm({ values, onChange, onSubmit, submitting, error, submitLabel }) {

  function handleCVSSScore(score, severityLabel) {
    onChange('cvss_score', score !== null ? score : '');
    if (severityLabel && severityLabel !== 'NONE') {
      onChange('severity', severityLabel);
    }
  }

  return (
    <form className="vuln-form" onSubmit={onSubmit}>

      {/* ── LEFT COLUMN ── */}

      <div className="form-group form-left">
        <label>CVE ID <span className="required">*</span></label>
        <input
          type="text"
          value={values.cve_id}
          onChange={(e) => onChange('cve_id', e.target.value)}
          placeholder="CVE-2024-12345"
          required
        />
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
        <CVSSCalculator onScore={handleCVSSScore} />
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
