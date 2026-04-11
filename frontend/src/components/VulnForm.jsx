import './VulnForm.css';

function VulnForm({ values, onChange, onSubmit, submitting, error, submitLabel }) {
  return (
    <form className="vuln-form" onSubmit={onSubmit}>
      <div className="form-row">
        <div className="form-group">
          <label>CVE ID <span className="required">*</span></label>
          <input
            type="text"
            value={values.cve_id}
            onChange={(e) => onChange('cve_id', e.target.value)}
            placeholder="CVE-2024-12345"
            required
          />
        </div>
        <div className="form-group">
          <label>CVSS Score</label>
          <input
            type="number"
            value={values.cvss_score}
            onChange={(e) => onChange('cvss_score', e.target.value)}
            placeholder="0.0 – 10.0"
            min="0"
            max="10"
            step="0.1"
          />
        </div>
      </div>

      <div className="form-group">
        <label>Title <span className="required">*</span></label>
        <input
          type="text"
          value={values.title}
          onChange={(e) => onChange('title', e.target.value)}
          placeholder="Short descriptive title"
          required
        />
      </div>

      <div className="form-group">
        <label>Description <span className="required">*</span></label>
        <textarea
          value={values.description}
          onChange={(e) => onChange('description', e.target.value)}
          placeholder="Full description of the vulnerability, impact, and exploitation conditions..."
          rows={2}
          required
        />
      </div>

      <div className="form-row">
        <div className="form-group">
          <label>Severity <span className="required">*</span></label>
          <select
            value={values.severity}
            onChange={(e) => onChange('severity', e.target.value)}
            required
          >
            <option value="">Select severity</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>
        </div>
        <div className="form-group">
          <label>Status</label>
          <select
            value={values.status}
            onChange={(e) => onChange('status', e.target.value)}
          >
            <option value="OPEN">Open</option>
            <option value="IN_PROGRESS">In Progress</option>
            <option value="MITIGATED">Mitigated</option>
            <option value="RESOLVED">Resolved</option>
          </select>
        </div>
      </div>

      <div className="form-row">
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
          <label>Affected Version</label>
          <input
            type="text"
            value={values.affected_version}
            onChange={(e) => onChange('affected_version', e.target.value)}
            placeholder="e.g. &lt; 3.0.7"
          />
        </div>
      </div>

      <div className="form-group">
        <label>Reporter</label>
        <input
          type="text"
          value={values.reporter}
          onChange={(e) => onChange('reporter', e.target.value)}
          placeholder="Your name (optional)"
        />
      </div>

      {error && <p className="form-error">{error}</p>}

      <button type="submit" className="btn-submit" disabled={submitting}>
        {submitting ? 'Saving...' : submitLabel}
      </button>
    </form>
  );
}

export default VulnForm;
