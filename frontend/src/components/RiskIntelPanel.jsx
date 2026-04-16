import { useState } from 'react';
import './RiskIntelPanel.css';

const SCORE_CLASS = {
  CRITICAL: 'risk-critical',
  HIGH: 'risk-high',
  MEDIUM: 'risk-medium',
  LOW: 'risk-low',
};

function RiskIntelPanel({ vulnId, initialData }) {
  const [state, setState] = useState(initialData ? 'loaded' : 'idle');
  const [data, setData] = useState(initialData || null);
  const [error, setError] = useState('');

  async function generate(forceRefresh = false) {
    setState('loading');
    setError('');
    try {
      const url = `/api/risk-intel/${vulnId}${forceRefresh ? '?refresh=1' : ''}`;
      const res = await fetch(url);
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || `HTTP ${res.status}`);
      }
      const json = await res.json();
      setData(json);
      setState('loaded');
    } catch (err) {
      setError(err.message);
      setState('error');
    }
  }

  if (state === 'idle') {
    return (
      <div className="risk-intel-panel risk-intel-idle">
        <button className="btn-generate-risk" onClick={() => generate()}>
          Generate Risk Intelligence
        </button>
        <p className="risk-intel-hint">Synthesizes CVSS · EPSS · CISA KEV · Compliance frameworks via Claude</p>
      </div>
    );
  }

  if (state === 'loading') {
    return (
      <div className="risk-intel-panel risk-intel-loading">
        <span className="risk-spinner" />
        <span className="risk-loading-text">Analyzing with Claude…</span>
      </div>
    );
  }

  if (state === 'error') {
    return (
      <div className="risk-intel-panel risk-intel-error">
        <span className="risk-error-msg">{error}</span>
        <button className="btn-retry-risk" onClick={() => generate()}>Retry</button>
      </div>
    );
  }

  // Loaded
  const cachedAt = data.cached_at
    ? new Date(data.cached_at).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
    : null;

  return (
    <div className="risk-intel-panel risk-intel-loaded">
      <div className="risk-intel-header">
        <h2>Risk Intelligence</h2>
        <button className="btn-regenerate-risk" onClick={() => generate(true)} title="Force refresh">
          Regenerate
        </button>
      </div>

      <div className="risk-composite">
        <span className={`risk-score-badge ${SCORE_CLASS[data.composite_risk_score] ?? ''}`}>
          {data.composite_risk_score}
        </span>
        <span className="risk-rationale">{data.score_rationale}</span>
      </div>

      <div className="risk-section">
        <h3>Exploitation Assessment</h3>
        <p>{data.exploitation_assessment}</p>
      </div>

      <div className="risk-section">
        <h3>Compliance Impact</h3>
        <div className="risk-compliance-grid">
          {data.compliance_impacts.map((item, i) => (
            <div key={i} className="risk-compliance-card">
              <span className="compliance-framework">{item.framework}</span>
              <span className="compliance-control">{item.control}</span>
              <p className="compliance-impact">{item.impact}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="risk-section">
        <h3>Recommended Action</h3>
        <p>{data.recommended_action}</p>
      </div>

      <div className="risk-intel-footer">
        <span>AI-generated · Verify before action · Human review required</span>
        {cachedAt && <span>Cached {cachedAt}</span>}
        <span>Claude Opus 4.6</span>
      </div>
    </div>
  );
}

export default RiskIntelPanel;
