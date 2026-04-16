import { useState } from 'react';
import './RiskIntelPanel.css';

const LABEL_CLASS = {
  IMMEDIATE:    'label-immediate',
  URGENT:       'label-urgent',
  'SHORT-TERM': 'label-short-term',
  ONGOING:      'label-ongoing',
  GOVERNANCE:   'label-governance',
  'LONG-TERM':  'label-long-term',
};

function ActionItem({ text }) {
  const match = text.match(/^([A-Z][A-Z\s\-]+?):\s*/);
  if (!match) return <>{text}</>;
  const label = match[1].trim();
  const cls = LABEL_CLASS[label] || 'label-default';
  return <><span className={`action-label ${cls}`}>{label}</span>{text.slice(match[0].length)}</>;
}

function RecommendedAction({ text }) {
  const items = text.split(/\d+\)/).map(s => s.trim()).filter(Boolean);
  if (items.length <= 1) return <p className="risk-action-text">{text}</p>;
  return (
    <ul className="risk-action-list">
      {items.map((item, i) => <li key={i}><ActionItem text={item} /></li>)}
    </ul>
  );
}

function RiskSkeleton() {
  return (
    <div className="risk-skeleton">
      {/* Header */}
      <div className="risk-skeleton-header">
        <div className="skel skel-label" />
        <div className="skel skel-btn" />
      </div>

      {/* Score composite */}
      <div className="risk-skeleton-composite">
        <div className="skel skel-badge" />
        <div className="risk-skeleton-lines">
          <div className="skel skel-line w-full" />
          <div className="skel skel-line w-3/4" />
        </div>
      </div>

      {/* Exploitation Assessment */}
      <div className="risk-skeleton-section">
        <div className="skel skel-section-label" />
        <div className="skel skel-line w-full" />
        <div className="skel skel-line w-full" />
        <div className="skel skel-line w-2/3" />
      </div>

      {/* Compliance Impact */}
      <div className="risk-skeleton-section">
        <div className="skel skel-section-label" />
        <div className="risk-skeleton-cards">
          {[0, 1, 2, 3].map(i => (
            <div key={i} className="risk-skeleton-card">
              <div className="skel skel-card-framework" />
              <div className="skel skel-card-control" />
              <div className="skel skel-line w-full" />
              <div className="skel skel-line w-4/5" />
            </div>
          ))}
        </div>
      </div>

      {/* Recommended Action */}
      <div className="risk-skeleton-section">
        <div className="skel skel-section-label" />
        <div className="skel skel-line w-full" />
        <div className="skel skel-line w-full" />
        <div className="skel skel-line w-3/4" />
        <div className="skel skel-line w-full" />
        <div className="skel skel-line w-1/2" />
      </div>

      {/* Footer */}
      <div className="risk-skeleton-footer">
        <div className="skel skel-footer-text" />
        <div className="skel skel-footer-text skel-footer-short" />
      </div>
    </div>
  );
}

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
    setState('streaming');
    setError('');

    try {
      const url = `/api/risk-intel/${vulnId}${forceRefresh ? '?refresh=1' : ''}`;
      const res = await fetch(url);

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || `HTTP ${res.status}`);
      }

      const contentType = res.headers.get('content-type') || '';

      // Cache hit returns plain JSON
      if (contentType.includes('application/json')) {
        const json = await res.json();
        setData(json);
        setState('loaded');
        return;
      }

      // New generation via SSE — show skeleton while streaming, snap to loaded on done
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop();

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          let payload;
          try { payload = JSON.parse(line.slice(6)); } catch { continue; }

          if (payload.type === 'done') {
            setData(payload.data);
            setState('loaded');
          } else if (payload.type === 'error') {
            throw new Error(payload.error);
          }
          // 'chunk' events are intentionally ignored — skeleton is shown instead
        }
      }
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

  if (state === 'loading' || state === 'streaming') {
    return (
      <div className="risk-intel-panel">
        <RiskSkeleton />
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
        <RecommendedAction text={data.recommended_action} />
      </div>

      <div className="risk-intel-footer">
        <span>AI-generated · Verify before action · Human review required</span>
        {cachedAt && <span>Cached {cachedAt}</span>}
        <span>Claude Sonnet 4.6</span>
      </div>
    </div>
  );
}

export default RiskIntelPanel;
