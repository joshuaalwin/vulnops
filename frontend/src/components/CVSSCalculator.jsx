import { useState, useEffect } from 'react';
import './CVSSCalculator.css';

const METRICS = [
  {
    id: 'AV', label: 'Attack Vector',
    options: [
      { value: 'N', label: 'Network',  short: 'N', sev: 'critical', tip: 'Exploitable remotely over the internet' },
      { value: 'A', label: 'Adjacent', short: 'A', sev: 'high',     tip: 'Requires access to the local network' },
      { value: 'L', label: 'Local',    short: 'L', sev: 'medium',   tip: 'Requires local access or authenticated session' },
      { value: 'P', label: 'Physical', short: 'P', sev: 'low',      tip: 'Requires physical access to the device' },
    ],
  },
  {
    id: 'AC', label: 'Attack Complexity',
    options: [
      { value: 'L', label: 'Low',  short: 'L', sev: 'high', tip: 'No special conditions required' },
      { value: 'H', label: 'High', short: 'H', sev: 'low',  tip: 'Requires specific conditions or reconnaissance' },
    ],
  },
  {
    id: 'PR', label: 'Privileges Required',
    options: [
      { value: 'N', label: 'None', short: 'N', sev: 'high',   tip: 'No authentication needed' },
      { value: 'L', label: 'Low',  short: 'L', sev: 'medium', tip: 'Basic user privileges required' },
      { value: 'H', label: 'High', short: 'H', sev: 'low',    tip: 'Admin/root privileges required' },
    ],
  },
  {
    id: 'UI', label: 'User Interaction',
    options: [
      { value: 'N', label: 'None',     short: 'N', sev: 'high', tip: 'No user interaction needed' },
      { value: 'R', label: 'Required', short: 'R', sev: 'low',  tip: 'Requires a user to take an action' },
    ],
  },
  {
    id: 'S', label: 'Scope',
    options: [
      { value: 'U', label: 'Unchanged', short: 'U', sev: 'low',      tip: 'Impact limited to the vulnerable component' },
      { value: 'C', label: 'Changed',   short: 'C', sev: 'critical', tip: 'Impact extends beyond the vulnerable component' },
    ],
  },
  {
    id: 'C', label: 'Confidentiality',
    options: [
      { value: 'N', label: 'None', short: 'N', sev: 'low',      tip: 'No impact on confidentiality' },
      { value: 'L', label: 'Low',  short: 'L', sev: 'medium',   tip: 'Some restricted information disclosed' },
      { value: 'H', label: 'High', short: 'H', sev: 'critical', tip: 'Total loss of confidentiality' },
    ],
  },
  {
    id: 'I', label: 'Integrity',
    options: [
      { value: 'N', label: 'None', short: 'N', sev: 'low',      tip: 'No impact on integrity' },
      { value: 'L', label: 'Low',  short: 'L', sev: 'medium',   tip: 'Modification of some data possible' },
      { value: 'H', label: 'High', short: 'H', sev: 'critical', tip: 'Total loss of integrity' },
    ],
  },
  {
    id: 'A', label: 'Availability',
    options: [
      { value: 'N', label: 'None', short: 'N', sev: 'low',      tip: 'No impact on availability' },
      { value: 'L', label: 'Low',  short: 'L', sev: 'medium',   tip: 'Reduced performance or interruptions' },
      { value: 'H', label: 'High', short: 'H', sev: 'critical', tip: 'Total loss of availability' },
    ],
  },
];

const WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.20 },
  AC: { L: 0.77, H: 0.44 },
  PR: {
    U: { N: 0.85, L: 0.62, H: 0.27 },
    C: { N: 0.85, L: 0.68, H: 0.50 },
  },
  UI: { N: 0.85, R: 0.62 },
  C:  { N: 0.00, L: 0.22, H: 0.56 },
  I:  { N: 0.00, L: 0.22, H: 0.56 },
  A:  { N: 0.00, L: 0.22, H: 0.56 },
};

function roundup(n) {
  return Math.ceil(n * 10) / 10;
}

function calculateScore(v) {
  if (!v.AV || !v.AC || !v.PR || !v.UI || !v.S || !v.C || !v.I || !v.A) return null;

  const iscBase = 1 - (1 - WEIGHTS.C[v.C]) * (1 - WEIGHTS.I[v.I]) * (1 - WEIGHTS.A[v.A]);
  const isc = v.S === 'U'
    ? 6.42 * iscBase
    : 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);

  if (isc <= 0) return 0;

  const exp = 8.22 * WEIGHTS.AV[v.AV] * WEIGHTS.AC[v.AC] * WEIGHTS.PR[v.S][v.PR] * WEIGHTS.UI[v.UI];

  const raw = v.S === 'U'
    ? Math.min(isc + exp, 10)
    : Math.min(1.08 * (isc + exp), 10);

  return roundup(raw);
}

function scoreSeverity(score) {
  if (score === null) return null;
  if (score === 0)    return { label: 'None',     cls: 'none' };
  if (score < 4)      return { label: 'Low',      cls: 'low' };
  if (score < 7)      return { label: 'Medium',   cls: 'medium' };
  if (score < 9)      return { label: 'High',     cls: 'high' };
  return                     { label: 'Critical', cls: 'critical' };
}

// Build CVSS vector string
function vectorString(v) {
  if (!v.AV) return '';
  const parts = ['CVSS:3.1'];
  const keys = ['AV','AC','PR','UI','S','C','I','A'];
  for (const k of keys) {
    if (v[k]) parts.push(`${k}:${v[k]}`);
  }
  return parts.join('/');
}

export default function CVSSCalculator({ onScore, initialVals = {} }) {
  const [vals, setVals] = useState({});
  const [tooltip, setTooltip] = useState(null);

  const score = calculateScore(vals);
  const sev   = scoreSeverity(score);
  const vec   = vectorString(vals);

  // Apply NVD-sourced metric values when a lookup populates them
  useEffect(() => {
    if (Object.keys(initialVals).length > 0) {
      setVals(initialVals);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [JSON.stringify(initialVals)]);

  useEffect(() => {
    onScore(score, sev?.label?.toUpperCase() ?? null);
  }, [score]);

  function pick(metric, value) {
    setVals(prev => ({ ...prev, [metric]: value }));
  }

  const filled = Object.keys(vals).length;
  const total  = METRICS.length;

  return (
    <div className="cvss-calc">
      <div className="cvss-calc-header">
        <span className="cvss-calc-title">CVSS v3.1 Calculator</span>
        <div className="cvss-calc-progress">
          <div
            className="cvss-calc-progress-bar"
            style={{ width: `${(filled / total) * 100}%` }}
          />
        </div>
        <span className="cvss-calc-progress-label">{filled}/{total} metrics</span>
      </div>

      <div className="cvss-metrics">
        {METRICS.map((m) => (
          <div key={m.id} className="cvss-metric">
            <span className="cvss-metric-label">
              {m.label}
              <span className="cvss-metric-id">({m.id})</span>
            </span>
            <div className="cvss-metric-options">
              {m.options.map((opt) => {
                const isSelected = vals[m.id] === opt.value;
                return (
                  <button
                    key={opt.value}
                    type="button"
                    className={`cvss-opt${isSelected ? ` selected selected-${opt.sev}` : ''}`}
                    onClick={() => pick(m.id, opt.value)}
                    onMouseEnter={() => setTooltip(opt.tip)}
                    onMouseLeave={() => setTooltip(null)}
                  >
                    {opt.label}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      <div className="cvss-tooltip">{tooltip ?? ''}</div>

      <div className="cvss-result">
        <div className={`cvss-score-display ${sev ? sev.cls : 'empty'}`}>
          <span className="cvss-score-number">{score !== null ? score.toFixed(1) : '—'}</span>
          <span className="cvss-score-label">{sev ? sev.label : 'Incomplete'}</span>
        </div>
        {vec && (
          <div className="cvss-vector">
            <span className="cvss-vector-label">Vector</span>
            <code className="cvss-vector-string">{vec}</code>
          </div>
        )}
      </div>
    </div>
  );
}
