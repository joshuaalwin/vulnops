import './EpssBadge.css';

function EpssBadge({ score, percentile }) {
  if (score == null) return <span className="epss-badge epss-null">—</span>;

  const pct = (score * 100).toFixed(1);
  const tier = score < 0.1 ? 'low' : score < 0.5 ? 'mid' : 'high';

  return (
    <span
      className={`epss-badge epss-${tier}`}
      title={`${pct}% exploitation probability within 30 days (FIRST.org EPSS)${percentile != null ? ` — ${percentile}th percentile` : ''}`}
    >
      {pct}%
    </span>
  );
}

export default EpssBadge;
