import './SeverityBadge.css';

const colorMap = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info',
};

function SeverityBadge({ severity }) {
  const cls = colorMap[severity] || 'info';
  return <span className={`severity-badge severity-${cls}`}>{severity}</span>;
}

export default SeverityBadge;
