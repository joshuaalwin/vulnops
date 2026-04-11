import './StatusBadge.css';

const colorMap = {
  OPEN: 'open',
  IN_PROGRESS: 'in-progress',
  MITIGATED: 'mitigated',
  RESOLVED: 'resolved',
};

const labelMap = {
  OPEN: 'Open',
  IN_PROGRESS: 'In Progress',
  MITIGATED: 'Mitigated',
  RESOLVED: 'Resolved',
};

function StatusBadge({ status }) {
  const cls = colorMap[status] || 'open';
  return <span className={`status-badge status-${cls}`}>{labelMap[status] || status}</span>;
}

export default StatusBadge;
