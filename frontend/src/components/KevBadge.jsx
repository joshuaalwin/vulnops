import './KevBadge.css';

function KevBadge({ isKev, dateAdded }) {
  if (!isKev) return null;

  return (
    <span
      className="kev-badge"
      title={`CISA Known Exploited Vulnerability — active exploitation confirmed${dateAdded ? ` (added ${dateAdded})` : ''}`}
    >
      KEV
    </span>
  );
}

export default KevBadge;
