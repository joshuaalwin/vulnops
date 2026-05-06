import './StatsCard.css';

function StatsCard({ label, value, color, icon }) {
  return (
    <div className="stats-card" style={{ '--card-accent': color }}>
      <div className="stats-card-icon">{icon}</div>
      <div className="stats-card-body">
        <span className="stats-card-value">{value}</span>
        <span className="stats-card-label">{label}</span>
      </div>
    </div>
  );
}

export default StatsCard;
