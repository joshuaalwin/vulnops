import { Link } from 'react-router-dom';
import SeverityBadge from './SeverityBadge';
import StatusBadge from './StatusBadge';
import EpssBadge from './EpssBadge';
import './VulnCard.css';

function VulnCard({ vuln }) {
  const date = new Date(vuln.created_at).toLocaleDateString('en-US', {
    month: 'short', day: 'numeric', year: '2-digit',
  });

  const cvss = vuln.cvss_score != null ? parseFloat(vuln.cvss_score).toFixed(1) : '—';

  return (
    <div className={`vuln-row vuln-row-${vuln.severity.toLowerCase()}`}>
      <span className="col-cve">
        <Link to={`/vuln/${vuln.id}`} className="cve-link">{vuln.cve_id}</Link>
      </span>

      <span className="col-title">
        <Link to={`/vuln/${vuln.id}`} className="vuln-title-link">{vuln.title}</Link>
        <span className="vuln-product-inline">{vuln.affected_product}{vuln.affected_version ? ` ${vuln.affected_version}` : ''}</span>
      </span>

      <span className="col-severity">
        <SeverityBadge severity={vuln.severity} />
      </span>

      <span className={`col-cvss cvss-val cvss-${vuln.severity.toLowerCase()}`}>{cvss}</span>

      <span className="col-epss">
        <EpssBadge
          score={vuln.epss_score != null ? parseFloat(vuln.epss_score) : null}
          percentile={vuln.epss_percentile}
        />
      </span>

      <span className="col-status">
        <StatusBadge status={vuln.status} />
      </span>

      <span className="col-date">{date}</span>

      <span className="col-notes">{vuln.note_count}</span>
    </div>
  );
}

export default VulnCard;
