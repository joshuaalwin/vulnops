import './VulnTableHeader.css';

function VulnTableHeader() {
  return (
    <div className="vuln-table-header">
      <span className="col-cve">CVE ID</span>
      <span className="col-title">Title / Product</span>
      <span className="col-severity">Severity</span>
      <span className="col-cvss">CVSS</span>
      <span className="col-status">Status</span>
      <span className="col-date">Reported</span>
      <span className="col-notes">Notes</span>
    </div>
  );
}

export default VulnTableHeader;
