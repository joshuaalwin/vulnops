import './VulnTableHeader.css';

const SORTABLE = {
  cve_id: 'CVE ID',
  title: 'Title / Product',
  severity: 'Severity',
  cvss_score: 'CVSS',
  epss_score: 'EPSS',
  status: 'Status',
  created_at: 'Reported',
};

function SortArrow({ field, sortBy, sortOrder }) {
  if (sortBy !== field) return <span className="sort-arrow sort-inactive">&#x2195;</span>;
  return (
    <span className="sort-arrow sort-active">
      {sortOrder === 'asc' ? '↑' : '↓'}
    </span>
  );
}

function VulnTableHeader({ sortBy, sortOrder, onSort }) {
  const sortable = !!onSort;

  function col(field, className) {
    const label = SORTABLE[field];
    if (!sortable || !label) return <span className={className}>{label || field}</span>;
    return (
      <button className={`col-sort ${className}`} onClick={() => onSort(field)}>
        {label}
        <SortArrow field={field} sortBy={sortBy} sortOrder={sortOrder} />
      </button>
    );
  }

  return (
    <div className="vuln-table-header">
      {col('cve_id', 'col-cve')}
      {col('title', 'col-title')}
      {col('severity', 'col-severity')}
      {col('cvss_score', 'col-cvss')}
      {col('epss_score', 'col-epss')}
      <span className="col-kev">KEV</span>
      {col('status', 'col-status')}
      {col('created_at', 'col-date')}
      <span className="col-notes">Notes</span>
    </div>
  );
}

export default VulnTableHeader;
