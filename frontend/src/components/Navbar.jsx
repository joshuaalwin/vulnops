import { Link, useLocation } from 'react-router-dom';
import logo from '../assets/VulnOps.svg';
import './Navbar.css';

function Navbar() {
  const location = useLocation();

  return (
    <nav className="navbar">
      <div className="navbar-inner">
        <Link to="/" className="navbar-brand">
          <img src={logo} alt="VulnOps" className="brand-logo" />
          VulnOps
        </Link>
        <div className="navbar-links">
          <Link to="/" className={location.pathname === '/' ? 'nav-active' : ''}>
            Dashboard
          </Link>
          <Link to="/vulnerabilities" className={location.pathname === '/vulnerabilities' ? 'nav-active' : ''}>
            Vulnerabilities
          </Link>
          <Link to="/add" className="btn-report">+ Report CVE</Link>
        </div>
      </div>
    </nav>
  );
}

export default Navbar;
