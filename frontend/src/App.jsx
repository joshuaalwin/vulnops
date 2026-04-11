import { Routes, Route } from 'react-router-dom';
import Navbar from './components/Navbar';
import Dashboard from './pages/Dashboard';
import VulnDetail from './pages/VulnDetail';
import AddVuln from './pages/AddVuln';
import EditVuln from './pages/EditVuln';
import './App.css';

function App() {
  return (
    <div className="app">
      <Navbar />
      <main className="main-content">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/vuln/:id" element={<VulnDetail />} />
          <Route path="/add" element={<AddVuln />} />
          <Route path="/edit/:id" element={<EditVuln />} />
        </Routes>
      </main>
    </div>
  );
}

export default App;
