import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

export default function Logout() {
  const navigate = useNavigate();
  useEffect(() => {
    localStorage.removeItem('isAuthenticated');
    setTimeout(() => navigate('/login'), 1000);
  }, [navigate]);
  return (
    <div className="login-bg-pro">
      <div className="login-card-pro">
        <div className="login-card-icon-pro" style={{ background: 'linear-gradient(135deg, #ef4444 0%, #f59e42 100%)' }}><span className="material-icons">logout</span></div>
        <h2 className="login-title-pro">Logging out...</h2>
        <div className="login-logout-desc-pro">You are being signed out and redirected to login.</div>
      </div>
    </div>
  );
}
