import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (!email || !password) {
      setError('Please enter email and password');
      return;
    }
    try {
      const res = await fetch('http://localhost:5000/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: email, password }),
        credentials: 'include'
      });
      const data = await res.json();
      if (res.ok) {
        localStorage.setItem('isAuthenticated', 'true');
        navigate('/');
      } else {
        setError(data.message || 'Login failed');
      }
    } catch (err) {
      setError('Server error. Please try again later.');
    }
  };

  return (
    <div className="login-bg-pro">
      <div className="login-card-pro">
        <div className="login-card-icon-pro"><span className="material-icons">lock</span></div>
        <h2 className="login-title-pro">Login</h2>
        <form onSubmit={handleSubmit} className="login-form-pro">
          <label className="login-label-pro">Email</label>
          <input type="email" className="login-input-pro" value={email} onChange={e => setEmail(e.target.value)} />
          <label className="login-label-pro">Password</label>
          <input type="password" className="login-input-pro" value={password} onChange={e => setPassword(e.target.value)} />
          {error && <div className="login-error-pro">{error}</div>}
          <button type="submit" className="login-btn-pro">Login</button>
        </form>
        <div className="login-link-pro">Don't have an account? <Link to="/signup">Sign up</Link></div>
      </div>
    </div>
  );
}
