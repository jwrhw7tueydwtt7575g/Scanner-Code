import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';

export default function Signup() {
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
      const res = await fetch('http://localhost:5000/api/auth/signup', {
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
        setError(data.message || 'Signup failed');
      }
    } catch (err) {
      setError('Server error. Please try again later.');
    }
  };

  return (
    <div className="login-bg-pro">
      <div className="login-card-pro">
        <div className="login-card-icon-pro"><span className="material-icons">person_add</span></div>
        <h2 className="login-title-pro">Sign Up</h2>
        <form onSubmit={handleSubmit} className="login-form-pro">
          <label className="login-label-pro">Email</label>
          <input type="email" className="login-input-pro" value={email} onChange={e => setEmail(e.target.value)} />
          <label className="login-label-pro">Password</label>
          <input type="password" className="login-input-pro" value={password} onChange={e => setPassword(e.target.value)} />
          {error && <div className="login-error-pro">{error}</div>}
          <button type="submit" className="login-btn-pro">Sign Up</button>
        </form>
        <div className="login-link-pro">Already have an account? <Link to="/login">Login</Link></div>
      </div>
    </div>
  );
}
