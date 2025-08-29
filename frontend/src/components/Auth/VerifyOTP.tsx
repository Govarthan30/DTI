import React, { useState } from 'react';
import api from '../../../public/api';

const VerifyOTP = ({ email }: { email: string }) => {
  const [otp, setOtp] = useState('');
  const [error, setError] = useState('');

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const response = await api.post('/auth/verify-otp', { email, otp });
      localStorage.setItem('token', response.data.token);
      window.location.href = '/dashboard';
    } catch (err: any) {
      setError(err.response?.data?.error || 'OTP verification failed');
    }
  };

  return (
    <form onSubmit={handleVerify}>
      <h2>Verify OTP for {email}</h2>
      {error && <p style={{ color: 'red' }}>{error}</p>}
      <input
        type="text"
        placeholder="OTP"
        value={otp}
        onChange={(e) => setOtp(e.target.value)}
        required
      />
      <button type="submit">Verify</button>
    </form>
  );
};

export default VerifyOTP;