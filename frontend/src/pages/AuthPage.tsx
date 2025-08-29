import React, { useState } from 'react';
import Login from '../components/Auth/Login';
import Signup from '../components/Auth/Signup';
import VerifyOTP from '../components/Auth/VerifyOTP';

const AuthPage: React.FC = () => {
  const [showVerify, setShowVerify] = useState(false);
  const [emailForOtp, setEmailForOtp] = useState('');

  // Called when signup is successful to trigger OTP verification
  const handleSignupSuccess = (email: string) => {
    setEmailForOtp(email);
    setShowVerify(true);
  };

  return (
    <div style={{ maxWidth: '400px', margin: '0 auto', padding: '2rem' }}>
      <h1 style={{ textAlign: 'center' }}>Authentication</h1>

      {!showVerify ? (
        <>
          <Login />
          <hr style={{ margin: '2rem 0' }} />
          <Signup onSignupSuccess={handleSignupSuccess} />
        </>
      ) : (
        <VerifyOTP email={emailForOtp} />
      )}
    </div>
  );
};

export default AuthPage;
