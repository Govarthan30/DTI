import React from 'react';
import { Link } from 'react-router-dom';

const HomePage = () => {
  return (
    <div>
      <h1>Welcome to QuickServe</h1>
      <Link to="/auth">Login/Signup</Link>
      <br />
      <Link to="/claim">Claim Order</Link>
    </div>
  );
};

export default HomePage;