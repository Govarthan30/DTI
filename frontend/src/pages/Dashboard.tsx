import React from 'react';
import CreateOrder from '../components/Orders/CreateOrder';
import OrderHistory from '../components/Orders/OrderHistory';

const Dashboard = () => {
  const handleLogout = () => {
    localStorage.removeItem('token');
    window.location.href = '/';
  };

  return (
    <div>
      <h1>Dashboard</h1>
      <button onClick={handleLogout}>Logout</button>
      <CreateOrder />
      <OrderHistory />
    </div>
  );
};

export default Dashboard;