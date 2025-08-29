import React from 'react';
import { BrowserRouter as Router, Route, Routes, Navigate } from 'react-router-dom';
import HomePage from './pages/HomePage';
import AuthPage from './pages/AuthPage';
import Dashboard from './pages/Dashboard';
import ClaimPage from './pages/ClaimPage';

// This is a helper component to protect routes that require a user to be logged in.
const PrivateRoute = ({ children }: { children: JSX.Element }) => {
  const token = localStorage.getItem('token');
  // If a token exists, render the child component (e.g., the Dashboard).
  // Otherwise, redirect the user to the authentication page.
  return token ? children : <Navigate to="/auth" />;
};

// This is the main App component.
function App() {
  return (
    <Router>
      <div className="App">
        <Routes>
          {/* Public Routes */}
          <Route path="/" element={<HomePage />} />
          <Route path="/auth" element={<AuthPage />} />
          <Route path="/claim" element={<ClaimPage />} />

          {/* Private Route */}
          <Route
            path="/dashboard"
            element={
              <PrivateRoute>
                <Dashboard />
              </PrivateRoute>
            }
          />
        </Routes>
      </div>
    </Router>
  );
}

// Export the App component as the default export for this file.
export default App;