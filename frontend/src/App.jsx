import React, { useEffect } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import SignupPage from './pages/SignupPage'
import LoginPage from './pages/LoginPage'
import Homepage from './pages/Homepage'
import UserPage from './pages/UserPage'
import Admin from './pages/Admin'
import UnauthorizedPage from './pages/UnauthorizedPage'
import { useAuth } from './context/AuthContext'
import AuthCallback from './components/AuthCallback'
import ProtectedRoute from './components/ProtectedRoute'

function App() {
  useEffect(() => {
    // Initialize Google client
    if (window.google && document.getElementById('google-signin-script')) {
      return; // Already initialized
    }

    // Load the Google Sign-In API script
    const script = document.createElement('script');
    script.id = 'google-signin-script';
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.defer = true;
    document.body.appendChild(script);

    return () => {
      const scriptTag = document.getElementById('google-signin-script');
      if (scriptTag) document.body.removeChild(scriptTag);
    };
  }, []);

  const { user, loading } = useAuth();

  if (loading) {
    // Read initial theme preference directly for the loading screen
    const savedTheme = localStorage.getItem('theme');
    // Default to dark mode if no theme is saved or value is invalid
    const initialIsDarkMode = savedTheme ? savedTheme === 'dark' : true;

    return (
      // Updated: Background color based on initial theme check
      <div className={`flex items-center justify-center h-screen ${initialIsDarkMode ? 'bg-black text-white' : 'bg-gray-100 text-gray-900'}`}>
        {/* Updated: Spinner border color based on initial theme check */}
        <div className={`animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 ${initialIsDarkMode ? 'border-blue-500' : 'border-blue-600'}`}></div>
      </div>
    );
  }

  const getDefaultPathForUser = (loggedInUser) => {
    if (!loggedInUser) return "/";
    // Updated: Changed '/employee' to '/user/dashboard' as the default user path
    return loggedInUser.role === 'admin' ? '/admin/dashboard' : '/user/dashboard';
  };

  return (
    <>
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: '#363636',
            color: '#fff',
          },
          success: {
            duration: 3000,
            iconTheme: {
              primary: '#10B981',
              secondary: '#FFFFFF'
            }
          },
          error: {
            duration: 5000,
            iconTheme: {
              primary: '#EF4444',
              secondary: '#FFFFFF'
            }
          }
        }}
      />
      <Routes>
        {/* Updated: Navigate logged-in users to their default path */}
        <Route path="/" element={!user ? <Homepage /> : <Navigate to={getDefaultPathForUser(user)} replace />} />
        <Route path="/login" element={!user ? <LoginPage /> : <Navigate to={getDefaultPathForUser(user)} replace />} />
        <Route path="/signup" element={!user ? <SignupPage /> : <Navigate to={getDefaultPathForUser(user)} replace />} />
        <Route path="/unauthorized" element={<UnauthorizedPage />} />

        {/* Updated: Changed '/employee' route to '/user/*' to match UserPage structure */}
        <Route path="/user/*" element={
          <ProtectedRoute allowedRoles={['employee', 'admin']}>
            <UserPage />
          </ProtectedRoute>
        } />

        <Route path="/admin/*" element={
          <ProtectedRoute allowedRoles={['admin']}>
            <Admin />
          </ProtectedRoute>
        } />

        <Route path="/auth/callback" element={<AuthCallback />} />

        {/* Fallback route */}
        <Route path="*" element={<Navigate to={getDefaultPathForUser(user)} replace />} />
      </Routes>
    </>
  )
}

export default App
