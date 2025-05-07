import React, { createContext, useState, useContext, useEffect, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { axiosInstance, setAccessToken, getAccessToken, removeAccessToken } from '../api/axiosInstance';


const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [accessToken, _setAccessToken] = useState(() => getAccessToken());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();
  const location = useLocation();


  const updateAccessToken = useCallback((token) => {
    if (token) {
      setAccessToken(token);
      _setAccessToken(token);
    } else {
      removeAccessToken();
      _setAccessToken(null);
    }
  }, []);


  const fetchUser = useCallback(async () => {
    const currentToken = getAccessToken();
    if (!currentToken) {
      const savedUser = localStorage.getItem('user');
      if (savedUser) {
        try {
          setUser(JSON.parse(savedUser));
          const response = await axiosInstance.post('/api/auth/refresh');
          if (response.data && response.data.accessToken) {
            updateAccessToken(response.data.accessToken);
          }
        } catch (e) {
          console.error("Failed to use saved user data:", e);
          setUser(null);
          localStorage.removeItem('user');
        }
      } else {
        setUser(null);
      }
      setLoading(false);
      return;
    }

    setLoading(true);
    try {
      const response = await axiosInstance.get('/api/auth/me');
      if (response.data) {
        setUser(response.data);
        localStorage.setItem('user', JSON.stringify(response.data));
      } else {
        updateAccessToken(null);
        setUser(null);
        localStorage.removeItem('user');
      }
    } catch (err) {
      console.error("Error fetching user:", err);
      updateAccessToken(null);
      setUser(null);
      localStorage.removeItem('user');
    } finally {
      setLoading(false);
    }
  }, [updateAccessToken]);


  useEffect(() => {
    if (accessToken) {
      fetchUser();
    } else {
      setLoading(false);
    }
  }, [accessToken, fetchUser]);

  const handleAuthCallback = useCallback((token, userData) => {
    updateAccessToken(token);
    setUser(userData);
    setLoading(false);


    localStorage.setItem('user', JSON.stringify(userData));

    if (userData?.role === 'admin') {
      navigate('/admin', { replace: true });
    } else {
      navigate('/employee', { replace: true });
    }
  }, [navigate, updateAccessToken]);


  const login = async (email, password) => {
    setLoading(true);
    setError(null);
    try {
      const response = await axiosInstance.post('/api/auth/login', { email, password });
      if (response.data?.accessToken && response.data?.user) {
        updateAccessToken(response.data.accessToken);
        setUser(response.data.user);
        if (response.data.user.role === 'admin') {
          navigate('/admin');
        } else {
          navigate('/employee');
        }
      } else {
        setError('Login failed: Invalid response from server.');
        updateAccessToken(null);
        setUser(null);
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Login failed');
      updateAccessToken(null);
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const signup = async (name, email, password) => {
    setLoading(true);
    setError(null);
    try {
      const response = await axiosInstance.post('/api/auth/signup', { name, email, password });
      if (response.status === 201) {
        navigate('/login?signup=success');
      } else {
        setError(response.data?.message || 'Signup completed but with unexpected status.');
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Signup failed');
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    setLoading(true);
    setError(null);
    const currentToken = getAccessToken();

    try {
      if (currentToken && user) {
        try {
          await axiosInstance.put('/api/auth/me/inactive');
        } catch (inactiveErr) {
          console.error("Failed to mark user as inactive (proceeding with logout):", inactiveErr.response?.data?.message || inactiveErr.message);
        }
      }

      await axiosInstance.post('/api/auth/logout');

    } catch (err) {
      setError(err.response?.data?.message || 'Logout failed');
    } finally {
      updateAccessToken(null);
      setUser(null);
      delete axiosInstance.defaults.headers.common['Authorization'];
      setLoading(false);
      navigate('/login');
    }
  };

  const googleAuthInitiate = () => {
    setLoading(true);
    try {
      const redirectUrl = `${axiosInstance.defaults.baseURL}/api/auth/google`;

      updateAccessToken(null);
      setUser(null);

      window.location.href = redirectUrl;
    } catch (err) {
      setLoading(false);
      setError('Google authentication initiation failed');
    }
  };


  return (
    <AuthContext.Provider value={{
      user,
      accessToken,
      loading,
      error,
      login,
      signup,
      logout,
      googleAuthInitiate,
      handleAuthCallback,
      fetchUser,
      setError
    }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  return useContext(AuthContext);
};
