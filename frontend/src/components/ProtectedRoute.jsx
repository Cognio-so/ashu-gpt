import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const ProtectedRoute = ({ children, allowedRoles }) => {
    const { user, loading, accessToken } = useAuth();
    const location = useLocation();

    if (loading) {

        return (
            <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
                Loading...
            </div>
        );
    }

    const currentToken = accessToken || localStorage.getItem('accessToken');

    if (!currentToken || !user) {
        return <Navigate to="/login" state={{ from: location }} replace />;
    }

    if (allowedRoles && !allowedRoles.includes(user.role)) {

        console.warn(`User role '${user.role}' not authorized for route requiring roles: ${allowedRoles.join(', ')} at ${location.pathname}`);
        return <Navigate to="/unauthorized" replace />;
    }

    return children;
};

export default ProtectedRoute; 