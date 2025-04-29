import React, { useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const AuthCallback = () => {
    const [searchParams] = useSearchParams();
    const navigate = useNavigate();
    const { handleAuthCallback, setError } = useAuth();

    useEffect(() => {
        const accessToken = searchParams.get('accessToken');
        const userParam = searchParams.get('user');
        const errorParam = searchParams.get('error'); // Check for errors passed back

        if (errorParam) {
            console.error("OAuth Callback Error:", errorParam);
            setError(`Authentication failed: ${errorParam}`);
            navigate('/login', { replace: true });
            return;
        }

        if (accessToken && userParam) {
            try {
                const user = JSON.parse(userParam);
                // Call the context function to handle the tokens and user data
                handleAuthCallback(accessToken, user);
                // Navigation is handled inside handleAuthCallback now
            } catch (e) {
                console.error("Failed to parse user data from callback:", e);
                setError('Authentication callback failed: Invalid data received.');
                navigate('/login', { replace: true });
            }
        } else {
            // Missing token or user data in callback
            console.error("OAuth Callback missing token or user data");
            setError('Authentication callback failed: Missing data.');
            navigate('/login', { replace: true });
        }
        // No need for dependency array re-run, this should only run once on mount
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []); // Run only once on component mount

    // Display a loading indicator while processing
    return (
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
            Processing authentication...
        </div>
    );
};

export default AuthCallback;