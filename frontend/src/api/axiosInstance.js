import axios from 'axios';

const baseURL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:5000';

const axiosInstance = axios.create({
    baseURL: baseURL,
    withCredentials: true, // Include cookies by default
    timeout: 30000 // 30 seconds timeout
});

// Token management functions
const setAccessToken = (token) => {
    if (token) {
        localStorage.setItem('token', token);
        // Also update the default headers for future requests
        axiosInstance.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    } else {
        // Clear token if null/undefined is passed
        removeAccessToken();
    }
};

const getAccessToken = () => {
    // Prefer localStorage, fallback to sessionStorage
    return localStorage.getItem('token') || sessionStorage.getItem('token') || null;
};

const removeAccessToken = () => {
    localStorage.removeItem('token');
    sessionStorage.removeItem('token');
    // Also remove from default headers
    delete axiosInstance.defaults.headers.common['Authorization'];
};

// Track if we're currently refreshing the token
let isRefreshing = false;
// Store pending requests that should be retried after token refresh
let failedQueue = [];

const processQueue = (error, token = null) => {
    failedQueue.forEach(prom => {
        if (error) {
            prom.reject(error);
        } else {
            prom.resolve(token);
        }
    });
    
    failedQueue = [];
};

// Add request interceptor to attach token to every request
axiosInstance.interceptors.request.use(
    (config) => {
        // Ensure withCredentials is set for all requests
        config.withCredentials = true;
        
        // Get the token from localStorage
        const token = getAccessToken();
        if (token) {
            config.headers['Authorization'] = `Bearer ${token}`;
        }
        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);

// Add response interceptor to handle auth errors
axiosInstance.interceptors.response.use(
    (response) => {
        return response;
    },
    async (error) => {
        const originalRequest = error.config;
        
        // Don't retry if we already tried or it's a refresh token request
        if (error.response?.status === 401 && !originalRequest._retry &&
            !originalRequest.url.includes('/api/auth/refresh')) {
            
            if (isRefreshing) {
                // If refresh is in progress, queue this request
                return new Promise((resolve, reject) => {
                    failedQueue.push({ resolve, reject });
                }).then(token => {
                    originalRequest.headers['Authorization'] = `Bearer ${token}`;
                    return axios(originalRequest);
                }).catch(err => {
                    return Promise.reject(err);
                });
            }
            
            originalRequest._retry = true;
            isRefreshing = true;
            
            try {
                // Use the correct refresh endpoint from AuthContext
                const response = await axios.post(`${baseURL}/api/auth/refresh`, {}, 
                    { withCredentials: true });
                
                if (response.data && response.data.accessToken) {
                    const newToken = response.data.accessToken;
                    setAccessToken(newToken);
                    
                    // Process any queued requests with the new token
                    processQueue(null, newToken);
                    
                    // Update the current request and retry
                    originalRequest.headers['Authorization'] = `Bearer ${newToken}`;
                    return axios(originalRequest);
                } else {
                    // Handle cases where refresh might succeed but not return a token
                    const refreshError = new Error('Failed to refresh token: No new token received');
                    processQueue(refreshError);
                    removeAccessToken();
                    // Don't redirect here - let the auth context handle that
                    return Promise.reject(refreshError); // Reject with specific error
                }
            } catch (refreshError) {
                // Log the actual refresh error for better debugging
                console.error("Token refresh failed:", refreshError.response?.data || refreshError.message);
                processQueue(refreshError);
                removeAccessToken();
                // Don't redirect here - let the auth context handle that
                return Promise.reject(refreshError);
            } finally {
                isRefreshing = false;
            }
        }
        
        // For non-401 errors or retried requests, just reject
        return Promise.reject(error);
    }
);

// Export all the necessary functions
export { 
    axiosInstance, 
    setAccessToken, 
    getAccessToken, 
    removeAccessToken 
}; 