import React from 'react';
import { Link } from 'react-router-dom';

const UnauthorizedPage = () => {
    return (
        <div className="flex flex-col items-center justify-center h-screen bg-gray-100 text-gray-800">
            <h1 className="text-6xl font-bold text-red-600 mb-4">403</h1>
            <h2 className="text-3xl font-semibold mb-2">Access Denied</h2>
            <p className="text-lg mb-6 text-center px-4">
                Sorry, you do not have the necessary permissions to access this page.
            </p>
            <Link
                to="/" // Link back to the homepage or a default logged-in page
                className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition duration-300"
            >
                Go Back Home
            </Link>
        </div>
    );
};

export default UnauthorizedPage; 