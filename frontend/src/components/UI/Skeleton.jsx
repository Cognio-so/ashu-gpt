import React from 'react';

export const Skeleton = ({ className, ...props }) => {
  return (
    <div 
      className={`animate-pulse bg-gray-300 dark:bg-gray-700 rounded ${className}`}
      {...props}
    />
  );
}; 