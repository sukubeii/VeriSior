import React from 'react';
import PrivateNavBar from '../specific/PrivateNavBar';

const RoleLayout = ({ children, role }) => {
  return (
    <div style={{ 
      display: 'flex', 
      minHeight: '100vh',
      backgroundColor: '#f8f9fa'
    }}>
      <PrivateNavBar role={role} />
      <main style={{ 
        marginLeft: '250px', // Same as navbar width
        padding: '20px',
        width: 'calc(100% - 250px)',
        minHeight: '100vh',
        overflow: 'auto'
      }}>
        <div className="container-fluid">
          {children}
        </div>
      </main>
    </div>
  );
};

export default RoleLayout;
