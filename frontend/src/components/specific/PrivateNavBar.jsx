import React, { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";

const PrivateNavBar = ({ role }) => {
  const navigate = useNavigate();
  const [rolePermissions, setRolePermissions] = useState(null);

  // Load role permissions when component mounts or role changes
  useEffect(() => {
    // In a real app, this would be an API call to fetch permissions
    // For now, we'll use localStorage to simulate this
    const loadRolePermissions = () => {
      try {
        const customPermissions = localStorage.getItem('customRolePermissions');
        if (customPermissions) {
          const parsedPermissions = JSON.parse(customPermissions);
          // Convert role name to match storage format (lowercase, no spaces)
          const roleKey = role.toLowerCase().replace(' ', '');
          
          if (parsedPermissions[roleKey]) {
            setRolePermissions(parsedPermissions[roleKey]);
            return;
          }
        }
        
        // If no custom permissions found, use default
        setRolePermissions(null);
      } catch (error) {
        console.error("Error loading role permissions:", error);
        setRolePermissions(null);
      }
    };

    loadRolePermissions();
  }, [role]);

  // Define navigation items based on role and permissions
  const getNavItems = () => {
    const defaultNavItems = {
      superAdmin: [
        { label: "Dashboard", path: "/dashboard", icon: "📊", permission: "dashboard" },
        { label: "Profile", path: "/profile", icon: "👤", permission: "profile" },
        { label: "User Management", path: "/user-management", icon: "👥", permission: "userManagement" },
        { label: "ID Template", path: "/id-template", icon: "🪪", permission: "idTemplate" },
        { label: "System Management", path: "/system-management", icon: "⚙️", permission: "systemManagement" },
        { label: "Settings", path: "/settings", icon: "⚙️", permission: "settings" }
      ],
      admin: [
        { label: "Dashboard", path: "/dashboard", icon: "📊", permission: "dashboard" },
        { label: "Profile", path: "/profile", icon: "👤", permission: "profile" },
        { label: "User Management", path: "/user-management", icon: "👥", permission: "userManagement" },
        { label: "ID Template", path: "/id-template", icon: "🪪", permission: "idTemplate" },
        { label: "ID Management", path: "/id-management", icon: "🪪", permission: "idManagement" },
        { label: "Page Management", path: "/page-management", icon: "📄", permission: "pageManagement" },
        { label: "Settings", path: "/settings", icon: "⚙️", permission: "settings" }
      ],
      employee: [
        { label: "Dashboard", path: "/dashboard", icon: "📊", permission: "dashboard" },
        { label: "Profile", path: "/profile", icon: "👤", permission: "profile" },
        { label: "ID Processing", path: "/id-processing", icon: "🔄", permission: "idProcessing" },
        { label: "Customer Service", path: "/customer-service", icon: "💬", permission: "customerService" },
        { label: "Settings", path: "/settings", icon: "⚙️", permission: "settings" }
      ]
    };

    // Define all possible navigation items
    const allNavItems = [
      { label: "Dashboard", path: "/dashboard", icon: "📊", permission: "dashboard" },
      { label: "Profile", path: "/profile", icon: "👤", permission: "profile" },
      { label: "User Management", path: "/user-management", icon: "👥", permission: "userManagement" },
      { label: "ID Template", path: "/id-template", icon: "🪪", permission: "idTemplate" },
      { label: "System Management", path: "/system-management", icon: "⚙️", permission: "systemManagement" },
      { label: "ID Management", path: "/id-management", icon: "🪪", permission: "idManagement" },
      { label: "Page Management", path: "/page-management", icon: "📄", permission: "pageManagement" },
      { label: "ID Processing", path: "/id-processing", icon: "🔄", permission: "idProcessing" },
      { label: "Customer Service", path: "/customer-service", icon: "💬", permission: "customerService" },
      { label: "Settings", path: "/settings", icon: "⚙️", permission: "settings" }
    ];

    // If we have custom permissions, filter the navigation items based on permissions
    if (rolePermissions) {
      return allNavItems.filter(item => rolePermissions[item.permission]);
    }

    // Otherwise, use the default navigation items for the role
    return defaultNavItems[role] || [];
  };

  const handleLogout = () => {
    // Here you would typically clear authentication tokens/state
    navigate('/');
  };

  return (
    <div style={{
      height: '100vh',
      width: '250px',
      backgroundColor: '#2c3e50',
      color: 'white',
      display: 'flex',
      flexDirection: 'column',
      borderRight: '1px solid #1a2530',
      boxShadow: '2px 0 5px rgba(0, 0, 0, 0.1)',
      position: 'fixed',
      top: 0,
      left: 0,
      zIndex: 1000,
      overflowY: 'auto'
    }}>
      {/* Brand Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        padding: '20px 15px',
        borderBottom: '1px solid #34495e',
      }}>
        <div style={{ marginRight: '10px' }}>
          <div style={{ 
            height: '40px', 
            width: '40px', 
            textAlign: 'center', 
            display: 'flex', 
            alignItems: 'center', 
            justifyContent: 'center' 
          }}>
            🔐
          </div>
        </div>
        <h1 style={{ 
          fontSize: '20px', 
          fontWeight: 'bold', 
          margin: 0, 
          color: 'white' 
        }}>VERISIOR</h1>
      </div>

      {/* Navigation Links */}
      <div style={{
        display: 'flex',
        flexDirection: 'column',
        padding: '15px 0',
        flex: 1,
        overflowY: 'auto'
      }}>
        {getNavItems().map((item, index) => (
          <Link 
            key={index}
            to={item.path} 
            style={{
              textDecoration: 'none',
              color: '#ecf0f1',
              fontWeight: '500',
              padding: '14px 20px',
              display: 'flex',
              alignItems: 'center',
              borderLeft: '4px solid transparent',
              transition: 'all 0.2s ease',
              marginBottom: '5px'
            }}
            onMouseOver={(e) => {
              e.currentTarget.style.backgroundColor = '#34495e';
              e.currentTarget.style.borderLeft = '4px solid #3498db';
            }}
            onMouseOut={(e) => {
              e.currentTarget.style.backgroundColor = '';
              e.currentTarget.style.borderLeft = '4px solid transparent';
            }}
          >
            <span style={{
              marginRight: '12px',
              width: '24px',
              height: '24px',
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center'
            }}>{item.icon}</span>
            <span>{item.label}</span>
          </Link>
        ))}
      </div>

      {/* User Section */}
      <div style={{
        borderTop: '1px solid #34495e',
        padding: '15px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'flex-start',
        flexDirection: 'column'
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          width: '100%',
          marginBottom: '15px'
        }}>
          <div style={{
            height: '40px',
            width: '40px',
            borderRadius: '50%',
            backgroundColor: '#3498db',
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            fontWeight: 'bold',
            marginRight: '10px'
          }}>
            {role.charAt(0).toUpperCase()}
          </div>
          <div>
            <div style={{ fontWeight: '500' }}>User</div>
            <div style={{
              backgroundColor: '#3498db',
              color: 'white',
              padding: '5px 10px',
              borderRadius: '4px',
              fontSize: '14px'
            }}>{role.toUpperCase()}</div>
          </div>
        </div>

        <button 
          style={{
            backgroundColor: '#e74c3c',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            padding: '8px 15px',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '100%',
            transition: 'all 0.2s ease'
          }}
          onClick={handleLogout}
        >
          <span style={{ marginRight: '8px' }}>🚪</span>
          <span>Logout</span>
        </button>
      </div>
    </div>
  );
};

export default PrivateNavBar;
