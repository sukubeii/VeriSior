import React, { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";

const PrivateNavBar = ({ role, navItems }) => {
  const [collapsed, setCollapsed] = useState(false);
  const navigate = useNavigate();

  // Update document body class when sidebar state changes
  useEffect(() => {
    document.body.className = collapsed ? 'sidebar-collapsed' : '';
    
    // Notify the layout about sidebar state change
    const contentWrapper = document.getElementById('content-wrapper');
    if (contentWrapper) {
      contentWrapper.style.marginLeft = collapsed ? '80px' : '250px';
      contentWrapper.style.width = `calc(100% - ${collapsed ? '80px' : '250px'})`;
    }
    
    // Clean up on unmount
    return () => {
      document.body.className = '';
    };
  }, [collapsed]);

  // Handle logout function
  const handleLogout = () => {
    // Here you would typically clear authentication tokens/state
    // For this example we're just navigating back to landing page
    navigate('/');
  };

  // Inline styles
  const styles = {
    privateNavbar: {
      position: 'fixed',
      top: 0,
      left: 0,
      height: '100vh',
      width: collapsed ? '80px' : '250px',
      backgroundColor: '#2c3e50',
      borderRight: '1px solid #1a2530',
      boxShadow: '2px 0 5px rgba(0, 0, 0, 0.1)',
      color: 'white',
      transition: 'width 0.3s ease',
      display: 'flex',
      flexDirection: 'column',
      zIndex: 1000
    },
    navbarBrand: {
      display: 'flex',
      alignItems: 'center',
      padding: '20px 15px',
      borderBottom: '1px solid #34495e',
      justifyContent: collapsed ? 'center' : 'flex-start'
    },
    logoContainer: {
      marginRight: collapsed ? '0' : '10px'
    },
    logo: {
      height: '40px',
      width: 'auto'
    },
    appTitle: {
      fontSize: '20px',
      fontWeight: 'bold',
      margin: 0,
      color: 'white',
      display: collapsed ? 'none' : 'block'
    },
    navbarLinks: {
      display: 'flex',
      flexDirection: 'column',
      padding: '15px 0',
      flex: 1
    },
    navItem: {
      textDecoration: 'none',
      color: '#ecf0f1',
      fontWeight: '500',
      padding: '14px 20px',
      display: 'flex',
      alignItems: 'center',
      borderLeft: '4px solid transparent',
      transition: 'all 0.2s ease',
      marginBottom: '5px'
    },
    navItemActive: {
      backgroundColor: '#34495e',
      borderLeft: '4px solid #3498db'
    },
    navItemHover: {
      backgroundColor: '#34495e',
      borderLeft: '4px solid #3498db'
    },
    navItemIcon: {
      marginRight: collapsed ? '0' : '12px',
      width: '24px',
      height: '24px',
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center'
    },
    navItemLabel: {
      display: collapsed ? 'none' : 'block'
    },
    userSection: {
      borderTop: '1px solid #34495e',
      padding: '15px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: collapsed ? 'center' : 'flex-start',
      flexDirection: 'column'
    },
    userInfo: {
      display: 'flex',
      alignItems: 'center',
      width: '100%',
      marginBottom: '15px'
    },
    roleBadge: {
      backgroundColor: '#3498db',
      color: 'white',
      padding: '5px 10px',
      borderRadius: '4px',
      fontSize: '14px',
      display: collapsed ? 'none' : 'block'
    },
    userControls: {
      display: 'flex',
      alignItems: 'center',
      gap: '10px'
    },
    avatar: {
      height: '40px',
      width: '40px',
      borderRadius: '50%',
      backgroundColor: '#3498db',
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      fontWeight: 'bold',
      marginRight: collapsed ? '0' : '10px'
    },
    username: {
      fontWeight: '500',
      display: collapsed ? 'none' : 'block'
    },
    toggleButton: {
      position: 'absolute',
      right: '-12px',
      top: '20px',
      backgroundColor: '#2c3e50',
      color: 'white',
      border: 'none',
      borderRadius: '50%',
      width: '24px',
      height: '24px',
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      cursor: 'pointer',
      boxShadow: '0 0 5px rgba(0, 0, 0, 0.2)',
      zIndex: 1001
    },
    logoutButton: {
      backgroundColor: collapsed ? 'transparent' : '#e74c3c',
      color: 'white',
      border: 'none',
      borderRadius: '4px',
      padding: collapsed ? '10px' : '8px 15px',
      cursor: 'pointer',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      width: collapsed ? '40px' : '100%',
      transition: 'all 0.2s ease'
    },
    logoutIcon: {
      marginRight: collapsed ? '0' : '8px',
    }
  };

  // Icons for navigation items
  const getIcon = (label) => {
    switch(label.toLowerCase()) {
      case 'dashboard':
        return '📊';
      case 'profile':
        return '👤';
      case 'role management':
        return '🔑';
      case 'id management':
        return '🪪';
      case 'settings':
        return '⚙️';
      default:
        return '📄';
    }
  };

  return (
    <>
      <nav style={styles.privateNavbar}>
        <button 
          style={styles.toggleButton}
          onClick={() => setCollapsed(!collapsed)}
          title={collapsed ? "Expand" : "Collapse"}
        >
          {collapsed ? '›' : '‹'}
        </button>
        
        <div style={styles.navbarBrand}>
          <div style={styles.logoContainer}>
            <div style={{...styles.logo, textAlign: 'center'}}>
              🔐
            </div>
          </div>
          <h1 style={styles.appTitle}>VERISIOR</h1>
        </div>
        
        <div style={styles.navbarLinks}>
          {navItems.map((item, index) => (
            <Link 
              key={index} 
              to={item.path} 
              style={styles.navItem}
              onMouseOver={(e) => {
                e.currentTarget.style.backgroundColor = styles.navItemHover.backgroundColor;
                e.currentTarget.style.borderLeft = styles.navItemHover.borderLeft;
              }}
              onMouseOut={(e) => {
                e.currentTarget.style.backgroundColor = '';
                e.currentTarget.style.borderLeft = styles.navItem.borderLeft;
              }}
            >
              <span style={styles.navItemIcon}>{getIcon(item.label)}</span>
              <span style={styles.navItemLabel}>{item.label}</span>
            </Link>
          ))}
        </div>
        
        <div style={styles.userSection}>
          <div style={styles.userInfo}>
            <div style={styles.avatar}>
              {collapsed ? 'U' : ''}
            </div>
            {!collapsed && (
              <div>
                <div style={styles.username}>Username</div>
                <div style={styles.roleBadge}>{role.toUpperCase()}</div>
              </div>
            )}
          </div>
          
          {/* Logout Button */}
          <button 
            style={styles.logoutButton}
            onClick={handleLogout}
            title="Logout"
          >
            <span style={styles.logoutIcon}>🚪</span>
            {!collapsed && <span>Logout</span>}
          </button>
        </div>
      </nav>
    </>
  );
};

export default PrivateNavBar;
