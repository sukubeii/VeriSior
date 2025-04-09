import React, { useState, useEffect } from "react";
import { BrowserRouter as Router, Routes, Route, useLocation, useNavigate } from "react-router-dom";
import LandingPage from "./pages/LandingPage";
import ApplicationForm from "./pages/ApplicationForm";
import PublicNavBar from "./components/common/PublicNavBar";
import PrivateNavBar from "./components/specific/PrivateNavBar";
import Footer from "./components/common/Footer";
import RoleSwitcher from "./components/specific/RoleSwitcher";
import Dashboard from "./components/specific/Dashboard";
import IDManagement from "./components/specific/IDManagement";
import Profile from "./components/specific/Profile";
import RoleManagement from "./components/specific/RoleManagement";
import Settings from "./components/specific/Settings";

// Create a wrapper component to use React Router hooks
function AppContent() {
  const [userRole, setUserRole] = useState("admin");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();
  
  // Function to determine if page is public
  const isPublicPage = (pathname) => {
    return pathname === "/" || pathname === "/apply" || 
           pathname === "/services" || pathname === "/about" || 
           pathname === "/contact" || pathname === "/support";
  };

  // Function to determine if page is role-specific
  const isRoleSpecificPage = (pathname) => {
    return pathname === "/super-admin" || pathname === "/admin" || pathname === "/employee" ||
           pathname.startsWith("/dashboard") || pathname.startsWith("/profile") ||
           pathname.startsWith("/role-management") || pathname.startsWith("/id-management") ||
           pathname.startsWith("/admin-management") || pathname.startsWith("/employee-management") ||
           pathname.startsWith("/settings");
  };

  // Function to determine available navigation items based on role
  const getNavItems = (role) => {
    const commonItems = [
      { path: "/dashboard", label: "Dashboard" },
      { path: "/profile", label: "Profile" },
      { path: "/id-management", label: "ID Management" },
      { path: "/settings", label: "Settings" }
    ];
    
    // Add Role Management for admin and superAdmin
    if (role === "admin" || role === "superAdmin") {
      return [
        ...commonItems.slice(0, 2), // Dashboard and Profile
        { path: "/role-management", label: "Role Management" },
        ...commonItems.slice(2) // ID Management and Settings
      ];
    }
    
    return commonItems; // For employee role
  };

  // Handle role change from the role switcher
  const handleRoleChange = (newRole) => {
    setUserRole(newRole);
    
    // Redirect to the appropriate role page
    navigate(`/${newRole === "superAdmin" ? "super-admin" : newRole.toLowerCase()}`);
  };

  // Listen for sidebar state change
  useEffect(() => {
    const handleSidebarChange = () => {
      setSidebarCollapsed(document.body.classList.contains('sidebar-collapsed'));
    };

    // Create a MutationObserver to watch for class changes on the body element
    const observer = new MutationObserver(handleSidebarChange);
    observer.observe(document.body, { attributes: true, attributeFilter: ['class'] });

    return () => observer.disconnect();
  }, []);

  // Apply different wrapper class based on whether the page is public or private
  const layoutClass = isRoleSpecificPage(location.pathname) 
    ? `private-layout ${sidebarCollapsed ? 'sidebar-collapsed' : ''}` 
    : "public-layout";

  return (
    <div className={`app-container ${layoutClass}`}>
      {/* Show PublicNavBar on public pages */}
      {isPublicPage(location.pathname) && (
        <PublicNavBar isApplicationForm={location.pathname === "/apply"} />
      )}
      
      {/* Show PrivateNavBar on private/authenticated pages */}
      {isRoleSpecificPage(location.pathname) && (
        <PrivateNavBar 
          role={userRole} 
          navItems={getNavItems(userRole)}
        />
      )}

      {/* Main Content */}
      <div className={`main-content ${isRoleSpecificPage(location.pathname) ? "with-sidebar" : ""}`}>
        <Routes>
          {/* Public Routes */}
          <Route path="/" element={<LandingPage />} />
          <Route path="/services" element={<h2>Our Services</h2>} />
          <Route path="/about" element={<h2>About Us</h2>} />
          <Route path="/contact" element={<h2>Contact Us</h2>} />
          <Route path="/support" element={<h2>Support</h2>} />
          <Route path="/apply" element={<ApplicationForm />} />
          
          {/* Private Routes (should be protected with authentication) */}
          <Route path="/dashboard" element={<Dashboard role={userRole} />} />
          <Route path="/profile" element={<Profile role={userRole} />} />
          <Route path="/role-management" element={<RoleManagement role={userRole} />} />
          <Route path="/id-management" element={<IDManagement role={userRole} />} />
          <Route path="/settings" element={<Settings role={userRole} />} />
          <Route path="/admin-management" element={<h2>Admin Management</h2>} />
          <Route path="/employee-management" element={<h2>Employee Management</h2>} />
          
          {/* Role-specific pages */}
          <Route path="/admin" element={
            <div>
              <h2>Admin Dashboard</h2>
              <p>Welcome to the admin dashboard. You have access to role management features.</p>
              <div className="row mt-4">
                <div className="col-md-4 mb-3">
                  <div className="card">
                    <div className="card-body">
                      <h5 className="card-title">User Management</h5>
                      <p className="card-text">Manage system users and permissions</p>
                      <button className="btn btn-primary">View Users</button>
                    </div>
                  </div>
                </div>
                <div className="col-md-4 mb-3">
                  <div className="card">
                    <div className="card-body">
                      <h5 className="card-title">Applications</h5>
                      <p className="card-text">Review and process pending applications</p>
                      <button className="btn btn-primary">View Applications</button>
                    </div>
                  </div>
                </div>
                <div className="col-md-4 mb-3">
                  <div className="card">
                    <div className="card-body">
                      <h5 className="card-title">System Logs</h5>
                      <p className="card-text">View system activity and audit logs</p>
                      <button className="btn btn-primary">View Logs</button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          } />
          <Route path="/employee" element={
            <div>
              <h2>Employee Dashboard</h2>
              <p>Welcome to the employee dashboard. You can manage your daily tasks here.</p>
              <div className="row mt-4">
                <div className="col-md-4 mb-3">
                  <div className="card">
                    <div className="card-body">
                      <h5 className="card-title">My Tasks</h5>
                      <p className="card-text">View and manage your assigned tasks</p>
                      <button className="btn btn-primary">View Tasks</button>
                    </div>
                  </div>
                </div>
                <div className="col-md-4 mb-3">
                  <div className="card">
                    <div className="card-body">
                      <h5 className="card-title">My Calendar</h5>
                      <p className="card-text">Schedule and view appointments</p>
                      <button className="btn btn-primary">Open Calendar</button>
                    </div>
                  </div>
                </div>
                <div className="col-md-4 mb-3">
                  <div className="card">
                    <div className="card-body">
                      <h5 className="card-title">Documents</h5>
                      <p className="card-text">Access and manage your documents</p>
                      <button className="btn btn-primary">View Documents</button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          } />
          <Route path="/super-admin" element={
            <div>
              <h2>Super Admin Dashboard</h2>
              <p>Welcome to the super admin dashboard. You have full system access and configuration capabilities.</p>
              <div className="row mt-4">
                <div className="col-md-4 mb-3">
                  <div className="card">
                    <div className="card-body">
                      <h5 className="card-title">System Configuration</h5>
                      <p className="card-text">Configure global system settings</p>
                      <button className="btn btn-primary">Configure</button>
                    </div>
                  </div>
                </div>
                <div className="col-md-4 mb-3">
                  <div className="card">
                    <div className="card-body">
                      <h5 className="card-title">Admin Management</h5>
                      <p className="card-text">Manage admin accounts and permissions</p>
                      <button className="btn btn-primary">Manage Admins</button>
                    </div>
                  </div>
                </div>
                <div className="col-md-4 mb-3">
                  <div className="card">
                    <div className="card-body">
                      <h5 className="card-title">Analytics</h5>
                      <p className="card-text">View comprehensive system analytics</p>
                      <button className="btn btn-primary">View Analytics</button>
                    </div>
                  </div>
                </div>
                <div className="col-md-4 mb-3">
                  <div className="card">
                    <div className="card-body">
                      <h5 className="card-title">Security Settings</h5>
                      <p className="card-text">Manage system security and access controls</p>
                      <button className="btn btn-primary">Security Panel</button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          } />
        </Routes>
      </div>

      {/* Role Switcher (temporary for testing) */}
      <RoleSwitcher currentRole={userRole} onRoleChange={handleRoleChange} />

      {/* Footer - only show on public pages */}
      {isPublicPage(location.pathname) && <Footer />}
    </div>
  );
}

// Main App component
function App() {
  return (
    <Router>
      <AppContent />
    </Router>
  );
}

export default App;
