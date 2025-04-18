import React, { useState, useEffect } from "react";
import { BrowserRouter as Router, Routes, Route, useLocation, useNavigate } from "react-router-dom";
import { UpdatesProvider } from "./contexts/UpdatesContext";
import LandingPage from "./pages/LandingPage";
import ApplicationForm from "./pages/ApplicationForm";
import PublicNavBar from "./components/common/PublicNavBar";
import PrivateNavBar from "./components/specific/PrivateNavBar";
import Footer from "./components/common/Footer";
import RoleSwitcher from "./components/specific/RoleSwitcher";
import Dashboard from "./components/specific/Dashboard";
import IDManagement from "./components/specific/IDManagement";
import Profile from "./components/specific/Profile";
import Settings from "./components/specific/Settings";
import PageManagement from "./components/specific/PageManagement";
import SystemManagement from "./components/specific/SystemManagement";
import UserManagement from "./components/specific/UserManagement";
import Services from "./components/specific/Services";

// Create a wrapper component to use React Router hooks
function AppContent() {
  const [userRole, setUserRole] = useState("admin");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();
  
  // Function to determine if page is public
  const isPublicPage = (pathname) => {
    return pathname === "/" || pathname === "/apply" || pathname === "/about" || 
           pathname === "/contact" || pathname === "/support";
  };

  // Function to determine if page is role-specific
  const isRoleSpecificPage = (pathname) => {
    return pathname === "/super-admin" || pathname === "/admin" || pathname === "/employee" ||
           pathname.startsWith("/dashboard") || pathname.startsWith("/profile") ||
           pathname.startsWith("/id-management") || pathname.startsWith("/services") ||
           pathname.startsWith("/settings") || pathname.startsWith("/system-management") ||
           pathname.startsWith("/user-management") || pathname.startsWith("/page-management");
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
        <PrivateNavBar role={userRole} />
      )}

      {/* Main Content */}
      <div className={`main-content ${isRoleSpecificPage(location.pathname) ? "with-sidebar" : ""}`}>
        <Routes>
          {/* Public Routes */}
          <Route path="/" element={<LandingPage />} />
          <Route path="/about" element={<h2>About Us</h2>} />
          <Route path="/contact" element={<h2>Contact Us</h2>} />
          <Route path="/support" element={<h2>Support</h2>} />
          <Route path="/apply" element={<ApplicationForm />} />
          
          {/* Private Routes (should be protected with authentication) */}
          <Route path="/dashboard" element={<Dashboard role={userRole} />} />
          <Route path="/profile" element={<Profile role={userRole} />} />
          <Route path="/id-management" element={<IDManagement role={userRole} />} />
          <Route path="/settings" element={<Settings role={userRole} />} />
          <Route path="/page-management" element={<PageManagement role={userRole} />} />
          <Route path="/system-management" element={<SystemManagement role={userRole} />} />
          <Route path="/user-management" element={<UserManagement role={userRole} />} />
          <Route path="/services" element={<Services role={userRole} />} />
          
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
                      <button className="btn btn-primary" onClick={() => navigate('/user-management')}>View Users</button>
                    </div>
                  </div>
                </div>
                <div className="col-md-4 mb-3">
                  <div className="card">
                    <div className="card-body">
                      <h5 className="card-title">Applications</h5>
                      <p className="card-text">Review and process pending applications</p>
                      <button className="btn btn-primary" onClick={() => navigate('/id-management')}>View Applications</button>
                    </div>
                  </div>
                </div>
                <div className="col-md-4 mb-3">
                  <div className="card">
                    <div className="card-body">
                      <h5 className="card-title">System Logs</h5>
                      <p className="card-text">View system activity and audit logs</p>
                      <button className="btn btn-primary" onClick={() => navigate('/settings')}>View Logs</button>
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
                      <button className="btn btn-primary" onClick={() => navigate('/id-management')}>View Tasks</button>
                    </div>
                  </div>
                </div>
                <div className="col-md-4 mb-3">
                  <div className="card">
                    <div className="card-body">
                      <h5 className="card-title">Messages</h5>
                      <p className="card-text">Manage communications with applicants</p>
                      <button className="btn btn-primary" onClick={() => navigate('/services')}>View Messages</button>
                    </div>
                  </div>
                </div>
                <div className="col-md-4 mb-3">
                  <div className="card">
                    <div className="card-body">
                      <h5 className="card-title">ID Management</h5>
                      <p className="card-text">Process ID applications and print IDs</p>
                      <button className="btn btn-primary" onClick={() => navigate('/id-management')}>Open ID Management</button>
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
                      <button className="btn btn-primary" onClick={() => navigate('/system-management')}>Configure</button>
                    </div>
                  </div>
                </div>
                <div className="col-md-4 mb-3">
                  <div className="card">
                    <div className="card-body">
                      <h5 className="card-title">User Management</h5>
                      <p className="card-text">Manage accounts and permissions</p>
                      <button className="btn btn-primary" onClick={() => navigate('/user-management')}>Manage Users</button>
                    </div>
                  </div>
                </div>
                <div className="col-md-4 mb-3">
                  <div className="card">
                    <div className="card-body">
                      <h5 className="card-title">Analytics</h5>
                      <p className="card-text">View comprehensive system analytics</p>
                      <button className="btn btn-primary" onClick={() => navigate('/dashboard')}>View Analytics</button>
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
      <UpdatesProvider>
        <AppContent />
      </UpdatesProvider>
    </Router>
  );
}

export default App;
