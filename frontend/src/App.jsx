import React, { useState } from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import LandingPage from "./pages/LandingPage";
import ApplicationForm from "./pages/ApplicationForm";
import PublicNavBar from "./components/common/PublicNavBar";
import PrivateNavBar from "./components/specific/PrivateNavBar";
import Footer from "./components/common/Footer";

function App() {
  // Temporary role state (this should be retrieved from authentication)
  const [userRole, setUserRole] = useState("admin"); // Example: "superAdmin", "admin", "employee"
  
  // Function to determine if page is public
  const isPublicPage = (pathname) => {
    return pathname === "/" || pathname === "/apply" || 
           pathname === "/services" || pathname === "/about" || 
           pathname === "/contact";
  };

  const pathname = window.location.pathname;

  return (
    <Router>
      <div className="app-container">
        {/* Show PublicNavBar on public pages */}
        {isPublicPage(pathname) && (
          <PublicNavBar isApplicationForm={pathname === "/apply"} />
        )}
        
        {/* Show PrivateNavBar on private/authenticated pages */}
        {!isPublicPage(pathname) && (
          <PrivateNavBar role={userRole} />
        )}

        {/* Main Content */}
        <div className="main-content">
          <Routes>
            {/* Public Routes */}
            <Route path="/" element={<LandingPage />} />
            <Route path="/services" element={<h2>Our Services</h2>} />
            <Route path="/about" element={<h2>About Us</h2>} />
            <Route path="/contact" element={<h2>Contact Us</h2>} />
            <Route path="/apply" element={<ApplicationForm />} />
            
            {/* Private Routes (should be protected with authentication) */}
            <Route path="/dashboard" element={<h2>Dashboard</h2>} />
            <Route path="/profile" element={<h2>Profile</h2>} />
            <Route path="/role-management" element={<h2>Role Management</h2>} />
            <Route path="/id-management" element={<h2>ID Management</h2>} />
            <Route path="/settings" element={<h2>Settings</h2>} />
          </Routes>
        </div>

        {/* Footer */}
        <Footer />
      </div>
    </Router>
  );
}

export default App;
