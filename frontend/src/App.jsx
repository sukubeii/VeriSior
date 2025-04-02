import React, { useState } from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import LandingPage from "./pages/LandingPage";
import ApplicationForm from "./pages/ApplicationForm"; // Import ApplicationForm component
import NavBar from "./components/common/NavBar";
import Footer from "./components/common/Footer";

function App() {
  // Temporary role state (this should be retrieved from authentication)
  const [userRole, setUserRole] = useState("admin"); // Example: "superAdmin", "admin", "employee"

  return (
    <Router>
      <div className="app-container">
        {/* Show global NavBar only if NOT on the landing page */}
        {window.location.pathname !== "/" && <NavBar role={userRole} />}

        {/* Main Content */}
        <div className="main-content">
          <Routes>
            <Route path="/" element={<LandingPage />} />
            <Route path="/dashboard" element={<h2>Dashboard</h2>} />
            <Route path="/profile" element={<h2>Profile</h2>} />
            <Route path="/role-management" element={<h2>Role Management</h2>} />
            <Route path="/id-management" element={<h2>ID Management</h2>} />
            <Route path="/settings" element={<h2>Settings</h2>} />
            <Route path="/apply" element={<ApplicationForm />} /> {/* Add the new route */}
          </Routes>
        </div>

        {/* Footer */}
        <Footer />
      </div>
    </Router>
  );
}

export default App;
