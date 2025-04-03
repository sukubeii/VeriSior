import React, { useState } from "react";
import { useNavigate } from "react-router-dom";

const PublicNavBar = ({ isApplicationForm = false }) => {
  const navigate = useNavigate();
  const [showPrompt, setShowPrompt] = useState(false);
  const [pendingNavigation, setPendingNavigation] = useState("");

  // Define menu items for public pages
  const publicMenuItems = ["Home", "Services", "About", "Contact", "Apply Now"];
  const publicPaths = ["/", "/services", "/about", "/contact", "/apply"];

  const handleNavigation = (path, index) => {
    // If we're on the application form and trying to navigate away
    if (isApplicationForm && path !== "/apply") {
      // Show confirmation prompt
      setShowPrompt(true);
      setPendingNavigation(path);
    } else {
      // Navigate directly if not on application form or navigating within application
      navigate(path);
    }
  };

  const confirmNavigation = () => {
    setShowPrompt(false);
    navigate(pendingNavigation);
  };

  const cancelNavigation = () => {
    setShowPrompt(false);
    setPendingNavigation("");
  };

  return (
    <>
      <nav className="public-navbar">
        <div className="nav-container">
          <h1 className="logo">VeriSior</h1>
          <ul className="nav-links">
            {publicMenuItems.map((item, index) => (
              <li key={index}>
                <a
                  href="#"
                  onClick={(e) => {
                    e.preventDefault();
                    handleNavigation(publicPaths[index], index);
                  }}
                  className={`nav-item ${window.location.pathname === publicPaths[index] ? "active" : ""}`}
                >
                  {item}
                </a>
              </li>
            ))}
          </ul>
        </div>
      </nav>

      {/* Navigation Confirmation Modal */}
      {showPrompt && (
        <div className="navigation-modal">
          <div className="modal-content">
            <h3>Discard Changes?</h3>
            <p>You are currently filling out an application form. If you navigate away, any unsaved changes will be lost.</p>
            <div className="modal-actions">
              <button onClick={cancelNavigation} className="cancel-btn">Stay on Form</button>
              <button onClick={confirmNavigation} className="confirm-btn">Discard Changes</button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default PublicNavBar;
