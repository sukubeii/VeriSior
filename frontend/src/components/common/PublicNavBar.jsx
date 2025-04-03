import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import logo from "../../images/logo1.png";

const PublicNavBar = ({ isApplicationForm = false }) => {
  const navigate = useNavigate();
  const [showPrompt, setShowPrompt] = useState(false);
  const [pendingNavigation, setPendingNavigation] = useState("");
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  // Define menu items for public pages
  const publicMenuItems = ["Home", "About", "Services", "Contact", "Support", "Apply Now"];
  const publicPaths = ["/", "/about", "/services", "/contact", "/support", "/apply"];

  // Scroll to section function
  const scrollToSection = (sectionId) => {
    const section = document.getElementById(sectionId);
    if (section) {
      // Calculate position accounting for the fixed navbar height
      const navbarHeight = 60; // This should match your navbar height
      const sectionPosition = section.getBoundingClientRect().top + window.pageYOffset;
      const offsetPosition = sectionPosition - navbarHeight;

      window.scrollTo({
        top: offsetPosition,
        behavior: "smooth"
      });
    }
    // Close mobile menu if open
    setIsMobileMenuOpen(false);
  };

  const handleNavigation = (path, index) => {
    // If we're on the landing page and not navigating to another page
    if (window.location.pathname === "/" && index < publicPaths.length - 1) {
      // Scroll to the section instead of navigating
      scrollToSection(publicMenuItems[index].toLowerCase().replace(" ", "-"));
    }
    // If we're on the application form and trying to navigate away
    else if (isApplicationForm && path !== "/apply") {
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

  // Handle window resize for responsive navigation
  useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth > 768) {
        setIsMobileMenuOpen(false);
      }
    };

    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  return (
    <>
      {/* Public Navigation Bar */}
      <nav
        className="navbar navbar-expand-lg fixed-top"
        style={{
          background: "linear-gradient(90deg,rgb(0, 183, 255),rgb(0, 204, 255))",
          padding: "5px 0",
          boxShadow: "0px 4px 6px rgba(0, 0, 0, 0.1)",
          color: "white",
          height: "60px"
        }}
      >
        <div className="container">
          <div className="d-flex align-items-center">
            <img src={logo} alt="VeriSior Logo" style={{ height: "40px" }} />
            <h2 className="ms-2 my-0 d-flex align-items-center" style={{ fontSize: "1.5rem" }}>VeriSior</h2>
          </div>

          {/* Mobile menu toggle button */}
          <button
            className="navbar-toggler"
            type="button"
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
            style={{ border: "none", color: "white" }}
          >
            <span className="navbar-toggler-icon">
              ☰
            </span>
          </button>

          {/* Desktop Navigation */}
          <div className={`collapse navbar-collapse ${isMobileMenuOpen ? 'show' : ''}`} id="navbarNav">
            <ul className="navbar-nav ms-auto text-center">
              {publicMenuItems.map((item, index) => (
                <li className="nav-item" key={index}>
                  <a
                    href="#"
                    onClick={(e) => {
                      e.preventDefault();
                      handleNavigation(publicPaths[index], index);
                    }}
                    className="nav-link text-white fw-bold text-uppercase px-3"
                  >
                    {item}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Mobile Navigation Overlay */}
          {isMobileMenuOpen && (
            <div
              className="position-fixed bg-white w-100 shadow-lg"
              style={{
                top: "60px",
                left: 0,
                zIndex: 1000,
                padding: "15px 0",
                display: "block"
              }}
            >
              <ul className="navbar-nav text-center">
                {publicMenuItems.map((item, index) => (
                  <li className="nav-item py-2" key={index}>
                    <a
                      href="#"
                      onClick={(e) => {
                        e.preventDefault();
                        handleNavigation(publicPaths[index], index);
                      }}
                      className="nav-link text-dark fw-bold text-uppercase"
                    >
                      {item}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </nav>

      {/* Navigation Confirmation Modal */}
      {showPrompt && (
        <div className="navigation-modal" style={{
          position: "fixed",
          top: 0,
          left: 0,
          width: "100%",
          height: "100%",
          backgroundColor: "rgba(0, 0, 0, 0.5)",
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          zIndex: 2000
        }}>
          <div className="modal-content" style={{
            backgroundColor: "white",
            padding: "20px",
            borderRadius: "5px",
            maxWidth: "400px",
            width: "90%"
          }}>
            <h3>Discard Changes?</h3>
            <p>You are currently filling out an application form. If you navigate away, any unsaved changes will be lost.</p>
            <div className="modal-actions d-flex justify-content-end mt-4">
              <button 
                onClick={cancelNavigation} 
                className="btn btn-secondary me-2"
              >
                Stay on Form
              </button>
              <button 
                onClick={confirmNavigation} 
                className="btn btn-danger"
              >
                Discard Changes
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default PublicNavBar;
