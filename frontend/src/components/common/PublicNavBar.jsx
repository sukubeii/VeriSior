import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import logo from "../../images/logo1.png";

const PublicNavBar = ({ isApplicationForm = false }) => {
  const navigate = useNavigate();
  const [showPrompt, setShowPrompt] = useState(false);
  const [pendingNavigation, setPendingNavigation] = useState("");
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [showLoginModal, setShowLoginModal] = useState(false);
  
  // Login form state
  const [loginForm, setLoginForm] = useState({
    email: "",
    password: "",
    role: "admin" // Default role selection
  });
  const [formErrors, setFormErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Define menu items for public pages
  const publicMenuItems = ["Home", "About", "Services", "Contact", "Support", "Login"];
  const publicPaths = ["/", "/about", "/services", "/contact", "/support", "#"];

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
    // Handle login click
    if (path === "#" && index === publicMenuItems.length - 1) {
      setShowLoginModal(true);
      setIsMobileMenuOpen(false);
      return;
    }
    
    // If we're on the landing page and not navigating to another page
    if (window.location.pathname === "/" && index < publicPaths.length - 1 && publicPaths[index] !== "#") {
      // Scroll to the section instead of navigating
      scrollToSection(publicMenuItems[index].toLowerCase().replace(" ", "-"));
    }
    // If we're on the application form and trying to navigate away
    else if (isApplicationForm && path !== "/apply") {
      // Show confirmation prompt
      setShowPrompt(true);
      setPendingNavigation(path);
    } else if (path !== "#") {
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

  // Handle form input changes
  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setLoginForm({
      ...loginForm,
      [name]: value,
    });
    
    // Clear error when user starts typing
    if (formErrors[name]) {
      setFormErrors({
        ...formErrors,
        [name]: "",
      });
    }
  };

  // Validate email format
  const validateEmail = (email) => {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(email);
  };

  // Validate password strength (simplified for testing)
  const validatePassword = (password) => {
    // For testing purposes, accept any password with at least 4 characters
    return password.length >= 4;
  };

  // Handle login form submission
  const handleLogin = (e) => {
    e.preventDefault();
    
    // Validate form inputs
    const errors = {};
    
    if (!loginForm.email.trim()) {
      errors.email = "Email is required";
    } else if (!validateEmail(loginForm.email)) {
      errors.email = "Please enter a valid email address";
    }
    
    if (!loginForm.password) {
      errors.password = "Password is required";
    } else if (!validatePassword(loginForm.password)) {
      errors.password = "Password must be at least 4 characters";
    }
    
    // If there are errors, update state and prevent submission
    if (Object.keys(errors).length > 0) {
      setFormErrors(errors);
      return;
    }
    
    // If validation passes, proceed with login
    setIsSubmitting(true);
    
    // Simulate API call for login (replace with your actual authentication logic)
    setTimeout(() => {
      console.log("Login form submitted:", loginForm);
      
      // On successful login, close modal and navigate to role-specific page
      setShowLoginModal(false);
      setIsSubmitting(false);
      
      // Navigate based on selected role
      const rolePath = loginForm.role === "superAdmin" ? "/super-admin" : 
                      loginForm.role === "admin" ? "/admin" : "/employee";
      navigate(rolePath);
      
      // Reset form
      setLoginForm({
        email: "",
        password: "",
        role: "admin"
      });
    }, 1000);
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

      {/* Login Modal with Role Selection */}
      {showLoginModal && (
        <div className="login-modal" style={{
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
            padding: "25px",
            borderRadius: "8px",
            maxWidth: "400px",
            width: "90%"
          }}>
            <div className="d-flex justify-content-between align-items-center mb-4">
              <h3 className="m-0">Login</h3>
              <button 
                onClick={() => setShowLoginModal(false)} 
                className="btn-close"
                aria-label="Close"
              ></button>
            </div>
            
            <form onSubmit={handleLogin}>
              <div className="mb-3">
                <label htmlFor="email" className="form-label">Email</label>
                <input
                  type="email"
                  className={`form-control ${formErrors.email ? 'is-invalid' : ''}`}
                  id="email"
                  name="email"
                  value={loginForm.email}
                  onChange={handleInputChange}
                  placeholder="Enter your email"
                  autoComplete="username"
                />
                {formErrors.email && (
                  <div className="invalid-feedback">{formErrors.email}</div>
                )}
              </div>
              
              <div className="mb-3">
                <label htmlFor="password" className="form-label">Password</label>
                <input
                  type="password"
                  className={`form-control ${formErrors.password ? 'is-invalid' : ''}`}
                  id="password"
                  name="password"
                  value={loginForm.password}
                  onChange={handleInputChange}
                  placeholder="Enter your password"
                  autoComplete="current-password"
                />
                {formErrors.password && (
                  <div className="invalid-feedback">{formErrors.password}</div>
                )}
              </div>
              
              {/* Role selection for testing */}
              <div className="mb-4">
                <label htmlFor="role" className="form-label">Role (For Testing)</label>
                <select
                  className="form-select"
                  id="role"
                  name="role"
                  value={loginForm.role}
                  onChange={handleInputChange}
                >
                  <option value="admin">Admin</option>
                  <option value="superAdmin">Super Admin</option>
                  <option value="employee">Employee</option>
                </select>
                <div className="form-text text-muted">
                  This selection will be removed when backend is implemented.
                </div>
              </div>
              
              <div className="d-flex justify-content-between align-items-center mb-3">
                <div className="form-check">
                  <input
                    type="checkbox"
                    className="form-check-input"
                    id="rememberMe"
                  />
                  <label className="form-check-label" htmlFor="rememberMe">
                    Remember me
                  </label>
                </div>
                <a href="#" className="text-decoration-none">Forgot password?</a>
              </div>
              
              <button 
                type="submit" 
                className="btn btn-primary w-100 py-2"
                disabled={isSubmitting}
              >
                {isSubmitting ? (
                  <span className="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                ) : null}
                {isSubmitting ? 'Logging in...' : 'Login'}
              </button>
              
              <div className="text-center mt-3">
                <p className="mb-0">
                  Don't have an account? <a href="#" className="text-decoration-none">Sign up</a>
                </p>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
};

export default PublicNavBar;
