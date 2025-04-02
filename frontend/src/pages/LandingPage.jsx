import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import "bootstrap/dist/css/bootstrap.min.css";
import image1 from "../images/tempo1.jpeg";
import image2 from "../images/tempo2.jpeg";
import image3 from "../images/tempo3.jpeg";
import image4 from "../images/tempo4.jpeg";
import image5 from "../images/tempo5.jpeg";
import logo from "../images/logo1.png";
// Import profile images
import beaProfile from "../images/bea-profile.jpeg";
import reeceProfile from "../images/reece-profile.jpg";
import garmaProfile from "../images/garma-profile.jpg";
import mrXProfile from "../images/mr_x.jpg";

const LandingPage = () => {
  const images = [
    { src: image1 },
    { src: image2 },
    { src: image3 },
    { src: image4 },
    { src: image5 }
  ];
  const [currentImageIndex, setCurrentImageIndex] = useState(0);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  // State for contact form
  const [contactForm, setContactForm] = useState({
    fullName: "",
    email: "",
    contactNumber: "",
    message: ""
  });

  // Handle form input changes
  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setContactForm({
      ...contactForm,
      [name]: value
    });
  };

  // Handle form submission
  const handleSubmit = (e) => {
    e.preventDefault();
    // Here you would typically send the form data to your backend
    console.log("Form submitted:", contactForm);
    // Reset form after submission
    setContactForm({
      fullName: "",
      email: "",
      contactNumber: "",
      message: ""
    });
    // Show success message (you can implement this however you want)
    alert("Thank you for your message! We'll get back to you soon.");
  };

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

  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentImageIndex((prevIndex) => (prevIndex + 1) % images.length);
    }, 3000);
    return () => clearInterval(interval);
  }, [images.length]);

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
    <div style={{ backgroundColor: "#f0faff", minHeight: "100vh" }}>
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

          {/* Desktop & Mobile Navigation */}
          <div className={`collapse navbar-collapse ${isMobileMenuOpen ? 'show' : ''}`} id="navbarNav">
            <ul className="navbar-nav ms-auto text-center">
              <li className="nav-item">
                <a href="#home"
                  onClick={(e) => { e.preventDefault(); scrollToSection("home"); }}
                  className="nav-link text-white fw-bold text-uppercase px-3">
                  Home
                </a>
              </li>
              <li className="nav-item">
                <a href="#about"
                  onClick={(e) => { e.preventDefault(); scrollToSection("about"); }}
                  className="nav-link text-white fw-bold text-uppercase px-3">
                  About
                </a>
              </li>
              <li className="nav-item">
                <a href="#services"
                  onClick={(e) => { e.preventDefault(); scrollToSection("services"); }}
                  className="nav-link text-white fw-bold text-uppercase px-3">
                  Services
                </a>
              </li>
              <li className="nav-item">
                <a href="#contact"
                  onClick={(e) => { e.preventDefault(); scrollToSection("contact"); }}
                  className="nav-link text-white fw-bold text-uppercase px-3">
                  Contact
                </a>
              </li>
              <li className="nav-item">
                <a href="#support"
                  onClick={(e) => { e.preventDefault(); scrollToSection("support"); }}
                  className="nav-link text-white fw-bold text-uppercase px-3">
                  Support
                </a>
              </li>
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
                <li className="nav-item py-2">
                  <a
                    href="#home"
                    onClick={(e) => { e.preventDefault(); scrollToSection("home"); }}
                    className="nav-link text-dark fw-bold text-uppercase">
                    Home
                  </a>
                </li>
                <li className="nav-item py-2">
                  <a
                    href="#about"
                    onClick={(e) => { e.preventDefault(); scrollToSection("about"); }}
                    className="nav-link text-dark fw-bold text-uppercase">
                    About
                  </a>
                </li>
                <li className="nav-item py-2">
                  <a
                    href="#services"
                    onClick={(e) => { e.preventDefault(); scrollToSection("services"); }}
                    className="nav-link text-dark fw-bold text-uppercase">
                    Services
                  </a>
                </li>
                <li className="nav-item py-2">
                  <a
                    href="#contact"
                    onClick={(e) => { e.preventDefault(); scrollToSection("contact"); }}
                    className="nav-link text-dark fw-bold text-uppercase">
                    Contact
                  </a>
                </li>
                <li className="nav-item py-2">
                  <a
                    href="#support"
                    onClick={(e) => { e.preventDefault(); scrollToSection("support"); }}
                    className="nav-link text-dark fw-bold text-uppercase">
                    Support
                  </a>
                </li>
              </ul>
            </div>
          )}
        </div>
      </nav>

      {/* Add padding to account for fixed navbar */}
      <div style={{ paddingTop: "60px" }}></div>

      {/* Home Section (Page Header) */}
      <section id="home" className="d-flex align-items-center justify-content-center position-relative" style={{ minHeight: "100vh" }}>
        {/* Image Container */}
        <div className="position-absolute w-100 h-100" style={{ top: 0, left: 0, overflow: "hidden" }}>
          <img
            src={images[currentImageIndex].src}
            alt="Slider"
            className="w-100 h-100"
            style={{
              objectFit: "cover",
              transition: "opacity 0.5s",
            }}
          />
        </div>

        {/* Text Container */}
        <div
          className="position-relative text-center p-4 p-md-5 mx-auto"
          style={{
            width: "90%",
            maxWidth: "800px",
            backgroundColor: "rgba(255, 255, 255, 0.8)",
            borderRadius: "10px",
            boxShadow: "0px 4px 15px rgba(0, 0, 0, 0.3)",
            zIndex: 10
          }}
        >
          <h2 className="text-center mb-4" style={{ color: "#0080ff", fontSize: "clamp(1.8rem, 5vw, 2.5rem)", fontWeight: "bold" }}>
            WELCOME TO VERISIOR
          </h2>
          <p className="mb-0" style={{ fontSize: "clamp(0.9rem, 2vw, 1.2rem)", color: "#333", lineHeight: "1.6" }}>
            VeriSior provides a secure platform for senior citizen ID registration, authentication, and verification.
            Our system ensures that senior citizens can easily register and receive their identification cards without hassle.
            We prioritize security by implementing advanced encryption methods to protect user data.
            Efficiency is at the core of our services, allowing for seamless ID processing and verification.
            With a user-friendly interface, VeriSior guarantees accessibility and ease of use for all individuals.
          </p>
        </div>
      </section>

      {/* About Section */}
<section id="about" className="py-5">
  <div className="container py-3">
    <h2 className="text-center mb-4" style={{ color: "#0080ff" }}>About Us</h2>

    {/* About Intro Card */}
    <div className="card shadow-lg mb-5 border-0" style={{ backgroundColor: "#e6f7ff" }}>
      <div className="card-body p-4">
        <p className="text-center mb-0">
          We are a dedicated team of 3rd-year college students from <strong>STI College - Novaliches</strong>, committed to developing an efficient and secure web-based application for senior citizen ID authentication and publication.
        </p>
        <p className="text-center mt-2">
          Our project streamlines the registration process, ensuring that senior citizens can easily obtain their official identification cards with minimal hassle. By leveraging modern web technologies and advanced security protocols, we strive to create a user-friendly and highly reliable system.
        </p>
        <p className="text-center mt-2">
          Our goal is to enhance accessibility while maintaining the integrity and confidentiality of user data. Through this initiative, we aim to contribute to a more inclusive and technology-driven solution for senior citizen identification and verification.
        </p>
      </div>
    </div>

    {/* Team Members Container */}
    <div className="row mt-4">
      {/* Beatriz Mae Buan - Project Manager */}
      <div className="col-12 col-md-6 mb-4">
        <div className="d-flex flex-column flex-sm-row align-items-center align-items-sm-start h-100 border rounded p-3">
          <img src={beaProfile} alt="Beatriz Mae Buan" className="rounded-circle mb-3 mb-sm-0" style={{ width: "100px", height: "100px", objectFit: "cover" }} />
          <div className="text-center text-sm-start ms-sm-3">
            <h4 className="mb-2" style={{ color: "#0080ff" }}>Beatriz Mae Buan</h4>
            <p className="mb-1"><strong>Role:</strong> Project Manager</p>
            <p className="mb-1"><strong>About:</strong> A third-year student at STI Novaliches with a passion for project leadership and system development. I also run a crochet business and enjoy playing volleyball.</p>
            <p className="mb-1"><strong>Technical Skills:</strong> Java, JavaScript, HTML, CSS, Graphic Design, Video Editing</p>
            <p className="mb-0"><strong>Soft Skills:</strong> Effective Communication, Teamwork, Time Management, Adaptability, Critical Thinking</p>
          </div>
        </div>
      </div>

            {/* Reece Roque - System Analyst */}
            <div className="col-12 col-md-6 mb-4">
              <div className="d-flex flex-column flex-sm-row align-items-center align-items-sm-start h-100 border rounded p-3">
                <img src={reeceProfile} alt="Reece Roque" className="rounded-circle mb-3 mb-sm-0" style={{ width: "100px", height: "100px", objectFit: "cover" }} />
                <div className="text-center text-sm-start ms-sm-3">
                  <h4 className="mb-2" style={{ color: "#0080ff" }}>Reece Roque</h4>
                  <p className="mb-1"><strong>Role:</strong> System Analyst</p>
                  <p className="mb-1"><strong>About:</strong> An IT Student passionate about cybersecurity and innovative technology solutions.</p>
                  <p className="mb-1"><strong>Technical Skills:</strong> Cloud Backup, Cybersecurity, IoT, C#, Python, Web Development, Encryption Techniques</p>
                  <p className="mb-0"><strong>Soft Skills:</strong> Honesty, Leadership, Problem-solving, Adaptability</p>
                </div>
              </div>
            </div>

            {/* Christian Joshua Garma - Quality Assurance */}
            <div className="col-12 col-md-6 mb-4">
              <div className="d-flex flex-column flex-sm-row align-items-center align-items-sm-start h-100 border rounded p-3">
                <img src={garmaProfile} alt="Christian Joshua Garma" className="rounded-circle mb-3 mb-sm-0" style={{ width: "100px", height: "100px", objectFit: "cover" }} />
                <div className="text-center text-sm-start ms-sm-3">
                  <h4 className="mb-2" style={{ color: "#0080ff" }}>Christian Joshua Garma</h4>
                  <p className="mb-1"><strong>Role:</strong> Quality Assurance</p>
                  <p className="mb-1"><strong>About:</strong> A BSIT student from STI Novaliches who enjoys sports, music, and puzzle-solving.</p>
                  <p className="mb-1"><strong>Technical Skills:</strong> System Testing, Troubleshooting, Creative Problem Solving, Crafting and Fixing</p>
                  <p className="mb-0"><strong>Soft Skills:</strong> Attention to Detail, Persistence, Creativity, Analytical Thinking</p>
                </div>
              </div>
            </div>

            {/* Mr. X - Lead Programmer */}
            <div className="col-12 col-md-6 mb-4">
              <div className="d-flex flex-column flex-sm-row align-items-center align-items-sm-start h-100 border rounded p-3">
                <img src={mrXProfile} alt="Mr. X" className="rounded-circle mb-3 mb-sm-0" style={{ width: "100px", height: "100px", objectFit: "cover" }} />
                <div className="text-center text-sm-start ms-sm-3">
                  <h4 className="mb-2" style={{ color: "#0080ff" }}>Mr. X</h4>
                  <p className="mb-1"><strong>Role:</strong> Lead Programmer</p>
                  <p className="mb-1"><strong>About:</strong> A skilled developer with extensive experience in secure system architecture.</p>
                  <p className="mb-1"><strong>Technical Skills:</strong> Full-stack Development, Security Implementation, Database Management, API Integration</p>
                  <p className="mb-0"><strong>Soft Skills:</strong> Problem-solving, Attention to Detail, Efficient Coding, System Design</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Services Section */}
      <section id="services" className="py-5" style={{ backgroundColor: "#e6f7ff" }}>
        <div className="container py-3">
          <h2 className="text-center mb-4" style={{ color: "#0080ff" }}>Our Services</h2>
          <div className="row">
            <div className="col-md-4 mb-4">
              <div className="card h-100 shadow-sm">
                <div className="card-body text-center p-4">
                  <div className="mb-3" style={{ fontSize: "clamp(2rem, 5vw, 3rem)", color: "#0080ff" }}>
                    <i className="fas fa-id-card"></i>
                  </div>
                  <h4 className="mb-3">ID Registration</h4>
                  <p className="mb-0">Streamlined process for senior citizens to register for their official identification cards.</p>
                </div>
              </div>
            </div>
            <div className="col-md-4 mb-4">
              <div className="card h-100 shadow-sm">
                <div className="card-body text-center p-4">
                  <div className="mb-3" style={{ fontSize: "clamp(2rem, 5vw, 3rem)", color: "#0080ff" }}>
                    <i className="fas fa-user-check"></i>
                  </div>
                  <h4 className="mb-3">Authentication</h4>
                  <p className="mb-0">Secure authentication system to verify the identity of senior citizens accurately.</p>
                </div>
              </div>
            </div>
            <div className="col-md-4 mb-4">
              <div className="card h-100 shadow-sm">
                <div className="card-body text-center p-4">
                  <div className="mb-3" style={{ fontSize: "clamp(2rem, 5vw, 3rem)", color: "#0080ff" }}>
                    <i className="fas fa-check-circle"></i>
                  </div>
                  <h4 className="mb-3">Verification</h4>
                  <p className="mb-0">Comprehensive verification process to ensure the validity of provided information.</p>
                </div>
              </div>
            </div>
          </div>

          {/* New row for Apply for an ID button */}
          <div className="row justify-content-center">
            <div className="col-md-4 mb-4">
              <div className="card h-100 shadow-sm">
                <div className="card-body text-center p-4">
                  <div className="mb-3" style={{ fontSize: "clamp(2rem, 5vw, 3rem)", color: "#0080ff" }}>
                    <i className="fas fa-file-alt"></i>
                  </div>
                  <h4 className="mb-3">Apply for an ID</h4>
                  <p className="mb-3">Start the senior citizen ID application process by filling out the registration form.</p>
                  <button
                    onClick={() => window.location.href = "/apply"}
                    className="btn"
                    style={{
                      backgroundColor: "#0080ff",
                      color: "white",
                      fontWeight: "bold",
                      padding: "10px 20px",
                      border: "none",
                      borderRadius: "5px",
                      cursor: "pointer",
                      transition: "background-color 0.3s ease-in-out"
                    }}
                  >
                    Apply Now
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>


      {/* Contact Section */}
      <section id="contact" className="py-5">
        <div className="container py-3">
          <h2 className="text-center mb-3" style={{ color: "#0080ff" }}>Contact Us</h2>
          <p className="text-center mb-4">Have questions? Reach out to us anytime!</p>

          {/* Contact Form */}
          <div className="row justify-content-center">
            <div className="col-12 col-lg-8">
              <div className="card shadow">
                <div className="card-body p-3 p-md-4">
                  <form onSubmit={handleSubmit}>
                    <div className="mb-3">
                      <label htmlFor="fullName" className="form-label">Full Name</label>
                      <input
                        type="text"
                        className="form-control"
                        id="fullName"
                        name="fullName"
                        value={contactForm.fullName}
                        onChange={handleInputChange}
                        placeholder="Enter your full name"
                        required
                      />
                    </div>

                    <div className="mb-3">
                      <label htmlFor="email" className="form-label">Email Address</label>
                      <input
                        type="email"
                        className="form-control"
                        id="email"
                        name="email"
                        value={contactForm.email}
                        onChange={handleInputChange}
                        placeholder="Enter your email address"
                        required
                      />
                    </div>

                    <div className="mb-3">
                      <label htmlFor="contactNumber" className="form-label">Contact Number</label>
                      <input
                        type="tel"
                        className="form-control"
                        id="contactNumber"
                        name="contactNumber"
                        value={contactForm.contactNumber}
                        onChange={handleInputChange}
                        placeholder="Enter your contact number"
                        required
                      />
                    </div>

                    <div className="mb-3">
                      <label htmlFor="message" className="form-label">Message</label>
                      <textarea
                        className="form-control"
                        id="message"
                        name="message"
                        value={contactForm.message}
                        onChange={handleInputChange}
                        rows="5"
                        placeholder="Enter your message here"
                        required
                      ></textarea>
                    </div>

                    <div className="text-center">
                      <button
                        type="submit"
                        className="btn btn-lg"
                        style={{
                          backgroundColor: "#00b7ff",
                          color: "white",
                          fontWeight: "bold",
                          padding: "10px 30px",
                          borderRadius: "30px"
                        }}
                      >
                        Submit Message
                      </button>
                    </div>
                  </form>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Support Section */}
      <section id="support" className="py-5" style={{ backgroundColor: "#e6f7ff" }}>
        <div className="container py-3">
          <h2 className="text-center mb-4" style={{ color: "#0080ff" }}>Support</h2>

          <div className="row justify-content-center">
            <div className="col-12 col-lg-8">
              <div className="card shadow mb-4">
                <div className="card-body p-3 p-md-4">
                  <h4 style={{ color: "#0080ff" }}>Frequently Asked Questions</h4>

                  <div className="accordion mt-3" id="faqAccordion">
                    {/* FAQ Item 1 */}
                    <div className="accordion-item">
                      <h2 className="accordion-header" id="headingOne">
                        <button className="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapseOne" aria-expanded="true" aria-controls="collapseOne">
                          How do I register for a senior citizen ID?
                        </button>
                      </h2>
                      <div id="collapseOne" className="accordion-collapse collapse show" aria-labelledby="headingOne" data-bs-parent="#faqAccordion">
                        <div className="accordion-body">
                          To register for a senior citizen ID, you need to create an account on our platform, provide the required personal information, upload necessary documents for verification, and submit your application. Our team will review your application and notify you once your ID is ready for pickup or delivery.
                        </div>
                      </div>
                    </div>

                    {/* FAQ Item 2 */}
                    <div className="accordion-item">
                      <h2 className="accordion-header" id="headingTwo">
                        <button className="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseTwo" aria-expanded="false" aria-controls="collapseTwo">
                          What documents do I need to provide?
                        </button>
                      </h2>
                      <div id="collapseTwo" className="accordion-collapse collapse" aria-labelledby="headingTwo" data-bs-parent="#faqAccordion">
                        <div className="accordion-body">
                          You will need to provide a valid government-issued ID, proof of age (birth certificate or passport), proof of residence (utility bill or lease agreement), and a recent 2x2 ID photo. Additional documents may be required based on your specific situation.
                        </div>
                      </div>
                    </div>

                    {/* FAQ Item 3 */}
                    <div className="accordion-item">
                      <h2 className="accordion-header" id="headingThree">
                        <button className="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseThree" aria-expanded="false" aria-controls="collapseThree">
                          How long does the verification process take?
                        </button>
                      </h2>
                      <div id="collapseThree" className="accordion-collapse collapse" aria-labelledby="headingThree" data-bs-parent="#faqAccordion">
                        <div className="accordion-body">
                          The verification process typically takes 3-5 business days. Once verified, the ID processing may take an additional 7-10 business days. You will receive notifications regarding the status of your application throughout the process.
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="card shadow">
                <div className="card-body p-3 p-md-4">
                  <h4 style={{ color: "#0080ff" }}>Customer Support</h4>
                  <p>Need additional help? Our support team is available during the following hours:</p>

                  <div className="row mt-3">
                    <div className="col-12 col-sm-6 mb-3 mb-sm-0">
                      <h5>Business Hours</h5>
                      <ul className="list-unstyled">
                        <li>Monday - Friday: 8:00 AM - 5:00 PM</li>
                        <li>Saturday: 9:00 AM - 12:00 PM</li>
                        <li>Sunday: Closed</li>
                      </ul>
                    </div>
                    <div className="col-12 col-sm-6">
                      <h5>Contact Information</h5>
                      <ul className="list-unstyled">
                        <li>Email: support@verisior.com</li>
                        <li>Phone: (02) 8123-4567</li>
                        <li>Hotline: 1-800-VERISIOR</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Scroll to Top Button */}
      <button
        onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
        className="btn position-fixed"
        style={{
          backgroundColor: "#00f7ff",
          color: "#0080ff",
          fontWeight: "bold",
          borderRadius: "0", /* Changed to square */
          width: "50px",
          height: "50px",
          bottom: "20px",
          right: "20px",
          zIndex: 999,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          boxShadow: "0 2px 5px rgba(0, 0, 0, 0.2)",
          transition: "opacity 0.3s ease-in-out"
        }}
      >
        ↑
      </button>


      {/* Bootstrap JS - Important for accordion functionality */}
      <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    </div>
  );
};

export default LandingPage;