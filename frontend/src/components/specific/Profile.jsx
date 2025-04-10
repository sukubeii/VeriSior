import React, { useState, useEffect } from 'react';
import RoleLayout from '../common/RoleLayout';

const Profile = ({ role }) => {
  const [notifications, setNotifications] = useState([]);
  const [isEditing, setIsEditing] = useState(false);
  const [showOtpModal, setShowOtpModal] = useState(false);
  const [otpValue, setOtpValue] = useState('');
  const [otpError, setOtpError] = useState('');
  const [pendingChanges, setPendingChanges] = useState(null);
  const [passwordStrength, setPasswordStrength] = useState(0);
  const [passwordFeedback, setPasswordFeedback] = useState('');
  const [errors, setErrors] = useState({
    firstName: '',
    middleName: '',
    lastName: '',
    email: '',
    phone: '',
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });

  // Original profile data
  const [originalProfileData, setOriginalProfileData] = useState({
    firstName: 'John',
    middleName: '',
    lastName: 'Doe',
    email: 'john.doe@example.com',
    phone: '09123456789',
    department: 'Administration',
    position: 'System Administrator',
    joinDate: '2023-10-15',
    lastLogin: '2024-04-10 09:30:22'
  });

  // Current profile data (for editing)
  const [profileData, setProfileData] = useState({...originalProfileData});

  // Password data
  const [passwordData, setPasswordData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });

  useEffect(() => {
    // Evaluate password strength whenever newPassword changes
    if (passwordData.newPassword) {
      const strength = evaluatePasswordStrength(passwordData.newPassword);
      setPasswordStrength(strength.score);
      setPasswordFeedback(strength.feedback);
    } else {
      setPasswordStrength(0);
      setPasswordFeedback('');
    }
  }, [passwordData.newPassword]);

  // Function to evaluate password strength (0-4)
  const evaluatePasswordStrength = (password) => {
    let score = 0;
    let feedback = '';

    // Length check
    if (password.length >= 8) score += 1;
    
    // Complexity checks
    if (/[A-Z]/.test(password)) score += 1; // Has uppercase
    if (/[a-z]/.test(password)) score += 1; // Has lowercase
    if (/[0-9]/.test(password)) score += 1; // Has number
    if (/[^A-Za-z0-9]/.test(password)) score += 1; // Has special character

    // Feedback based on score
    switch (score) {
      case 0:
        feedback = 'Very weak';
        break;
      case 1:
        feedback = 'Weak';
        break;
      case 2:
        feedback = 'Fair';
        break;
      case 3:
        feedback = 'Good';
        break;
      case 4:
      case 5:
        feedback = 'Strong';
        break;
      default:
        feedback = '';
    }

    return { score, feedback };
  };

  // Function to add notification
  const showNotification = (message, type = 'info') => {
    const newNotification = {
      id: Date.now(),
      message,
      type
    };
    setNotifications(prev => [newNotification, ...prev]);
    
    // Auto remove notification after 5 seconds
    setTimeout(() => {
      setNotifications(current => current.filter(notif => notif.id !== newNotification.id));
    }, 5000);
  };

  // Input validation functions
  const validateName = (name, field) => {
    if (name.length === 0 && field === 'middleName') return ''; // Middle name is optional
    if (name.length === 0) return 'This field is required';
    if (name.length > 20) return 'Maximum 20 characters allowed';
    if (/[0-9]/.test(name)) return 'Numbers are not allowed';
    if (/[^A-Za-z\s]/.test(name)) return 'Special characters are not allowed';
    return '';
  };

  const validateEmail = (email) => {
    if (email.length === 0) return 'Email is required';
    if (email.length > 30) return 'Maximum 30 characters allowed';
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) return 'Invalid email format';
    return '';
  };

  const validatePhone = (phone) => {
    if (phone.length === 0) return 'Phone number is required';
    if (!/^09\d{9}$/.test(phone)) return 'Must be a valid Philippine number (e.g., 09123456789)';
    return '';
  };

  const validatePassword = (password, type) => {
    if (type === 'current' && password.length === 0) return 'Current password is required';
    if (type === 'new') {
      if (password.length === 0) return 'New password is required';
      if (password.length < 8) return 'Minimum 8 characters required';
      if (password.length > 20) return 'Maximum 20 characters allowed';
      if (!/[A-Z]/.test(password)) return 'Must include uppercase letter';
      if (!/[a-z]/.test(password)) return 'Must include lowercase letter';
      if (!/[0-9]/.test(password)) return 'Must include a number';
      if (!/[^A-Za-z0-9]/.test(password)) return 'Must include a special character';
    }
    if (type === 'confirm' && password !== passwordData.newPassword) return 'Passwords do not match';
    return '';
  };

  // Input sanitization function (basic)
  const sanitizeInput = (input) => {
    // Prevent HTML injection and common SQL injection patterns
    return input
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/'/g, '&#39;')
      .replace(/"/g, '&quot;')
      .replace(/;/g, '&#59;')
      .replace(/--/g, '&#45;&#45;')
      .replace(/\/\*/g, '&#47;&#42;')
      .replace(/\*\//g, '&#42;&#47;');
  };

  // Format name with first letter capitalized
  const formatName = (name) => {
    if (!name) return '';
    return name.trim().toLowerCase().replace(/\b\w/g, char => char.toUpperCase());
  };

  const handleEditProfile = () => {
    setIsEditing(true);
  };

  const handleCancelEdit = () => {
    setIsEditing(false);
    setProfileData({...originalProfileData});
    setErrors({
      firstName: '',
      middleName: '',
      lastName: '',
      email: '',
      phone: '',
      currentPassword: '',
      newPassword: '',
      confirmPassword: ''
    });
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    const sanitizedValue = sanitizeInput(value);
    
    setProfileData(prev => ({
      ...prev,
      [name]: sanitizedValue
    }));

    // Validate field immediately
    let errorMessage = '';
    switch (name) {
      case 'firstName':
      case 'middleName':
      case 'lastName':
        errorMessage = validateName(sanitizedValue, name);
        break;
      case 'email':
        errorMessage = validateEmail(sanitizedValue);
        break;
      case 'phone':
        errorMessage = validatePhone(sanitizedValue);
        break;
      default:
        errorMessage = '';
    }

    setErrors(prev => ({
      ...prev,
      [name]: errorMessage
    }));
  };

  const handlePasswordChange = (e) => {
    const { name, value } = e.target;
    const sanitizedValue = sanitizeInput(value);
    
    setPasswordData(prev => ({
      ...prev,
      [name]: sanitizedValue
    }));

    // Validate password fields
    let errorMessage = '';
    switch (name) {
      case 'currentPassword':
        errorMessage = validatePassword(sanitizedValue, 'current');
        break;
      case 'newPassword':
        errorMessage = validatePassword(sanitizedValue, 'new');
        break;
      case 'confirmPassword':
        errorMessage = validatePassword(sanitizedValue, 'confirm');
        break;
      default:
        errorMessage = '';
    }

    setErrors(prev => ({
      ...prev,
      [name]: errorMessage
    }));
  };

  const handleSaveProfile = (e) => {
    e.preventDefault();
    
    // Validate all fields
    const newErrors = {
      firstName: validateName(profileData.firstName, 'firstName'),
      middleName: validateName(profileData.middleName, 'middleName'),
      lastName: validateName(profileData.lastName, 'lastName'),
      email: validateEmail(profileData.email),
      phone: validatePhone(profileData.phone)
    };
    
    // Check if there are any errors
    const hasErrors = Object.values(newErrors).some(error => error !== '');
    if (hasErrors) {
      setErrors(prev => ({
        ...prev,
        ...newErrors
      }));
      showNotification('Please correct the errors in the form', 'danger');
      return;
    }

    // Format names with capitalized first letters
    const formattedData = {
      ...profileData,
      firstName: formatName(profileData.firstName),
      middleName: formatName(profileData.middleName),
      lastName: formatName(profileData.lastName)
    };

    // Store pending changes before OTP verification
    setPendingChanges(formattedData);
    
    // Simulate sending OTP to user's phone
    simulateSendOTP(profileData.phone);
    
    // Show OTP verification modal
    setShowOtpModal(true);
  };

  const handleChangePassword = (e) => {
    e.preventDefault();
    
    // Validate all password fields
    const newErrors = {
      currentPassword: validatePassword(passwordData.currentPassword, 'current'),
      newPassword: validatePassword(passwordData.newPassword, 'new'),
      confirmPassword: validatePassword(passwordData.confirmPassword, 'confirm')
    };
    
    // Check if there are any errors
    const hasErrors = Object.values(newErrors).some(error => error !== '');
    if (hasErrors) {
      setErrors(prev => ({
        ...prev,
        ...newErrors
      }));
      showNotification('Please correct the errors in the form', 'danger');
      return;
    }
    
    // Store pending changes (in this case, just a flag to indicate password change)
    setPendingChanges({ changePassword: true });
    
    // Simulate sending OTP to user's phone
    simulateSendOTP(profileData.phone);
    
    // Show OTP verification modal
    setShowOtpModal(true);
  };

  // Function to simulate sending OTP to phone
  const simulateSendOTP = (phone) => {
    // In a real application, this would make an API call to send OTP
    console.log(`Simulating OTP sent to ${phone}`);
    showNotification(`OTP has been sent to your phone number (${phone.substring(0, 3)}***${phone.substring(phone.length - 3)})`, 'info');
  };

  const handleOtpChange = (e) => {
    const { value } = e.target;
    // Only allow numeric input
    if (/^\d*$/.test(value) && value.length <= 6) {
      setOtpValue(value);
      setOtpError('');
    }
  };

  const handleVerifyOtp = () => {
    // In a real app, you would validate this against a server
    if (otpValue !== '123456') { // Simulated correct OTP
      setOtpError('Invalid OTP. Please try again.');
      return;
    }
    
    // Proceed with the pending changes
    if (pendingChanges) {
      if (pendingChanges.changePassword) {
        // Handle password change
        setPasswordData({
          currentPassword: '',
          newPassword: '',
          confirmPassword: ''
        });
        showNotification('Password changed successfully!', 'success');
      } else {
        // Handle profile update
        setOriginalProfileData(pendingChanges);
        setProfileData(pendingChanges);
        showNotification('Profile updated successfully!', 'success');
      }
    }
    
    // Reset states
    setPendingChanges(null);
    setOtpValue('');
    setOtpError('');
    setShowOtpModal(false);
    setIsEditing(false);
  };

  const handleCancelOtp = () => {
    setPendingChanges(null);
    setOtpValue('');
    setOtpError('');
    setShowOtpModal(false);
  };

  return (
    <RoleLayout role={role}>
      <div className="profile-content">
        <div className="container py-5">
          <h1 className="mb-4">User Profile</h1>
          
          {/* Notification area */}
          {notifications.length > 0 && (
            <div className="mb-4">
              {notifications.map(notification => (
                <div key={notification.id} className={`alert alert-${notification.type} alert-dismissible fade show`}>
                  {notification.message}
                  <button type="button" className="btn-close" onClick={() => setNotifications(current => 
                    current.filter(notif => notif.id !== notification.id)
                  )}></button>
                </div>
              ))}
            </div>
          )}
          
          <div className="bg-white shadow rounded-lg overflow-hidden">
            <div className="row">
              {/* Left column with profile picture and basic info */}
              <div className="col-md-4 border-end">
                <div className="p-4 text-center">
                  <div className="mb-4 position-relative mx-auto" style={{width: "150px"}}>
                    <div className="rounded-circle bg-primary d-flex justify-content-center align-items-center text-white" 
                         style={{width: "150px", height: "150px", fontSize: "60px"}}>
                      {originalProfileData.firstName.charAt(0)}{originalProfileData.lastName.charAt(0)}
                    </div>
                    {!isEditing && (
                      <button className="btn btn-sm btn-primary position-absolute bottom-0 end-0 rounded-circle"
                              style={{width: "40px", height: "40px"}}
                              title="Change Photo">
                        <i className="fas fa-camera"></i>
                      </button>
                    )}
                  </div>
                  
                  <h4 className="mb-0">{originalProfileData.firstName} {originalProfileData.lastName}</h4>
                  <p className="text-secondary mb-1">{originalProfileData.position}</p>
                  <p className="text-muted">{role.charAt(0).toUpperCase() + role.slice(1)}</p>
                  
                  <div className="d-grid gap-2 mb-3">
                    {!isEditing ? (
                      <button className="btn btn-primary" onClick={handleEditProfile}>
                        <i className="fas fa-edit me-2"></i>Edit Profile
                      </button>
                    ) : (
                      <button className="btn btn-secondary" onClick={handleCancelEdit}>
                        <i className="fas fa-times me-2"></i>Cancel Editing
                      </button>
                    )}
                  </div>
                  
                  <hr />
                  
                  <div className="text-start">
                    <div className="mb-3">
                      <h6 className="mb-1 text-muted fs-6">Department</h6>
                      <p className="mb-0">{originalProfileData.department}</p>
                    </div>
                    <div className="mb-3">
                      <h6 className="mb-1 text-muted fs-6">Join Date</h6>
                      <p className="mb-0">{originalProfileData.joinDate}</p>
                    </div>
                    <div className="mb-3">
                      <h6 className="mb-1 text-muted fs-6">Last Login</h6>
                      <p className="mb-0">{originalProfileData.lastLogin}</p>
                    </div>
                  </div>
                </div>
              </div>
              
              {/* Right column with forms */}
              <div className="col-md-8">
                <div className="p-4">
                  <h5 className="border-bottom pb-2">Profile Information</h5>
                  
                  <form onSubmit={handleSaveProfile}>
                    <div className="row mb-3 mt-4">
                      <div className="col-md-4">
                        <div className="form-floating mb-3">
                          <input
                            type="text"
                            className={`form-control ${errors.firstName ? 'is-invalid' : ''}`}
                            id="firstName"
                            name="firstName"
                            placeholder="First Name"
                            value={profileData.firstName}
                            onChange={handleInputChange}
                            disabled={!isEditing}
                          />
                          <label htmlFor="firstName">First Name</label>
                          {errors.firstName && <div className="invalid-feedback">{errors.firstName}</div>}
                        </div>
                      </div>
                      <div className="col-md-4">
                        <div className="form-floating mb-3">
                          <input
                            type="text"
                            className={`form-control ${errors.middleName ? 'is-invalid' : ''}`}
                            id="middleName"
                            name="middleName"
                            placeholder="Middle Name"
                            value={profileData.middleName}
                            onChange={handleInputChange}
                            disabled={!isEditing}
                          />
                          <label htmlFor="middleName">Middle Name (Optional)</label>
                          {errors.middleName && <div className="invalid-feedback">{errors.middleName}</div>}
                        </div>
                      </div>
                      <div className="col-md-4">
                        <div className="form-floating mb-3">
                          <input
                            type="text"
                            className={`form-control ${errors.lastName ? 'is-invalid' : ''}`}
                            id="lastName"
                            name="lastName"
                            placeholder="Last Name"
                            value={profileData.lastName}
                            onChange={handleInputChange}
                            disabled={!isEditing}
                          />
                          <label htmlFor="lastName">Last Name</label>
                          {errors.lastName && <div className="invalid-feedback">{errors.lastName}</div>}
                        </div>
                      </div>
                    </div>
                    
                    <div className="form-floating mb-3">
                      <input
                        type="email"
                        className={`form-control ${errors.email ? 'is-invalid' : ''}`}
                        id="email"
                        name="email"
                        placeholder="Email"
                        value={profileData.email}
                        onChange={handleInputChange}
                        disabled={!isEditing}
                      />
                      <label htmlFor="email">Email Address</label>
                      {errors.email && <div className="invalid-feedback">{errors.email}</div>}
                    </div>
                    
                    <div className="form-floating mb-3">
                      <input
                        type="tel"
                        className={`form-control ${errors.phone ? 'is-invalid' : ''}`}
                        id="phone"
                        name="phone"
                        placeholder="Phone"
                        value={profileData.phone}
                        onChange={handleInputChange}
                        disabled={!isEditing}
                      />
                      <label htmlFor="phone">Phone Number (e.g., 09123456789)</label>
                      {errors.phone && <div className="invalid-feedback">{errors.phone}</div>}
                    </div>
                    
                    {isEditing && (
                      <div className="d-grid gap-2 d-md-flex justify-content-md-end">
                        <button type="submit" className="btn btn-primary">
                          <i className="fas fa-save me-2"></i>Save Changes
                        </button>
                      </div>
                    )}
                  </form>
                  
                  <hr className="my-4" />
                  
                  <h5 className="border-bottom pb-2">Security Settings</h5>
                  
                  <form onSubmit={handleChangePassword} className="mt-4">
                    <div className="mb-3">
                      <div className="form-floating">
                        <input
                          type="password"
                          className={`form-control ${errors.currentPassword ? 'is-invalid' : ''}`}
                          id="currentPassword"
                          name="currentPassword"
                          placeholder="Current Password"
                          value={passwordData.currentPassword}
                          onChange={handlePasswordChange}
                        />
                        <label htmlFor="currentPassword">Current Password</label>
                        {errors.currentPassword && <div className="invalid-feedback">{errors.currentPassword}</div>}
                      </div>
                    </div>
                    
                    <div className="mb-3">
                      <div className="form-floating">
                        <input
                          type="password"
                          className={`form-control ${errors.newPassword ? 'is-invalid' : ''}`}
                          id="newPassword"
                          name="newPassword"
                          placeholder="New Password"
                          value={passwordData.newPassword}
                          onChange={handlePasswordChange}
                        />
                        <label htmlFor="newPassword">New Password</label>
                        {errors.newPassword && <div className="invalid-feedback">{errors.newPassword}</div>}
                      </div>
                      
                      {/* Password strength meter */}
                      {passwordData.newPassword && (
                        <div className="mt-2">
                          <div className="progress" style={{ height: '8px' }}>
                            <div 
                              className={`progress-bar ${
                                passwordStrength <= 1 ? 'bg-danger' : 
                                passwordStrength === 2 ? 'bg-warning' : 
                                passwordStrength === 3 ? 'bg-info' : 'bg-success'
                              }`} 
                              role="progressbar" 
                              style={{ width: `${passwordStrength * 20}%` }}
                              aria-valuenow={passwordStrength * 20} 
                              aria-valuemin="0" 
                              aria-valuemax="100"
                            ></div>
                          </div>
                          <small className="text-muted">
                            Password strength: <span className={
                              passwordStrength <= 1 ? 'text-danger' : 
                              passwordStrength === 2 ? 'text-warning' : 
                              passwordStrength === 3 ? 'text-info' : 'text-success'
                            }>{passwordFeedback}</span>
                          </small>
                        </div>
                      )}
                      
                      <div className="mt-2">
                        <small className="text-muted">
                          Password must contain 8-20 characters, including uppercase, lowercase, 
                          numbers, and special characters.
                        </small>
                      </div>
                    </div>
                    
                    <div className="mb-3">
                      <div className="form-floating">
                        <input
                          type="password"
                          className={`form-control ${errors.confirmPassword ? 'is-invalid' : ''}`}
                          id="confirmPassword"
                          name="confirmPassword"
                          placeholder="Confirm Password"
                          value={passwordData.confirmPassword}
                          onChange={handlePasswordChange}
                        />
                        <label htmlFor="confirmPassword">Confirm New Password</label>
                        {errors.confirmPassword && <div className="invalid-feedback">{errors.confirmPassword}</div>}
                      </div>
                    </div>
                    
                    <div className="d-grid gap-2 d-md-flex justify-content-md-end">
                      <button 
                        type="submit" 
                        className="btn btn-primary"
                        disabled={!passwordData.currentPassword || !passwordData.newPassword || !passwordData.confirmPassword}
                      >
                        <i className="fas fa-key me-2"></i>Change Password
                      </button>
                    </div>
                  </form>
                </div>
              </div>
            </div>
          </div>
        </div>
        
        {/* OTP Verification Modal */}
        {showOtpModal && (
          <div className="modal fade show" tabIndex="-1" style={{ display: 'block', backgroundColor: 'rgba(0,0,0,0.5)' }}>
            <div className="modal-dialog modal-dialog-centered">
              <div className="modal-content">
                <div className="modal-header">
                  <h5 className="modal-title">OTP Verification</h5>
                  <button type="button" className="btn-close" onClick={handleCancelOtp}></button>
                </div>
                <div className="modal-body">
                  <p>
                    A 6-digit OTP has been sent to your phone number
                    ({profileData.phone.substring(0, 3)}***{profileData.phone.substring(profileData.phone.length - 3)}).
                  </p>
                  <p className="text-muted small">
                    <strong>Note:</strong> For demo purposes, the OTP is 123456
                  </p>
                  
                  <div className="form-group mb-3">
                    <label htmlFor="otp" className="form-label">Enter OTP</label>
                    <input
                      type="text"
                      className={`form-control form-control-lg text-center ${otpError ? 'is-invalid' : ''}`}
                      id="otp"
                      value={otpValue}
                      onChange={handleOtpChange}
                      placeholder="Enter 6-digit OTP"
                      maxLength="6"
                    />
                    {otpError && <div className="invalid-feedback">{otpError}</div>}
                  </div>
                </div>
                <div className="modal-footer">
                  <button type="button" className="btn btn-secondary" onClick={handleCancelOtp}>Cancel</button>
                  <button 
                    type="button" 
                    className="btn btn-primary" 
                    onClick={handleVerifyOtp}
                    disabled={otpValue.length !== 6}
                  >
                    Verify
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </RoleLayout>
  );
};

export default Profile;
