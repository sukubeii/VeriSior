import React, { useState } from 'react';
import RoleLayout from '../common/RoleLayout';

const Profile = ({ role }) => {
  const [notifications, setNotifications] = useState([]);
  const [profileData, setProfileData] = useState({
    firstName: 'John',
    lastName: 'Doe',
    email: 'john.doe@example.com',
    phone: '+1 (123) 456-7890'
  });
  const [passwordData, setPasswordData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });
  const [editMode, setEditMode] = useState(false);

  // Function to add notification
  const showNotification = (message, type = 'info') => {
    const newNotification = {
      id: Date.now(),
      message,
      type
    };
    setNotifications(prev => [newNotification, ...prev]);
    
    // Auto remove notification after 3 seconds
    setTimeout(() => {
      setNotifications(current => current.filter(notif => notif.id !== newNotification.id));
    }, 3000);
  };

  const handleEditProfile = () => {
    setEditMode(true);
  };

  const handleProfileChange = (e) => {
    const { name, value } = e.target;
    setProfileData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handlePasswordChange = (e) => {
    const { name, value } = e.target;
    setPasswordData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleSaveProfile = (e) => {
    e.preventDefault();
    
    // Validation could be added here
    
    showNotification('Profile updated successfully!', 'success');
    setEditMode(false);
  };

  const handleChangePassword = (e) => {
    e.preventDefault();
    
    // Check if passwords match
    if (passwordData.newPassword !== passwordData.confirmPassword) {
      showNotification('New passwords do not match', 'danger');
      return;
    }
    
    // Check if current password is entered
    if (!passwordData.currentPassword) {
      showNotification('Current password is required', 'warning');
      return;
    }
    
    // Check if new password meets requirements
    if (passwordData.newPassword.length < 8) {
      showNotification('New password must be at least 8 characters long', 'warning');
      return;
    }
    
    // Reset password fields
    setPasswordData({
      currentPassword: '',
      newPassword: '',
      confirmPassword: ''
    });
    
    showNotification('Password changed successfully!', 'success');
  };

  const getProfileContent = () => {
    return (
      <div className="profile-content">
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
        
        <div className="row">
          <div className="col-md-4 mb-4">
            <div className="card">
              <div className="card-body text-center">
                <div style={{
                  width: '120px',
                  height: '120px',
                  borderRadius: '50%',
                  backgroundColor: '#3498db',
                  color: 'white',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '48px',
                  margin: '0 auto 20px auto'
                }}>
                  {role.charAt(0).toUpperCase()}
                </div>
                <h5 className="card-title">{profileData.firstName} {profileData.lastName}</h5>
                <p className="text-muted">{role.charAt(0).toUpperCase() + role.slice(1)}</p>
                <div className="mt-3">
                  <button 
                    className="btn btn-primary"
                    onClick={handleEditProfile}
                  >
                    Edit Profile
                  </button>
                </div>
              </div>
            </div>
          </div>
          
          <div className="col-md-8">
            <div className="card mb-4">
              <div className="card-header">
                <h5 className="mb-0">Personal Information</h5>
              </div>
              <div className="card-body">
                <form onSubmit={handleSaveProfile}>
                  <div className="row mb-3">
                    <div className="col-md-6">
                      <label className="form-label">First Name</label>
                      <input 
                        type="text" 
                        className="form-control" 
                        name="firstName"
                        value={profileData.firstName}
                        onChange={handleProfileChange}
                        disabled={!editMode}
                      />
                    </div>
                    <div className="col-md-6">
                      <label className="form-label">Last Name</label>
                      <input 
                        type="text" 
                        className="form-control" 
                        name="lastName"
                        value={profileData.lastName}
                        onChange={handleProfileChange}
                        disabled={!editMode}
                      />
                    </div>
                  </div>
                  
                  <div className="mb-3">
                    <label className="form-label">Email Address</label>
                    <input 
                      type="email" 
                      className="form-control" 
                      name="email"
                      value={profileData.email}
                      onChange={handleProfileChange}
                      disabled={!editMode}
                    />
                  </div>
                  
                  <div className="mb-3">
                    <label className="form-label">Phone Number</label>
                    <input 
                      type="tel" 
                      className="form-control" 
                      name="phone"
                      value={profileData.phone}
                      onChange={handleProfileChange}
                      disabled={!editMode}
                    />
                  </div>
                  
                  {editMode && (
                    <button 
                      type="submit" 
                      className="btn btn-primary"
                    >
                      Save Changes
                    </button>
                  )}
                </form>
              </div>
            </div>
            
            <div className="card">
              <div className="card-header">
                <h5 className="mb-0">Security Settings</h5>
              </div>
              <div className="card-body">
                <form onSubmit={handleChangePassword}>
                  <div className="mb-3">
                    <label className="form-label">Current Password</label>
                    <input 
                      type="password" 
                      className="form-control"
                      name="currentPassword"
                      value={passwordData.currentPassword}
                      onChange={handlePasswordChange}
                    />
                  </div>
                  
                  <div className="mb-3">
                    <label className="form-label">New Password</label>
                    <input 
                      type="password" 
                      className="form-control"
                      name="newPassword"
                      value={passwordData.newPassword}
                      onChange={handlePasswordChange}
                    />
                  </div>
                  
                  <div className="mb-3">
                    <label className="form-label">Confirm New Password</label>
                    <input 
                      type="password" 
                      className="form-control"
                      name="confirmPassword"
                      value={passwordData.confirmPassword}
                      onChange={handlePasswordChange}
                    />
                  </div>
                  
                  <button 
                    type="submit" 
                    className="btn btn-primary"
                  >
                    Change Password
                  </button>
                </form>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  };
  
  return (
    <RoleLayout role={role}>
      {getProfileContent()}
    </RoleLayout>
  );
};

export default Profile;
