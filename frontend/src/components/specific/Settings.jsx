import React, { useState } from 'react';
import RoleLayout from '../common/RoleLayout';

const Settings = ({ role }) => {
  const [notifications, setNotifications] = useState([]);
  const [appSettings, setAppSettings] = useState({
    appName: 'VeriSior',
    systemEmail: 'system@verisior.com'
  });
  const [notificationPrefs, setNotificationPrefs] = useState({
    emailNotifs: true,
    smsNotifs: true,
    systemNotifs: true
  });
  const [maintenanceStats, setMaintenanceStats] = useState({
    cacheSize: '256MB'
  });

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

  const handleAppSettingsChange = (e) => {
    const { name, value } = e.target;
    setAppSettings(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleNotificationPrefsChange = (e) => {
    const { id, checked } = e.target;
    setNotificationPrefs(prev => ({
      ...prev,
      [id]: checked
    }));
  };

  const handleSaveAppSettings = () => {
    // Validate settings
    if (!appSettings.appName.trim()) {
      showNotification('Application name cannot be empty', 'warning');
      return;
    }
    
    if (!appSettings.systemEmail.trim() || !appSettings.systemEmail.includes('@')) {
      showNotification('Please enter a valid email address', 'warning');
      return;
    }
    
    showNotification('Application settings saved successfully!', 'success');
  };

  const handleUpdatePreferences = () => {
    showNotification('Notification preferences updated successfully!', 'success');
  };

  const handleClearCache = () => {
    // Reset cache size
    setMaintenanceStats(prev => ({
      ...prev,
      cacheSize: '0MB'
    }));
    
    showNotification('System cache cleared successfully!', 'success');
  };

  const getSettingsContent = () => {
    return (
      <div className="settings-content">
        <h1 className="mb-4">System Settings</h1>
        
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
          <div className="col-md-6 mb-4">
            <div className="card">
              <div className="card-header">
                <h5 className="mb-0">Application Settings</h5>
              </div>
              <div className="card-body">
                <div className="mb-3">
                  <label className="form-label">Application Name</label>
                  <input 
                    type="text" 
                    className="form-control" 
                    name="appName"
                    value={appSettings.appName}
                    onChange={handleAppSettingsChange}
                  />
                </div>
                <div className="mb-3">
                  <label className="form-label">System Email</label>
                  <input 
                    type="email" 
                    className="form-control" 
                    name="systemEmail"
                    value={appSettings.systemEmail}
                    onChange={handleAppSettingsChange}
                  />
                </div>
                <button 
                  className="btn btn-primary"
                  onClick={handleSaveAppSettings}
                >
                  Save Changes
                </button>
              </div>
            </div>
          </div>
          
          <div className="col-md-6 mb-4">
            <div className="card">
              <div className="card-header">
                <h5 className="mb-0">Notification Settings</h5>
              </div>
              <div className="card-body">
                <div className="form-check form-switch mb-3">
                  <input 
                    className="form-check-input" 
                    type="checkbox" 
                    id="emailNotifs" 
                    checked={notificationPrefs.emailNotifs}
                    onChange={handleNotificationPrefsChange}
                  />
                  <label className="form-check-label" htmlFor="emailNotifs">
                    Email Notifications
                  </label>
                </div>
                <div className="form-check form-switch mb-3">
                  <input 
                    className="form-check-input" 
                    type="checkbox" 
                    id="smsNotifs" 
                    checked={notificationPrefs.smsNotifs}
                    onChange={handleNotificationPrefsChange}
                  />
                  <label className="form-check-label" htmlFor="smsNotifs">
                    SMS Notifications
                  </label>
                </div>
                <div className="form-check form-switch mb-3">
                  <input 
                    className="form-check-input" 
                    type="checkbox" 
                    id="systemNotifs" 
                    checked={notificationPrefs.systemNotifs}
                    onChange={handleNotificationPrefsChange}
                  />
                  <label className="form-check-label" htmlFor="systemNotifs">
                    System Notifications
                  </label>
                </div>
                <button 
                  className="btn btn-primary"
                  onClick={handleUpdatePreferences}
                >
                  Update Preferences
                </button>
              </div>
            </div>
          </div>
        </div>
        
        <div className="row">
          <div className="col-12">
            <div className="card">
              <div className="card-body">
                <h5 className="card-title">System Maintenance</h5>
                <p className="card-text">
                  Manage system maintenance tasks and monitor system health.
                </p>
                
                <div className="row">
                  <div className="col-md-6 mb-3">
                    <div className="card bg-light">
                      <div className="card-body">
                        <h6 className="card-title">Clear System Cache</h6>
                        <p className="card-text">Cache size: {maintenanceStats.cacheSize}</p>
                        <button 
                          className="btn btn-warning"
                          onClick={handleClearCache}
                        >
                          Clear Cache
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  };
  
  return (
    <RoleLayout role={role}>
      {getSettingsContent()}
    </RoleLayout>
  );
};

export default Settings;
