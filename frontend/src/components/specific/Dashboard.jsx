import React, { useState } from 'react';
import RoleLayout from '../common/RoleLayout';

const Dashboard = ({ role }) => {
  const [notifications, setNotifications] = useState([]);
  
  // Function to handle button clicks and show notification
  const handleButtonClick = (action) => {
    const newNotification = {
      id: Date.now(),
      message: `${action} operation initiated`,
      type: 'info'
    };
    setNotifications([newNotification, ...notifications]);
    
    // Auto remove notification after 3 seconds
    setTimeout(() => {
      setNotifications(current => current.filter(notif => notif.id !== newNotification.id));
    }, 3000);
  };
  
  const getDashboardContent = () => {
    switch (role) {
      case "superAdmin":
        return (
          <>
            <h1 className="mb-4">Super Admin Dashboard</h1>
            
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
                  <div className="card-body">
                    <h5 className="card-title">Total Admins</h5>
                    <p className="card-text display-4">12</p>
                    <button 
                      className="btn btn-primary mt-2"
                      onClick={() => handleButtonClick('View admins')}
                    >
                      View Details
                    </button>
                  </div>
                </div>
              </div>
              <div className="col-md-4 mb-4">
                <div className="card">
                  <div className="card-body">
                    <h5 className="card-title">Total Employees</h5>
                    <p className="card-text display-4">45</p>
                    <button 
                      className="btn btn-primary mt-2"
                      onClick={() => handleButtonClick('View employees')}
                    >
                      View Details
                    </button>
                  </div>
                </div>
              </div>
              <div className="col-md-4 mb-4">
                <div className="card">
                  <div className="card-body">
                    <h5 className="card-title">Total IDs Processed</h5>
                    <p className="card-text display-4">1,234</p>
                    <button 
                      className="btn btn-primary mt-2"
                      onClick={() => handleButtonClick('View processed IDs')}
                    >
                      View Details
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </>
        );
      case "admin":
        return (
          <>
            <h1 className="mb-4">Admin Dashboard</h1>
            
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
                  <div className="card-body">
                    <h5 className="card-title">Pending ID Applications</h5>
                    <p className="card-text display-4">24</p>
                    <button 
                      className="btn btn-primary mt-2"
                      onClick={() => handleButtonClick('View pending applications')}
                    >
                      Process Now
                    </button>
                  </div>
                </div>
              </div>
              <div className="col-md-4 mb-4">
                <div className="card">
                  <div className="card-body">
                    <h5 className="card-title">Total Employees</h5>
                    <p className="card-text display-4">15</p>
                    <button 
                      className="btn btn-primary mt-2"
                      onClick={() => handleButtonClick('View employees')}
                    >
                      Manage Employees
                    </button>
                  </div>
                </div>
              </div>
              <div className="col-md-4 mb-4">
                <div className="card">
                  <div className="card-body">
                    <h5 className="card-title">Processed IDs Today</h5>
                    <p className="card-text display-4">8</p>
                    <button 
                      className="btn btn-primary mt-2"
                      onClick={() => handleButtonClick('View today\'s processed IDs')}
                    >
                      View Details
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </>
        );
      case "employee":
        return (
          <>
            <h1 className="mb-4">Employee Dashboard</h1>
            
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
                  <div className="card-body">
                    <h5 className="card-title">Pending Tasks</h5>
                    <p className="card-text display-4">5</p>
                    <button 
                      className="btn btn-primary mt-2"
                      onClick={() => handleButtonClick('View pending tasks')}
                    >
                      Start Working
                    </button>
                  </div>
                </div>
              </div>
              <div className="col-md-4 mb-4">
                <div className="card">
                  <div className="card-body">
                    <h5 className="card-title">Completed Today</h5>
                    <p className="card-text display-4">12</p>
                    <button 
                      className="btn btn-primary mt-2"
                      onClick={() => handleButtonClick('View completed tasks')}
                    >
                      View Details
                    </button>
                  </div>
                </div>
              </div>
              <div className="col-md-4 mb-4">
                <div className="card">
                  <div className="card-body">
                    <h5 className="card-title">Total Processed</h5>
                    <p className="card-text display-4">156</p>
                    <button 
                      className="btn btn-primary mt-2"
                      onClick={() => handleButtonClick('View all processed tasks')}
                    >
                      View History
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </>
        );
      default:
        return null;
    }
  };

  return (
    <RoleLayout role={role}>
      {getDashboardContent()}
    </RoleLayout>
  );
};

export default Dashboard;
