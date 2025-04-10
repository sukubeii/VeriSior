import React, { useState, useEffect } from 'react';
import RoleLayout from '../common/RoleLayout';

const SystemManagement = ({ role }) => {
  const [notifications, setNotifications] = useState([]);
  const [backupStatus, setBackupStatus] = useState('idle');
  const [backupLocation, setBackupLocation] = useState('local'); // 'local' or 'external'
  const [backupPath, setBackupPath] = useState('');
  const [systemStats, setSystemStats] = useState({
    cpuUsage: '45%',
    memoryUsage: '60%',
    diskSpace: '75%',
    systemUptime: '15 days, 7 hours',
    activeUsers: 12,
    lastBackup: 'April 10, 2024, 2:30 AM'
  });
  
  const [activeTab, setActiveTab] = useState('systemLogs');
  
  // Logs data
  const [systemLogs, setSystemLogs] = useState([
    {
      id: 1,
      timestamp: '2024-04-10 10:30:45',
      level: 'INFO',
      component: 'System',
      message: 'System started successfully'
    },
    {
      id: 2,
      timestamp: '2024-04-10 10:31:15',
      level: 'INFO',
      component: 'Database',
      message: 'Database connection established'
    },
    {
      id: 3,
      timestamp: '2024-04-10 10:35:22',
      level: 'WARNING',
      component: 'Cache',
      message: 'Cache utilization above 75%'
    },
    {
      id: 4,
      timestamp: '2024-04-10 11:15:42',
      level: 'ERROR',
      component: 'Authentication',
      message: 'Failed login attempt for user admin@example.com'
    },
    {
      id: 5,
      timestamp: '2024-04-10 11:30:18',
      level: 'INFO',
      component: 'Backup',
      message: 'Daily backup started'
    },
    {
      id: 6,
      timestamp: '2024-04-10 11:35:06',
      level: 'INFO',
      component: 'Backup',
      message: 'Daily backup completed successfully'
    },
    {
      id: 7,
      timestamp: '2024-04-10 12:10:33',
      level: 'INFO',
      component: 'ID Processing',
      message: 'New batch of 15 IDs queued for processing'
    },
    {
      id: 8,
      timestamp: '2024-04-10 12:45:19',
      level: 'WARNING',
      component: 'Memory',
      message: 'Memory usage spike detected'
    },
    {
      id: 9,
      timestamp: '2024-04-10 13:20:05',
      level: 'INFO',
      component: 'Memory',
      message: 'Memory usage normalized'
    },
    {
      id: 10,
      timestamp: '2024-04-10 14:05:48',
      level: 'INFO',
      component: 'User Management',
      message: 'New admin user created: john.smith@example.com'
    }
  ]);
  
  const [userActivityLogs, setUserActivityLogs] = useState([
    {
      id: 1,
      timestamp: '2024-04-10 10:30:45',
      user: 'admin@example.com',
      action: 'Login',
      details: 'User logged in successfully',
      ipAddress: '192.168.1.105'
    },
    {
      id: 2,
      timestamp: '2024-04-10 10:45:22',
      user: 'admin@example.com',
      action: 'View Users',
      details: 'Accessed user management page',
      ipAddress: '192.168.1.105'
    },
    {
      id: 3,
      timestamp: '2024-04-10 10:52:15',
      user: 'admin@example.com',
      action: 'Edit User',
      details: 'Modified user john.doe@example.com',
      ipAddress: '192.168.1.105'
    },
    {
      id: 4,
      timestamp: '2024-04-10 11:05:33',
      user: 'employee1@example.com',
      action: 'Login',
      details: 'User logged in successfully',
      ipAddress: '192.168.1.110'
    },
    {
      id: 5,
      timestamp: '2024-04-10 11:10:48',
      user: 'employee1@example.com',
      action: 'Process ID',
      details: 'Processed ID SC-2024-005',
      ipAddress: '192.168.1.110'
    },
    {
      id: 6,
      timestamp: '2024-04-10 11:30:12',
      user: 'superadmin@example.com',
      action: 'Login',
      details: 'User logged in successfully',
      ipAddress: '192.168.1.100'
    },
    {
      id: 7,
      timestamp: '2024-04-10 11:35:27',
      user: 'superadmin@example.com',
      action: 'System Settings',
      details: 'Modified system backup settings',
      ipAddress: '192.168.1.100'
    },
    {
      id: 8,
      timestamp: '2024-04-10 11:42:55',
      user: 'admin2@example.com',
      action: 'Login',
      details: 'User logged in successfully',
      ipAddress: '192.168.1.115'
    },
    {
      id: 9,
      timestamp: '2024-04-10 11:50:18',
      user: 'admin2@example.com',
      action: 'ID Management',
      details: 'Approved 5 pending ID applications',
      ipAddress: '192.168.1.115'
    },
    {
      id: 10,
      timestamp: '2024-04-10 12:15:42',
      user: 'employee2@example.com',
      action: 'Login',
      details: 'User logged in successfully',
      ipAddress: '192.168.1.120'
    }
  ]);

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

  const handleBackupNow = () => {
    setBackupStatus('in-progress');
    showNotification('Starting database backup...', 'info');

    // Simulate backup process
    setTimeout(() => {
      // Create a dummy backup file
      const backupData = {
        timestamp: new Date().toISOString(),
        tables: ['users', 'admins', 'employees', 'applications', 'logs'],
        size: '2.5 MB'
      };

      const blob = new Blob([JSON.stringify(backupData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `database_backup_${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setBackupStatus('completed');
      showNotification('Database backup completed successfully', 'success');
      
      // Update last backup time
      setSystemStats(prev => ({
        ...prev,
        lastBackup: new Date().toLocaleString('en-US', {
          month: 'long',
          day: 'numeric',
          year: 'numeric',
          hour: 'numeric',
          minute: 'numeric',
          hour12: true
        })
      }));
      
      // Reset status after a delay
      setTimeout(() => {
        setBackupStatus('idle');
      }, 2000);
    }, 2000);
  };

  const handleBackupLocationChange = (e) => {
    setBackupLocation(e.target.value);
  };

  const handleBackupPathChange = (e) => {
    setBackupPath(e.target.value);
  };

  const handleChooseBackupPath = () => {
    // In a real app, you would use a proper file system dialog
    // For this example, we'll simulate it with a prompt
    const path = prompt('Enter backup path:', '/var/backups/verisior');
    if (path) {
      setBackupPath(path);
    }
  };

  const handleClearCache = () => {
    showNotification('Clearing system cache...', 'info');
    
    // Simulate cache clearing
    setTimeout(() => {
      showNotification('System cache cleared successfully!', 'success');
    }, 1500);
  };
  
  const handleTabChange = (tab) => {
    setActiveTab(tab);
  };
  
  const downloadSystemLogs = () => {
    const logsText = systemLogs.map(log => 
      `[${log.timestamp}] ${log.level} - ${log.component}\nMessage: ${log.message}\n\n`
    ).join('');

    const blob = new Blob([logsText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `system_logs_${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showNotification('System logs downloaded successfully', 'success');
  };
  
  const downloadUserActivityLogs = () => {
    const logsText = userActivityLogs.map(log => 
      `[${log.timestamp}] User: ${log.user} - ${log.action}\nDetails: ${log.details}\nIP: ${log.ipAddress}\n\n`
    ).join('');

    const blob = new Blob([logsText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `user_activity_logs_${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showNotification('User activity logs downloaded successfully', 'success');
  };

  // Function to render appropriate content based on active tab
  const renderTabContent = () => {
    switch (activeTab) {
      case 'systemLogs':
        return (
          <div className="system-logs">
            <div className="d-flex justify-content-between align-items-center mb-3">
              <h5 className="mb-0">System Logs</h5>
              <button className="btn btn-primary" onClick={downloadSystemLogs}>
                <i className="fas fa-download me-2"></i>Download Logs
              </button>
            </div>
            <div className="table-responsive">
              <table className="table table-bordered table-hover">
                <thead className="table-light">
                  <tr>
                    <th>Timestamp</th>
                    <th>Level</th>
                    <th>Component</th>
                    <th>Message</th>
                  </tr>
                </thead>
                <tbody>
                  {systemLogs.map(log => (
                    <tr key={log.id} className={
                      log.level === 'ERROR' ? 'table-danger' : 
                      log.level === 'WARNING' ? 'table-warning' : ''
                    }>
                      <td>{log.timestamp}</td>
                      <td>
                        <span className={`badge ${
                          log.level === 'INFO' ? 'bg-info' :
                          log.level === 'WARNING' ? 'bg-warning' :
                          log.level === 'ERROR' ? 'bg-danger' : 'bg-secondary'
                        }`}>
                          {log.level}
                        </span>
                      </td>
                      <td>{log.component}</td>
                      <td>{log.message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        );
      
      case 'userActivity':
        return (
          <div className="user-activity">
            <div className="d-flex justify-content-between align-items-center mb-3">
              <h5 className="mb-0">User Activity Logs</h5>
              <button className="btn btn-primary" onClick={downloadUserActivityLogs}>
                <i className="fas fa-download me-2"></i>Download Logs
              </button>
            </div>
            <div className="table-responsive">
              <table className="table table-bordered table-hover">
                <thead className="table-light">
                  <tr>
                    <th>Timestamp</th>
                    <th>User</th>
                    <th>Action</th>
                    <th>Details</th>
                    <th>IP Address</th>
                  </tr>
                </thead>
                <tbody>
                  {userActivityLogs.map(log => (
                    <tr key={log.id}>
                      <td>{log.timestamp}</td>
                      <td>{log.user}</td>
                      <td>{log.action}</td>
                      <td>{log.details}</td>
                      <td>{log.ipAddress}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        );
      
      case 'databaseBackup':
        return (
          <div className="database-backup">
            <h5 className="mb-4">Database Backup Configuration</h5>
            <div className="row">
              <div className="col-md-6">
                <div className="mb-3">
                  <label className="form-label">Backup Location</label>
                  <div className="form-check">
                    <input
                      className="form-check-input"
                      type="radio"
                      name="backupLocation"
                      id="localBackup"
                      value="local"
                      checked={backupLocation === 'local'}
                      onChange={handleBackupLocationChange}
                    />
                    <label className="form-check-label" htmlFor="localBackup">
                      Local Download
                    </label>
                  </div>
                  <div className="form-check">
                    <input
                      className="form-check-input"
                      type="radio"
                      name="backupLocation"
                      id="externalBackup"
                      value="external"
                      checked={backupLocation === 'external'}
                      onChange={handleBackupLocationChange}
                    />
                    <label className="form-check-label" htmlFor="externalBackup">
                      External Storage
                    </label>
                  </div>
                </div>
                {backupLocation === 'external' && (
                  <div className="mb-3">
                    <label className="form-label">Backup Path</label>
                    <div className="input-group mb-3">
                      <input
                        type="text"
                        className="form-control"
                        value={backupPath}
                        onChange={handleBackupPathChange}
                        placeholder="Select backup location"
                      />
                      <button
                        className="btn btn-outline-secondary"
                        type="button"
                        onClick={handleChooseBackupPath}
                      >
                        Choose
                      </button>
                    </div>
                  </div>
                )}
                <div className="mb-3">
                  <label className="form-label">Backup Schedule</label>
                  <select className="form-select" defaultValue="daily">
                    <option value="hourly">Hourly</option>
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="monthly">Monthly</option>
                  </select>
                </div>
                <div className="mb-3">
                  <label className="form-label">Retention Policy</label>
                  <select className="form-select" defaultValue="7">
                    <option value="3">Keep last 3 backups</option>
                    <option value="7">Keep last 7 backups</option>
                    <option value="30">Keep last 30 backups</option>
                    <option value="90">Keep last 90 backups</option>
                  </select>
                </div>
                <button
                  className="btn btn-primary"
                  onClick={handleBackupNow}
                  disabled={backupStatus === 'in-progress'}
                >
                  {backupStatus === 'in-progress' ? (
                    <>
                      <span className="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                      Backing up...
                    </>
                  ) : backupStatus === 'completed' ? (
                    <>
                      <i className="fas fa-check me-2"></i>
                      Backup Complete
                    </>
                  ) : (
                    'Backup Now'
                  )}
                </button>
              </div>
              <div className="col-md-6">
                <div className="card bg-light">
                  <div className="card-body">
                    <h6 className="card-title">Backup Status</h6>
                    <table className="table table-sm">
                      <tbody>
                        <tr>
                          <th scope="row">Last Backup</th>
                          <td>{systemStats.lastBackup}</td>
                        </tr>
                        <tr>
                          <th scope="row">Next Scheduled</th>
                          <td>April 11, 2024, 2:30 AM</td>
                        </tr>
                        <tr>
                          <th scope="row">Status</th>
                          <td>
                            <span className="badge bg-success">Active</span>
                          </td>
                        </tr>
                        <tr>
                          <th scope="row">Total Backups</th>
                          <td>12</td>
                        </tr>
                        <tr>
                          <th scope="row">Backup Size</th>
                          <td>~2.5 MB</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>
                <div className="card bg-light mt-3">
                  <div className="card-body">
                    <h6 className="card-title">Recent Backups</h6>
                    <ul className="list-group">
                      <li className="list-group-item d-flex justify-content-between align-items-center">
                        April 10, 2024, 2:30 AM
                        <span className="badge bg-success rounded-pill">Success</span>
                      </li>
                      <li className="list-group-item d-flex justify-content-between align-items-center">
                        April 9, 2024, 2:30 AM
                        <span className="badge bg-success rounded-pill">Success</span>
                      </li>
                      <li className="list-group-item d-flex justify-content-between align-items-center">
                        April 8, 2024, 2:30 AM
                        <span className="badge bg-danger rounded-pill">Failed</span>
                      </li>
                      <li className="list-group-item d-flex justify-content-between align-items-center">
                        April 7, 2024, 2:30 AM
                        <span className="badge bg-success rounded-pill">Success</span>
                      </li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          </div>
        );
      
      case 'maintenance':
        return (
          <div className="system-maintenance">
            <h5 className="mb-4">System Maintenance</h5>
            <div className="row">
              <div className="col-md-6 mb-4">
                <div className="card">
                  <div className="card-header">
                    <h6 className="mb-0">Cache Management</h6>
                  </div>
                  <div className="card-body">
                    <p>Current cache size: <strong>128 MB</strong></p>
                    <p>Cache hit ratio: <strong>87%</strong></p>
                    <button
                      className="btn btn-warning"
                      onClick={handleClearCache}
                    >
                      Clear Cache
                    </button>
                  </div>
                </div>
              </div>
              <div className="col-md-6 mb-4">
                <div className="card">
                  <div className="card-header">
                    <h6 className="mb-0">Temporary Files</h6>
                  </div>
                  <div className="card-body">
                    <p>Temporary files size: <strong>45 MB</strong></p>
                    <p>Oldest file: <strong>15 days</strong></p>
                    <button
                      className="btn btn-warning"
                      onClick={() => showNotification('Temporary files cleared successfully', 'success')}
                    >
                      Clear Temporary Files
                    </button>
                  </div>
                </div>
              </div>
              <div className="col-md-6 mb-4">
                <div className="card">
                  <div className="card-header">
                    <h6 className="mb-0">Database Optimization</h6>
                  </div>
                  <div className="card-body">
                    <p>Last optimization: <strong>7 days ago</strong></p>
                    <p>Database size: <strong>156 MB</strong></p>
                    <button
                      className="btn btn-primary"
                      onClick={() => showNotification('Database optimization started', 'info')}
                    >
                      Optimize Database
                    </button>
                  </div>
                </div>
              </div>
              <div className="col-md-6 mb-4">
                <div className="card">
                  <div className="card-header">
                    <h6 className="mb-0">System Services</h6>
                  </div>
                  <div className="card-body">
                    <div className="d-flex justify-content-between mb-2">
                      <span>Web Server</span>
                      <span className="badge bg-success">Running</span>
                    </div>
                    <div className="d-flex justify-content-between mb-2">
                      <span>Database Server</span>
                      <span className="badge bg-success">Running</span>
                    </div>
                    <div className="d-flex justify-content-between mb-2">
                      <span>Cache Server</span>
                      <span className="badge bg-success">Running</span>
                    </div>
                    <div className="d-flex justify-content-between">
                      <span>Background Jobs</span>
                      <span className="badge bg-success">Running</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        );
      
      default:
        return <div>Select a tab to view content</div>;
    }
  };

  // Render the component based on role permission
  const getSystemManagementContent = () => {
    if (role !== "superAdmin") {
      return (
        <div className="alert alert-danger">
          You don't have permission to access this page.
        </div>
      );
    }

    return (
      <div className="system-management-content">
        <h1 className="mb-4">System Management</h1>
        
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

        {/* System Stats */}
        <div className="row mb-4">
          <div className="col-md-3">
            <div className="card h-100">
              <div className="card-body text-center">
                <h5 className="card-title">CPU Usage</h5>
                <div className="display-4">{systemStats.cpuUsage}</div>
                <div className="progress mt-2">
                  <div 
                    className="progress-bar" 
                    role="progressbar" 
                    style={{ width: systemStats.cpuUsage }}
                    aria-valuenow={parseInt(systemStats.cpuUsage)} 
                    aria-valuemin="0" 
                    aria-valuemax="100"
                  ></div>
                </div>
              </div>
            </div>
          </div>
          <div className="col-md-3">
            <div className="card h-100">
              <div className="card-body text-center">
                <h5 className="card-title">Memory Usage</h5>
                <div className="display-4">{systemStats.memoryUsage}</div>
                <div className="progress mt-2">
                  <div 
                    className="progress-bar bg-success" 
                    role="progressbar" 
                    style={{ width: systemStats.memoryUsage }}
                    aria-valuenow={parseInt(systemStats.memoryUsage)} 
                    aria-valuemin="0" 
                    aria-valuemax="100"
                  ></div>
                </div>
              </div>
            </div>
          </div>
          <div className="col-md-3">
            <div className="card h-100">
              <div className="card-body text-center">
                <h5 className="card-title">Disk Space</h5>
                <div className="display-4">{systemStats.diskSpace}</div>
                <div className="progress mt-2">
                  <div 
                    className="progress-bar bg-info" 
                    role="progressbar" 
                    style={{ width: systemStats.diskSpace }}
                    aria-valuenow={parseInt(systemStats.diskSpace)} 
                    aria-valuemin="0" 
                    aria-valuemax="100"
                  ></div>
                </div>
              </div>
            </div>
          </div>
          <div className="col-md-3">
            <div className="card h-100">
              <div className="card-body text-center">
                <h5 className="card-title">Uptime</h5>
                <div className="display-4 fs-3">{systemStats.systemUptime}</div>
                <div className="mt-2 text-muted">
                  Active Users: {systemStats.activeUsers}
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="card mb-4">
          <div className="card-body">
            <ul className="nav nav-tabs" id="systemTabs" role="tablist">
              <li className="nav-item" role="presentation">
                <button 
                  className={`nav-link ${activeTab === 'systemLogs' ? 'active' : ''}`}
                  onClick={() => handleTabChange('systemLogs')}
                >
                  System Logs
                </button>
              </li>
              <li className="nav-item" role="presentation">
                <button 
                  className={`nav-link ${activeTab === 'userActivity' ? 'active' : ''}`}
                  onClick={() => handleTabChange('userActivity')}
                >
                  User Activity
                </button>
              </li>
              <li className="nav-item" role="presentation">
                <button 
                  className={`nav-link ${activeTab === 'databaseBackup' ? 'active' : ''}`}
                  onClick={() => handleTabChange('databaseBackup')}
                >
                  Database Backup
                </button>
              </li>
              <li className="nav-item" role="presentation">
                <button 
                  className={`nav-link ${activeTab === 'maintenance' ? 'active' : ''}`}
                  onClick={() => handleTabChange('maintenance')}
                >
                  Maintenance
                </button>
              </li>
            </ul>
            <div className="tab-content mt-3" id="systemTabsContent">
              {renderTabContent()}
            </div>
          </div>
        </div>
      </div>
    );
  };

  return (
    <RoleLayout role={role}>
      {getSystemManagementContent()}
    </RoleLayout>
  );
};

export default SystemManagement;
