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

  const [activeTab, setActiveTab] = useState('newsUpdates');

  // News & Updates state
  const [companyUpdates, setCompanyUpdates] = useState([
    {
      id: 1,
      title: 'System Upgrade Scheduled',
      date: 'April 15, 2024',
      content: 'A system upgrade is scheduled for April 15th at 2:00 AM. The system will be unavailable for approximately 30 minutes.',
      important: true
    },
    {
      id: 2,
      title: 'New ID Template Released',
      date: 'April 8, 2024',
      content: 'A new ID template for government employees has been released. Please review and approve.',
      important: false
    },
    {
      id: 3,
      title: 'Employee Training Session',
      date: 'April 20, 2024',
      content: 'A training session for new ID processing procedures will be held on April 20th at 10:00 AM.',
      important: true
    }
  ]);

  // News & Updates form state
  const [newUpdate, setNewUpdate] = useState({
    title: '',
    content: '',
    important: false
  });

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

  // News & Updates Functions
  const handleNewUpdateChange = (e) => {
    const { name, value, type, checked } = e.target;
    setNewUpdate(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  const handleAddUpdate = (e) => {
    e.preventDefault();

    if (!newUpdate.title.trim() || !newUpdate.content.trim()) {
      showNotification('Title and content are required', 'warning');
      return;
    }

    const currentDate = new Date();
    const formattedDate = currentDate.toLocaleDateString('en-US', {
      month: 'long',
      day: 'numeric',
      year: 'numeric'
    });

    const newItem = {
      id: Date.now(),
      title: newUpdate.title,
      content: newUpdate.content,
      date: formattedDate,
      important: newUpdate.important
    };

    // Add to company updates
    setCompanyUpdates(prev => [newItem, ...prev]);

    // Reset form
    setNewUpdate({
      title: '',
      content: '',
      important: false
    });

    showNotification('News/Update added successfully', 'success');

    // In a real application, you would save this to a database or state management
    // and propagate it to the Dashboard components
  };

  const handleDeleteUpdate = (id) => {
    setCompanyUpdates(prev => prev.filter(update => update.id !== id));
    showNotification('News/Update deleted successfully', 'success');
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
      case 'newsUpdates':
        return (
          <div className="news-updates">
            <div className="row">
              <div className="col-lg-5">
                <div className="card shadow mb-4">
                  <div className="card-header py-3">
                    <h6 className="m-0 font-weight-bold text-primary">Post New Update</h6>
                  </div>
                  <div className="card-body">
                    <form onSubmit={handleAddUpdate}>
                      <div className="mb-3">
                        <label htmlFor="title" className="form-label">Title</label>
                        <input
                          type="text"
                          className="form-control"
                          id="title"
                          name="title"
                          value={newUpdate.title}
                          onChange={handleNewUpdateChange}
                          placeholder="Enter update title"
                          required
                        />
                      </div>
                      <div className="mb-3">
                        <label htmlFor="content" className="form-label">Content</label>
                        <textarea
                          className="form-control"
                          id="content"
                          name="content"
                          rows="4"
                          value={newUpdate.content}
                          onChange={handleNewUpdateChange}
                          placeholder="Enter update content"
                          required
                        ></textarea>
                      </div>
                      <div className="mb-3 form-check">
                        <input
                          type="checkbox"
                          className="form-check-input"
                          id="important"
                          name="important"
                          checked={newUpdate.important}
                          onChange={handleNewUpdateChange}
                        />
                        <label className="form-check-label" htmlFor="important">
                          Mark as Important
                        </label>
                      </div>
                      <button type="submit" className="btn btn-primary">
                        Post Update
                      </button>
                    </form>
                  </div>
                </div>
              </div>
              <div className="col-lg-7">
                <div className="card shadow">
                  <div className="card-header py-3 d-flex justify-content-between align-items-center">
                    <h6 className="m-0 font-weight-bold text-primary">Current News & Updates</h6>
                    <span className="badge bg-primary rounded-pill">{companyUpdates.length}</span>
                  </div>
                  <div className="card-body">
                    {companyUpdates.length === 0 ? (
                      <div className="text-center py-4">
                        <p className="text-muted">No updates available</p>
                      </div>
                    ) : (
                      <div className="updates-list">
                        {companyUpdates.map(update => (
                          <div key={update.id} className={`card mb-3 ${update.important ? 'border-left-warning' : 'border-left-primary'}`}>
                            <div className="card-body py-3 px-3">
                              <div className="d-flex justify-content-between align-items-start">
                                <div>
                                  <div className="d-flex align-items-center mb-1">
                                    <h5 className="mb-0">{update.title}</h5>
                                    {update.important && (
                                      <span className="badge bg-warning text-dark ms-2">Important</span>
                                    )}
                                  </div>
                                  <div className="text-muted small mb-2">{update.date}</div>
                                  <p className="mb-0">{update.content}</p>
                                </div>
                                <button
                                  className="btn btn-sm btn-outline-danger"
                                  onClick={() => handleDeleteUpdate(update.id)}
                                >
                                  <i className="fas fa-trash"></i>
                                </button>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        );

      case 'systemLogs':
        return (
          <div className="system-logs">
            <div className="card shadow">
              <div className="card-header py-3 d-flex justify-content-between align-items-center">
                <h6 className="m-0 font-weight-bold text-primary">System Logs</h6>
                <button className="btn btn-sm btn-primary" onClick={downloadSystemLogs}>
                  <i className="fas fa-download me-2"></i>Download Logs
                </button>
              </div>
              <div className="card-body">
                <div className="table-responsive">
                  <table className="table table-hover">
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
                            <span className={`badge ${log.level === 'INFO' ? 'bg-info' :
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
            </div>
          </div>
        );
      case 'userActivity':
        return (
          <div className="user-activity">
            <div className="card shadow">
              <div className="card-header py-3 d-flex justify-content-between align-items-center">
                <h6 className="m-0 font-weight-bold text-primary">User Activity Logs</h6>
                <button className="btn btn-sm btn-primary" onClick={downloadUserActivityLogs}>
                  <i className="fas fa-download me-2"></i>Download Logs
                </button>
              </div>
              <div className="card-body">
                <div className="table-responsive">
                  <table className="table table-hover">
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
            </div>
          </div>
        );

      case 'databaseBackup':
        return (
          <div className="database-backup">
            <div className="row">
              <div className="col-md-6">
                <div className="card shadow mb-4">
                  <div className="card-header py-3">
                    <h6 className="m-0 font-weight-bold text-primary">Backup Configuration</h6>
                  </div>
                  <div className="card-body">
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
                </div>
              </div>
              <div className="col-md-6">
                <div className="card shadow mb-4">
                  <div className="card-header py-3">
                    <h6 className="m-0 font-weight-bold text-primary">Backup Status</h6>
                  </div>
                  <div className="card-body">
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
                <div className="card shadow">
                  <div className="card-header py-3">
                    <h6 className="m-0 font-weight-bold text-primary">Recent Backups</h6>
                  </div>
                  <div className="card-body">
                    <ul className="list-group list-group-flush">
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
            <div className="row">
              <div className="col-md-6 mb-4">
                <div className="card shadow">
                  <div className="card-header py-3">
                    <h6 className="m-0 font-weight-bold text-primary">Cache Management</h6>
                  </div>
                  <div className="card-body">
                    <div className="d-flex justify-content-between align-items-center mb-3">
                      <span>Current cache size:</span>
                      <span className="fw-bold">128 MB</span>
                    </div>
                    <div className="d-flex justify-content-between align-items-center mb-3">
                      <span>Cache hit ratio:</span>
                      <span className="fw-bold">87%</span>
                    </div>
                    <button
                      className="btn btn-warning"
                      onClick={handleClearCache}
                    >
                      <i className="fas fa-broom me-2"></i>
                      Clear Cache
                    </button>
                  </div>
                </div>
              </div>
              <div className="col-md-6 mb-4">
                <div className="card shadow">
                  <div className="card-header py-3">
                    <h6 className="m-0 font-weight-bold text-primary">Temporary Files</h6>
                  </div>
                  <div className="card-body">
                    <div className="d-flex justify-content-between align-items-center mb-3">
                      <span>Temporary files size:</span>
                      <span className="fw-bold">45 MB</span>
                    </div>
                    <div className="d-flex justify-content-between align-items-center mb-3">
                      <span>Oldest file:</span>
                      <span className="fw-bold">15 days</span>
                    </div>
                    <button
                      className="btn btn-warning"
                      onClick={() => showNotification('Temporary files cleared successfully', 'success')}
                    >
                      <i className="fas fa-trash-alt me-2"></i>
                      Clear Temporary Files
                    </button>
                  </div>
                </div>
              </div>
              <div className="col-md-6 mb-4">
                <div className="card shadow">
                  <div className="card-header py-3">
                    <h6 className="m-0 font-weight-bold text-primary">Database Optimization</h6>
                  </div>
                  <div className="card-body">
                    <div className="d-flex justify-content-between align-items-center mb-3">
                      <span>Last optimization:</span>
                      <span className="fw-bold">7 days ago</span>
                    </div>
                    <div className="d-flex justify-content-between align-items-center mb-3">
                      <span>Database size:</span>
                      <span className="fw-bold">156 MB</span>
                    </div>
                    <button
                      className="btn btn-primary"
                      onClick={() => showNotification('Database optimization started', 'info')}
                    >
                      <i className="fas fa-database me-2"></i>
                      Optimize Database
                    </button>
                  </div>
                </div>
              </div>
              <div className="col-md-6 mb-4">
                <div className="card shadow">
                  <div className="card-header py-3">
                    <h6 className="m-0 font-weight-bold text-primary">System Services</h6>
                  </div>
                  <div className="card-body">
                    <div className="list-group">
                      <div className="list-group-item d-flex justify-content-between align-items-center">
                        <span>Web Server</span>
                        <span className="badge bg-success rounded-pill">Running</span>
                      </div>
                      <div className="list-group-item d-flex justify-content-between align-items-center">
                        <span>Database Server</span>
                        <span className="badge bg-success rounded-pill">Running</span>
                      </div>
                      <div className="list-group-item d-flex justify-content-between align-items-center">
                        <span>Cache Server</span>
                        <span className="badge bg-success rounded-pill">Running</span>
                      </div>
                      <div className="list-group-item d-flex justify-content-between align-items-center">
                        <span>Background Jobs</span>
                        <span className="badge bg-success rounded-pill">Running</span>
                      </div>
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
          <i className="fas fa-exclamation-triangle me-2"></i>
          You don't have permission to access this page.
        </div>
      );
    }

    return (
      <div className="system-management-content">
        <div className="d-sm-flex align-items-center justify-content-between mb-4">
          <h1 className="h3 mb-0 text-gray-800">System Management</h1>
        </div>

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

        {/* Tab Navigation */}
        <div className="card shadow mb-4">
          <div className="card-header py-3">
            <ul className="nav nav-tabs card-header-tabs">
              <li className="nav-item">
                <button
                  className={`nav-link ${activeTab === 'newsUpdates' ? 'active' : ''}`}
                  onClick={() => handleTabChange('newsUpdates')}
                >
                  <i className="fas fa-newspaper me-1"></i> News & Updates
                </button>
              </li>
              <li className="nav-item">
                <button
                  className={`nav-link ${activeTab === 'systemLogs' ? 'active' : ''}`}
                  onClick={() => handleTabChange('systemLogs')}
                >
                  <i className="fas fa-list me-1"></i> System Logs
                </button>
              </li>
              <li className="nav-item">
                <button
                  className={`nav-link ${activeTab === 'userActivity' ? 'active' : ''}`}
                  onClick={() => handleTabChange('userActivity')}
                >
                  <i className="fas fa-user-clock me-1"></i> User Activity
                </button>
              </li>
              <li className="nav-item">
                <button
                  className={`nav-link ${activeTab === 'databaseBackup' ? 'active' : ''}`}
                  onClick={() => handleTabChange('databaseBackup')}
                >
                  <i className="fas fa-database me-1"></i> Database Backup
                </button>
              </li>
              <li className="nav-item">
                <button
                  className={`nav-link ${activeTab === 'maintenance' ? 'active' : ''}`}
                  onClick={() => handleTabChange('maintenance')}
                >
                  <i className="fas fa-tools me-1"></i> Maintenance
                </button>
              </li>
            </ul>
          </div>
          <div className="card-body">
            {renderTabContent()}
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
