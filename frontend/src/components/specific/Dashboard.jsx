import React, { useState, useEffect } from 'react';
import RoleLayout from '../common/RoleLayout';
import { Chart } from 'react-chartjs-2';
import { 
  Chart as ChartJS, 
  CategoryScale, 
  LinearScale, 
  PointElement, 
  LineElement, 
  BarElement, 
  Title, 
  Tooltip, 
  Legend, 
  ArcElement,
  DoughnutController
} from 'chart.js';

// Register ChartJS components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  DoughnutController
);

const SuperAdminDashboard = ({ role }) => {
  const [notifications, setNotifications] = useState([]);
  const [currentTime, setCurrentTime] = useState(new Date());
  const [activityLogs, setActivityLogs] = useState([
    {
      id: 1,
      type: 'user',
      action: 'Login',
      user: 'Admin 1',
      timestamp: '2024-04-10 10:30:45',
      details: 'User logged in successfully'
    },
    {
      id: 2,
      type: 'system',
      action: 'Database Update',
      user: 'System',
      timestamp: '2024-04-10 10:31:15',
      details: 'Database backup completed'
    },
    {
      id: 3,
      type: 'user',
      action: 'ID Created',
      user: 'Employee 1',
      timestamp: '2024-04-10 09:15:22',
      details: 'New ID SC-2024-003 created for Juan Torres'
    },
    {
      id: 4,
      type: 'user',
      action: 'ID Approved',
      user: 'Admin 2',
      timestamp: '2024-04-09 16:45:32',
      details: 'ID SC-2024-002 approved for Maria Santos'
    },
    {
      id: 5,
      type: 'system',
      action: 'System Update',
      user: 'System',
      timestamp: '2024-04-09 01:00:00',
      details: 'Scheduled system maintenance completed'
    }
  ]);
  
  const [systemStats, setSystemStats] = useState({
    cpuUsage: 45,
    memoryUsage: 60,
    diskSpace: 75,
    uptime: '15 days, 7 hours',
    activeUsers: 12,
    lastBackup: 'April 10, 2024, 2:30 AM'
  });

  const [userStats, setUserStats] = useState({
    totalUsers: 58,
    totalAdmins: 5,
    totalEmployees: 53,
    activeUsers: 42,
    inactiveUsers: 16
  });

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

  // Update current time every minute
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date());
    }, 60000);
    
    return () => clearInterval(timer);
  }, []);

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
  
  const addNotification = (message, type) => {
    const id = Date.now();
    setNotifications([...notifications, { id, message, type }]);
    setTimeout(() => {
      setNotifications(notifications.filter(notification => notification.id !== id));
    }, 5000);
  };

  const downloadLogs = () => {
    const logsText = activityLogs.map(log => 
      `[${log.timestamp}] ${log.type.toUpperCase()} - ${log.action}\nUser: ${log.user}\nDetails: ${log.details}\n\n`
    ).join('');

    const blob = new Blob([logsText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `activity_logs_${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    addNotification('Activity logs downloaded successfully', 'success');
  };

  // Chart data for user distribution
  const userDistributionData = {
    labels: ['Admins', 'Employees'],
    datasets: [
      {
        data: [userStats.totalAdmins, userStats.totalEmployees],
        backgroundColor: ['#4e73df', '#1cc88a'],
        hoverBackgroundColor: ['#2e59d9', '#17a673'],
        hoverBorderColor: "rgba(234, 236, 244, 1)",
      }
    ]
  };

  // Chart data for system usage
  const systemUsageData = {
    labels: ['CPU', 'Memory', 'Disk'],
    datasets: [
      {
        label: 'Usage (%)',
        data: [systemStats.cpuUsage, systemStats.memoryUsage, systemStats.diskSpace],
        backgroundColor: ['#4e73df', '#1cc88a', '#36b9cc'],
        borderColor: ['#4e73df', '#1cc88a', '#36b9cc'],
        borderWidth: 1
      }
    ]
  };

  // Chart options
  const doughnutOptions = {
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom'
      }
    },
    cutout: '70%'
  };

  const barOptions = {
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: false
      }
    },
    scales: {
      y: {
        beginAtZero: true,
        max: 100
      }
    }
  };

  // Format current date and time
  const formattedDate = currentTime.toLocaleDateString('en-US', {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });
  
  const formattedTime = currentTime.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit'
  });

  return (
    <RoleLayout role={role}>
      <div className="super-admin-dashboard">
        <div className="d-sm-flex align-items-center justify-content-between mb-4">
          <h1 className="h3 mb-0 text-gray-800">Super Admin Dashboard</h1>
          <div className="d-none d-sm-inline-block ml-auto mr-3">
            <div className="text-right">
              <div className="text-primary">{formattedDate}</div>
              <div className="h4">{formattedTime}</div>
            </div>
          </div>
          <div className="d-none d-sm-inline-block">
            <button 
              className="btn btn-primary shadow-sm"
              onClick={() => handleButtonClick('Refresh dashboard')}
            >
              <i className="fas fa-sync-alt fa-sm mr-2"></i>Refresh
            </button>
          </div>
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

        {/* System Status Section */}
        <div className="row">
          <div className="col-lg-8">
            <div className="card mb-4">
              <div className="card-header py-3 d-flex flex-row align-items-center justify-content-between">
                <h6 className="m-0 font-weight-bold text-primary">System Status</h6>
              </div>
              <div className="card-body">
                <div className="row">
                  <div className="col-md-6">
                    <div className="mb-3">
                      <h4 className="small font-weight-bold">CPU Usage <span className="float-right">{systemStats.cpuUsage}%</span></h4>
                      <div className="progress mb-4">
                        <div className="progress-bar bg-primary" role="progressbar" style={{ width: `${systemStats.cpuUsage}%` }}></div>
                      </div>
                    </div>
                    <div className="mb-3">
                      <h4 className="small font-weight-bold">Memory Usage <span className="float-right">{systemStats.memoryUsage}%</span></h4>
                      <div className="progress mb-4">
                        <div className="progress-bar bg-success" role="progressbar" style={{ width: `${systemStats.memoryUsage}%` }}></div>
                      </div>
                    </div>
                    <div className="mb-3">
                      <h4 className="small font-weight-bold">Disk Space <span className="float-right">{systemStats.diskSpace}%</span></h4>
                      <div className="progress mb-4">
                        <div className="progress-bar bg-info" role="progressbar" style={{ width: `${systemStats.diskSpace}%` }}></div>
                      </div>
                    </div>
                  </div>
                  <div className="col-md-6">
                    <div style={{ height: '200px' }}>
                      <Chart type="bar" data={systemUsageData} options={barOptions} />
                    </div>
                  </div>
                </div>
                <div className="row mt-3">
                  <div className="col-md-6">
                    <div className="card bg-light mb-0">
                      <div className="card-body py-2">
                        <div className="row no-gutters align-items-center">
                          <div className="col mr-2">
                            <div className="text-xs font-weight-bold text-primary text-uppercase mb-1">System Uptime</div>
                            <div className="h5 mb-0 font-weight-bold text-gray-800">{systemStats.uptime}</div>
                          </div>
                          <div className="col-auto">
                            <i className="fas fa-clock fa-2x text-gray-300"></i>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="col-md-6">
                    <div className="card bg-light mb-0">
                      <div className="card-body py-2">
                        <div className="row no-gutters align-items-center">
                          <div className="col mr-2">
                            <div className="text-xs font-weight-bold text-primary text-uppercase mb-1">Last Backup</div>
                            <div className="h5 mb-0 font-weight-bold text-gray-800">{systemStats.lastBackup}</div>
                          </div>
                          <div className="col-auto">
                            <i className="fas fa-database fa-2x text-gray-300"></i>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Total Users Section */}
          <div className="col-lg-4">
            <div className="card mb-4">
              <div className="card-header py-3">
                <h6 className="m-0 font-weight-bold text-primary">User Distribution</h6>
              </div>
              <div className="card-body">
                <div style={{ height: '200px' }}>
                  <Chart type="doughnut" data={userDistributionData} options={doughnutOptions} />
                </div>
                <div className="mt-4 text-center small">
                  <span className="mr-2">
                    <i className="fas fa-circle text-primary"></i> Admins: {userStats.totalAdmins}
                  </span>
                  <span className="ml-2">
                    <i className="fas fa-circle text-success"></i> Employees: {userStats.totalEmployees}
                  </span>
                </div>
                <div className="text-center mt-3">
                  <div className="h4 mb-0 font-weight-bold text-gray-800">Total Users: {userStats.totalUsers}</div>
                  <div className="small text-muted mt-1">
                    Active: {userStats.activeUsers} | Inactive: {userStats.inactiveUsers}
                  </div>
                </div>
                <div className="text-center mt-3">
                  <button 
                    className="btn btn-sm btn-primary"
                    onClick={() => handleButtonClick('View detailed user statistics')}
                  >
                    View Details
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Company Updates Section */}
        <div className="row">
          <div className="col-lg-6">
            <div className="card mb-4">
              <div className="card-header py-3 d-flex flex-row align-items-center justify-content-between">
                <h6 className="m-0 font-weight-bold text-primary">Company Updates</h6>
                <div className="dropdown no-arrow">
                  <button 
                    className="btn btn-sm btn-primary"
                    onClick={() => handleButtonClick('Add new company update')}
                  >
                    <i className="fas fa-plus fa-sm"></i> New Update
                  </button>
                </div>
              </div>
              <div className="card-body">
                <div className="company-updates">
                  {companyUpdates.map(update => (
                    <div key={update.id} className={`card mb-3 ${update.important ? 'border-left-warning' : 'border-left-primary'}`}>
                      <div className="card-body py-2">
                        <div className="row no-gutters align-items-center">
                          <div className="col mr-2">
                            <div className="d-flex justify-content-between align-items-center">
                              <div className="text-xs font-weight-bold text-primary text-uppercase mb-1">
                                {update.date}
                              </div>
                              {update.important && (
                                <div className="badge bg-warning text-white">Important</div>
                              )}
                            </div>
                            <div className="h5 mb-0 font-weight-bold text-gray-800">{update.title}</div>
                            <div className="mt-2 text-gray-600">
                              {update.content}
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Activity Logs Section */}
          <div className="col-lg-6">
            <div className="card mb-4">
              <div className="card-header py-3 d-flex flex-row align-items-center justify-content-between">
                <h6 className="m-0 font-weight-bold text-primary">Recent Activity</h6>
                <button className="btn btn-sm btn-primary" onClick={downloadLogs}>
                  <i className="fas fa-download fa-sm"></i> Download Logs
                </button>
              </div>
              <div className="card-body">
                <div className="activity-timeline">
                  {activityLogs.slice(0, 5).map((log, index) => (
                    <div key={log.id} className="timeline-item">
                      <div className="timeline-item-marker">
                        <div className={`timeline-item-marker-indicator bg-${log.type === 'user' ? 'primary' : 'warning'}`}></div>
                      </div>
                      <div className="timeline-item-content pt-0">
                        <div className="timeline-item-content-header d-flex">
                          <div className="mr-auto">
                            <span className="font-weight-bold">{log.action}</span>
                            <span className="text-muted ml-2">by {log.user}</span>
                          </div>
                          <div className="text-xs text-muted">{log.timestamp}</div>
                        </div>
                        <div className="timeline-item-content-details small text-muted">
                          {log.details}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="text-center mt-3">
                  <button 
                    className="btn btn-sm btn-primary"
                    onClick={() => handleButtonClick('View all activity logs')}
                  >
                    View All Activity
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Additional Info Cards Section */}
        <div className="row">
          <div className="col-lg-3 col-md-6 mb-4">
            <div className="card border-left-primary shadow h-100 py-2">
              <div className="card-body">
                <div className="row no-gutters align-items-center">
                  <div className="col mr-2">
                    <div className="text-xs font-weight-bold text-primary text-uppercase mb-1">
                      Pending Applications
                    </div>
                    <div className="h5 mb-0 font-weight-bold text-gray-800">18</div>
                  </div>
                  <div className="col-auto">
                    <i className="fas fa-calendar fa-2x text-gray-300"></i>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="col-lg-3 col-md-6 mb-4">
            <div className="card border-left-success shadow h-100 py-2">
              <div className="card-body">
                <div className="row no-gutters align-items-center">
                  <div className="col mr-2">
                    <div className="text-xs font-weight-bold text-success text-uppercase mb-1">
                      Processed Today
                    </div>
                    <div className="h5 mb-0 font-weight-bold text-gray-800">24</div>
                  </div>
                  <div className="col-auto">
                    <i className="fas fa-clipboard-check fa-2x text-gray-300"></i>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="col-lg-3 col-md-6 mb-4">
            <div className="card border-left-info shadow h-100 py-2">
              <div className="card-body">
                <div className="row no-gutters align-items-center">
                  <div className="col mr-2">
                    <div className="text-xs font-weight-bold text-info text-uppercase mb-1">
                      Active Admins
                    </div>
                    <div className="h5 mb-0 font-weight-bold text-gray-800">4</div>
                  </div>
                  <div className="col-auto">
                    <i className="fas fa-user-shield fa-2x text-gray-300"></i>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="col-lg-3 col-md-6 mb-4">
            <div className="card border-left-warning shadow h-100 py-2">
              <div className="card-body">
                <div className="row no-gutters align-items-center">
                  <div className="col mr-2">
                    <div className="text-xs font-weight-bold text-warning text-uppercase mb-1">
                      System Alerts
                    </div>
                    <div className="h5 mb-0 font-weight-bold text-gray-800">2</div>
                  </div>
                  <div className="col-auto">
                    <i className="fas fa-exclamation-triangle fa-2x text-gray-300"></i>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </RoleLayout>
  );
};

export default SuperAdminDashboard;
