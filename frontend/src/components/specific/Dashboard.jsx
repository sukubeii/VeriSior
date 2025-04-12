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
import { useNavigate } from 'react-router-dom';
import { useUpdates } from '../../contexts/UpdatesContext';

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

const Dashboard = ({ role }) => {
  // Use the updates context
  const { companyUpdates } = useUpdates();

  const [notifications, setNotifications] = useState([]);
  const [currentTime, setCurrentTime] = useState(new Date());
  const [activityLogs, setActivityLogs] = useState([
    {
      id: 1,
      type: 'user',
      action: 'ID Approved',
      user: 'Admin 1',
      timestamp: '2024-04-10 10:30:45',
      details: 'ID application SC-2024-003 approved'
    },
    {
      id: 2,
      type: 'system',
      action: 'Template Updated',
      user: 'System',
      timestamp: '2024-04-10 10:31:15',
      details: 'New ID template submitted for review'
    },
    {
      id: 3,
      type: 'user',
      action: 'ID Rejected',
      user: 'Admin 2',
      timestamp: '2024-04-10 09:15:22',
      details: 'ID application SC-2024-004 rejected - incomplete requirements'
    },
    {
      id: 4,
      type: 'user',
      action: 'Page Updated',
      user: 'Admin 1',
      timestamp: '2024-04-09 16:45:32',
      details: 'Application form requirements updated'
    },
    {
      id: 5,
      type: 'system',
      action: 'Employee Added',
      user: 'Admin 2',
      timestamp: '2024-04-09 01:00:00',
      details: 'New employee account created'
    }
  ]);

  const [systemStats, setSystemStats] = useState({
    uptime: '15 days, 7 hours',
    lastBackup: 'April 10, 2024, 2:30 AM',
    status: 'Online'
  });

  const [userStats, setUserStats] = useState({
    totalUsers: 58,
    totalAdmins: 5,
    totalEmployees: 53,
    activeUsers: 42,
    inactiveUsers: 16
  });

  // No longer needed - using context instead
  // const [companyUpdates, setCompanyUpdates] = useState([...]);

  const [adminStats, setAdminStats] = useState({
    pendingApplications: 18,
    processedToday: 24,
    activeAdmins: 5,
    activeEmployees: 42,
    pendingRenewals: 7,
    pendingMessages: 12
  });

  const navigate = useNavigate();

  // Update current time every minute
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date());
    }, 60000);

    return () => clearInterval(timer);
  }, []);
  // Function to generate random number within range
  const getRandomNumber = (min, max) => {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  };

  // Function to get current formatted date
  const getCurrentFormattedDate = () => {
    return new Date().toLocaleString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: 'numeric',
      minute: 'numeric',
      hour12: true
    });
  };

  // Function to refresh system stats
  const refreshSystemStats = () => {
    setSystemStats({
      uptime: `${getRandomNumber(10, 20)} days, ${getRandomNumber(1, 23)} hours`,
      lastBackup: getCurrentFormattedDate(),
      status: 'Online',
      cpuUsage: `${getRandomNumber(30, 70)}%`,
      memoryUsage: `${getRandomNumber(40, 80)}%`,
      diskSpace: `${getRandomNumber(50, 90)}%`,
      systemUptime: `${getRandomNumber(10, 20)} days, ${getRandomNumber(1, 23)} hours`,
      activeUsers: getRandomNumber(8, 15),
      lastBackup: getCurrentFormattedDate()
    });
  };

  // Function to refresh user stats
  const refreshUserStats = () => {
    const totalAdmins = getRandomNumber(3, 8);
    const totalEmployees = getRandomNumber(40, 60);
    const activeAdmins = getRandomNumber(2, totalAdmins);
    const activeEmployees = getRandomNumber(30, totalEmployees);

    setUserStats({
      totalUsers: totalAdmins + totalEmployees,
      totalAdmins: totalAdmins,
      totalEmployees: totalEmployees,
      activeUsers: activeAdmins + activeEmployees,
      inactiveUsers: (totalAdmins + totalEmployees) - (activeAdmins + activeEmployees)
    });

    // Update admin stats as well
    setAdminStats(prev => ({
      ...prev,
      activeAdmins: activeAdmins,
      activeEmployees: activeEmployees,
      pendingApplications: getRandomNumber(10, 25),
      processedToday: getRandomNumber(15, 35),
      pendingRenewals: getRandomNumber(5, 15),
      pendingMessages: getRandomNumber(5, 20)
    }));
  };

  // Function to refresh activity logs
  const refreshActivityLogs = () => {
    const actions = ['ID Approved', 'Template Updated', 'ID Rejected', 'Page Updated', 'Employee Added'];
    const users = ['Admin 1', 'Admin 2', 'System', 'Employee 1', 'Employee 2'];
    const components = ['ID Management', 'Template', 'System', 'Page Management', 'User Management'];

    const newSystemLogs = Array(10).fill(null).map((_, index) => ({
      id: Date.now() + index,
      type: Math.random() > 0.7 ? 'system' : 'user',
      action: actions[Math.floor(Math.random() * actions.length)],
      user: users[Math.floor(Math.random() * users.length)],
      timestamp: new Date(Date.now() - Math.random() * 86400000).toISOString().replace('T', ' ').substring(0, 19),
      component: components[Math.floor(Math.random() * components.length)],
      message: `Action completed successfully`
    }));

    const newUserLogs = Array(10).fill(null).map((_, index) => ({
      id: Date.now() + index,
      user: users[Math.floor(Math.random() * users.length)],
      action: actions[Math.floor(Math.random() * actions.length)],
      details: 'Action completed successfully',
      timestamp: new Date(Date.now() - Math.random() * 86400000).toISOString().replace('T', ' ').substring(0, 19),
      ipAddress: `192.168.1.${getRandomNumber(100, 200)}`
    }));

    setSystemLogs && setSystemLogs(newSystemLogs);
    setActivityLogs(newUserLogs);
  };
  // Function to handle refresh button click
  const handleButtonClick = (action) => {
    // Show refresh notification
    const newNotification = {
      id: Date.now(),
      message: `${action} operation initiated`,
      type: 'info'
    };
    setNotifications([newNotification, ...notifications]);

    // Refresh all dashboard data
    refreshSystemStats();
    refreshUserStats();
    refreshActivityLogs();

    // Show success notification after a brief delay
    setTimeout(() => {
      const successNotification = {
        id: Date.now() + 1,
        message: 'Dashboard refreshed successfully',
        type: 'success'
      };
      setNotifications(notifications => [successNotification, ...notifications.filter(n => n.id !== newNotification.id)]);
    }, 1000);

    // Auto remove notifications after 3 seconds
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

  // -------------------- EMPLOYEE DASHBOARD --------------------
  if (role === 'employee') {
    return (
      <RoleLayout role={role}>
        <div className="employee-dashboard">
          {/* Row 1: Dashboard Header */}
          <div className="row mb-4">
            <div className="col-12">
              <div className="d-sm-flex align-items-center justify-content-between">
                <h1 className="h3 mb-0 text-gray-800">Employee Dashboard</h1>
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
            </div>
          </div>

          {/* Row 2: Notification Area */}
          <div className="row mb-4">
            <div className="col-12">
              {notifications.length > 0 && (
                <div>
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
            </div>
          </div>
          {/* Row 3: Task Stats Cards */}
          <div className="row mb-4">
            <div className="col-xl-3 col-md-6 mb-4">
              <div className="card border-left-primary shadow h-100 py-2">
                <div className="card-body">
                  <div className="row no-gutters align-items-center">
                    <div className="col mr-2">
                      <div className="text-xs font-weight-bold text-primary text-uppercase mb-1">
                        Pending Applications
                      </div>
                      <div className="h5 mb-0 font-weight-bold text-gray-800">
                        {adminStats.pendingApplications}
                      </div>
                    </div>
                    <div className="col-auto">
                      <i className="fas fa-clipboard-list fa-2x text-gray-300"></i>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="col-xl-3 col-md-6 mb-4">
              <div className="card border-left-success shadow h-100 py-2">
                <div className="card-body">
                  <div className="row no-gutters align-items-center">
                    <div className="col mr-2">
                      <div className="text-xs font-weight-bold text-success text-uppercase mb-1">
                        Pending Renewals
                      </div>
                      <div className="h5 mb-0 font-weight-bold text-gray-800">
                        {adminStats.pendingRenewals}
                      </div>
                    </div>
                    <div className="col-auto">
                      <i className="fas fa-redo-alt fa-2x text-gray-300"></i>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="col-xl-3 col-md-6 mb-4">
              <div className="card border-left-info shadow h-100 py-2">
                <div className="card-body">
                  <div className="row no-gutters align-items-center">
                    <div className="col mr-2">
                      <div className="text-xs font-weight-bold text-info text-uppercase mb-1">
                        Pending Messages
                      </div>
                      <div className="h5 mb-0 font-weight-bold text-gray-800">
                        {adminStats.pendingMessages}
                      </div>
                    </div>
                    <div className="col-auto">
                      <i className="fas fa-envelope fa-2x text-gray-300"></i>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="col-xl-3 col-md-6 mb-4">
              <div className="card border-left-warning shadow h-100 py-2">
                <div className="card-body">
                  <div className="row no-gutters align-items-center">
                    <div className="col mr-2">
                      <div className="text-xs font-weight-bold text-warning text-uppercase mb-1">
                        Active Employees
                      </div>
                      <div className="h5 mb-0 font-weight-bold text-gray-800">
                        {adminStats.activeEmployees}
                      </div>
                    </div>
                    <div className="col-auto">
                      <i className="fas fa-users fa-2x text-gray-300"></i>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Row 4: News & Updates and Activity Logs */}
          <div className="row">
            {/* Activity Logs Section */}
            <div className="col-lg-6">
              <div className="card shadow h-100 mb-4">
                <div className="card-header py-3 d-flex flex-row align-items-center justify-content-between">
                  <h6 className="m-0 font-weight-bold text-primary">Recent Activity</h6>
                  <button className="btn btn-sm btn-primary" onClick={downloadLogs}>
                    <i className="fas fa-download fa-sm"></i> Download Logs
                  </button>
                </div>
                <div className="card-body">
                  <div className="activity-timeline">
                    {activityLogs.slice(0, 5).map((log) => (
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
                </div>
              </div>
            </div>
            {/* News & Updates Section */}
            <div className="col-lg-6">
              <div className="card shadow h-100 mb-4">
                <div className="card-header py-3 d-flex flex-row align-items-center justify-content-between">
                  <h6 className="m-0 font-weight-bold text-primary">News & Updates</h6>
                  {companyUpdates.length > 0 && (
                    <span className="badge bg-primary rounded-pill">{companyUpdates.length}</span>
                  )}
                </div>
                <div className="card-body">
                  <div className="company-updates">
                    {companyUpdates.length === 0 ? (
                      <div className="text-center py-4">
                        <p className="text-muted">No updates available</p>
                      </div>
                    ) : (
                      companyUpdates.map(update => (
                        <div key={update.id} className={`card mb-3 ${update.important ? 'border-left-warning' : 'border-left-primary'}`}>
                          <div className="card-body py-2">
                            <div className="row no-gutters align-items-center">
                              <div className="col mr-2">
                                <div className="d-flex justify-content-between align-items-center">
                                  <div className="text-xs font-weight-bold text-primary text-uppercase mb-1">
                                    {update.date}
                                  </div>
                                  {update.important && (
                                    <div className="badge bg-warning text-dark">Important</div>
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
                      ))
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </RoleLayout>
    );
  }

  // -------------------- ADMIN DASHBOARD --------------------
  if (role === 'admin') {
    return (
      <RoleLayout role={role}>
        <div className="admin-dashboard">
          {/* First Row - Admin Dashboard Header */}
          <div className="row">
            <div className="col-12">
              <div className="d-sm-flex align-items-center justify-content-between mb-4">
                <h1 className="h3 mb-0 text-gray-800">Admin Dashboard</h1>
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
            </div>
          </div>

          {/* Second Row - Notification Area */}
          <div className="row">
            <div className="col-12">
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
            </div>
          </div>
          {/* Third Row - Admin Stats Cards */}
          <div className="row mb-4">
            <div className="col-xl-3 col-md-6 mb-4">
              <div className="card border-left-primary shadow h-100 py-2">
                <div className="card-body">
                  <div className="row no-gutters align-items-center">
                    <div className="col mr-2">
                      <div className="text-xs font-weight-bold text-primary text-uppercase mb-1">
                        Pending Applications
                      </div>
                      <div className="h5 mb-0 font-weight-bold text-gray-800">
                        {adminStats.pendingApplications}
                      </div>
                    </div>
                    <div className="col-auto">
                      <i className="fas fa-clipboard-list fa-2x text-gray-300"></i>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="col-xl-3 col-md-6 mb-4">
              <div className="card border-left-success shadow h-100 py-2">
                <div className="card-body">
                  <div className="row no-gutters align-items-center">
                    <div className="col mr-2">
                      <div className="text-xs font-weight-bold text-success text-uppercase mb-1">
                        Processed Today
                      </div>
                      <div className="h5 mb-0 font-weight-bold text-gray-800">
                        {adminStats.processedToday}
                      </div>
                    </div>
                    <div className="col-auto">
                      <i className="fas fa-check-circle fa-2x text-gray-300"></i>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="col-xl-3 col-md-6 mb-4">
              <div className="card border-left-info shadow h-100 py-2">
                <div className="card-body">
                  <div className="row no-gutters align-items-center">
                    <div className="col mr-2">
                      <div className="text-xs font-weight-bold text-info text-uppercase mb-1">
                        Active Admins
                      </div>
                      <div className="h5 mb-0 font-weight-bold text-gray-800">
                        {adminStats.activeAdmins}
                      </div>
                    </div>
                    <div className="col-auto">
                      <i className="fas fa-user-shield fa-2x text-gray-300"></i>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="col-xl-3 col-md-6 mb-4">
              <div className="card border-left-warning shadow h-100 py-2">
                <div className="card-body">
                  <div className="row no-gutters align-items-center">
                    <div className="col mr-2">
                      <div className="text-xs font-weight-bold text-warning text-uppercase mb-1">
                        Active Employees
                      </div>
                      <div className="h5 mb-0 font-weight-bold text-gray-800">
                        {adminStats.activeEmployees}
                      </div>
                    </div>
                    <div className="col-auto">
                      <i className="fas fa-users fa-2x text-gray-300"></i>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Fourth Row - Recent Activity & Company Updates (swapped) */}
          <div className="row">
            {/* Activity Logs Section (now first) */}
            <div className="col-lg-6">
              <div className="card shadow h-100 mb-4">
                <div className="card-header py-3 d-flex flex-row align-items-center justify-content-between">
                  <h6 className="m-0 font-weight-bold text-primary">Recent Activity</h6>
                  <button className="btn btn-sm btn-primary" onClick={downloadLogs}>
                    <i className="fas fa-download fa-sm"></i> Download Logs
                  </button>
                </div>
                <div className="card-body">
                  <div className="activity-timeline">
                    {activityLogs.map((log) => (
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
                </div>
              </div>
            </div>
            {/* News & Updates Section (now second) */}
            <div className="col-lg-6">
              <div className="card shadow h-100 mb-4">
                <div className="card-header py-3 d-flex flex-row align-items-center justify-content-between">
                  <h6 className="m-0 font-weight-bold text-primary">News & Updates</h6>
                  {companyUpdates.length > 0 && (
                    <span className="badge bg-primary rounded-pill">{companyUpdates.length}</span>
                  )}
                </div>
                <div className="card-body">
                  <div className="company-updates">
                    {companyUpdates.length === 0 ? (
                      <div className="text-center py-4">
                        <p className="text-muted">No updates available</p>
                      </div>
                    ) : (
                      companyUpdates.map(update => (
                        <div key={update.id} className={`card mb-3 ${update.important ? 'border-left-warning' : 'border-left-primary'}`}>
                          <div className="card-body py-2">
                            <div className="row no-gutters align-items-center">
                              <div className="col mr-2">
                                <div className="d-flex justify-content-between align-items-center">
                                  <div className="text-xs font-weight-bold text-primary text-uppercase mb-1">
                                    {update.date}
                                  </div>
                                  {update.important && (
                                    <div className="badge bg-warning text-dark">Important</div>
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
                      ))
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </RoleLayout>
    );
  }

  // -------------------- SUPER ADMIN DASHBOARD --------------------
  return (
    <RoleLayout role={role}>
      <div className="super-admin-dashboard">
        {/* First Row - Dashboard Header */}
        <div className="row">
          <div className="col-12">
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
          </div>
        </div>

        {/* Second Row - Notification area */}
        <div className="row">
          <div className="col-12">
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
          </div>
        </div>
        {/* Third Row - Combined Active Users and System Status */}
        <div className="row mb-4">
          {/* Active Users Card */}
          <div className="col-xl-6 col-md-6 mb-4 mb-xl-0">
            <div className="card shadow h-100">
              <div className="card-header py-3 d-flex flex-row align-items-center justify-content-between">
                <h6 className="m-0 font-weight-bold text-primary">Active Users</h6>
              </div>
              <div className="card-body">
                <div className="row">
                  {/* Active Admins Card */}
                  <div className="col-md-6 mb-4 mb-md-0">
                    <div className="card h-100 border-left-primary shadow py-2">
                      <div className="card-body">
                        <div className="row no-gutters align-items-center">
                          <div className="col mr-2">
                            <div className="text-xs font-weight-bold text-primary text-uppercase mb-1">
                              Active Admins
                            </div>
                            <div className="h5 mb-0 font-weight-bold text-gray-800">12</div>
                          </div>
                          <div className="col-auto">
                            <i className="fas fa-user-shield fa-2x text-gray-300"></i>
                          </div>
                        </div>
                        <div className="mt-3 pt-3 border-top">
                          <div className="d-flex justify-content-between align-items-center mb-1">
                            <span className="small text-muted">Currently Online:</span>
                            <span className="small font-weight-bold text-success">8</span>
                          </div>
                          <div className="d-flex justify-content-between align-items-center">
                            <span className="small text-muted">Last Login:</span>
                            <span className="small">3 minutes ago</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Active Employees Card */}
                  <div className="col-md-6">
                    <div className="card h-100 border-left-success shadow py-2">
                      <div className="card-body">
                        <div className="row no-gutters align-items-center">
                          <div className="col mr-2">
                            <div className="text-xs font-weight-bold text-success text-uppercase mb-1">
                              Active Employees
                            </div>
                            <div className="h5 mb-0 font-weight-bold text-gray-800">47</div>
                          </div>
                          <div className="col-auto">
                            <i className="fas fa-users fa-2x text-gray-300"></i>
                          </div>
                        </div>
                        <div className="mt-3 pt-3 border-top">
                          <div className="d-flex justify-content-between align-items-center mb-1">
                            <span className="small text-muted">Currently Online:</span>
                            <span className="small font-weight-bold text-success">8</span>
                          </div>
                          <div className="d-flex justify-content-between align-items-center">
                            <span className="small text-muted">Last Login:</span>
                            <span className="small">3 minutes ago</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* System Status Card */}
          <div className="col-xl-6 col-md-6">
            <div className="card shadow h-100">
              <div className="card-header py-3">
                <h6 className="m-0 font-weight-bold text-primary">System Status</h6>
              </div>
              <div className="card-body">
                <div className="row align-items-center h-100">
                  <div className="col-xl-4 col-md-12 mb-4 mb-xl-0">
                    <div className="text-center">
                      <div className="mb-2 text-xs text-uppercase fw-bold text-primary">System Status</div>
                      <div className="h1 text-success mb-0">Online</div>
                    </div>
                  </div>
                  <div className="col-xl-8 col-md-12">
                    <ul className="list-group list-group-flush">
                      <li className="list-group-item d-flex justify-content-between align-items-center px-0">
                        <span>System Uptime:</span>
                        <span className="text-primary">{systemStats.uptime}</span>
                      </li>
                      <li className="list-group-item d-flex justify-content-between align-items-center px-0">
                        <span>Last Backup:</span>
                        <span className="text-primary">{systemStats.lastBackup}</span>
                      </li>
                      <li className="list-group-item d-flex justify-content-between align-items-center px-0">
                        <span>Server Status:</span>
                        <span className="badge bg-success rounded-pill">{systemStats.status}</span>
                      </li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        {/* Fourth Row - Combined News & Updates and Recent Activity */}
        <div className="row">
          {/* Recent Activity Card */}
          <div className="col-xl-6 col-md-6 mb-4 mb-xl-0">
            <div className="card shadow h-100">
              <div className="card-header py-3 d-flex flex-row align-items-center justify-content-between">
                <h6 className="m-0 font-weight-bold text-primary">Recent Activity</h6>
                <button className="btn btn-sm btn-primary" onClick={downloadLogs}>
                  <i className="fas fa-download fa-sm"></i> Download Logs
                </button>
              </div>
              <div className="card-body">
                <div className="activity-timeline">
                  {activityLogs.map((log) => (
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
              </div>
            </div>
          </div>

          {/* News & Updates Card */}
          <div className="col-xl-6 col-md-6">
            <div className="card shadow h-100">
              <div className="card-header py-3 d-flex flex-row align-items-center justify-content-between">
                <h6 className="m-0 font-weight-bold text-primary">News & Updates</h6>
                <div className="d-flex align-items-center">
                  {companyUpdates.length > 0 && (
                    <span className="badge bg-primary rounded-pill me-2">{companyUpdates.length}</span>
                  )}
                  <a href="/system-management" className="btn btn-sm btn-outline-primary">
                    <i className="fas fa-plus fa-sm"></i> Manage Updates
                  </a>
                </div>
              </div>
              <div className="card-body">
                <div className="company-updates">
                  {companyUpdates.length === 0 ? (
                    <div className="text-center py-4">
                      <p className="text-muted">No updates available</p>
                    </div>
                  ) : (
                    companyUpdates.map(update => (
                      <div key={update.id} className={`card mb-3 ${update.important ? 'border-left-warning' : 'border-left-primary'}`}>
                        <div className="card-body py-2">
                          <div className="row no-gutters align-items-center">
                            <div className="col mr-2">
                              <div className="d-flex justify-content-between align-items-center">
                                <div className="text-xs font-weight-bold text-primary text-uppercase mb-1">
                                  {update.date}
                                </div>
                                {update.important && (
                                  <div className="badge bg-warning text-dark">Important</div>
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
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </RoleLayout>
  );
};

export default Dashboard;
