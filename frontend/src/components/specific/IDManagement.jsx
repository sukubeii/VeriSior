import React, { useState } from 'react';
import RoleLayout from '../common/RoleLayout';

const IDManagement = ({ role }) => {
  const [notifications, setNotifications] = useState([]);
  const [applications, setApplications] = useState([
    {
      id: 'SC-2024-001',
      name: 'Juan Dela Cruz',
      status: 'Pending',
      dateApplied: '2024-04-01'
    },
    {
      id: 'SC-2024-002',
      name: 'Maria Santos',
      status: 'Approved',
      dateApplied: '2024-04-02'
    }
  ]);
  
  const [tasks, setTasks] = useState([
    {
      id: 'T-2024-001',
      applicantName: 'Maria Santos',
      status: 'In Progress',
      assignedDate: '2024-04-01'
    },
    {
      id: 'T-2024-002',
      applicantName: 'Pedro Reyes',
      status: 'Pending',
      assignedDate: '2024-04-03'
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

  // Admin functions
  const handleApproveID = (id) => {
    setApplications(prev => 
      prev.map(app => 
        app.id === id ? { ...app, status: 'Approved' } : app
      )
    );
    showNotification(`ID ${id} has been approved`, 'success');
  };

  const handleRejectID = (id) => {
    setApplications(prev => 
      prev.map(app => 
        app.id === id ? { ...app, status: 'Rejected' } : app
      )
    );
    showNotification(`ID ${id} has been rejected`, 'danger');
  };

  const handleRevokeID = (id) => {
    setApplications(prev => 
      prev.map(app => 
        app.id === id ? { ...app, status: 'Revoked' } : app
      )
    );
    showNotification(`ID ${id} has been revoked`, 'warning');
  };

  const handleViewID = (id) => {
    showNotification(`Viewing details for ID ${id}`);
  };

  const handlePrintID = (id) => {
    showNotification(`Printing ID ${id}`, 'info');
  };

  const handleAddNewID = () => {
    const newID = {
      id: `SC-2024-00${applications.length + 1}`,
      name: 'New Applicant',
      status: 'Pending',
      dateApplied: '2024-04-09'
    };
    setApplications(prev => [newID, ...prev]);
    showNotification('New ID application added', 'success');
  };

  // Employee functions
  const handleStartTask = (id) => {
    setTasks(prev => 
      prev.map(task => 
        task.id === id ? { ...task, status: 'In Progress' } : task
      )
    );
    showNotification(`Task ${id} started`, 'success');
  };

  const handleProcessTask = (id) => {
    setTasks(prev => 
      prev.map(task => 
        task.id === id ? { ...task, status: 'Completed' } : task
      )
    );
    showNotification(`Task ${id} completed`, 'success');
  };

  const handleViewTaskDetails = (id) => {
    showNotification(`Viewing details for task ${id}`);
  };

  const handleStartNewTask = () => {
    const newTask = {
      id: `T-2024-00${tasks.length + 1}`,
      applicantName: 'New Applicant',
      status: 'Pending',
      assignedDate: '2024-04-09'
    };
    setTasks(prev => [newTask, ...prev]);
    showNotification('New task added', 'success');
  };

  const getIDManagementContent = () => {
    switch (role) {
      case "admin":
        return (
          <div className="id-management-content">
            <h1 className="mb-4">ID Management</h1>
            
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
            
            <div className="card">
              <div className="card-body">
                <div className="d-flex justify-content-between align-items-center mb-4">
                  <h5 className="card-title mb-0">ID Applications</h5>
                  <button className="btn btn-primary" onClick={handleAddNewID}>Add New ID</button>
                </div>
                <div className="table-responsive">
                  <table className="table table-hover">
                    <thead>
                      <tr>
                        <th>ID Number</th>
                        <th>Name</th>
                        <th>Status</th>
                        <th>Date Applied</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {applications.map(app => (
                        <tr key={app.id}>
                          <td>{app.id}</td>
                          <td>{app.name}</td>
                          <td>
                            <span className={`badge bg-${
                              app.status === 'Approved' ? 'success' : 
                              app.status === 'Pending' ? 'warning' : 
                              app.status === 'Rejected' ? 'danger' : 
                              'secondary'
                            }`}>
                              {app.status}
                            </span>
                          </td>
                          <td>{app.dateApplied}</td>
                          <td>
                            <button 
                              className="btn btn-sm btn-info me-2"
                              onClick={() => handleViewID(app.id)}
                            >
                              View
                            </button>
                            
                            {app.status === 'Pending' && (
                              <>
                                <button 
                                  className="btn btn-sm btn-success me-2"
                                  onClick={() => handleApproveID(app.id)}
                                >
                                  Approve
                                </button>
                                <button 
                                  className="btn btn-sm btn-danger"
                                  onClick={() => handleRejectID(app.id)}
                                >
                                  Reject
                                </button>
                              </>
                            )}
                            
                            {app.status === 'Approved' && (
                              <>
                                <button 
                                  className="btn btn-sm btn-secondary me-2"
                                  onClick={() => handlePrintID(app.id)}
                                >
                                  Print
                                </button>
                                <button 
                                  className="btn btn-sm btn-danger"
                                  onClick={() => handleRevokeID(app.id)}
                                >
                                  Revoke
                                </button>
                              </>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        );
      case "employee":
        return (
          <div className="id-processing-content">
            <h1 className="mb-4">ID Processing</h1>
            
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
            
            <div className="card">
              <div className="card-body">
                <div className="d-flex justify-content-between align-items-center mb-4">
                  <h5 className="card-title mb-0">My Tasks</h5>
                  <button 
                    className="btn btn-primary"
                    onClick={handleStartNewTask}
                  >
                    Start New Task
                  </button>
                </div>
                <div className="table-responsive">
                  <table className="table table-hover">
                    <thead>
                      <tr>
                        <th>Task ID</th>
                        <th>Applicant Name</th>
                        <th>Status</th>
                        <th>Assigned Date</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {tasks.map(task => (
                        <tr key={task.id}>
                          <td>{task.id}</td>
                          <td>{task.applicantName}</td>
                          <td>
                            <span className={`badge bg-${
                              task.status === 'Completed' ? 'success' : 
                              task.status === 'In Progress' ? 'info' : 
                              'warning'
                            }`}>
                              {task.status}
                            </span>
                          </td>
                          <td>{task.assignedDate}</td>
                          <td>
                            {task.status === 'In Progress' && (
                              <button 
                                className="btn btn-sm btn-primary me-2"
                                onClick={() => handleProcessTask(task.id)}
                              >
                                Complete
                              </button>
                            )}
                            
                            {task.status === 'Pending' && (
                              <button 
                                className="btn btn-sm btn-primary me-2"
                                onClick={() => handleStartTask(task.id)}
                              >
                                Start
                              </button>
                            )}
                            
                            <button 
                              className="btn btn-sm btn-secondary"
                              onClick={() => handleViewTaskDetails(task.id)}
                            >
                              Details
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        );
      default:
        return (
          <div className="alert alert-danger">
            You don't have permission to access this page.
          </div>
        );
    }
  };

  return (
    <RoleLayout role={role}>
      {getIDManagementContent()}
    </RoleLayout>
  );
};

export default IDManagement;
