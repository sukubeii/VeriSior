import React, { useState } from 'react';
import RoleLayout from '../common/RoleLayout';

const IDManagement = ({ role }) => {
  const [notifications, setNotifications] = useState([]);
  const [activeTab, setActiveTab] = useState('new');
  const [searchQuery, setSearchQuery] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');
  const [dateFilter, setDateFilter] = useState('');

  const [newApplications, setNewApplications] = useState([
    {
      id: 'SC-2024-001',
      name: 'Juan Dela Cruz',
      status: 'Pending',
      dateApplied: '2024-04-01',
      type: 'New'
    },
    {
      id: 'SC-2024-002',
      name: 'Maria Santos',
      status: 'Approved',
      dateApplied: '2024-04-02',
      type: 'New'
    }
  ]);
  
  const [renewalApplications, setRenewalApplications] = useState([
    {
      id: 'SC-2024-003',
      name: 'Pedro Reyes',
      status: 'Pending',
      dateApplied: '2024-04-03',
      type: 'Renewal',
      previousID: 'SC-2023-045'
    },
    {
      id: 'SC-2024-004',
      name: 'Ana Garcia',
      status: 'Approved',
      dateApplied: '2024-04-04',
      type: 'Renewal',
      previousID: 'SC-2023-032'
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
  const handleApproveID = (id, isRenewal) => {
    const updateApplications = (applications, setApplications) => {
      setApplications(prev => 
        prev.map(app => 
          app.id === id ? { ...app, status: 'Approved' } : app
        )
      );
    };

    if (isRenewal) {
      updateApplications(renewalApplications, setRenewalApplications);
    } else {
      updateApplications(newApplications, setNewApplications);
    }
    showNotification(`ID ${id} has been approved`, 'success');
  };

  const handleRejectID = (id, isRenewal) => {
    const updateApplications = (applications, setApplications) => {
      setApplications(prev => 
        prev.map(app => 
          app.id === id ? { ...app, status: 'Rejected' } : app
        )
      );
    };

    if (isRenewal) {
      updateApplications(renewalApplications, setRenewalApplications);
    } else {
      updateApplications(newApplications, setNewApplications);
    }
    showNotification(`ID ${id} has been rejected`, 'danger');
  };

  const handleRevokeID = (id, isRenewal) => {
    const updateApplications = (applications, setApplications) => {
      setApplications(prev => 
        prev.map(app => 
          app.id === id ? { ...app, status: 'Revoked' } : app
        )
      );
    };

    if (isRenewal) {
      updateApplications(renewalApplications, setRenewalApplications);
    } else {
      updateApplications(newApplications, setNewApplications);
    }
    showNotification(`ID ${id} has been revoked`, 'warning');
  };

  const handleViewID = (id) => {
    showNotification(`Viewing details for ID ${id}`);
  };

  const handlePrintID = (id) => {
    // In a real application, this would generate a PDF with the ID card
    // using the approved template and applicant information
    showNotification('Generating ID card...', 'info');

    // Simulate ID generation delay
    setTimeout(() => {
      // Create a dummy ID card data
      const idCardData = {
        id: id,
        template: "Standard ID Card",
        applicantName: newApplications.find(app => app.id === id)?.name || "Unknown",
        dateGenerated: new Date().toISOString(),
        qrCode: `https://verisior.com/verify/${id}`
      };

      // Create a simple HTML representation of the ID card
      const idCardHTML = `
        <html>
          <head>
            <title>ID Card - ${id}</title>
            <style>
              body { font-family: Arial, sans-serif; }
              .id-card {
                width: 3.375in;
                height: 2.125in;
                border: 1px solid #000;
                padding: 20px;
                margin: 20px;
                position: relative;
              }
              .id-card h2 { margin: 0 0 10px 0; }
              .id-card p { margin: 5px 0; }
              .qr-code {
                position: absolute;
                right: 20px;
                top: 20px;
                width: 60px;
                height: 60px;
                border: 1px solid #000;
                display: flex;
                align-items: center;
                justify-content: center;
              }
            </style>
          </head>
          <body>
            <div class="id-card">
              <h2>VERISIOR ID CARD</h2>
              <p><strong>ID:</strong> ${idCardData.id}</p>
              <p><strong>Name:</strong> ${idCardData.applicantName}</p>
              <p><strong>Date:</strong> ${new Date().toLocaleDateString()}</p>
              <div class="qr-code">QR</div>
            </div>
          </body>
        </html>
      `;

      // Create a new window for printing
      const printWindow = window.open('', '_blank');
      printWindow.document.write(idCardHTML);
      printWindow.document.close();

      // Print the window
      setTimeout(() => {
        printWindow.print();
        printWindow.close();
        showNotification(`ID ${id} has been sent to printer`, 'success');
      }, 500);
    }, 1500);
  };

  const handleAddNewApplication = () => {
    const newID = {
      id: `SC-2024-00${newApplications.length + renewalApplications.length + 1}`,
      name: 'New Applicant',
      status: 'Pending',
      dateApplied: new Date().toISOString().split('T')[0],
      type: activeTab === 'renewal' ? 'Renewal' : 'New'
    };

    if (activeTab === 'renewal') {
      setRenewalApplications(prev => [newID, ...prev]);
    } else {
      setNewApplications(prev => [newID, ...prev]);
    }
    showNotification('New application added', 'success');
  };

  const handleSearchChange = (e) => {
    setSearchQuery(e.target.value);
  };

  const handleStatusFilterChange = (e) => {
    setFilterStatus(e.target.value);
  };

  const handleDateFilterChange = (e) => {
    setDateFilter(e.target.value);
  };

  const filterApplications = (applications) => {
    return applications.filter(app => {
      const matchesSearch = app.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          app.id.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesStatus = filterStatus === 'all' || app.status.toLowerCase() === filterStatus.toLowerCase();
      const matchesDate = !dateFilter || app.dateApplied === dateFilter;

      return matchesSearch && matchesStatus && matchesDate;
    });
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
    if (role !== "admin") {
      return (
        <div className="alert alert-danger">
          You don't have permission to access this page.
        </div>
      );
    }

    const filteredApplications = activeTab === 'renewal' 
      ? filterApplications(renewalApplications)
      : filterApplications(newApplications);

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

        {/* Tabs */}
        <div className="mb-4">
          <ul className="nav nav-tabs">
            <li className="nav-item">
              <button
                className={`nav-link ${activeTab === 'new' ? 'active' : ''}`}
                onClick={() => setActiveTab('new')}
              >
                New Applications
              </button>
            </li>
            <li className="nav-item">
              <button
                className={`nav-link ${activeTab === 'renewal' ? 'active' : ''}`}
                onClick={() => setActiveTab('renewal')}
              >
                Renewals
              </button>
            </li>
          </ul>
        </div>
        
        <div className="card">
          <div className="card-body">
            <div className="d-flex justify-content-between align-items-center mb-4">
              <h5 className="card-title mb-0">
                {activeTab === 'renewal' ? 'ID Renewal Applications' : 'New ID Applications'}
              </h5>
            </div>

            {/* Filters */}
            <div className="row mb-4">
              <div className="col-md-4">
                <div className="input-group">
                  <input
                    type="text"
                    className="form-control"
                    placeholder="Search by name or ID..."
                    value={searchQuery}
                    onChange={handleSearchChange}
                  />
                  <button className="btn btn-primary">
                    <i className="fas fa-search"></i>
                  </button>
                </div>
              </div>
              <div className="col-md-4">
                <select
                  className="form-control"
                  value={filterStatus}
                  onChange={handleStatusFilterChange}
                >
                  <option value="all">All Status</option>
                  <option value="pending">Pending</option>
                  <option value="approved">Approved</option>
                  <option value="rejected">Rejected</option>
                  <option value="revoked">Revoked</option>
                </select>
              </div>
              <div className="col-md-4">
                <input
                  type="date"
                  className="form-control"
                  value={dateFilter}
                  onChange={handleDateFilterChange}
                  placeholder="Filter by date"
                />
              </div>
            </div>

            <div className="table-responsive">
              <table className="table table-hover">
                <thead>
                  <tr>
                    <th>ID Number</th>
                    <th>Name</th>
                    {activeTab === 'renewal' && <th>Previous ID</th>}
                    <th>Status</th>
                    <th>Date Applied</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredApplications.map(app => (
                    <tr key={app.id}>
                      <td>{app.id}</td>
                      <td>{app.name}</td>
                      {activeTab === 'renewal' && <td>{app.previousID}</td>}
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
                              onClick={() => handleApproveID(app.id, activeTab === 'renewal')}
                            >
                              Approve
                            </button>
                            <button 
                              className="btn btn-sm btn-danger"
                              onClick={() => handleRejectID(app.id, activeTab === 'renewal')}
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
                              Print ID
                            </button>
                            <button 
                              className="btn btn-sm btn-danger"
                              onClick={() => handleRevokeID(app.id, activeTab === 'renewal')}
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
  };

  return (
    <RoleLayout role={role}>
      {getIDManagementContent()}
    </RoleLayout>
  );
};

export default IDManagement;
