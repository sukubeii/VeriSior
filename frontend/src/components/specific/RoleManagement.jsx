import React, { useState } from 'react';
import RoleLayout from '../common/RoleLayout';

const RoleManagement = ({ role }) => {
  const [notifications, setNotifications] = useState([]);
  const [roles, setRoles] = useState([
    {
      name: 'Super Admin',
      description: 'Full system access and control',
      userCount: 3,
      createdDate: 'Jan 10, 2024'
    },
    {
      name: 'Admin',
      description: 'ID management and employee oversight',
      userCount: 12,
      createdDate: 'Jan 10, 2024'
    },
    {
      name: 'Employee',
      description: 'Basic ID processing capabilities',
      userCount: 45,
      createdDate: 'Jan 10, 2024'
    }
  ]);
  
  const [showNewRoleModal, setShowNewRoleModal] = useState(false);
  const [showEditRoleModal, setShowEditRoleModal] = useState(false);
  const [currentEditRole, setCurrentEditRole] = useState(null);
  const [newRoleData, setNewRoleData] = useState({
    name: '',
    description: ''
  });

  // Function to handle notifications
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

  // Role functions
  const handleAddRole = () => {
    setShowNewRoleModal(true);
  };

  const handleEditRole = (roleName) => {
    const roleToEdit = roles.find(r => r.name === roleName);
    if (roleToEdit) {
      setCurrentEditRole(roleToEdit);
      setNewRoleData({
        name: roleToEdit.name,
        description: roleToEdit.description
      });
      setShowEditRoleModal(true);
    }
  };

  const handleDeleteRole = (roleName) => {
    if (roleName === 'Super Admin') {
      showNotification('Cannot delete Super Admin role', 'danger');
      return;
    }
    
    setRoles(prev => prev.filter(r => r.name !== roleName));
    showNotification(`Role "${roleName}" has been deleted`, 'success');
  };

  const handleSaveNewRole = () => {
    if (!newRoleData.name || !newRoleData.description) {
      showNotification('Please fill in all fields', 'warning');
      return;
    }
    
    const newRole = {
      name: newRoleData.name,
      description: newRoleData.description,
      userCount: 0,
      createdDate: new Date().toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      })
    };
    
    setRoles(prev => [...prev, newRole]);
    showNotification(`New role "${newRole.name}" created successfully`, 'success');
    setShowNewRoleModal(false);
    setNewRoleData({ name: '', description: '' });
  };

  const handleUpdateRole = () => {
    if (!newRoleData.name || !newRoleData.description) {
      showNotification('Please fill in all fields', 'warning');
      return;
    }
    
    setRoles(prev => 
      prev.map(r => 
        r.name === currentEditRole.name 
          ? { ...r, name: newRoleData.name, description: newRoleData.description }
          : r
      )
    );
    
    showNotification(`Role "${currentEditRole.name}" updated successfully`, 'success');
    setShowEditRoleModal(false);
    setCurrentEditRole(null);
    setNewRoleData({ name: '', description: '' });
  };
  
  // This component is only accessible to superAdmin
  const getRoleManagementContent = () => {
    if (role !== "superAdmin") {
      return (
        <div className="alert alert-danger">
          You don't have permission to access this page.
        </div>
      );
    }
    
    return (
      <div className="role-management-content">
        <h1 className="mb-4">Role Management</h1>
        
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
        
        <div className="card mb-4">
          <div className="card-header d-flex justify-content-between align-items-center">
            <h5 className="mb-0">System Roles</h5>
            <button className="btn btn-primary" onClick={handleAddRole}>Add New Role</button>
          </div>
          <div className="card-body">
            <div className="table-responsive">
              <table className="table table-hover">
                <thead>
                  <tr>
                    <th>Role Name</th>
                    <th>Description</th>
                    <th>Users Count</th>
                    <th>Created Date</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {roles.map((role, index) => (
                    <tr key={index}>
                      <td>{role.name}</td>
                      <td>{role.description}</td>
                      <td>{role.userCount}</td>
                      <td>{role.createdDate}</td>
                      <td>
                        <button 
                          className="btn btn-sm btn-info me-2"
                          onClick={() => handleEditRole(role.name)}
                        >
                          Edit
                        </button>
                        <button 
                          className="btn btn-sm btn-danger"
                          onClick={() => handleDeleteRole(role.name)}
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
        
        <div className="card">
          <div className="card-header">
            <h5 className="mb-0">Role Permissions</h5>
          </div>
          <div className="card-body">
            <div className="table-responsive">
              <table className="table table-hover">
                <thead>
                  <tr>
                    <th>Permission</th>
                    <th>Super Admin</th>
                    <th>Admin</th>
                    <th>Employee</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>Dashboard Access</td>
                    <td><span className="badge bg-success">✓</span></td>
                    <td><span className="badge bg-success">✓</span></td>
                    <td><span className="badge bg-success">✓</span></td>
                  </tr>
                  <tr>
                    <td>User Management</td>
                    <td><span className="badge bg-success">✓</span></td>
                    <td><span className="badge bg-danger">✕</span></td>
                    <td><span className="badge bg-danger">✕</span></td>
                  </tr>
                  <tr>
                    <td>Role Management</td>
                    <td><span className="badge bg-success">✓</span></td>
                    <td><span className="badge bg-danger">✕</span></td>
                    <td><span className="badge bg-danger">✕</span></td>
                  </tr>
                  <tr>
                    <td>ID Processing</td>
                    <td><span className="badge bg-success">✓</span></td>
                    <td><span className="badge bg-success">✓</span></td>
                    <td><span className="badge bg-success">✓</span></td>
                  </tr>
                  <tr>
                    <td>ID Approval</td>
                    <td><span className="badge bg-success">✓</span></td>
                    <td><span className="badge bg-success">✓</span></td>
                    <td><span className="badge bg-danger">✕</span></td>
                  </tr>
                  <tr>
                    <td>System Settings</td>
                    <td><span className="badge bg-success">✓</span></td>
                    <td><span className="badge bg-success">✓</span></td>
                    <td><span className="badge bg-danger">✕</span></td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
        
        {/* New Role Modal */}
        {showNewRoleModal && (
          <div className="modal" style={{ display: 'block', backgroundColor: 'rgba(0,0,0,0.5)' }}>
            <div className="modal-dialog">
              <div className="modal-content">
                <div className="modal-header">
                  <h5 className="modal-title">Add New Role</h5>
                  <button 
                    type="button" 
                    className="btn-close" 
                    onClick={() => setShowNewRoleModal(false)}
                  ></button>
                </div>
                <div className="modal-body">
                  <div className="mb-3">
                    <label className="form-label">Role Name</label>
                    <input 
                      type="text" 
                      className="form-control"
                      value={newRoleData.name}
                      onChange={(e) => setNewRoleData(prev => ({ ...prev, name: e.target.value }))}
                    />
                  </div>
                  <div className="mb-3">
                    <label className="form-label">Description</label>
                    <textarea 
                      className="form-control"
                      value={newRoleData.description}
                      onChange={(e) => setNewRoleData(prev => ({ ...prev, description: e.target.value }))}
                    ></textarea>
                  </div>
                </div>
                <div className="modal-footer">
                  <button 
                    type="button" 
                    className="btn btn-secondary" 
                    onClick={() => setShowNewRoleModal(false)}
                  >
                    Cancel
                  </button>
                  <button 
                    type="button" 
                    className="btn btn-primary"
                    onClick={handleSaveNewRole}
                  >
                    Save Role
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
        
        {/* Edit Role Modal */}
        {showEditRoleModal && (
          <div className="modal" style={{ display: 'block', backgroundColor: 'rgba(0,0,0,0.5)' }}>
            <div className="modal-dialog">
              <div className="modal-content">
                <div className="modal-header">
                  <h5 className="modal-title">Edit Role</h5>
                  <button 
                    type="button" 
                    className="btn-close" 
                    onClick={() => setShowEditRoleModal(false)}
                  ></button>
                </div>
                <div className="modal-body">
                  <div className="mb-3">
                    <label className="form-label">Role Name</label>
                    <input 
                      type="text" 
                      className="form-control"
                      value={newRoleData.name}
                      onChange={(e) => setNewRoleData(prev => ({ ...prev, name: e.target.value }))}
                    />
                  </div>
                  <div className="mb-3">
                    <label className="form-label">Description</label>
                    <textarea 
                      className="form-control"
                      value={newRoleData.description}
                      onChange={(e) => setNewRoleData(prev => ({ ...prev, description: e.target.value }))}
                    ></textarea>
                  </div>
                </div>
                <div className="modal-footer">
                  <button 
                    type="button" 
                    className="btn btn-secondary" 
                    onClick={() => setShowEditRoleModal(false)}
                  >
                    Cancel
                  </button>
                  <button 
                    type="button" 
                    className="btn btn-primary"
                    onClick={handleUpdateRole}
                  >
                    Update Role
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  };

  return (
    <RoleLayout role={role}>
      {getRoleManagementContent()}
    </RoleLayout>
  );
};

export default RoleManagement;
