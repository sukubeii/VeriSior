import React, { useState } from 'react';
import RoleLayout from '../common/RoleLayout';

const RoleManagement = ({ role }) => {
  const [notifications, setNotifications] = useState([]);
  const [roles, setRoles] = useState([
    {
      name: 'Super Admin',
      description: 'Full system access and control',
      userCount: 1,
      createdDate: 'Jan 10, 2024',
      permissions: {
        dashboard: true,
        profile: true,
        roleManagement: true,
        userManagement: true,
        idTemplate: true,
        systemManagement: true,
        settings: true,
        idManagement: true,
        pageManagement: true,
        employeeManagement: true,
        idProcessing: false,
        customerService: false
      }
    },
    {
      name: 'Admin',
      description: 'ID management and employee oversight',
      userCount: 12,
      createdDate: 'Jan 10, 2024',
      permissions: {
        dashboard: true,
        profile: true,
        roleManagement: true,
        userManagement: true,
        idTemplate: true,
        systemManagement: false, // This is the permission we'll be toggling as an example
        settings: true,
        idManagement: true,
        pageManagement: true,
        employeeManagement: true,
        idProcessing: false,
        customerService: false
      }
    },
    {
      name: 'Employee',
      description: 'Basic ID processing capabilities',
      userCount: 45,
      createdDate: 'Jan 10, 2024',
      permissions: {
        dashboard: true,
        profile: true,
        roleManagement: false,
        userManagement: false,
        idTemplate: false,
        systemManagement: false,
        settings: true,
        idManagement: false,
        pageManagement: false,
        employeeManagement: false,
        idProcessing: true,
        customerService: true
      }
    }
  ]);
  
  // Define all available permissions and their display names
  const allPermissions = [
    { key: 'dashboard', display: 'Dashboard Access' },
    { key: 'profile', display: 'Profile Access' },
    { key: 'roleManagement', display: 'Role Management Access' },
    { key: 'userManagement', display: 'User Management Access' },
    { key: 'idTemplate', display: 'ID Template Management' },
    { key: 'systemManagement', display: 'System Management' },
    { key: 'idManagement', display: 'ID Management' },
    { key: 'pageManagement', display: 'Page Management' },
    { key: 'employeeManagement', display: 'Employee Management' },
    { key: 'idProcessing', display: 'ID Processing' },
    { key: 'customerService', display: 'Customer Service' },
    { key: 'settings', display: 'Settings Access' }
  ];
  
  const [showNewRoleModal, setShowNewRoleModal] = useState(false);
  const [showEditRoleModal, setShowEditRoleModal] = useState(false);
  const [currentEditRole, setCurrentEditRole] = useState(null);
  const [newRoleData, setNewRoleData] = useState({
    name: '',
    description: '',
    permissions: {} // Will be initialized when adding a new role
  });
  
  // For editing permissions in the table
  const [isEditingPermissions, setIsEditingPermissions] = useState(false);
  const [tempPermissions, setTempPermissions] = useState({});
  
  // Load saved permissions from localStorage on component mount
  React.useEffect(() => {
    try {
      const savedPermissions = localStorage.getItem('customRolePermissions');
      if (savedPermissions) {
        const parsedPermissions = JSON.parse(savedPermissions);
        
        // Update roles with saved permissions
        const updatedRoles = roles.map(r => {
          const roleKey = r.name.toLowerCase().replace(' ', '');
          if (parsedPermissions[roleKey]) {
            return {
              ...r,
              permissions: { ...r.permissions, ...parsedPermissions[roleKey] }
            };
          }
          return r;
        });
        
        setRoles(updatedRoles);
      }
    } catch (error) {
      console.error("Error loading saved permissions:", error);
    }
  }, []);

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

  // Save permissions to localStorage
  const savePermissionsToStorage = (updatedRoles) => {
    try {
      const formattedPermissions = {};
      
      // Format the permissions for storage
      updatedRoles.forEach(r => {
        const roleKey = r.name.toLowerCase().replace(' ', '');
        formattedPermissions[roleKey] = r.permissions;
      });
      
      localStorage.setItem('customRolePermissions', JSON.stringify(formattedPermissions));
      return true;
    } catch (error) {
      console.error("Error saving permissions:", error);
      return false;
    }
  };

  // Role functions
  const handleAddRole = () => {
    // Initialize permissions with all false
    const initialPermissions = {};
    allPermissions.forEach(perm => {
      initialPermissions[perm.key] = false;
    });
    
    // Set default values for a new role
    setNewRoleData({
      name: '',
      description: '',
      permissions: initialPermissions
    });
    
    setShowNewRoleModal(true);
  };

  const handleEditRole = (roleName) => {
    const roleToEdit = roles.find(r => r.name === roleName);
    if (roleToEdit) {
      setCurrentEditRole(roleToEdit);
      setNewRoleData({
        name: roleToEdit.name,
        description: roleToEdit.description,
        permissions: { ...roleToEdit.permissions }
      });
      setShowEditRoleModal(true);
    }
  };

  const handleDeleteRole = (roleName) => {
    if (roleName === 'Super Admin') {
      showNotification('Cannot delete Super Admin role', 'danger');
      return;
    }
    
    const updatedRoles = roles.filter(r => r.name !== roleName);
    setRoles(updatedRoles);
    
    // Save updated permissions to localStorage
    savePermissionsToStorage(updatedRoles);
    
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
      }),
      permissions: newRoleData.permissions
    };
    
    const updatedRoles = [...roles, newRole];
    setRoles(updatedRoles);
    
    // Save updated permissions to localStorage
    savePermissionsToStorage(updatedRoles);
    
    showNotification(`New role "${newRole.name}" created successfully`, 'success');
    setShowNewRoleModal(false);
    setNewRoleData({ name: '', description: '', permissions: {} });
  };

  const handleUpdateRole = () => {
    if (!newRoleData.name || !newRoleData.description) {
      showNotification('Please fill in all fields', 'warning');
      return;
    }
    
    const updatedRoles = roles.map(r => 
      r.name === currentEditRole.name 
        ? { 
            ...r, 
            name: newRoleData.name, 
            description: newRoleData.description,
            permissions: newRoleData.permissions
          }
        : r
    );
    
    setRoles(updatedRoles);
    
    // Save updated permissions to localStorage
    savePermissionsToStorage(updatedRoles);
    
    showNotification(`Role "${currentEditRole.name}" updated successfully`, 'success');
    setShowEditRoleModal(false);
    setCurrentEditRole(null);
    setNewRoleData({ name: '', description: '', permissions: {} });
  };
  
  // Handle permission checkbox change in modal
  const handlePermissionChange = (permKey) => {
    setNewRoleData(prev => ({
      ...prev,
      permissions: {
        ...prev.permissions,
        [permKey]: !prev.permissions[permKey]
      }
    }));
  };
  
  // Handle permission changes in the permissions table
  const handleTablePermissionChange = (roleName, permKey) => {
    // Update tempPermissions during editing mode
    if (isEditingPermissions) {
      // Deep copy of current temp permissions
      const updatedTempPermissions = { ...tempPermissions };
      
      // Initialize role permissions if not present
      if (!updatedTempPermissions[roleName]) {
        const role = roles.find(r => r.name === roleName);
        updatedTempPermissions[roleName] = { ...role.permissions };
      }
      
      // Toggle the permission
      updatedTempPermissions[roleName][permKey] = !updatedTempPermissions[roleName][permKey];
      
      setTempPermissions(updatedTempPermissions);
    }
  };
  
  // Begin editing permissions in the table
  const startEditingPermissions = () => {
    // Initialize temporary permissions with current values
    const initial = {};
    roles.forEach(r => {
      initial[r.name] = { ...r.permissions };
    });
    setTempPermissions(initial);
    setIsEditingPermissions(true);
  };
  
  // Save edited permissions to roles
  const savePermissionChanges = () => {
    // Update all roles with the temporary permissions
    const updatedRoles = roles.map(r => ({
      ...r,
      permissions: tempPermissions[r.name] || r.permissions
    }));
    
    setRoles(updatedRoles);
    
    // Save updated permissions to localStorage
    const success = savePermissionsToStorage(updatedRoles);
    
    if (success) {
      showNotification('Role permissions updated successfully. Navigation will update after refresh.', 'success');
    } else {
      showNotification('There was an error saving permissions', 'danger');
    }
    
    setIsEditingPermissions(false);
    setTempPermissions({});
  };
  
  // Cancel permission editing
  const cancelPermissionEditing = () => {
    setIsEditingPermissions(false);
    setTempPermissions({});
  };
  
  // Get the current permission value (either from the temp state during editing or from the role object)
  const getPermissionValue = (roleName, permKey) => {
    if (isEditingPermissions && tempPermissions[roleName]) {
      return tempPermissions[roleName][permKey];
    }
    
    const roleObj = roles.find(r => r.name === roleName);
    return roleObj ? roleObj.permissions[permKey] : false;
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
                  {roles.map((roleItem, index) => (
                    <tr key={index}>
                      <td>{roleItem.name}</td>
                      <td>{roleItem.description}</td>
                      <td>{roleItem.userCount}</td>
                      <td>{roleItem.createdDate}</td>
                      <td>
                        <button 
                          className="btn btn-sm btn-info me-2"
                          onClick={() => handleEditRole(roleItem.name)}
                        >
                          Edit
                        </button>
                        <button 
                          className="btn btn-sm btn-danger"
                          onClick={() => handleDeleteRole(roleItem.name)}
                          disabled={roleItem.name === 'Super Admin'}
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
          <div className="card-header d-flex justify-content-between align-items-center">
            <h5 className="mb-0">Role Permissions</h5>
            <div>
              {isEditingPermissions ? (
                <>
                  <button 
                    className="btn btn-success me-2" 
                    onClick={savePermissionChanges}
                  >
                    Save Changes
                  </button>
                  <button 
                    className="btn btn-secondary" 
                    onClick={cancelPermissionEditing}
                  >
                    Cancel
                  </button>
                </>
              ) : (
                <button 
                  className="btn btn-primary" 
                  onClick={startEditingPermissions}
                >
                  Edit Permissions
                </button>
              )}
            </div>
          </div>
          <div className="card-body">
            <div className="table-responsive">
              <table className="table table-hover">
                <thead>
                  <tr>
                    <th style={{ width: '30%' }}>Permission</th>
                    {roles.map((r, index) => (
                      <th key={index} className="text-center">{r.name}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {allPermissions.map((permission, index) => (
                    <tr key={index}>
                      <td>{permission.display}</td>
                      {roles.map((r, roleIndex) => (
                        <td key={roleIndex} className="text-center">
                          {isEditingPermissions ? (
                            <div className="form-check form-switch d-flex justify-content-center">
                              <input
                                className="form-check-input"
                                type="checkbox"
                                checked={getPermissionValue(r.name, permission.key)}
                                onChange={() => handleTablePermissionChange(r.name, permission.key)}
                                disabled={r.name === 'Super Admin' && 
                                         (permission.key === 'dashboard' || 
                                          permission.key === 'profile' || 
                                          permission.key === 'roleManagement' || 
                                          permission.key === 'settings')}
                              />
                            </div>
                          ) : (
                            <span className={`badge ${getPermissionValue(r.name, permission.key) ? 'bg-success' : 'bg-danger'}`}>
                              {getPermissionValue(r.name, permission.key) ? '✓' : '✕'}
                            </span>
                          )}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {isEditingPermissions && (
              <div className="alert alert-info mt-3">
                <i className="fas fa-info-circle me-2"></i>
                Note: Some permissions for the Super Admin role are mandatory and cannot be disabled.
                <br />
                <strong>Navigation changes will take effect after page refresh.</strong>
              </div>
            )}
          </div>
        </div>
        
        {/* New Role Modal */}
        {showNewRoleModal && (
          <div className="modal" style={{ display: 'block', backgroundColor: 'rgba(0,0,0,0.5)' }}>
            <div className="modal-dialog modal-lg">
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
                  
                  <div className="mb-3">
                    <label className="form-label">Permissions</label>
                    <div className="row">
                      {allPermissions.map((perm, index) => (
                        <div className="col-md-4 mb-2" key={index}>
                          <div className="form-check">
                            <input
                              className="form-check-input"
                              type="checkbox"
                              id={`new-${perm.key}`}
                              checked={newRoleData.permissions[perm.key] || false}
                              onChange={() => handlePermissionChange(perm.key)}
                            />
                            <label className="form-check-label" htmlFor={`new-${perm.key}`}>
                              {perm.display}
                            </label>
                          </div>
                        </div>
                      ))}
                    </div>
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
            <div className="modal-dialog modal-lg">
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
                      disabled={currentEditRole && currentEditRole.name === 'Super Admin'}
                    />
                    {currentEditRole && currentEditRole.name === 'Super Admin' && (
                      <small className="text-muted">Super Admin name cannot be changed</small>
                    )}
                  </div>
                  <div className="mb-3">
                    <label className="form-label">Description</label>
                    <textarea 
                      className="form-control"
                      value={newRoleData.description}
                      onChange={(e) => setNewRoleData(prev => ({ ...prev, description: e.target.value }))}
                    ></textarea>
                  </div>
                  
                  <div className="mb-3">
                    <label className="form-label">Permissions</label>
                    <div className="row">
                      {allPermissions.map((perm, index) => (
                        <div className="col-md-4 mb-2" key={index}>
                          <div className="form-check">
                            <input
                              className="form-check-input"
                              type="checkbox"
                              id={`edit-${perm.key}`}
                              checked={newRoleData.permissions[perm.key] || false}
                              onChange={() => handlePermissionChange(perm.key)}
                              disabled={currentEditRole && currentEditRole.name === 'Super Admin' && 
                                      (perm.key === 'dashboard' || 
                                       perm.key === 'profile' || 
                                       perm.key === 'roleManagement' || 
                                       perm.key === 'settings')}
                            />
                            <label className="form-check-label" htmlFor={`edit-${perm.key}`}>
                              {perm.display}
                            </label>
                          </div>
                        </div>
                      ))}
                    </div>
                    {currentEditRole && currentEditRole.name === 'Super Admin' && (
                      <div className="alert alert-info mt-3">
                        <i className="fas fa-info-circle me-2"></i>
                        Some permissions for the Super Admin role are mandatory and cannot be disabled.
                      </div>
                    )}
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
