import React, { useState, useEffect } from 'react';
import RoleLayout from '../common/RoleLayout';

const UserManagement = ({ role }) => {
  const [notifications, setNotifications] = useState([]);
  const [activeTab, setActiveTab] = useState('admins');
  const [searchQuery, setSearchQuery] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');
  const [showRoleSection, setShowRoleSection] = useState(false);

  // Define all available permissions and their display names
  const allPermissions = [
    { key: 'dashboard', display: 'Dashboard Access' },
    { key: 'profile', display: 'Profile Access' },
    { key: 'userManagement', display: 'User Management Access' },
    { key: 'idTemplate', display: 'ID Template Management' },
    { key: 'systemManagement', display: 'System Management' },
    { key: 'idManagement', display: 'ID Management' },
    { key: 'pageManagement', display: 'Page Management' },
    { key: 'employeeManagement', display: 'Employee Management' },
    { key: 'services', display: 'Services' },
    { key: 'settings', display: 'Settings Access' }
  ];

  // Roles data
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
        systemManagement: false,
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

  // Role modal states
  const [showNewRoleModal, setShowNewRoleModal] = useState(false);
  const [showEditRoleModal, setShowEditRoleModal] = useState(false);
  const [currentEditRole, setCurrentEditRole] = useState(null);
  const [newRoleData, setNewRoleData] = useState({
    name: '',
    description: '',
    permissions: {}
  });

  // Admins data
  const [admins, setAdmins] = useState([
    {
      id: 1,
      name: 'Admin One',
      phone: '123-456-7890',
      lastLogin: '2024-04-09 15:30:22',
      role: 'Admin',
      department: 'ID Management',
      status: 'Active'
    },
    {
      id: 2,
      name: 'Admin Two',
      phone: '234-567-8901',
      lastLogin: '2024-04-08 09:15:47',
      role: 'Admin',
      department: 'Verification',
      status: 'Active'
    },
    {
      id: 3,
      name: 'Admin Three',
      phone: '345-678-9012',
      lastLogin: '2024-04-01 11:22:36',
      role: 'Admin',
      department: 'Technical Support',
      status: 'Inactive'
    },
    {
      id: 4,
      name: 'Admin Four',
      phone: '456-789-0123',
      lastLogin: '2024-04-07 14:50:19',
      role: 'Admin',
      department: 'Customer Service',
      status: 'Active'
    },
    {
      id: 5,
      name: 'Admin Five',
      phone: '567-890-1234',
      lastLogin: 'Never',
      role: 'Admin',
      department: 'ID Management',
      status: 'Pending'
    }
  ]);

  // Employees data
  const [employees, setEmployees] = useState([
    {
      id: 1,
      name: 'John Doe',
      phone: '678-901-2345',
      lastLogin: '2024-04-10 09:30:15',
      role: 'Employee',
      department: 'ID Processing',
      status: 'Active'
    },
    {
      id: 2,
      name: 'Jane Smith',
      phone: '789-012-3456',
      lastLogin: '2024-04-09 14:22:36',
      role: 'Employee',
      department: 'Verification',
      status: 'Active'
    },
    {
      id: 3,
      name: 'Michael Brown',
      phone: '890-123-4567',
      lastLogin: '2024-04-08 11:45:08',
      role: 'Employee',
      department: 'ID Processing',
      status: 'Active'
    },
    {
      id: 4,
      name: 'Emily Johnson',
      phone: '901-234-5678',
      lastLogin: '2024-03-28 16:15:22',
      role: 'Employee',
      department: 'Customer Support',
      status: 'Inactive'
    },
    {
      id: 5,
      name: 'David Wilson',
      phone: '012-345-6789',
      lastLogin: '2024-04-10 08:05:47',
      role: 'Employee',
      department: 'Verification',
      status: 'Active'
    },
    {
      id: 6,
      name: 'Sarah Martinez',
      phone: '123-456-7891',
      lastLogin: '2024-04-09 13:40:19',
      role: 'Employee',
      department: 'ID Processing',
      status: 'Active'
    },
    {
      id: 7,
      name: 'James Taylor',
      phone: '234-567-8902',
      lastLogin: '2024-04-05 10:22:33',
      role: 'Employee',
      department: 'Technical Support',
      status: 'Active'
    },
    {
      id: 8,
      name: 'Robert Anderson',
      phone: '345-678-9013',
      lastLogin: 'Never',
      role: 'Employee',
      department: 'Customer Support',
      status: 'Pending'
    }
  ]);

  // User modal state
  const [isUserModalOpen, setIsUserModalOpen] = useState(false);
  const [currentUser, setCurrentUser] = useState(null);
  const [formData, setFormData] = useState({
    name: '',
    phone: '',
    role: 'Admin',
    department: '',
    status: 'Active',
    userPermissions: {} // For individual user permissions
  });
  // Stats
  const [userStats, setUserStats] = useState({
    totalAdmins: 0,
    activeAdmins: 0,
    inactiveAdmins: 0,
    pendingAdmins: 0,
    totalEmployees: 0,
    activeEmployees: 0,
    inactiveEmployees: 0,
    pendingEmployees: 0,
    totalRoles: 0
  });

  // Update stats when admins, employees, or roles change
  useEffect(() => {
    const activeAdmins = admins.filter(admin => admin.status === 'Active').length;
    const inactiveAdmins = admins.filter(admin => admin.status === 'Inactive').length;
    const pendingAdmins = admins.filter(admin => admin.status === 'Pending').length;

    const activeEmployees = employees.filter(employee => employee.status === 'Active').length;
    const inactiveEmployees = employees.filter(employee => employee.status === 'Inactive').length;
    const pendingEmployees = employees.filter(employee => employee.status === 'Pending').length;

    setUserStats({
      totalAdmins: admins.length,
      activeAdmins,
      inactiveAdmins,
      pendingAdmins,
      totalEmployees: employees.length,
      activeEmployees,
      inactiveEmployees,
      pendingEmployees,
      totalRoles: roles.length
    });
  }, [admins, employees, roles]);

  // Load saved roles and permissions from localStorage on component mount
  useEffect(() => {
    try {
      const savedRoles = localStorage.getItem('systemRoles');
      const savedPermissions = localStorage.getItem('customRolePermissions');

      if (savedRoles) {
        setRoles(JSON.parse(savedRoles));
      }

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
      console.error("Error loading saved roles/permissions:", error);
    }
  }, []);

  // Filter users based on search query and status filter
  const getFilteredUsers = () => {
    const users = activeTab === 'admins' ? admins : employees;

    return users.filter(user => {
      // Filter by search query
      const matchesSearch =
        user.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        user.phone.toLowerCase().includes(searchQuery.toLowerCase()) ||
        user.department.toLowerCase().includes(searchQuery.toLowerCase());

      // Filter by status
      const matchesStatus = filterStatus === 'all' || user.status.toLowerCase() === filterStatus.toLowerCase();

      return matchesSearch && matchesStatus;
    });
  };

  const addNotification = (message, type) => {
    const id = Date.now();
    setNotifications(prevNotifications => [...prevNotifications, { id, message, type }]);
    setTimeout(() => {
      setNotifications(currentNotifications =>
        currentNotifications.filter(notification => notification.id !== id)
      );
    }, 5000);
  };

  // Save roles and permissions to localStorage
  const saveRolesToStorage = (updatedRoles) => {
    try {
      localStorage.setItem('systemRoles', JSON.stringify(updatedRoles));

      const formattedPermissions = {};
      // Format the permissions for storage
      updatedRoles.forEach(r => {
        const roleKey = r.name.toLowerCase().replace(' ', '');
        formattedPermissions[roleKey] = r.permissions;
      });

      localStorage.setItem('customRolePermissions', JSON.stringify(formattedPermissions));
      return true;
    } catch (error) {
      console.error("Error saving roles/permissions:", error);
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
      addNotification('Cannot delete Super Admin role', 'danger');
      return;
    }

    // Check if any users are using this role
    const adminsWithRole = admins.filter(a => a.role === roleName).length;
    const employeesWithRole = employees.filter(e => e.role === roleName).length;

    if (adminsWithRole > 0 || employeesWithRole > 0) {
      addNotification(`Cannot delete role "${roleName}" because it is assigned to ${adminsWithRole + employeesWithRole} users`, 'danger');
      return;
    }

    const updatedRoles = roles.filter(r => r.name !== roleName);
    setRoles(updatedRoles);

    // Save updated roles to localStorage
    saveRolesToStorage(updatedRoles);

    addNotification(`Role "${roleName}" has been deleted`, 'success');
  };
  const handleSaveNewRole = () => {
    if (!newRoleData.name || !newRoleData.description) {
      addNotification('Please fill in all fields', 'warning');
      return;
    }

    // Check if role name already exists
    if (roles.some(r => r.name.toLowerCase() === newRoleData.name.toLowerCase())) {
      addNotification('A role with this name already exists', 'warning');
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

    // Save updated roles to localStorage
    saveRolesToStorage(updatedRoles);

    addNotification(`New role "${newRole.name}" created successfully`, 'success');
    setShowNewRoleModal(false);
    setNewRoleData({ name: '', description: '', permissions: {} });
  };

  const handleUpdateRole = () => {
    if (!newRoleData.name || !newRoleData.description) {
      addNotification('Please fill in all fields', 'warning');
      return;
    }

    // Check if renamed role would conflict with existing role
    if (newRoleData.name !== currentEditRole.name &&
      roles.some(r => r.name.toLowerCase() === newRoleData.name.toLowerCase())) {
      addNotification('A role with this name already exists', 'warning');
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

    // Update role name in users if it changed
    if (newRoleData.name !== currentEditRole.name) {
      const updatedAdmins = admins.map(admin =>
        admin.role === currentEditRole.name ? { ...admin, role: newRoleData.name } : admin
      );
      setAdmins(updatedAdmins);

      const updatedEmployees = employees.map(employee =>
        employee.role === currentEditRole.name ? { ...employee, role: newRoleData.name } : employee
      );
      setEmployees(updatedEmployees);
    }

    // Save updated roles to localStorage
    saveRolesToStorage(updatedRoles);

    addNotification(`Role "${currentEditRole.name}" updated successfully`, 'success');
    setShowEditRoleModal(false);
    setCurrentEditRole(null);
    setNewRoleData({ name: '', description: '', permissions: {} });
  };

  // Handle permission checkbox change in role modal
  const handlePermissionChange = (permKey) => {
    setNewRoleData(prev => ({
      ...prev,
      permissions: {
        ...prev.permissions,
        [permKey]: !prev.permissions[permKey]
      }
    }));
  };

  // User functions
  const handleAddUser = () => {
    setCurrentUser(null);

    // Initialize permissions with all false
    const initialPermissions = {};
    allPermissions.forEach(perm => {
      initialPermissions[perm.key] = false;
    });

    setFormData({
      name: '',
      phone: '',
      role: activeTab === 'admins' ? 'Admin' : 'Employee',
      department: '',
      status: 'Active',
      userPermissions: initialPermissions
    });

    setIsUserModalOpen(true);
  };

  const handleEditUser = (user) => {
    setCurrentUser(user);

    // Get role permissions as a base
    const roleObj = roles.find(r => r.name === user.role);
    let basePermissions = {};

    if (roleObj) {
      basePermissions = { ...roleObj.permissions };
    } else {
      // Initialize with false if role not found
      allPermissions.forEach(perm => {
        basePermissions[perm.key] = false;
      });
    }

    // If user has custom permissions, merge them
    const userPermissions = user.permissions || basePermissions;

    setFormData({
      ...user,
      userPermissions: userPermissions
    });

    setIsUserModalOpen(true);
  };

  const handleDeleteUser = (id) => {
    if (activeTab === 'admins') {
      setAdmins(admins.filter(admin => admin.id !== id));
      addNotification('Admin deleted successfully', 'success');
    } else {
      setEmployees(employees.filter(employee => employee.id !== id));
      addNotification('Employee deleted successfully', 'success');
    }
  };
  const handleSubmitUser = (e) => {
    e.preventDefault();

    if (!formData.name || !formData.phone || !formData.department || !formData.role) {
      addNotification('Please fill in all required fields', 'warning');
      return;
    }

    // Validate phone number format
    const phoneRegex = /^\d{3}-\d{3}-\d{4}$/;
    if (!phoneRegex.test(formData.phone)) {
      addNotification('Phone number must be in format XXX-XXX-XXXX', 'warning');
      return;
    }

    if (activeTab === 'admins') {
      if (currentUser) {
        // Update existing admin
        setAdmins(admins.map(admin =>
          admin.id === currentUser.id ? {
            ...formData,
            id: admin.id,
            permissions: formData.userPermissions
          } : admin
        ));
        addNotification('Admin updated successfully', 'success');
      } else {
        // Check if phone already exists
        if (admins.some(a => a.phone === formData.phone)) {
          addNotification('An admin with this phone number already exists', 'warning');
          return;
        }

        // Add new admin
        const newAdmin = {
          ...formData,
          id: admins.length + 1,
          lastLogin: 'Never',
          permissions: formData.userPermissions
        };
        setAdmins([...admins, newAdmin]);
        addNotification('Admin added successfully', 'success');
      }
    } else {
      if (currentUser) {
        // Update existing employee
        setEmployees(employees.map(employee =>
          employee.id === currentUser.id ? {
            ...formData,
            id: employee.id,
            permissions: formData.userPermissions
          } : employee
        ));
        addNotification('Employee updated successfully', 'success');
      } else {
        // Check if phone already exists
        if (employees.some(e => e.phone === formData.phone)) {
          addNotification('An employee with this phone number already exists', 'warning');
          return;
        }

        // Add new employee
        const newEmployee = {
          ...formData,
          id: employees.length + 1,
          lastLogin: 'Never',
          permissions: formData.userPermissions
        };
        setEmployees([...employees, newEmployee]);
        addNotification('Employee added successfully', 'success');
      }
    }

    setIsUserModalOpen(false);
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });

    // If role changed, update base permissions
    if (name === 'role') {
      const roleObj = roles.find(r => r.name === value);
      if (roleObj) {
        setFormData(prev => ({
          ...prev,
          [name]: value,
          userPermissions: { ...roleObj.permissions }
        }));
      }
    }
  };

  // Handle individual user permission changes
  const handleUserPermissionChange = (permKey) => {
    setFormData(prev => ({
      ...prev,
      userPermissions: {
        ...prev.userPermissions,
        [permKey]: !prev.userPermissions[permKey]
      }
    }));
  };

  const handleSearchChange = (e) => {
    setSearchQuery(e.target.value);
  };

  const handleStatusFilterChange = (e) => {
    setFilterStatus(e.target.value);
  };

  // Fixed: Updated tab change logic to ensure only one tab is active
  const handleTabChange = (tab) => {
    if (tab === 'roles') {
      setShowRoleSection(true);
      setActiveTab(''); // Clear activeTab when showing roles
    } else {
      setActiveTab(tab);
      setShowRoleSection(false);
    }
    setSearchQuery('');
    setFilterStatus('all');
  };

  // New refresh function to update the interface
  const handleRefresh = () => {
    // Re-calculate statistics
    const activeAdmins = admins.filter(admin => admin.status === 'Active').length;
    const inactiveAdmins = admins.filter(admin => admin.status === 'Inactive').length;
    const pendingAdmins = admins.filter(admin => admin.status === 'Pending').length;

    const activeEmployees = employees.filter(employee => employee.status === 'Active').length;
    const inactiveEmployees = employees.filter(employee => employee.status === 'Inactive').length;
    const pendingEmployees = employees.filter(employee => employee.status === 'Pending').length;

    setUserStats({
      totalAdmins: admins.length,
      activeAdmins,
      inactiveAdmins,
      pendingAdmins,
      totalEmployees: employees.length,
      activeEmployees,
      inactiveEmployees,
      pendingEmployees,
      totalRoles: roles.length
    });

    // Reload data from localStorage
    try {
      const savedRoles = localStorage.getItem('systemRoles');
      if (savedRoles) {
        setRoles(JSON.parse(savedRoles));
      }
    } catch (error) {
      console.error("Error loading saved roles:", error);
    }

    addNotification('Interface refreshed successfully', 'success');
  };

  // Render statistics cards for users
  const renderUserStats = () => {
    if (activeTab === 'admins') {
      return (
        <div className="row mb-4">
          <div className="col-md-3">
            <div className="card border-left-primary shadow h-100 py-2">
              <div className="card-body">
                <div className="row no-gutters align-items-center">
                  <div className="col mr-2">
                    <div className="text-xs font-weight-bold text-primary text-uppercase mb-1">
                      Total Admins
                    </div>
                    <div className="h5 mb-0 font-weight-bold text-gray-800">{userStats.totalAdmins}</div>
                  </div>
                  <div className="col-auto">
                    <i className="fas fa-users fa-2x text-gray-300"></i>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className="col-md-3">
            <div className="card border-left-success shadow h-100 py-2">
              <div className="card-body">
                <div className="row no-gutters align-items-center">
                  <div className="col mr-2">
                    <div className="text-xs font-weight-bold text-success text-uppercase mb-1">
                      Active Admins
                    </div>
                    <div className="h5 mb-0 font-weight-bold text-gray-800">{userStats.activeAdmins}</div>
                  </div>
                  <div className="col-auto">
                    <i className="fas fa-user-check fa-2x text-gray-300"></i>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className="col-md-3">
            <div className="card border-left-warning shadow h-100 py-2">
              <div className="card-body">
                <div className="row no-gutters align-items-center">
                  <div className="col mr-2">
                    <div className="text-xs font-weight-bold text-warning text-uppercase mb-1">
                      Inactive Admins
                    </div>
                    <div className="h5 mb-0 font-weight-bold text-gray-800">{userStats.inactiveAdmins}</div>
                  </div>
                  <div className="col-auto">
                    <i className="fas fa-user-times fa-2x text-gray-300"></i>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className="col-md-3">
            <div className="card border-left-info shadow h-100 py-2">
              <div className="card-body">
                <div className="row no-gutters align-items-center">
                  <div className="col mr-2">
                    <div className="text-xs font-weight-bold text-info text-uppercase mb-1">
                      Pending Admins
                    </div>
                    <div className="h5 mb-0 font-weight-bold text-gray-800">{userStats.pendingAdmins}</div>
                  </div>
                  <div className="col-auto">
                    <i className="fas fa-user-clock fa-2x text-gray-300"></i>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      );
    } else {
      return (
        <div className="row mb-4">
          <div className="col-md-3">
            <div className="card border-left-primary shadow h-100 py-2">
              <div className="card-body">
                <div className="row no-gutters align-items-center">
                  <div className="col mr-2">
                    <div className="text-xs font-weight-bold text-primary text-uppercase mb-1">
                      Total Employees
                    </div>
                    <div className="h5 mb-0 font-weight-bold text-gray-800">{userStats.totalEmployees}</div>
                  </div>
                  <div className="col-auto">
                    <i className="fas fa-users fa-2x text-gray-300"></i>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className="col-md-3">
            <div className="card border-left-success shadow h-100 py-2">
              <div className="card-body">
                <div className="row no-gutters align-items-center">
                  <div className="col mr-2">
                    <div className="text-xs font-weight-bold text-success text-uppercase mb-1">
                      Active Employees
                    </div>
                    <div className="h5 mb-0 font-weight-bold text-gray-800">{userStats.activeEmployees}</div>
                  </div>
                  <div className="col-auto">
                    <i className="fas fa-user-check fa-2x text-gray-300"></i>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className="col-md-3">
            <div className="card border-left-warning shadow h-100 py-2">
              <div className="card-body">
                <div className="row no-gutters align-items-center">
                  <div className="col mr-2">
                    <div className="text-xs font-weight-bold text-warning text-uppercase mb-1">
                      Inactive Employees
                    </div>
                    <div className="h5 mb-0 font-weight-bold text-gray-800">{userStats.inactiveEmployees}</div>
                  </div>
                  <div className="col-auto">
                    <i className="fas fa-user-times fa-2x text-gray-300"></i>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className="col-md-3">
            <div className="card border-left-info shadow h-100 py-2">
              <div className="card-body">
                <div className="row no-gutters align-items-center">
                  <div className="col mr-2">
                    <div className="text-xs font-weight-bold text-info text-uppercase mb-1">
                      Pending Employees
                    </div>
                    <div className="h5 mb-0 font-weight-bold text-gray-800">{userStats.pendingEmployees}</div>
                  </div>
                  <div className="col-auto">
                    <i className="fas fa-user-clock fa-2x text-gray-300"></i>
                  </div>
                </div></div>
            </div>
          </div>
        </div>
      );
    }
  };

  // Render role stats card
  const renderRoleStats = () => {
    return (
      <div className="row mb-4">
        <div className="col-md-4">
          <div className="card border-left-primary shadow h-100 py-2">
            <div className="card-body">
              <div className="row no-gutters align-items-center">
                <div className="col mr-2">
                  <div className="text-xs font-weight-bold text-primary text-uppercase mb-1">
                    Total Roles
                  </div>
                  <div className="h5 mb-0 font-weight-bold text-gray-800">{userStats.totalRoles}</div>
                </div>
                <div className="col-auto">
                  <i className="fas fa-user-tag fa-2x text-gray-300"></i>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="col-md-4">
          <div className="card border-left-success shadow h-100 py-2">
            <div className="card-body">
              <div className="row no-gutters align-items-center">
                <div className="col mr-2">
                  <div className="text-xs font-weight-bold text-success text-uppercase mb-1">
                    Active Roles
                  </div>
                  <div className="h5 mb-0 font-weight-bold text-gray-800">{roles.length}</div>
                </div>
                <div className="col-auto">
                  <i className="fas fa-check-circle fa-2x text-gray-300"></i>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="col-md-4">
          <div className="card border-left-info shadow h-100 py-2">
            <div className="card-body">
              <div className="row no-gutters align-items-center">
                <div className="col mr-2">
                  <div className="text-xs font-weight-bold text-info text-uppercase mb-1">
                    Total Users
                  </div>
                  <div className="h5 mb-0 font-weight-bold text-gray-800">
                    {userStats.totalAdmins + userStats.totalEmployees}
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
    );
  };

  // Render roles table
  const renderRolesTable = () => {
    return (
      <div className="card shadow mb-4">
        <div className="card-header py-3 d-flex flex-row align-items-center justify-content-between">
          <h6 className="m-0 font-weight-bold text-primary">Roles</h6>
          <button
            className="btn btn-primary btn-sm"
            onClick={handleAddRole}
          >
            <i className="fas fa-plus fa-sm"></i> Add Role
          </button>
        </div>
        <div className="card-body">
          <div className="table-responsive">
            <table className="table table-bordered" width="100%" cellSpacing="0">
              <thead>
                <tr>
                  <th>Role Name</th>
                  <th>Description</th>
                  <th>Users</th>
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
                      <div className="d-flex justify-content-center">
                        <button
                          className="btn btn-primary btn-sm mx-1"
                          onClick={() => handleEditRole(role.name)}
                        >
                          <i className="fas fa-edit fa-sm mr-1"></i> Edit
                        </button>
                        <button
                          className="btn btn-danger btn-sm mx-1"
                          onClick={() => handleDeleteRole(role.name)}
                          disabled={role.name === 'Super Admin'}
                        >
                          <i className="fas fa-trash fa-sm mr-1"></i> Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    );
  };

  // Render users table
  const renderUsersTable = () => {
    const filteredUsers = getFilteredUsers();
    const usersType = activeTab === 'admins' ? 'Admin' : 'Employee';

    return (
      <div className="card shadow mb-4">
        <div className="card-header py-3 d-flex flex-row align-items-center justify-content-between">
          <h6 className="m-0 font-weight-bold text-primary">{usersType}s</h6>
          <button
            className="btn btn-primary btn-sm"
            onClick={handleAddUser}
          >
            <i className="fas fa-plus fa-sm"></i> Add {usersType}
          </button>
        </div>
        <div className="card-body">
          <div className="row mb-3">
            <div className="col-md-6">
              <div className="input-group">
                <input
                  type="text"
                  className="form-control"
                  placeholder={`Search ${usersType}s...`}
                  value={searchQuery}
                  onChange={handleSearchChange}
                />
                <div className="input-group-append">
                  <button className="btn btn-primary" type="button">
                    <i className="fas fa-search fa-sm"></i>
                  </button>
                </div>
              </div>
            </div>
            <div className="col-md-6">
              <select
                className="form-control"
                value={filterStatus}
                onChange={handleStatusFilterChange}
              >
                <option value="all">All Status</option>
                <option value="active">Active</option>
                <option value="inactive">Inactive</option>
                <option value="pending">Pending</option>
              </select>
            </div>
          </div>
          <div className="table-responsive">
            <table className="table table-bordered" width="100%" cellSpacing="0">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Phone</th>
                  <th>Department</th>
                  <th>Role</th>
                  <th>Last Login</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredUsers.map((user) => (
                  <tr key={user.id}>
                    <td>{user.name}</td>
                    <td>{user.phone}</td>
                    <td>{user.department}</td>
                    <td>{user.role}</td>
                    <td>{user.lastLogin}</td>
                    <td>
                      <span className={`badge badge-${user.status === 'Active' ? 'success' :
                        user.status === 'Inactive' ? 'danger' :
                          'warning'
                        }`}>
                        {user.status}
                      </span>
                    </td>
                    <td>
                      <div className="d-flex justify-content-center">
                        <button
                          className="btn btn-primary btn-sm mx-1"
                          onClick={() => handleEditUser(user)}
                        >
                          <i className="fas fa-edit fa-sm mr-1"></i> Edit
                        </button>
                        <button
                          className="btn btn-danger btn-sm mx-1"
                          onClick={() => handleDeleteUser(user.id)}
                        >
                          <i className="fas fa-trash fa-sm mr-1"></i> Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    );
  };

  // Render new role modal
  const renderNewRoleModal = () => {
    return (
      <div className={`modal ${showNewRoleModal ? 'show' : ''}`} style={{ display: showNewRoleModal ? 'block' : 'none' }}>
        <div className="modal-dialog modal-lg">
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title">Add New Role</h5>
              <button type="button" className="close" onClick={() => setShowNewRoleModal(false)}>
                <span>&times;</span>
              </button>
            </div>
            <div className="modal-body">
              <form>
                <div className="form-group">
                  <label>Role Name</label>
                  <input
                    type="text"
                    className="form-control"
                    value={newRoleData.name}
                    onChange={(e) => setNewRoleData({ ...newRoleData, name: e.target.value })}
                  />
                </div>
                <div className="form-group">
                  <label>Description</label>
                  <textarea
                    className="form-control"
                    value={newRoleData.description}
                    onChange={(e) => setNewRoleData({ ...newRoleData, description: e.target.value })}
                  ></textarea>
                </div>

                <div className="form-group">
                  <label>Permissions</label>
                  <div className="row">
                    {allPermissions.map((perm) => (
                      <div className="col-md-4 mb-2" key={perm.key}>
                        <div className="custom-control custom-checkbox">
                          <input
                            type="checkbox"
                            className="custom-control-input"
                            id={`perm-${perm.key}`}
                            checked={newRoleData.permissions[perm.key] || false}
                            onChange={() => handlePermissionChange(perm.key)}
                          />
                          <label className="custom-control-label" htmlFor={`perm-${perm.key}`}>
                            {perm.display}
                          </label>
                        </div>
                      </div>
                    ))}
                  </div>
                  <small className="form-text text-muted">
                    Select the permissions that should be included with this role.
                  </small>
                </div>
              </form>
            </div>
            <div className="modal-footer">
              <button type="button" className="btn btn-secondary" onClick={() => setShowNewRoleModal(false)}>
                Cancel
              </button>
              <button type="button" className="btn btn-primary" onClick={handleSaveNewRole}>
                Save Role
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  };

  // Render edit role modal
  const renderEditRoleModal = () => {
    return (
      <div className={`modal ${showEditRoleModal ? 'show' : ''}`} style={{ display: showEditRoleModal ? 'block' : 'none' }}>
        <div className="modal-dialog modal-lg">
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title">Edit Role</h5>
              <button type="button" className="close" onClick={() => setShowEditRoleModal(false)}>
                <span>&times;</span>
              </button>
            </div>
            <div className="modal-body">
              <form>
                <div className="form-group">
                  <label>Role Name</label>
                  <input
                    type="text"
                    className="form-control"
                    value={newRoleData.name}
                    onChange={(e) => setNewRoleData({ ...newRoleData, name: e.target.value })}
                    disabled={currentEditRole && currentEditRole.name === 'Super Admin'}
                  />
                </div>
                <div className="form-group">
                  <label>Description</label>
                  <textarea
                    className="form-control"
                    value={newRoleData.description}
                    onChange={(e) => setNewRoleData({ ...newRoleData, description: e.target.value })}
                  ></textarea>
                </div>

                <div className="form-group">
                  <label>Permissions</label>
                  <div className="row">
                    {allPermissions.map((perm) => (
                      <div className="col-md-4 mb-2" key={perm.key}>
                        <div className="custom-control custom-checkbox">
                          <input
                            type="checkbox"
                            className="custom-control-input"
                            id={`edit-perm-${perm.key}`}
                            checked={newRoleData.permissions[perm.key] || false}
                            onChange={() => handlePermissionChange(perm.key)}
                            disabled={currentEditRole && currentEditRole.name === 'Super Admin'}
                          />
                          <label className="custom-control-label" htmlFor={`edit-perm-${perm.key}`}>
                            {perm.display}
                          </label>
                        </div>
                      </div>
                    ))}
                  </div>
                  <small className="form-text text-muted">
                    {currentEditRole && currentEditRole.name === 'Super Admin'
                      ? "Super Admin permissions cannot be modified."
                      : "Modify the permissions that are included with this role."}
                  </small>
                </div>
              </form>
            </div>
            <div className="modal-footer">
              <button type="button" className="btn btn-secondary" onClick={() => setShowEditRoleModal(false)}>
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleUpdateRole}
                disabled={currentEditRole && currentEditRole.name === 'Super Admin'}
              >
                Update Role
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  };

  // Render user modal
  const renderUserModal = () => {
    const modalTitle = currentUser ? 'Edit User' : `Add New ${activeTab === 'admins' ? 'Admin' : 'Employee'}`;

    return (
      <div className={`modal ${isUserModalOpen ? 'show' : ''}`} style={{ display: isUserModalOpen ? 'block' : 'none' }}>
        <div className="modal-dialog modal-lg">
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title">{modalTitle}</h5>
              <button type="button" className="close" onClick={() => setIsUserModalOpen(false)}>
                <span>&times;</span>
              </button>
            </div>
            <div className="modal-body">
              <form onSubmit={handleSubmitUser}>
                <div className="row">
                  <div className="col-md-6">
                    <div className="form-group">
                      <label>Name</label>
                      <input
                        type="text"
                        className="form-control"
                        name="name"
                        value={formData.name}
                        onChange={handleInputChange}
                        required
                      />
                    </div>
                  </div>
                  <div className="col-md-6">
                    <div className="form-group">
                      <label>Phone</label>
                      <input
                        type="text"
                        className="form-control"
                        name="phone"
                        value={formData.phone}
                        onChange={handleInputChange}
                        placeholder="XXX-XXX-XXXX"
                        required
                      />
                    </div>
                  </div>
                </div>

                <div className="row">
                  <div className="col-md-6">
                    <div className="form-group">
                      <label>Role</label>
                      <select
                        className="form-control"
                        name="role"
                        value={formData.role}
                        onChange={handleInputChange}
                        required
                      >
                        {roles.map((role, index) => (
                          <option key={index} value={role.name}>{role.name}</option>
                        ))}
                      </select>
                    </div>
                  </div>
                  <div className="col-md-6">
                    <div className="form-group">
                      <label>Department</label>
                      <select
                        className="form-control"
                        name="department"
                        value={formData.department}
                        onChange={handleInputChange}
                        required
                      >
                        <option value="">Select Department</option>
                        <option value="ID Management">ID Management</option>
                        <option value="Verification">Verification</option>
                        <option value="ID Processing">ID Processing</option>
                        <option value="Customer Service">Customer Service</option>
                        <option value="Technical Support">Technical Support</option>
                      </select>
                    </div>
                  </div>
                </div>

                <div className="form-group">
                  <label>Status</label>
                  <select
                    className="form-control"
                    name="status"
                    value={formData.status}
                    onChange={handleInputChange}
                    required
                  >
                    <option value="Active">Active</option>
                    <option value="Inactive">Inactive</option>
                    <option value="Pending">Pending</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Individual User Permissions</label>
                  <div className="row">
                    {allPermissions.map((perm) => (
                      <div className="col-md-4 mb-2" key={perm.key}>
                        <div className="custom-control custom-checkbox">
                          <input
                            type="checkbox"
                            className="custom-control-input"
                            id={`user-perm-${perm.key}`}
                            checked={formData.userPermissions?.[perm.key] || false}
                            onChange={() => handleUserPermissionChange(perm.key)}
                          />
                          <label className="custom-control-label" htmlFor={`user-perm-${perm.key}`}>
                            {perm.display}
                          </label>
                        </div>
                      </div>
                    ))}
                  </div>
                  <small className="form-text text-muted">
                    These permissions override the default role permissions for this specific user.
                  </small>
                </div>
              </form>
            </div>
            <div className="modal-footer">
              <button type="button" className="btn btn-secondary" onClick={() => setIsUserModalOpen(false)}>
                Cancel
              </button>
              <button type="button" className="btn btn-primary" onClick={handleSubmitUser}>
                {currentUser ? 'Update User' : 'Add User'}
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  };

  // Render notifications
  const renderNotifications = () => {
    return (
      <div className="notification-container" style={{ position: 'fixed', top: '20px', right: '20px', zIndex: 1050 }}>
        {notifications.map(notification => (
          <div
            key={notification.id}
            className={`alert alert-${notification.type} alert-dismissible fade show`}
            role="alert"
          >
            {notification.message}
            <button
              type="button"
              className="close"
              onClick={() => setNotifications(notifications.filter(n => n.id !== notification.id))}
            >
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
        ))}
      </div>
    );
  };

  // Render modal backdrop
  const renderModalBackdrop = () => {
    const showBackdrop = showNewRoleModal || showEditRoleModal || isUserModalOpen;
    return (
      <div
        className={`modal-backdrop fade ${showBackdrop ? 'show' : ''}`}
        style={{ display: showBackdrop ? 'block' : 'none' }}
      ></div>
    );
  };

  return (
    <RoleLayout role={role}>
      <div className="container-fluid">
        {/* Page Heading */}
        <div className="d-flex justify-content-between align-items-center mb-4">
          <h1 className="h3 text-gray-800">User Management</h1>
          <button
            className="btn btn-primary"
            onClick={handleRefresh}
            title="Refresh Data"
          >
            <i className="fas fa-sync-alt fa-sm"></i> Refresh
          </button>
        </div>

        {/* Tabs */}
        <div className="mb-4">
          <ul className="nav nav-tabs">
            <li className="nav-item">
              <button
                className={`nav-link ${!showRoleSection && activeTab === 'admins' ? 'active' : ''}`}
                onClick={() => handleTabChange('admins')}
              >
                Admins
              </button>
            </li>
            <li className="nav-item">
              <button
                className={`nav-link ${!showRoleSection && activeTab === 'employees' ? 'active' : ''}`}
                onClick={() => handleTabChange('employees')}
              >
                Employees
              </button>
            </li>
            <li className="nav-item">
              <button
                className={`nav-link ${showRoleSection ? 'active' : ''}`}
                onClick={() => handleTabChange('roles')}
              >
                Roles
              </button>
            </li>
          </ul>
        </div>

        {/* Stats Cards */}
        {showRoleSection ? renderRoleStats() : renderUserStats()}

        {/* Main Content */}
        {showRoleSection ? (
          renderRolesTable()
        ) : (
          renderUsersTable()
        )}

        {/* Modals */}
        {renderNewRoleModal()}
        {renderEditRoleModal()}
        {renderUserModal()}
        {renderModalBackdrop()}

        {/* Notifications */}
        {renderNotifications()}
      </div>
    </RoleLayout>
  );
};

export default UserManagement;
