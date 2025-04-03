import React from 'react';

const RoleSwitcher = ({ currentRole, onRoleChange }) => {
  const roles = ["superAdmin", "admin", "employee"];
  
  return (
    <div className="role-switcher" style={{
      position: "fixed",
      bottom: "20px",
      right: "20px",
      backgroundColor: "#f0f8ff",
      border: "1px solid #b0c4de",
      borderRadius: "8px",
      padding: "12px",
      boxShadow: "0 4px 8px rgba(0,0,0,0.1)",
      zIndex: 1000
    }}>
      <div style={{ marginBottom: "8px", fontWeight: "bold" }}>
        Test Role Switcher
      </div>
      <div style={{ display: "flex", gap: "8px" }}>
        {roles.map(role => (
          <button
            key={role}
            onClick={() => onRoleChange(role)}
            style={{
              backgroundColor: currentRole === role ? "#0d6efd" : "#e9ecef",
              color: currentRole === role ? "white" : "#212529",
              border: "none",
              borderRadius: "4px",
              padding: "6px 12px",
              fontSize: "14px",
              cursor: "pointer"
            }}
          >
            {role.charAt(0).toUpperCase() + role.slice(1)}
          </button>
        ))}
      </div>
    </div>
  );
};

export default RoleSwitcher;
