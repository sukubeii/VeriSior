import React from "react";
import { Link } from "react-router-dom";

const PrivateNavBar = ({ role }) => {
  // Define role-based menu items
  const menuItems = {
    superAdmin: ["Dashboard", "Profile", "Role Management", "ID Management", "Settings"],
    admin: ["Dashboard", "Profile", "Role Management", "ID Management", "Settings"],
    employee: ["Dashboard", "Profile", "ID Management", "Settings"],
  };

  // Get the correct menu based on the role
  const userMenu = menuItems[role] || [];

  return (
    <nav className="private-navbar">
      <div className="nav-container">
        <h1 className="logo">VeriSior</h1>
        <ul className="nav-links">
          {userMenu.map((item, index) => (
            <li key={index}>
              <Link 
                to={`/${item.toLowerCase().replace(/\s/g, "-")}`} 
                className={`nav-item ${window.location.pathname === `/${item.toLowerCase().replace(/\s/g, "-")}` ? "active" : ""}`}
              >
                {item}
              </Link>
            </li>
          ))}
          <li>
            <Link to="/" className="nav-item logout">
              Logout
            </Link>
          </li>
        </ul>
      </div>
    </nav>
  );
};

export default PrivateNavBar;
