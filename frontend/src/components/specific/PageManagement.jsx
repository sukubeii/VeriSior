import React, { useState } from 'react';
import RoleLayout from '../common/RoleLayout';

const PageManagement = ({ role }) => {
  const [notifications, setNotifications] = useState([]);
  const [pages, setPages] = useState([
    {
      id: 1,
      title: 'Home',
      slug: 'home',
      status: 'published',
      lastModified: 'April 10, 2024',
      views: 1250
    },
    {
      id: 2,
      title: 'About Us',
      slug: 'about',
      status: 'published',
      lastModified: 'April 9, 2024',
      views: 850
    },
    {
      id: 3,
      title: 'Services',
      slug: 'services',
      status: 'draft',
      lastModified: 'April 8, 2024',
      views: 0
    }
  ]);
  const [showModal, setShowModal] = useState(false);
  const [currentPage, setCurrentPage] = useState(null);
  const [formData, setFormData] = useState({
    title: '',
    slug: '',
    content: '',
    status: 'draft'
  });

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

  const handleAddPage = () => {
    setCurrentPage(null);
    setFormData({
      title: '',
      slug: '',
      content: '',
      status: 'draft'
    });
    setShowModal(true);
  };

  const handleEditPage = (page) => {
    setCurrentPage(page);
    setFormData({
      title: page.title,
      slug: page.slug,
      content: 'Sample content for ' + page.title,
      status: page.status
    });
    setShowModal(true);
  };

  const handleDeletePage = (id) => {
    setPages(pages.filter(page => page.id !== id));
    showNotification('Page deleted successfully', 'success');
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    
    if (currentPage) {
      // Update existing page
      setPages(pages.map(page => 
        page.id === currentPage.id 
          ? { ...page, ...formData, lastModified: new Date().toLocaleDateString() }
          : page
      ));
      showNotification('Page updated successfully', 'success');
    } else {
      // Add new page
      const newPage = {
        id: pages.length + 1,
        ...formData,
        lastModified: new Date().toLocaleDateString(),
        views: 0
      };
      setPages([...pages, newPage]);
      showNotification('Page created successfully', 'success');
    }
    
    setShowModal(false);
  };

  const getPageManagementContent = () => {
    if (role !== "admin") {
      return (
        <div className="alert alert-danger">
          You don't have permission to access this page.
        </div>
      );
    }

    return (
      <div className="page-management-content">
        <h1 className="mb-4">Page Management</h1>
        
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

        <div className="d-flex justify-content-between align-items-center mb-4">
          <h2>Pages</h2>
          <button className="btn btn-primary" onClick={handleAddPage}>
            Add New Page
          </button>
        </div>

        <div className="table-responsive">
          <table className="table table-striped">
            <thead>
              <tr>
                <th>Title</th>
                <th>Slug</th>
                <th>Status</th>
                <th>Last Modified</th>
                <th>Views</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {pages.map(page => (
                <tr key={page.id}>
                  <td>{page.title}</td>
                  <td>{page.slug}</td>
                  <td>
                    <span className={`badge ${page.status === 'published' ? 'bg-success' : 'bg-warning'}`}>
                      {page.status}
                    </span>
                  </td>
                  <td>{page.lastModified}</td>
                  <td>{page.views}</td>
                  <td>
                    <button
                      className="btn btn-sm btn-primary me-2"
                      onClick={() => handleEditPage(page)}
                    >
                      Edit
                    </button>
                    <button
                      className="btn btn-sm btn-danger"
                      onClick={() => handleDeletePage(page.id)}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Page Form Modal */}
        {showModal && (
          <div className="modal show d-block" tabIndex="-1">
            <div className="modal-dialog">
              <div className="modal-content">
                <div className="modal-header">
                  <h5 className="modal-title">
                    {currentPage ? 'Edit Page' : 'Add New Page'}
                  </h5>
                  <button
                    type="button"
                    className="btn-close"
                    onClick={() => setShowModal(false)}
                  ></button>
                </div>
                <div className="modal-body">
                  <form onSubmit={handleSubmit}>
                    <div className="mb-3">
                      <label className="form-label">Title</label>
                      <input
                        type="text"
                        className="form-control"
                        name="title"
                        value={formData.title}
                        onChange={handleInputChange}
                        required
                      />
                    </div>
                    <div className="mb-3">
                      <label className="form-label">Slug</label>
                      <input
                        type="text"
                        className="form-control"
                        name="slug"
                        value={formData.slug}
                        onChange={handleInputChange}
                        required
                      />
                    </div>
                    <div className="mb-3">
                      <label className="form-label">Content</label>
                      <textarea
                        className="form-control"
                        name="content"
                        value={formData.content}
                        onChange={handleInputChange}
                        rows="5"
                        required
                      ></textarea>
                    </div>
                    <div className="mb-3">
                      <label className="form-label">Status</label>
                      <select
                        className="form-select"
                        name="status"
                        value={formData.status}
                        onChange={handleInputChange}
                      >
                        <option value="draft">Draft</option>
                        <option value="published">Published</option>
                      </select>
                    </div>
                    <div className="text-end">
                      <button
                        type="button"
                        className="btn btn-secondary me-2"
                        onClick={() => setShowModal(false)}
                      >
                        Cancel
                      </button>
                      <button type="submit" className="btn btn-primary">
                        {currentPage ? 'Update' : 'Create'}
                      </button>
                    </div>
                  </form>
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
      {getPageManagementContent()}
    </RoleLayout>
  );
};

export default PageManagement; 
