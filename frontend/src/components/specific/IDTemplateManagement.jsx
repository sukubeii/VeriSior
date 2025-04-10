import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

const IDTemplateManagement = ({ role }) => {
  const [templates, setTemplates] = useState([
    {
      templateID: 1,
      templateName: "Standard ID Card",
      templateDescription: "Default template for government IDs",
      status: "Active",
      reviewStatus: "Approved",
      createdAt: "2024-03-15",
      createdBy: "Admin 1",
      approvedBy: "Super Admin",
      approvedAt: "2024-03-16"
    },
    {
      templateID: 2,
      templateName: "Employee ID Card",
      templateDescription: "Template for employee identification",
      status: "Pending Review",
      reviewStatus: "Submitted",
      createdAt: "2024-04-08",
      createdBy: "Admin 2",
      approvedBy: null,
      approvedAt: null
    }
  ]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState(null);
  const [formData, setFormData] = useState({
    templateName: '',
    templateDescription: '',
    templateFile: null
  });
  const [permissions, setPermissions] = useState({
    canCreate: role === 'admin',
    canEdit: role === 'admin',
    canUpload: role === 'admin',
    canDelete: role === 'admin',
    canApprove: role === 'superAdmin'
  });

  useEffect(() => {
    // Simulate fetching templates
    setLoading(false);
  }, []);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleFileChange = (e) => {
    setFormData(prev => ({
      ...prev,
      templateFile: e.target.files[0]
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const formDataToSend = new FormData();
    formDataToSend.append('templateName', formData.templateName);
    formDataToSend.append('templateDescription', formData.templateDescription);
    if (formData.templateFile) {
      formDataToSend.append('templateFile', formData.templateFile);
    }

    try {
      // Simulate API call
      const newTemplate = {
        templateID: templates.length + 1,
        templateName: formData.templateName,
        templateDescription: formData.templateDescription,
        status: "Pending Review",
        reviewStatus: "Submitted",
        createdAt: new Date().toISOString().split('T')[0],
        createdBy: "Current Admin",
        approvedBy: null,
        approvedAt: null
      };

      if (selectedTemplate) {
        // Update existing template
        setTemplates(prev => prev.map(t => 
          t.templateID === selectedTemplate.templateID 
            ? { ...t, ...newTemplate, reviewStatus: "Submitted" }
            : t
        ));
        toast.success('Template updated and submitted for review');
      } else {
        // Add new template
        setTemplates(prev => [...prev, newTemplate]);
        toast.success('New template submitted for review');
      }

      setShowModal(false);
      setFormData({
        templateName: '',
        templateDescription: '',
        templateFile: null
      });
    } catch (error) {
      console.error('Error saving template:', error);
      toast.error('Failed to save template');
    }
  };

  const handleDelete = async (templateID) => {
    if (!window.confirm('Are you sure you want to delete this template?')) return;

    try {
      setTemplates(prev => prev.filter(t => t.templateID !== templateID));
      toast.success('Template deleted successfully');
    } catch (error) {
      console.error('Error deleting template:', error);
      toast.error('Failed to delete template');
    }
  };

  const handleEdit = (template) => {
    if (template.reviewStatus === "Approved" && role === "admin") {
      toast.warning('Cannot edit approved templates. Please create a new version instead.');
      return;
    }
    
    setSelectedTemplate(template);
    setFormData({
      templateName: template.templateName,
      templateDescription: template.templateDescription,
      templateFile: null
    });
    setShowModal(true);
  };

  const handleNewTemplate = () => {
    setSelectedTemplate(null);
    setFormData({
      templateName: '',
      templateDescription: '',
      templateFile: null
    });
    setShowModal(true);
  };

  const getStatusBadgeClass = (status, reviewStatus) => {
    if (status === "Active" && reviewStatus === "Approved") return "bg-success";
    if (reviewStatus === "Submitted") return "bg-warning";
    if (reviewStatus === "Rejected") return "bg-danger";
    return "bg-secondary";
  };

  if (loading) {
    return <div className="text-center mt-5">Loading...</div>;
  }

  return (
    <div className="container mt-4">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2>ID Template Management</h2>
        {permissions.canCreate && (
          <button className="btn btn-primary" onClick={handleNewTemplate}>
            Upload New Template
          </button>
        )}
      </div>

      <div className="table-responsive">
        <table className="table table-striped">
          <thead>
            <tr>
              <th>Template Name</th>
              <th>Description</th>
              <th>Status</th>
              <th>Created By</th>
              <th>Created At</th>
              <th>Approved By</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {templates.map(template => (
              <tr key={template.templateID}>
                <td>{template.templateName}</td>
                <td>{template.templateDescription}</td>
                <td>
                  <span className={`badge ${getStatusBadgeClass(template.status, template.reviewStatus)}`}>
                    {template.reviewStatus}
                  </span>
                </td>
                <td>{template.createdBy}</td>
                <td>{template.createdAt}</td>
                <td>{template.approvedBy || '-'}</td>
                <td>
                  <button
                    className="btn btn-sm btn-info me-2"
                    onClick={() => handleEdit(template)}
                  >
                    View
                  </button>
                  {permissions.canEdit && template.reviewStatus !== "Approved" && (
                    <button
                      className="btn btn-sm btn-primary me-2"
                      onClick={() => handleEdit(template)}
                    >
                      Edit
                    </button>
                  )}
                  {permissions.canDelete && template.reviewStatus !== "Approved" && (
                    <button
                      className="btn btn-sm btn-danger"
                      onClick={() => handleDelete(template.templateID)}
                    >
                      Delete
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Template Modal */}
      {showModal && (
        <div className="modal show" style={{ display: 'block' }}>
          <div className="modal-dialog">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">
                  {selectedTemplate ? 'Edit Template' : 'Upload New Template'}
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
                    <label className="form-label">Template Name</label>
                    <input
                      type="text"
                      className="form-control"
                      name="templateName"
                      value={formData.templateName}
                      onChange={handleInputChange}
                      required
                    />
                  </div>
                  <div className="mb-3">
                    <label className="form-label">Description</label>
                    <textarea
                      className="form-control"
                      name="templateDescription"
                      value={formData.templateDescription}
                      onChange={handleInputChange}
                      rows="3"
                    />
                  </div>
                  <div className="mb-3">
                    <label className="form-label">Template File</label>
                    <input
                      type="file"
                      className="form-control"
                      accept=".pdf,.jpg,.jpeg,.png"
                      onChange={handleFileChange}
                      required={!selectedTemplate}
                    />
                    <small className="form-text text-muted">
                      Supported formats: PDF, JPG, PNG
                    </small>
                  </div>
                  {role === 'admin' && (
                    <div className="alert alert-info">
                      <i className="fas fa-info-circle me-2"></i>
                      This template will be submitted for review by a Super Admin before it can be used.
                    </div>
                  )}
                  <div className="text-end">
                    <button
                      type="button"
                      className="btn btn-secondary me-2"
                      onClick={() => setShowModal(false)}
                    >
                      Cancel
                    </button>
                    <button type="submit" className="btn btn-primary">
                      {selectedTemplate ? 'Update & Submit' : 'Upload & Submit'}
                    </button>
                  </div>
                </form>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Modal Backdrop */}
      {showModal && <div className="modal-backdrop show"></div>}
    </div>
  );
};

export default IDTemplateManagement; 
