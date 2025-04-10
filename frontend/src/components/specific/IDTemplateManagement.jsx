import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

const IDTemplateManagement = ({ role }) => {
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState(null);
  const [formData, setFormData] = useState({
    templateName: '',
    templateDescription: '',
    templateFile: null
  });
  const [permissions, setPermissions] = useState({
    canCreate: false,
    canEdit: false,
    canUpload: false,
    canDelete: false
  });

  useEffect(() => {
    // Fetch template permissions based on role
    const fetchPermissions = async () => {
      try {
        const response = await fetch(`/api/template-permissions/${role}`);
        const data = await response.json();
        setPermissions(data);
      } catch (error) {
        console.error('Error fetching permissions:', error);
        toast.error('Failed to load permissions');
      }
    };

    // Fetch templates
    const fetchTemplates = async () => {
      try {
        const response = await fetch('/api/templates');
        const data = await response.json();
        setTemplates(data);
      } catch (error) {
        console.error('Error fetching templates:', error);
        toast.error('Failed to load templates');
      } finally {
        setLoading(false);
      }
    };

    fetchPermissions();
    fetchTemplates();
  }, [role]);

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
      const url = selectedTemplate 
        ? `/api/templates/${selectedTemplate.templateID}`
        : '/api/templates';
      
      const response = await fetch(url, {
        method: selectedTemplate ? 'PUT' : 'POST',
        body: formDataToSend
      });

      if (!response.ok) throw new Error('Failed to save template');

      toast.success(`Template ${selectedTemplate ? 'updated' : 'created'} successfully`);
      setShowModal(false);
      // Refresh templates list
      const updatedTemplates = await fetch('/api/templates').then(res => res.json());
      setTemplates(updatedTemplates);
    } catch (error) {
      console.error('Error saving template:', error);
      toast.error('Failed to save template');
    }
  };

  const handleDelete = async (templateID) => {
    if (!window.confirm('Are you sure you want to delete this template?')) return;

    try {
      const response = await fetch(`/api/templates/${templateID}`, {
        method: 'DELETE'
      });

      if (!response.ok) throw new Error('Failed to delete template');

      toast.success('Template deleted successfully');
      setTemplates(templates.filter(t => t.templateID !== templateID));
    } catch (error) {
      console.error('Error deleting template:', error);
      toast.error('Failed to delete template');
    }
  };

  const handleEdit = (template) => {
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

  if (loading) {
    return <div className="text-center mt-5">Loading...</div>;
  }

  return (
    <div className="container mt-4">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2>ID Template Management</h2>
        {permissions.canCreate && (
          <button className="btn btn-primary" onClick={handleNewTemplate}>
            Create New Template
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
              <th>Created At</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {templates.map(template => (
              <tr key={template.templateID}>
                <td>{template.templateName}</td>
                <td>{template.templateDescription}</td>
                <td>
                  <span className={`badge ${template.isActive ? 'bg-success' : 'bg-danger'}`}>
                    {template.isActive ? 'Active' : 'Inactive'}
                  </span>
                </td>
                <td>{new Date(template.createdAt).toLocaleDateString()}</td>
                <td>
                  {(permissions.canEdit || permissions.canUpload) && (
                    <button
                      className="btn btn-sm btn-primary me-2"
                      onClick={() => handleEdit(template)}
                    >
                      Edit
                    </button>
                  )}
                  {permissions.canDelete && (
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
                  {selectedTemplate ? 'Edit Template' : 'Create New Template'}
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
                      {selectedTemplate ? 'Update' : 'Create'}
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

export default IDTemplateManagement; 
