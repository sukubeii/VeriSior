import React, { useState } from 'react';
import RoleLayout from '../common/RoleLayout';

const PageManagement = ({ role }) => {
  const [notifications, setNotifications] = useState([]);
  const [content, setContent] = useState({
    about: {
      title: 'About Us',
      content: 'Welcome to VeriSior, your trusted partner in secure identification solutions. Our mission is to provide reliable and efficient ID processing services for government and private institutions.',
      images: [
        {
          url: '/images/about/office.jpg',
          caption: 'Our main office'
        },
        {
          url: '/images/about/process.jpg',
          caption: 'ID processing area'
        }
      ],
      lastModified: 'April 10, 2024',
      status: 'published'
    },
    terms: {
      title: 'Terms & Conditions',
      content: 'By submitting an application through our system, you agree to provide accurate and truthful information. Any falsification of documents or information may result in the rejection of your application and possible legal consequences.',
      lastModified: 'April 9, 2024',
      status: 'published'
    },
    application: {
      title: 'ID Application Form',
      sections: [
        {
          title: 'Personal Information',
          fields: [
            { name: 'fullName', label: 'Full Name', type: 'text', required: true },
            { name: 'birthDate', label: 'Date of Birth', type: 'date', required: true },
            { name: 'gender', label: 'Gender', type: 'select', options: ['Male', 'Female'], required: true }
          ]
        },
        {
          title: 'Contact Information',
          fields: [
            { name: 'email', label: 'Email Address', type: 'email', required: true },
            { name: 'phone', label: 'Phone Number', type: 'tel', required: true },
            { name: 'address', label: 'Current Address', type: 'textarea', required: true }
          ]
        }
      ],
      requirements: [
        'Valid government-issued ID',
        'Recent 2x2 ID picture',
        'Proof of address (utility bill)',
        'Birth certificate'
      ],
      lastModified: 'April 8, 2024',
      status: 'published'
    }
  });

  const [showModal, setShowModal] = useState(false);
  const [showImageModal, setShowImageModal] = useState(false);
  const [activeSection, setActiveSection] = useState('about');
  const [formData, setFormData] = useState({
    title: '',
    content: '',
    images: []
  });

  const [imageFormData, setImageFormData] = useState({
    url: '',
    caption: ''
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

  // Function to handle image upload
  const handleImageUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      // In a real app, you would upload this to a server
      // For now, we'll create a local URL
      const imageUrl = URL.createObjectURL(file);
      setImageFormData(prev => ({
        ...prev,
        url: imageUrl
      }));
    }
  };

  const handleAddImage = () => {
    if (!imageFormData.url || !imageFormData.caption) {
      showNotification('Please provide both image and caption', 'warning');
      return;
    }

    setContent(prev => ({
      ...prev,
      about: {
        ...prev.about,
        images: [...prev.about.images, { ...imageFormData }]
      }
    }));

    setImageFormData({
      url: '',
      caption: ''
    });

    setShowImageModal(false);
    showNotification('Image added successfully', 'success');
  };

  const handleRemoveImage = (index) => {
    setContent(prev => ({
      ...prev,
      about: {
        ...prev.about,
        images: prev.about.images.filter((_, i) => i !== index)
      }
    }));
    showNotification('Image removed successfully', 'success');
  };

  const handleEditContent = (section) => {
    let initialData = {
      title: content[section].title,
      content: content[section].content
    };

    if (section === 'application') {
      initialData = {
        ...initialData,
        sections: content[section].sections,
        requirements: content[section].requirements
      };
    }

    setFormData(initialData);
    setActiveSection(section);
    setShowModal(true);
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleRequirementChange = (index, value) => {
    setFormData(prev => ({
      ...prev,
      requirements: prev.requirements.map((req, i) => i === index ? value : req)
    }));
  };

  const handleAddRequirement = () => {
    setFormData(prev => ({
      ...prev,
      requirements: [...prev.requirements, '']
    }));
  };

  const handleRemoveRequirement = (index) => {
    setFormData(prev => ({
      ...prev,
      requirements: prev.requirements.filter((_, i) => i !== index)
    }));
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    
    if (!formData.title.trim() || !formData.content.trim()) {
      showNotification('Please fill in all required fields', 'warning');
      return;
    }

    setContent(prev => ({
      ...prev,
      [activeSection]: {
        ...prev[activeSection],
        ...formData,
        lastModified: new Date().toLocaleDateString('en-US', {
          year: 'numeric',
          month: 'long',
          day: 'numeric'
        })
      }
    }));

    showNotification('Content updated successfully', 'success');
    setShowModal(false);
  };

  const handlePreview = (section) => {
    // In a real application, this would show a preview in a new window/modal
    showNotification(`Previewing ${content[section].title}`, 'info');
  };

  const handlePublish = (section) => {
    setContent(prev => ({
      ...prev,
      [section]: {
        ...prev[section],
        status: 'published',
        lastModified: new Date().toLocaleDateString('en-US', {
          year: 'numeric',
          month: 'long',
          day: 'numeric'
        })
      }
    }));
    showNotification(`${content[section].title} has been published`, 'success');
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

        {/* Content Sections */}
        <div className="row">
          {/* About Us Section */}
          <div className="col-md-12 mb-4">
            <div className="card">
              <div className="card-header bg-primary text-white d-flex justify-content-between align-items-center">
                <h5 className="mb-0">About Us Section</h5>
                <div>
                  <button 
                    className="btn btn-light btn-sm me-2"
                    onClick={() => setShowImageModal(true)}
                  >
                    Add Image
                  </button>
                  <button 
                    className="btn btn-light btn-sm"
                    onClick={() => handleEditContent('about')}
                  >
                    Edit Content
                  </button>
                </div>
              </div>
              <div className="card-body">
                <h6 className="card-subtitle mb-2 text-muted">Last Modified: {content.about.lastModified}</h6>
                <div className="mb-4">
                  <h6>Content Preview:</h6>
                  <p>{content.about.content}</p>
                </div>
                <div className="mb-3">
                  <h6>Images:</h6>
                  <div className="row">
                    {content.about.images.map((image, index) => (
                      <div key={index} className="col-md-4 mb-3">
                        <div className="card">
                          <img src={image.url} className="card-img-top" alt={image.caption} style={{ height: '200px', objectFit: 'cover' }} />
                          <div className="card-body">
                            <p className="card-text">{image.caption}</p>
                            <button 
                              className="btn btn-danger btn-sm"
                              onClick={() => handleRemoveImage(index)}
                            >
                              Remove
                            </button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Terms & Conditions Section */}
          <div className="col-md-12 mb-4">
            <div className="card">
              <div className="card-header bg-primary text-white d-flex justify-content-between align-items-center">
                <h5 className="mb-0">Terms & Conditions</h5>
                <button 
                  className="btn btn-light btn-sm"
                  onClick={() => handleEditContent('terms')}
                >
                  Edit Content
                </button>
              </div>
              <div className="card-body">
                <h6 className="card-subtitle mb-2 text-muted">Last Modified: {content.terms.lastModified}</h6>
                <div className="mb-4">
                  <h6>Content Preview:</h6>
                  <p>{content.terms.content}</p>
                </div>
              </div>
            </div>
          </div>

          {/* Application Form Section */}
          <div className="col-md-12 mb-4">
            <div className="card">
              <div className="card-header bg-primary text-white d-flex justify-content-between align-items-center">
                <h5 className="mb-0">Application Form</h5>
                <button 
                  className="btn btn-light btn-sm"
                  onClick={() => handleEditContent('application')}
                >
                  Edit Form
                </button>
              </div>
              <div className="card-body">
                <h6 className="card-subtitle mb-2 text-muted">Last Modified: {content.application.lastModified}</h6>
                
                <div className="mb-4">
                  <h6>Form Sections:</h6>
                  {content.application.sections.map((section, index) => (
                    <div key={index} className="card mb-3">
                      <div className="card-header">
                        <h6 className="mb-0">{section.title}</h6>
                      </div>
                      <div className="card-body">
                        <div className="row">
                          {section.fields.map((field, fieldIndex) => (
                            <div key={fieldIndex} className="col-md-4 mb-3">
                              <div className="form-group">
                                <label>{field.label}</label>
                                <div className="text-muted small">
                                  Type: {field.type}
                                  {field.required && ' (Required)'}
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>

                <div className="mb-4">
                  <h6>Requirements:</h6>
                  <ul className="list-group">
                    {content.application.requirements.map((req, index) => (
                      <li key={index} className="list-group-item">{req}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Edit Content Modal */}
        {showModal && (
          <div className="modal show d-block" tabIndex="-1">
            <div className="modal-dialog modal-lg">
              <div className="modal-content">
                <div className="modal-header">
                  <h5 className="modal-title">
                    Edit {content[activeSection].title}
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

                    {activeSection === 'application' && (
                      <div className="mb-3">
                        <label className="form-label">Requirements</label>
                        {formData.requirements.map((req, index) => (
                          <div key={index} className="input-group mb-2">
                            <input
                              type="text"
                              className="form-control"
                              value={req}
                              onChange={(e) => handleRequirementChange(index, e.target.value)}
                            />
                            <button
                              type="button"
                              className="btn btn-danger"
                              onClick={() => handleRemoveRequirement(index)}
                            >
                              Remove
                            </button>
                          </div>
                        ))}
                        <button
                          type="button"
                          className="btn btn-secondary"
                          onClick={handleAddRequirement}
                        >
                          Add Requirement
                        </button>
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
                        Save Changes
                      </button>
                    </div>
                  </form>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Add Image Modal */}
        {showImageModal && (
          <div className="modal show d-block" tabIndex="-1">
            <div className="modal-dialog">
              <div className="modal-content">
                <div className="modal-header">
                  <h5 className="modal-title">Add Image</h5>
                  <button
                    type="button"
                    className="btn-close"
                    onClick={() => setShowImageModal(false)}
                  ></button>
                </div>
                <div className="modal-body">
                  <div className="mb-3">
                    <label className="form-label">Image</label>
                    <input
                      type="file"
                      className="form-control"
                      accept="image/*"
                      onChange={handleImageUpload}
                    />
                  </div>
                  <div className="mb-3">
                    <label className="form-label">Caption</label>
                    <input
                      type="text"
                      className="form-control"
                      value={imageFormData.caption}
                      onChange={(e) => setImageFormData(prev => ({
                        ...prev,
                        caption: e.target.value
                      }))}
                    />
                  </div>
                  <div className="text-end">
                    <button
                      type="button"
                      className="btn btn-secondary me-2"
                      onClick={() => setShowImageModal(false)}
                    >
                      Cancel
                    </button>
                    <button
                      type="button"
                      className="btn btn-primary"
                      onClick={handleAddImage}
                    >
                      Add Image
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Modal Backdrop */}
        {(showModal || showImageModal) && (
          <div className="modal-backdrop show"></div>
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
