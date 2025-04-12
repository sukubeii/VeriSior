import React, { useState, useEffect } from 'react';
import RoleLayout from '../common/RoleLayout';
import { QRCodeSVG } from 'qrcode.react';
import html2canvas from 'html2canvas';
import { jsPDF } from 'jspdf';

const IDManagement = ({ role }) => {
  const [notifications, setNotifications] = useState([]);
  const [activeTab, setActiveTab] = useState('members');
  const [searchQuery, setSearchQuery] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');
  const [dateFilter, setDateFilter] = useState('');
  const [expandedRows, setExpandedRows] = useState({});
  const [selectedIDForPrint, setSelectedIDForPrint] = useState(null);
  const [printModalOpen, setPrintModalOpen] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState('');
  const [selectedPrinter, setSelectedPrinter] = useState('default');
  const [printQuality, setPrintQuality] = useState('standard');
  const [printCopies, setPrintCopies] = useState(1);
  const [memberStatusFilter, setMemberStatusFilter] = useState('all');

  // File upload states for templates
  const [templateFile, setTemplateFile] = useState(null);
  const [templateName, setTemplateName] = useState('');
  const [showTemplateModal, setShowTemplateModal] = useState(false);

  // Edit member states
  const [showEditMemberModal, setShowEditMemberModal] = useState(false);
  const [editMemberData, setEditMemberData] = useState(null);

  // Member photo preview
  const [photoPreview, setPhotoPreview] = useState(null);

  // Data states
  const [members, setMembers] = useState([
    {
      id: 'SC-2024-001',
      name: 'Juan Dela Cruz',
      status: 'Active',
      dateApplied: '2024-04-01',
      type: 'Regular',
      qrCode: 'https://verisior.com/verify/SC-2024-001',
      information: {
        address: '123 Main St, Manila',
        contact: '555-1234',
        birthdate: '1985-06-15',
        email: 'juan@example.com'
      },
      discountHistory: [
        {
          transactionId: 'TXN-123456',
          timestamp: '2024-04-05T10:30:00Z',
          storeName: 'Mercury Drug Store',
          amount: 500.00,
          discount: 100.00,
          storeId: 'STORE-456',
          verified: true
        },
        {
          transactionId: 'TXN-123457',
          timestamp: '2024-04-03T14:15:00Z',
          storeName: 'National Bookstore',
          amount: 750.00,
          discount: 150.00,
          storeId: 'STORE-789',
          verified: true
        }
      ]
    },
    {
      id: 'SC-2024-002',
      name: 'Maria Santos',
      status: 'Active',
      dateApplied: '2024-03-15',
      type: 'Regular',
      qrCode: 'https://verisior.com/verify/SC-2024-002',
      information: {
        address: '456 Elm St, Quezon City',
        contact: '555-5678',
        birthdate: '1992-08-22',
        email: 'maria@example.com'
      },
      discountHistory: [
        {
          transactionId: 'TXN-123458',
          timestamp: '2024-04-04T09:45:00Z',
          storeName: 'SM Supermarket',
          amount: 1200.00,
          discount: 240.00,
          storeId: 'STORE-123',
          verified: true
        }
      ]
    },
    {
      id: 'SC-2023-045',
      name: 'Carlos Lim',
      status: 'Inactive',
      reason: 'Expired',
      dateApplied: '2023-01-15',
      dateExpired: '2024-01-15',
      type: 'Regular',
      qrCode: 'https://verisior.com/verify/SC-2023-045',
      information: {
        address: '789 Oak St, Makati',
        contact: '555-7890',
        birthdate: '1988-03-10',
        email: 'carlos@example.com'
      },
      discountHistory: []
    },
    {
      id: 'SC-2023-030',
      name: 'Elena Reyes',
      status: 'Inactive',
      reason: 'Deceased',
      dateApplied: '2023-02-10',
      dateDeceased: '2024-03-20',
      type: 'Regular',
      qrCode: 'https://verisior.com/verify/SC-2023-030',
      information: {
        address: '456 Pine St, Pasig',
        contact: '555-4567',
        birthdate: '1975-05-18',
        email: 'elena@example.com',
        dateOfDeath: '2024-03-20',
        causeOfDeath: 'Natural causes'
      },
      discountHistory: []
    }
  ]);

  const [pendingApplications, setPendingApplications] = useState([
    {
      id: 'SC-2024-004',
      name: 'Ana Garcia',
      status: 'Pending',
      type: 'New Application',
      dateApplied: '2024-04-04',
      qrCode: '',
      information: {
        address: '123 Elm St, Pasig',
        contact: '555-3456',
        birthdate: '1995-07-18',
        email: 'ana@example.com'
      }
    },
    {
      id: 'SC-2024-005',
      name: 'Carlos Lim',
      status: 'Pending',
      type: 'Renewal',
      dateApplied: '2024-04-05',
      previousID: 'SC-2023-045',
      qrCode: '',
      information: {
        address: '789 Oak St, Makati',
        contact: '555-7890',
        birthdate: '1988-03-10',
        email: 'carlos@example.com'
      }
    },
    {
      id: 'SC-2024-006',
      name: 'Roberto Santos',
      status: 'Pending',
      type: 'New Application',
      dateApplied: '2024-04-06',
      qrCode: '',
      information: {
        address: '567 Maple St, Pasay',
        contact: '555-9012',
        birthdate: '1990-12-05',
        email: 'roberto@example.com'
      }
    }
  ]);
  const [rejectedApplications, setRejectedApplications] = useState([
    {
      id: 'SC-2024-007',
      name: 'Miguel Tan',
      status: 'Rejected',
      type: 'New Application',
      dateApplied: '2024-04-02',
      dateRejected: '2024-04-03',
      rejectionReason: 'Incomplete requirements - missing valid ID',
      qrCode: '',
      information: {
        address: '890 Pine St, Manila',
        contact: '555-1122',
        birthdate: '1993-05-20',
        email: 'miguel@example.com'
      }
    },
    {
      id: 'SC-2024-008',
      name: 'Elena Cruz',
      status: 'Rejected',
      type: 'New Application',
      dateApplied: '2024-04-01',
      dateRejected: '2024-04-03',
      rejectionReason: 'Invalid address proof',
      qrCode: '',
      information: {
        address: '123 Cedar St, Taguig',
        contact: '555-3344',
        birthdate: '1991-09-15',
        email: 'elena@example.com'
      }
    }
  ]);

  const [archivedMembers, setArchivedMembers] = useState([
    {
      id: 'SC-2023-010',
      name: 'Pedro Santos',
      status: 'Archived',
      type: 'Regular',
      dateApplied: '2023-06-10',
      dateArchived: '2024-03-15',
      qrCode: 'https://verisior.com/verify/SC-2023-010',
      information: {
        address: '456 Acacia St, Mandaluyong',
        contact: '555-5566',
        birthdate: '1985-11-22',
        email: 'pedro@example.com',
        dateOfDeath: '2024-03-10',
        causeOfDeath: 'Natural causes'
      },
      discountHistory: []
    }
  ]);

  const [idTemplates, setIdTemplates] = useState([
    {
      id: 'template-001',
      name: 'Standard Member Card',
      type: 'Active',
      format: 'image',
      dateCreated: '2024-01-10',
      lastModified: '2024-03-15',
      templateImage: '/templates/standard.jpg',
      fields: {
        name: { x: 150, y: 80, fontSize: 16, fontWeight: 'bold' },
        id: { x: 150, y: 110, fontSize: 12 },
        birthdate: { x: 150, y: 140, fontSize: 12 },
        address: { x: 150, y: 170, fontSize: 10 },
        qrCode: { x: 300, y: 120, width: 100, height: 100 },
        photo: { x: 50, y: 100, width: 80, height: 100 }
      }
    },
    {
      id: 'template-002',
      name: 'Premium Member Card',
      type: 'Active',
      format: 'image',
      dateCreated: '2024-02-15',
      lastModified: '2024-03-20',
      templateImage: '/templates/premium.jpg',
      fields: {
        name: { x: 180, y: 100, fontSize: 18, fontWeight: 'bold' },
        id: { x: 180, y: 130, fontSize: 14 },
        birthdate: { x: 180, y: 160, fontSize: 14 },
        address: { x: 180, y: 190, fontSize: 12 },
        qrCode: { x: 320, y: 140, width: 120, height: 120 },
        photo: { x: 60, y: 120, width: 100, height: 120 }
      }
    }
  ]);

  const [archivedTemplates, setArchivedTemplates] = useState([
    {
      id: 'template-003',
      name: 'Old Standard Card',
      type: 'Archived',
      format: 'image',
      dateCreated: '2023-05-10',
      lastModified: '2023-12-15',
      dateArchived: '2024-01-10',
      templateImage: '/templates/old-standard.jpg',
      fields: {
        name: { x: 140, y: 75, fontSize: 15, fontWeight: 'bold' },
        id: { x: 140, y: 105, fontSize: 11 },
        birthdate: { x: 140, y: 135, fontSize: 11 },
        address: { x: 140, y: 165, fontSize: 9 },
        qrCode: { x: 290, y: 115, width: 90, height: 90 },
        photo: { x: 45, y: 95, width: 75, height: 95 }
      }
    }
  ]);

  // Use effect to set default template
  useEffect(() => {
    // Set default template selection if there are templates available
    if (idTemplates.length > 0 && !selectedTemplate) {
      setSelectedTemplate(idTemplates[0].id);
    }
  }, [idTemplates, selectedTemplate]);

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

  // Toggle row expansion
  const toggleRowExpansion = (id) => {
    setExpandedRows(prev => ({
      ...prev,
      [id]: !prev[id]
    }));
  };

  // Generate a QR code for the member
  const generateQRCode = (memberId) => {
    // Create a unique URL for verification including a secure token
    // In a real system, this would include encryption/signing for security
    const encryptionKey = btoa(`${memberId}-${Date.now()}`); // Simple example, not secure
    return `https://verisior.com/verify/${memberId}?token=${encryptionKey}`;
  };

  // Handle member status filter change
  const handleMemberStatusFilterChange = (status) => {
    setMemberStatusFilter(status);
  };
  // Function to open print modal for pending applications
  const handlePrintPendingID = (id) => {
    // Find the pending application
    const application = pendingApplications.find(app => app.id === id);

    if (!application) return;

    // Generate QR code for the member
    const qrCodeUrl = generateQRCode(id);

    // Add QR code to the application data for printing
    const applicationWithQR = {
      ...application,
      qrCode: qrCodeUrl
    };

    // Set the application as the selected ID for printing
    setSelectedIDForPrint(applicationWithQR);
    setPrintModalOpen(true);
  };

  // Function to handle rejection of pending application
  const handleRejectApplication = (id) => {
    // Find the pending application
    const application = pendingApplications.find(app => app.id === id);

    if (!application) return;

    // Move to rejected
    const updatedApplication = {
      ...application,
      status: 'Rejected',
      dateRejected: new Date().toISOString().split('T')[0],
      rejectionReason: 'Application rejected' // This would be from a form input in a real implementation
    };

    setRejectedApplications(prev => [updatedApplication, ...prev]);
    // Remove from pending
    setPendingApplications(prev => prev.filter(app => app.id !== id));

    showNotification(`Application ${id} has been rejected`, 'danger');
  };

  // Function to edit member details
  const handleEditMember = (id) => {
    // Find the member
    const member = members.find(m => m.id === id);
    if (member) {
      setEditMemberData({ ...member });
      setShowEditMemberModal(true);
    }
  };

  // Save edited member details
  const handleSaveEditedMember = () => {
    if (!editMemberData) return;

    // Update member in state
    setMembers(prev =>
      prev.map(member =>
        member.id === editMemberData.id
          ? { ...editMemberData }
          : member
      )
    );

    // Close the modal
    setShowEditMemberModal(false);
    setEditMemberData(null);
    showNotification('Member details updated successfully', 'success');
  };

  // Handle archive for members
  const handleArchiveMember = (id) => {
    // Find the member
    const member = members.find(m => m.id === id);

    if (!member) return;

    // Move to archived
    const archivedMember = {
      ...member,
      status: 'Archived',
      dateArchived: new Date().toISOString().split('T')[0]
    };

    setArchivedMembers(prev => [archivedMember, ...prev]);
    // Remove from members
    setMembers(prev => prev.filter(m => m.id !== id));

    showNotification(`Member ${id} has been archived`, 'warning');
  };

  // Handle printing for members that need reprinting
  const handlePrintMemberID = (id) => {
    const member = members.find(item => item.id === id);

    if (member) {
      setSelectedIDForPrint(member);
      setPrintModalOpen(true);
    }
  };

  // Handle file selection for member photo
  const handlePhotoUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onloadend = () => {
        setPhotoPreview(reader.result);
      };
      reader.readAsDataURL(file);
    }
  };

  // Function to actually print the ID
  const handlePrintID = () => {
    if (!selectedIDForPrint) return;

    // Capture the preview div as an image
    const idCard = document.getElementById('id-card-preview');
    if (!idCard) {
      showNotification('Error generating ID card preview', 'danger');
      return;
    }

    // Show printing status
    showNotification(`Preparing to print ID for ${selectedIDForPrint.id}...`, 'info');

    // Use html2canvas to convert the div to an image
    html2canvas(idCard).then(canvas => {
      // Create PDF from the canvas
      const imgData = canvas.toDataURL('image/png');
      const pdf = new jsPDF({
        orientation: 'landscape',
        unit: 'mm',
        format: [86, 54] // Standard ID card size (CR80)
      });

      pdf.addImage(imgData, 'PNG', 0, 0, 86, 54);

      // Save or print the PDF
      if (selectedPrinter === 'download') {
        // Download the PDF
        pdf.save(`ID_Card_${selectedIDForPrint.id}.pdf`);
      } else {
        // In a real implementation, this would send to printer
        // For now, we'll open in a new window
        window.open(URL.createObjectURL(pdf.output('blob')));
      }

      // Check if this was a pending application that needs to be moved to members
      const isPendingApplication = pendingApplications.some(app => app.id === selectedIDForPrint.id);

      if (isPendingApplication) {
        // Handle based on whether it's a new application or renewal
        const application = pendingApplications.find(app => app.id === selectedIDForPrint.id);

        if (application.type === 'Renewal') {
          // Update the existing member's status
          setMembers(prev =>
            prev.map(member =>
              member.id === application.previousID
                ? {
                  ...application,
                  status: 'Active',
                  id: application.previousID,
                  qrCode: selectedIDForPrint.qrCode,
                  discountHistory: member.discountHistory || [],
                  datePrinted: new Date().toISOString().split('T')[0]
                }
                : member
            )
          );

          // Remove from pending
          setPendingApplications(prev => prev.filter(app => app.id !== selectedIDForPrint.id));

          showNotification(`ID for ${application.name} has been renewed and printed. Status updated to Active.`, 'success');
        } else {
          // Add new member to members list
          const newMember = {
            ...selectedIDForPrint,
            status: 'Active',
            datePrinted: new Date().toISOString().split('T')[0],
            discountHistory: []
          };

          setMembers(prev => [newMember, ...prev]);

          // Remove from pending
          setPendingApplications(prev => prev.filter(app => app.id !== selectedIDForPrint.id));

          showNotification(`New member ${selectedIDForPrint.name} has been added and ID printed.`, 'success');
        }
      } else {
        // This is a reprint for an existing member
        setMembers(prev =>
          prev.map(member =>
            member.id === selectedIDForPrint.id
              ? {
                ...member,
                status: 'Active',
                datePrinted: new Date().toISOString().split('T')[0],
                // If the photo was updated, save it
                ...(photoPreview ? { photo: photoPreview } : {})
              }
              : member
          )
        );

        showNotification(`ID for ${selectedIDForPrint.name} has been reprinted. Status updated to Active.`, 'success');
      }

      // Close the print modal
      setPrintModalOpen(false);
      setSelectedIDForPrint(null);
      setPhotoPreview(null);
    })
      .catch(error => {
        console.error('Error generating ID card:', error);
        showNotification('Error generating ID card', 'danger');
      });
  };
  // Template functions
  const handleTemplateInputChange = (e) => {
    setTemplateName(e.target.value);
  };

  const handleTemplateFileChange = (e) => {
    setTemplateFile(e.target.files[0]);
  };

  const handleUploadTemplate = () => {
    if (!templateFile || !templateName) {
      showNotification('Please provide a template name and file', 'warning');
      return;
    }

    // Read the file
    const reader = new FileReader();
    reader.onload = (e) => {
      const templateImageUrl = e.target.result;

      // Create a new template
      const newTemplate = {
        id: `template-${Date.now()}`,
        name: templateName,
        type: 'Active',
        format: 'image',
        dateCreated: new Date().toISOString().split('T')[0],
        lastModified: new Date().toISOString().split('T')[0],
        templateImage: templateImageUrl,
        // Default field positions - these would be configurable in a real system
        fields: {
          name: { x: 150, y: 80, fontSize: 16, fontWeight: 'bold' },
          id: { x: 150, y: 110, fontSize: 12 },
          birthdate: { x: 150, y: 140, fontSize: 12 },
          address: { x: 150, y: 170, fontSize: 10 },
          qrCode: { x: 300, y: 120, width: 100, height: 100 },
          photo: { x: 50, y: 100, width: 80, height: 100 }
        }
      };

      setIdTemplates(prev => [newTemplate, ...prev]);
      setTemplateFile(null);
      setTemplateName('');
      setShowTemplateModal(false);
      showNotification('New template uploaded successfully', 'success');
    };

    reader.readAsDataURL(templateFile);
  };

  const handleArchiveTemplate = (id) => {
    // Find the template
    const template = idTemplates.find(template => template.id === id);

    if (!template) return;

    // Move to archived
    const archivedTemplate = {
      ...template,
      type: 'Archived',
      dateArchived: new Date().toISOString().split('T')[0]
    };

    setArchivedTemplates(prev => [archivedTemplate, ...prev]);
    // Remove from active templates
    setIdTemplates(prev => prev.filter(template => template.id !== id));

    showNotification(`Template ${template.name} has been archived`, 'success');
  };

  const handleDeleteTemplate = (id, source) => {
    if (source === 'active') {
      const template = idTemplates.find(t => t.id === id);
      if (template) {
        setIdTemplates(prev => prev.filter(template => template.id !== id));
        showNotification(`Template ${template.name} has been deleted`, 'warning');
      }
    } else if (source === 'archived') {
      const template = archivedTemplates.find(t => t.id === id);
      if (template) {
        setArchivedTemplates(prev => prev.filter(template => template.id !== id));
        showNotification(`Archived template ${template.name} has been deleted`, 'warning');
      }
    }
  };

  const handleRestoreTemplate = (id) => {
    // Find the archived template
    const template = archivedTemplates.find(template => template.id === id);

    if (!template) return;

    // Move to active templates
    const restoredTemplate = {
      ...template,
      type: 'Active',
      lastModified: new Date().toISOString().split('T')[0]
    };

    delete restoredTemplate.dateArchived;

    setIdTemplates(prev => [restoredTemplate, ...prev]);
    // Remove from archived templates
    setArchivedTemplates(prev => prev.filter(template => template.id !== id));

    showNotification(`Template ${template.name} has been restored to active templates`, 'success');
  };

  // Handle field changes for print options
  const handlePrintOptionChange = (e) => {
    const { name, value } = e.target;

    if (name === 'selectedTemplate') {
      setSelectedTemplate(value);
    } else if (name === 'selectedPrinter') {
      setSelectedPrinter(value);
    } else if (name === 'printQuality') {
      setPrintQuality(value);
    } else if (name === 'printCopies') {
      setPrintCopies(parseInt(value));
    }
  };

  // Handle edit member form changes
  const handleEditMemberInputChange = (e) => {
    const { name, value } = e.target;

    // Handle nested fields (information)
    if (name.includes('.')) {
      const [parent, child] = name.split('.');
      setEditMemberData(prev => ({
        ...prev,
        [parent]: {
          ...prev[parent],
          [child]: value
        }
      }));
    } else {
      setEditMemberData(prev => ({
        ...prev,
        [name]: value
      }));
    }
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

  // Filter data based on search query and filters
  const getFilteredData = (data, includeStatusFilter = true) => {
    return data.filter(item => {
      const matchesSearch =
        item.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.id.toLowerCase().includes(searchQuery.toLowerCase());

      const matchesStatus = !includeStatusFilter || filterStatus === 'all' ||
        item.status.toLowerCase() === filterStatus.toLowerCase();
      const matchesDate = !dateFilter || item.dateApplied === dateFilter;

      return matchesSearch && matchesStatus && matchesDate;
    });
  };

  // Get filtered members with member status filter
  const getFilteredMembers = () => {
    return members.filter(member => {
      // First apply regular filters
      const matchesRegularFilters =
        (member.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
          member.id.toLowerCase().includes(searchQuery.toLowerCase())) &&
        (filterStatus === 'all' || member.status.toLowerCase() === filterStatus.toLowerCase()) &&
        (!dateFilter || member.dateApplied === dateFilter);

      // Then apply member status filter
      const matchesMemberStatus =
        memberStatusFilter === 'all' ||
        (memberStatusFilter === 'active' && member.status === 'Active') ||
        (memberStatusFilter === 'inactive' && member.status === 'Inactive');

      return matchesRegularFilters && matchesMemberStatus;
    });
  };
  // Render expanded row content with QR code
  const renderExpandedRowContent = (item) => {
    return (
      <div className="expanded-row p-3 bg-light border-top">
        <div className="row">
          <div className="col-md-3 text-center">
            <div className="qr-code-container mb-2 p-2 bg-white d-inline-block border">
              {item.qrCode ? (
                <div>
                  <QRCodeSVG value={item.qrCode} size={100} />
                </div>
              ) : (
                <div style={{ width: '100px', height: '100px', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid #ddd' }}>
                  No QR Code
                </div>
              )}
            </div>
            <div><strong>ID:</strong> {item.id}</div>
          </div>
          <div className="col-md-9">
            <h5 className="mb-3">{item.name}</h5>
            <div className="row">
              <div className="col-md-6">
                <div className="mb-2"><strong>Status:</strong> {item.status}</div>
                <div className="mb-2"><strong>Type:</strong> {item.type}</div>
                <div className="mb-2"><strong>Date Applied:</strong> {item.dateApplied}</div>
                {item.dateArchived && <div className="mb-2"><strong>Date Archived:</strong> {item.dateArchived}</div>}
                {item.dateRejected && <div className="mb-2"><strong>Date Rejected:</strong> {item.dateRejected}</div>}
                {item.reason && <div className="mb-2"><strong>Reason:</strong> {item.reason}</div>}
                {item.dateExpired && <div className="mb-2"><strong>Date Expired:</strong> {item.dateExpired}</div>}
              </div>
              <div className="col-md-6">
                {item.information && (
                  <>
                    <div className="mb-2"><strong>Address:</strong> {item.information.address}</div>
                    <div className="mb-2"><strong>Contact:</strong> {item.information.contact}</div>
                    <div className="mb-2"><strong>Email:</strong> {item.information.email}</div>
                    <div className="mb-2"><strong>Birthdate:</strong> {item.information.birthdate}</div>
                    {item.information.dateOfDeath && (
                      <>
                        <div className="mb-2"><strong>Date of Death:</strong> {item.information.dateOfDeath}</div>
                        <div className="mb-2"><strong>Cause:</strong> {item.information.causeOfDeath}</div>
                      </>
                    )}
                  </>
                )}
                {item.rejectionReason && <div className="mb-2"><strong>Rejection Reason:</strong> {item.rejectionReason}</div>}
              </div>
            </div>

            {/* If the item has discount history, show it */}
            {item.discountHistory && item.discountHistory.length > 0 && (
              <div className="mt-3">
                <h6>Discount History</h6>
                <div className="table-responsive">
                  <table className="table table-sm">
                    <thead>
                      <tr>
                        <th>Date</th>
                        <th>Store</th>
                        <th>Amount</th>
                        <th>Discount</th>
                      </tr>
                    </thead>
                    <tbody>
                      {item.discountHistory.slice(0, 3).map((transaction, index) => (
                        <tr key={index}>
                          <td>{new Date(transaction.timestamp).toLocaleDateString()}</td>
                          <td>{transaction.storeName || 'Unknown Store'}</td>
                          <td>₱{transaction.amount?.toFixed(2) || '0.00'}</td>
                          <td>₱{transaction.discount?.toFixed(2) || '0.00'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  };

  const renderMembersTable = () => {
    const filteredMembers = getFilteredMembers();

    return (
      <div>
        {/* Member status filter buttons */}
        <div className="btn-group mb-3" role="group">
          <button
            type="button"
            className={`btn ${memberStatusFilter === 'all' ? 'btn-primary' : 'btn-outline-primary'}`}
            onClick={() => handleMemberStatusFilterChange('all')}
          >
            All Members
          </button>
          <button
            type="button"
            className={`btn ${memberStatusFilter === 'active' ? 'btn-primary' : 'btn-outline-primary'}`}
            onClick={() => handleMemberStatusFilterChange('active')}
          >
            Active Members
          </button>
          <button
            type="button"
            className={`btn ${memberStatusFilter === 'inactive' ? 'btn-primary' : 'btn-outline-primary'}`}
            onClick={() => handleMemberStatusFilterChange('inactive')}
          >
            Inactive Members
          </button>
        </div>

        <div className="table-responsive">
          <table className="table table-hover">
            <thead>
              <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Status</th>
                <th>Date Applied</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredMembers.map((item) => (
                <React.Fragment key={item.id}>
                  <tr>
                    <td>{item.id}</td>
                    <td>{item.name}</td>
                    <td>
                      <span className={`badge bg-${item.status === 'Active' ? 'success' :
                          item.status === 'Inactive' ? 'warning' : 'secondary'
                        }`}>
                        {item.status}
                        {item.reason ? ` (${item.reason})` : ''}
                      </span>
                    </td>
                    <td>{item.dateApplied}</td>
                    <td>
                      {/* Show different buttons based on member status */}
                      <button
                        className="btn btn-sm btn-primary me-2"
                        onClick={() => toggleRowExpansion(item.id)}
                      >
                        {expandedRows[item.id] ? 'Hide Details' : 'Show Details'}
                      </button>

                      {/* For active members - only show edit details */}
                      {item.status === 'Active' && (
                        <button
                          className="btn btn-sm btn-info"
                          onClick={() => handleEditMember(item.id)}
                        >
                          Edit Details
                        </button>
                      )}

                      {/* For inactive members due to expiration */}
                      {item.status === 'Inactive' && item.reason === 'Expired' && (
                        <>
                          <button
                            className="btn btn-sm btn-info me-2"
                            onClick={() => handleEditMember(item.id)}
                          >
                            Edit Details
                          </button>
                          <button
                            className="btn btn-sm btn-success"
                            onClick={() => handlePrintMemberID(item.id)}
                          >
                            Print ID
                          </button>
                        </>
                      )}

                      {/* For inactive members due to death */}
                      {item.status === 'Inactive' && item.reason === 'Deceased' && (
                        <button
                          className="btn btn-sm btn-danger"
                          onClick={() => handleArchiveMember(item.id)}
                        >
                          Archive
                        </button>
                      )}
                    </td>
                  </tr>
                  {expandedRows[item.id] && (
                    <tr>
                      <td colSpan="5">
                        {renderExpandedRowContent(item)}
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  const renderPendingTable = () => {
    const filteredPending = getFilteredData(pendingApplications);

    return (
      <div className="table-responsive">
        <table className="table table-hover">
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Type</th>
              <th>Date Applied</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredPending.map((item) => (
              <React.Fragment key={item.id}>
                <tr>
                  <td>{item.id}</td>
                  <td>{item.name}</td>
                  <td>{item.type}</td>
                  <td>{item.dateApplied}</td>
                  <td>
                    <button
                      className="btn btn-sm btn-primary me-2"
                      onClick={() => toggleRowExpansion(item.id)}
                    >
                      {expandedRows[item.id] ? 'Hide Details' : 'Show Details'}
                    </button>
                    <button
                      className="btn btn-sm btn-success me-2"
                      onClick={() => handlePrintPendingID(item.id)}
                    >
                      Print ID
                    </button>
                    <button
                      className="btn btn-sm btn-danger"
                      onClick={() => handleRejectApplication(item.id)}
                    >
                      Reject
                    </button>
                  </td>
                </tr>
                {expandedRows[item.id] && (
                  <tr>
                    <td colSpan="5">
                      {renderExpandedRowContent(item)}
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    );
  };
  const renderRejectedTable = () => {
    const filteredRejected = getFilteredData(rejectedApplications);

    return (
      <div className="table-responsive">
        <table className="table table-hover">
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Type</th>
              <th>Date Rejected</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredRejected.map((item) => (
              <React.Fragment key={item.id}>
                <tr>
                  <td>{item.id}</td>
                  <td>{item.name}</td>
                  <td>{item.type}</td>
                  <td>{item.dateRejected}</td>
                  <td>
                    <button
                      className="btn btn-sm btn-primary me-2"
                      onClick={() => toggleRowExpansion(item.id)}
                    >
                      {expandedRows[item.id] ? 'Hide Details' : 'Show Details'}
                    </button>
                    <button
                      className="btn btn-sm btn-danger"
                      onClick={() => handleArchiveMember(item.id)}
                    >
                      Archive
                    </button>
                  </td>
                </tr>
                {expandedRows[item.id] && (
                  <tr>
                    <td colSpan="5">
                      {renderExpandedRowContent(item)}
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  const renderArchivedTable = () => {
    const filteredArchived = getFilteredData(archivedMembers);

    return (
      <div className="table-responsive">
        <table className="table table-hover">
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Type</th>
              <th>Date Archived</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredArchived.map((item) => (
              <React.Fragment key={item.id}>
                <tr>
                  <td>{item.id}</td>
                  <td>{item.name}</td>
                  <td>{item.type}</td>
                  <td>{item.dateArchived}</td>
                  <td>
                    <button
                      className="btn btn-sm btn-primary me-2"
                      onClick={() => toggleRowExpansion(item.id)}
                    >
                      {expandedRows[item.id] ? 'Hide Details' : 'Show Details'}
                    </button>
                  </td>
                </tr>
                {expandedRows[item.id] && (
                  <tr>
                    <td colSpan="5">
                      {renderExpandedRowContent(item)}
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  // Template table rendering
  const renderTemplatesTable = () => {
    return (
      <div>
        <div className="d-flex justify-content-between align-items-center mb-4">
          <h5 className="m-0">ID Templates</h5>
          <button
            className="btn btn-primary"
            onClick={() => setShowTemplateModal(true)}
          >
            <i className="fas fa-plus me-2"></i>Add New Template
          </button>
        </div>

        <div className="card mb-4">
          <div className="card-header">
            <h6 className="m-0 font-weight-bold">Active Templates</h6>
          </div>
          <div className="card-body">
            <div className="row">
              {idTemplates.map(template => (
                <div className="col-lg-6 mb-4" key={template.id}>
                  <div className="card h-100">
                    <div className="card-header py-3 d-flex flex-row align-items-center justify-content-between">
                      <h6 className="m-0 font-weight-bold">{template.name}</h6>
                      <div>
                        <button
                          className="btn btn-danger btn-sm ms-2"
                          onClick={() => handleDeleteTemplate(template.id, 'active')}
                        >
                          <i className="fas fa-trash"></i>
                        </button>
                      </div>
                    </div>
                    <div className="card-body">
                      <div className="text-center mb-3">
                        <img
                          src={template.templateImage}
                          alt={template.name}
                          className="img-fluid border"
                          style={{ maxHeight: '200px' }}
                        />
                      </div>
                      <div className="small">
                        <div className="d-flex justify-content-between mb-1">
                          <span>Created:</span>
                          <span>{template.dateCreated}</span>
                        </div>
                        <div className="d-flex justify-content-between">
                          <span>Last Modified:</span>
                          <span>{template.lastModified}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {archivedTemplates.length > 0 && (
          <div className="card">
            <div className="card-header">
              <h6 className="m-0 font-weight-bold">Archived Templates</h6>
            </div>
            <div className="card-body">
              <div className="row">
                {archivedTemplates.map(template => (
                  <div className="col-lg-6 mb-4" key={template.id}>
                    <div className="card h-100">
                      <div className="card-header py-3 d-flex flex-row align-items-center justify-content-between">
                        <h6 className="m-0 font-weight-bold">{template.name}</h6>
                        <div>
                          <button
                            className="btn btn-success btn-sm me-2"
                            onClick={() => handleRestoreTemplate(template.id)}
                          >
                            <i className="fas fa-undo"></i> Restore
                          </button>
                          <button
                            className="btn btn-danger btn-sm"
                            onClick={() => handleDeleteTemplate(template.id, 'archived')}
                          >
                            <i className="fas fa-trash"></i>
                          </button>
                        </div>
                      </div>
                      <div className="card-body">
                        <div className="text-center mb-3">
                          <img
                            src={template.templateImage}
                            alt={template.name}
                            className="img-fluid border"
                            style={{ maxHeight: '200px', opacity: '0.7' }}
                          />
                        </div>
                        <div className="small">
                          <div className="d-flex justify-content-between mb-1">
                            <span>Created:</span>
                            <span>{template.dateCreated}</span>
                          </div>
                          <div className="d-flex justify-content-between mb-1">
                            <span>Archived:</span>
                            <span>{template.dateArchived}</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    );
  };

  // ID Card Preview and Print Modal
  const renderPrintPreviewModal = () => {
    if (!selectedIDForPrint) return null;

    // Get the selected template
    const template = idTemplates.find(t => t.id === selectedTemplate) || idTemplates[0];

    return (
      <div className={`modal fade ${printModalOpen ? 'show' : ''}`}
        style={{ display: printModalOpen ? 'block' : 'none' }}
        tabIndex="-1"
        role="dialog">
        <div className="modal-dialog modal-lg" role="document">
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title">Print ID Card</h5>
              <button
                type="button"
                className="btn-close"
                onClick={() => {
                  setPrintModalOpen(false);
                  setSelectedIDForPrint(null);
                  setPhotoPreview(null);
                }}
              ></button>
            </div>
            <div className="modal-body">
              <div className="row">
                <div className="col-md-6">
                  {/* ID Card Preview (will be captured for printing) */}
                  <div id="id-card-preview" className="mb-3 border p-0 position-relative"
                    style={{ width: '344px', height: '216px', overflow: 'hidden' }}>
                    {/* Background template image */}
                    {template && (
                      <img
                        src={template.templateImage}
                        alt="ID Template"
                        style={{ width: '100%', height: '100%', position: 'absolute', top: 0, left: 0 }}
                      />
                    )}
                    {/* Member information overlaid on template */}
                    <div className="position-absolute" style={{ width: '100%', height: '100%', top: 0, left: 0 }}>
                      {/* Name */}
                      <div style={{
                        position: 'absolute',
                        left: `${template?.fields.name.x || 150}px`,
                        top: `${template?.fields.name.y || 80}px`,
                        fontSize: `${template?.fields.name.fontSize || 16}px`,
                        fontWeight: template?.fields.name.fontWeight || 'bold'
                      }}>
                        {selectedIDForPrint.name}
                      </div>

                      {/* ID Number */}
                      <div style={{
                        position: 'absolute',
                        left: `${template?.fields.id.x || 150}px`,
                        top: `${template?.fields.id.y || 110}px`,
                        fontSize: `${template?.fields.id.fontSize || 12}px`
                      }}>
                        {selectedIDForPrint.id}
                      </div>

                      {/* Birthdate */}
                      <div style={{
                        position: 'absolute',
                        left: `${template?.fields.birthdate.x || 150}px`,
                        top: `${template?.fields.birthdate.y || 140}px`,
                        fontSize: `${template?.fields.birthdate.fontSize || 12}px`
                      }}>
                        {selectedIDForPrint.information?.birthdate || 'N/A'}
                      </div>

                      {/* Address (shortened if needed) */}
                      <div style={{
                        position: 'absolute',
                        left: `${template?.fields.address.x || 150}px`,
                        top: `${template?.fields.address.y || 170}px`,
                        fontSize: `${template?.fields.address.fontSize || 10}px`,
                        maxWidth: '180px',
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis'
                      }}>
                        {selectedIDForPrint.information?.address || 'N/A'}
                      </div>

                      {/* QR Code */}
                      <div style={{
                        position: 'absolute',
                        left: `${template?.fields.qrCode.x || 300}px`,
                        top: `${template?.fields.qrCode.y || 120}px`,
                      }}>
                        <QRCodeSVG
                          value={selectedIDForPrint.qrCode}
                          size={template?.fields.qrCode.width || 100}
                        />
                      </div>

                      {/* Photo placeholder or uploaded photo */}
                      <div style={{
                        position: 'absolute',
                        left: `${template?.fields.photo.x || 50}px`,
                        top: `${template?.fields.photo.y || 100}px`,
                        width: `${template?.fields.photo.width || 80}px`,
                        height: `${template?.fields.photo.height || 100}px`,
                        border: '1px dashed #aaa',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        backgroundColor: '#f8f9fa',
                        overflow: 'hidden'
                      }}>
                        {photoPreview ? (
                          <img
                            src={photoPreview}
                            alt="Member"
                            style={{ width: '100%', height: '100%', objectFit: 'cover' }}
                          />
                        ) : (
                          <span className="text-muted small">Photo</span>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="text-center mb-3">
                    <small className="text-muted">ID Card Preview (CR80 format)</small>
                  </div>
                </div>

                <div className="col-md-6">
                  <div className="card mb-3">
                    <div className="card-header">
                      <h6 className="mb-0">Print Options</h6>
                    </div>
                    <div className="card-body">
                      <div className="form-group mb-3">
                        <label className="form-label">ID Template</label>
                        <select
                          className="form-select"
                          name="selectedTemplate"
                          value={selectedTemplate}
                          onChange={handlePrintOptionChange}
                        >
                          {idTemplates.map(template => (
                            <option key={template.id} value={template.id}>{template.name}</option>
                          ))}
                        </select>
                      </div>

                      <div className="form-group mb-3">
                        <label className="form-label">Upload Photo</label>
                        <input
                          type="file"
                          className="form-control"
                          accept="image/*"
                          onChange={handlePhotoUpload}
                        />
                        <small className="text-muted">Upload a photo for the ID card</small>
                      </div>

                      <div className="form-group mb-3">
                        <label className="form-label">Printer</label>
                        <select
                          className="form-select"
                          name="selectedPrinter"
                          value={selectedPrinter}
                          onChange={handlePrintOptionChange}
                        >
                          <option value="default">Default Printer</option>
                          <option value="hp-office">HP Office Printer</option>
                          <option value="epson-id">Epson ID Printer</option>
                          <option value="download">Download as PDF</option>
                        </select>
                      </div>

                      <div className="form-group mb-3">
                        <label className="form-label">Print Quality</label>
                        <select
                          className="form-select"
                          name="printQuality"
                          value={printQuality}
                          onChange={handlePrintOptionChange}
                        >
                          <option value="standard">Standard</option>
                          <option value="high">High Quality</option>
                          <option value="draft">Draft (Faster)</option>
                        </select>
                      </div>

                      <div className="form-group mb-3">
                        <label className="form-label">Copies</label>
                        <input
                          type="number"
                          className="form-control"
                          min="1"
                          max="10"
                          name="printCopies"
                          value={printCopies}
                          onChange={handlePrintOptionChange}
                        />
                      </div>
                    </div>
                  </div>

                  <div className="mb-3">
                    <button className="btn btn-primary w-100" onClick={handlePrintID}>
                      <i className="fas fa-print me-2"></i> Print ID Card
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  };

  // Template Upload Modal
  const renderTemplateUploadModal = () => {
    return (
      <div className={`modal fade ${showTemplateModal ? 'show' : ''}`}
        style={{ display: showTemplateModal ? 'block' : 'none' }}
        tabIndex="-1"
        role="dialog">
        <div className="modal-dialog" role="document">
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title">Upload ID Template</h5>
              <button
                type="button"
                className="btn-close"
                onClick={() => setShowTemplateModal(false)}
              ></button>
            </div>
            <div className="modal-body">
              <div className="form-group mb-3">
                <label className="form-label">Template Name</label>
                <input
                  type="text"
                  className="form-control"
                  value={templateName}
                  onChange={handleTemplateInputChange}
                  placeholder="Enter template name"
                />
              </div>

              <div className="form-group mb-3">
                <label className="form-label">Template Image</label>
                <input
                  type="file"
                  className="form-control"
                  accept="image/*"
                  onChange={handleTemplateFileChange}
                />
                <small className="text-muted">Upload an image to use as your ID template background</small>
              </div>

              <div className="alert alert-info">
                <i className="fas fa-info-circle me-2"></i>
                The template will use default field positions. You can adjust these in template settings.
              </div>
            </div>
            <div className="modal-footer">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setShowTemplateModal(false)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleUploadTemplate}
                disabled={!templateName || !templateFile}
              >
                Upload Template
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  };

  // Edit Member Modal
  const renderEditMemberModal = () => {
    if (!editMemberData) return null;

    return (
      <div className={`modal fade ${showEditMemberModal ? 'show' : ''}`}
        style={{ display: showEditMemberModal ? 'block' : 'none' }}
        tabIndex="-1"
        role="dialog">
        <div className="modal-dialog" role="document">
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title">Edit Member Details</h5>
              <button
                type="button"
                className="btn-close"
                onClick={() => setShowEditMemberModal(false)}
              ></button>
            </div>
            <div className="modal-body">
              <form>
                <div className="form-group mb-3">
                  <label className="form-label">Member ID</label>
                  <input
                    type="text"
                    className="form-control"
                    value={editMemberData.id}
                    readOnly
                  />
                </div>

                <div className="form-group mb-3">
                  <label className="form-label">Name</label>
                  <input
                    type="text"
                    className="form-control"
                    name="name"
                    value={editMemberData.name}
                    onChange={handleEditMemberInputChange}
                  />
                </div>

                <div className="form-group mb-3">
                  <label className="form-label">Address</label>
                  <input
                    type="text"
                    className="form-control"
                    name="information.address"
                    value={editMemberData.information.address}
                    onChange={handleEditMemberInputChange}
                  />
                </div>

                <div className="form-group mb-3">
                  <label className="form-label">Contact</label>
                  <input
                    type="text"
                    className="form-control"
                    name="information.contact"
                    value={editMemberData.information.contact}
                    onChange={handleEditMemberInputChange}
                  />
                </div>

                <div className="form-group mb-3">
                  <label className="form-label">Email</label>
                  <input
                    type="email"
                    className="form-control"
                    name="information.email"
                    value={editMemberData.information.email}
                    onChange={handleEditMemberInputChange}
                  />
                </div>

                <div className="form-group mb-3">
                  <label className="form-label">Status</label>
                  <select
                    className="form-select"
                    name="status"
                    value={editMemberData.status}
                    onChange={handleEditMemberInputChange}
                  >
                    <option value="Active">Active</option>
                    <option value="Inactive">Inactive</option>
                  </select>
                </div>

                {editMemberData.status === 'Inactive' && (
                  <div className="form-group mb-3">
                    <label className="form-label">Reason</label>
                    <select
                      className="form-select"
                      name="reason"
                      value={editMemberData.reason || 'Expired'}
                      onChange={handleEditMemberInputChange}
                    >
                      <option value="Expired">Expired</option>
                      <option value="Deceased">Deceased</option>
                    </select>
                  </div>
                )}
              </form>
            </div>
            <div className="modal-footer">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setShowEditMemberModal(false)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleSaveEditedMember}
              >
                Save Changes
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  };
  // Main component render for ID Management
  const renderIDManagementContent = () => {
    if (role !== "admin" && role !== "employee") {
      return (
        <div className="alert alert-danger">
          You don't have permission to access this page.
        </div>
      );
    }

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
                className={`nav-link ${activeTab === 'members' ? 'active' : ''}`}
                onClick={() => setActiveTab('members')}
              >
                Members
              </button>
            </li>
            <li className="nav-item">
              <button
                className={`nav-link ${activeTab === 'pending' ? 'active' : ''}`}
                onClick={() => setActiveTab('pending')}
              >
                Pending
                {pendingApplications.length > 0 && (
                  <span className="badge bg-danger ms-2">{pendingApplications.length}</span>
                )}
              </button>
            </li>
            <li className="nav-item">
              <button
                className={`nav-link ${activeTab === 'rejected' ? 'active' : ''}`}
                onClick={() => setActiveTab('rejected')}
              >
                Rejected
              </button>
            </li>
            <li className="nav-item">
              <button
                className={`nav-link ${activeTab === 'archived' ? 'active' : ''}`}
                onClick={() => setActiveTab('archived')}
              >
                Archived
              </button>
            </li>
            <li className="nav-item">
              <button
                className={`nav-link ${activeTab === 'templates' ? 'active' : ''}`}
                onClick={() => setActiveTab('templates')}
              >
                ID Templates
              </button>
            </li>
          </ul>
        </div>

        {/* Content based on active tab */}
        <div className="card">
          <div className="card-body">
            {activeTab !== 'templates' && (
              <div className="d-flex justify-content-between align-items-center mb-4">
                <h5 className="card-title mb-0">
                  {activeTab === 'members' ? 'Member List' :
                    activeTab === 'pending' ? 'Pending Applications' :
                      activeTab === 'rejected' ? 'Rejected Applications' :
                        'Archived Members'}
                </h5>
              </div>
            )}

            {/* Filters - not shown for templates tab */}
            {activeTab !== 'templates' && (
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
                    <option value="active">Active</option>
                    <option value="inactive">Inactive</option>
                    <option value="pending">Pending</option>
                    <option value="rejected">Rejected</option>
                    <option value="archived">Archived</option>
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
            )}

            {/* Render appropriate content based on active tab */}
            {activeTab === 'members' && renderMembersTable()}
            {activeTab === 'pending' && renderPendingTable()}
            {activeTab === 'rejected' && renderRejectedTable()}
            {activeTab === 'archived' && renderArchivedTable()}
            {activeTab === 'templates' && renderTemplatesTable()}
          </div>
        </div>

        {/* Print Preview Modal */}
        {renderPrintPreviewModal()}

        {/* Template Upload Modal */}
        {renderTemplateUploadModal()}

        {/* Edit Member Modal */}
        {renderEditMemberModal()}

        {/* Modal backdrop */}
        {(printModalOpen || showTemplateModal || showEditMemberModal) && (
          <div
            className="modal-backdrop fade show"
            onClick={() => {
              setPrintModalOpen(false);
              setShowTemplateModal(false);
              setShowEditMemberModal(false);
              setSelectedIDForPrint(null);
              setEditMemberData(null);
            }}
          ></div>
        )}
      </div>
    );
  };

  return (
    <RoleLayout role={role}>
      {renderIDManagementContent()}
    </RoleLayout>
  );
};

export default IDManagement;
