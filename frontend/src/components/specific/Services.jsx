import React, { useState } from 'react';
import RoleLayout from '../common/RoleLayout';

const Services = ({ role }) => {
  const [activeTab, setActiveTab] = useState('inbox');
  const [searchQuery, setSearchQuery] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');
  const [selectedMessage, setSelectedMessage] = useState(null);
  const [replyText, setReplyText] = useState('');
  const [replyMethod, setReplyMethod] = useState('email'); // Default reply method
  
  // Sample data for messages
  const [messages, setMessages] = useState({
    inbox: [
      {
        id: 'msg-001',
        from: 'Juan Dela Cruz',
        email: 'juan@example.com',
        phone: '09123456789',
        subject: 'Question about ID Application',
        message: 'Hello, I submitted my application last week but haven\'t heard back. Could you please check the status?',
        date: '2024-04-05',
        status: 'unread',
        contactMethod: 'email'
      },
      {
        id: 'msg-002',
        from: 'Maria Santos',
        email: 'maria@example.com',
        subject: 'Renewal Process',
        message: 'I need to renew my senior citizen ID. What documents do I need to prepare?',
        date: '2024-04-04',
        status: 'read',
        contactMethod: 'sms',
        phone: '09555567890'
      }
    ],
    outbox: [
      {
        id: 'msg-003',
        to: 'Pedro Reyes',
        email: 'pedro@example.com',
        subject: 'Your ID Application Status',
        message: 'Your application has been approved. Please visit our office to claim your ID.',
        date: '2024-04-03',
        status: 'sent',
        contactMethod: 'email'
      }
    ]
  });

  // Function to display success/error messages (uses alert instead of notifications)
  const displayMessage = (message, type = 'info') => {
    const alertClass = type === 'success' ? 'alert-success' : 
                       type === 'danger' ? 'alert-danger' : 
                       type === 'warning' ? 'alert-warning' : 'alert-info';
    
    alert(`${message} (${type})`);
    // In a real application, you might use a toast notification library
    // or other UI feedback mechanism instead of alerts
  };

  // Function to handle message selection
  const handleSelectMessage = (message) => {
    setSelectedMessage(message);
    setReplyText('');
    setReplyMethod(message.contactMethod || 'email');
    
    // Mark as read if it's unread
    if (message.status === 'unread' && activeTab === 'inbox') {
      setMessages(prev => ({
        ...prev,
        inbox: prev.inbox.map(msg => 
          msg.id === message.id ? { ...msg, status: 'read' } : msg
        )
      }));
    }
  };
  
  // Function to handle search
  const handleSearchChange = (e) => {
    setSearchQuery(e.target.value);
  };

  // Function to handle filter status change
  const handleStatusFilterChange = (e) => {
    setFilterStatus(e.target.value);
  };

  // Function to handle reply method change
  const handleReplyMethodChange = (e) => {
    setReplyMethod(e.target.value);
  };

  // Function to handle reply
  const handleReply = () => {
    if (!selectedMessage || !replyText.trim()) return;
    
    const newReply = {
      id: `msg-${Date.now()}`,
      to: selectedMessage.from || selectedMessage.to,
      email: selectedMessage.email,
      phone: selectedMessage.phone,
      subject: `Re: ${selectedMessage.subject}`,
      message: replyText,
      date: new Date().toISOString().split('T')[0],
      status: 'sent',
      contactMethod: replyMethod // Use the selected reply method
    };
    
    setMessages(prev => ({
      ...prev,
      outbox: [newReply, ...prev.outbox]
    }));
    
    setReplyText('');
    displayMessage(`Reply sent via ${replyMethod === 'email' ? 'email' : 'SMS'} successfully`, 'success');
  };

  // Function to handle new message
  const handleNewMessage = () => {
    setSelectedMessage({
      id: null,
      to: '',
      email: '',
      phone: '',
      subject: '',
      message: '',
      contactMethod: 'email'
    });
    setReplyText('');
    setReplyMethod('email');
  };

  // Function to handle send new message
  const handleSendNewMessage = () => {
    if (!selectedMessage.to || !replyText.trim()) {
      displayMessage('Please fill in all required fields', 'danger');
      return;
    }
    
    if (replyMethod === 'email' && !selectedMessage.email) {
      displayMessage('Please provide an email address', 'danger');
      return;
    }
    
    if (replyMethod === 'sms' && !selectedMessage.phone) {
      displayMessage('Please provide a phone number', 'danger');
      return;
    }
    
    const newMessage = {
      id: `msg-${Date.now()}`,
      to: selectedMessage.to,
      email: selectedMessage.email,
      phone: selectedMessage.phone,
      subject: selectedMessage.subject || 'No Subject',
      message: replyText,
      date: new Date().toISOString().split('T')[0],
      status: 'sent',
      contactMethod: replyMethod
    };
    
    setMessages(prev => ({
      ...prev,
      outbox: [newMessage, ...prev.outbox]
    }));
    
    setSelectedMessage(null);
    setReplyText('');
    displayMessage(`Message sent via ${replyMethod === 'email' ? 'email' : 'SMS'} successfully`, 'success');
  };

  // Removed notification-related functions
  
  // Filter messages based on search query and status
  const getFilteredMessages = (messageList) => {
    return messageList.filter(message => {
      const searchInMessage = 
        (message.from && message.from.toLowerCase().includes(searchQuery.toLowerCase())) ||
        (message.to && message.to.toLowerCase().includes(searchQuery.toLowerCase())) ||
        message.subject.toLowerCase().includes(searchQuery.toLowerCase()) ||
        message.message.toLowerCase().includes(searchQuery.toLowerCase());
        
      const matchesStatus = filterStatus === 'all' || message.status === filterStatus;
      
      return searchInMessage && matchesStatus;
    });
  };

  // Render messages list
  const renderMessagesList = () => {
    let messageList = [];
    
    switch (activeTab) {
      case 'inbox':
        messageList = getFilteredMessages(messages.inbox);
        break;
      case 'outbox':
        messageList = getFilteredMessages(messages.outbox);
        break;
      default:
        messageList = [];
    }
    
    return (
      <div className="list-group">
        {messageList.length === 0 ? (
          <div className="list-group-item text-center py-3">
            <p className="mb-0 text-muted">No messages found</p>
          </div>
        ) : (
          messageList.map(message => (
            <div 
              key={message.id}
              className={`list-group-item list-group-item-action ${
                selectedMessage && selectedMessage.id === message.id ? 'active' : ''
              } ${message.status === 'unread' ? 'fw-bold' : ''}`}
              onClick={() => handleSelectMessage(message)}
            >
              <div className="d-flex w-100 justify-content-between">
                <h5 className="mb-1">
                  {message.from || message.to}
                  {message.status === 'unread' && (
                    <span className="badge bg-primary ms-2">New</span>
                  )}
                </h5>
                <small>{message.date}</small>
              </div>
              <p className="mb-1">{message.subject}</p>
              <small className="d-flex justify-content-between">
                <span>
                  {message.contactMethod === 'email' ? (
                    <><i className="fas fa-envelope me-1"></i> {message.email}</>
                  ) : message.contactMethod === 'sms' ? (
                    <><i className="fas fa-sms me-1"></i> {message.phone}</>
                  ) : (
                    <><i className="fas fa-bell me-1"></i> {message.type || 'Notification'}</>
                  )}
                </span>
                <span className={`badge bg-${
                  message.status === 'unread' ? 'primary' : 
                  message.status === 'read' ? 'success' : 
                  message.status === 'sent' ? 'info' : 
                  'secondary'
                }`}>
                  {message.status}
                </span>
              </small>
            </div>
          ))
        )}
      </div>
    );
  };
  
  // Render message details
  const renderMessageDetails = () => {
    if (!selectedMessage) {
      return (
        <div className="text-center p-5">
          <div className="mb-4">
            <i className="fas fa-envelope fa-3x text-muted"></i>
          </div>
          <h5 className="mb-2">Select a message to view</h5>
          <p className="text-muted">Click on a message from the list to view its contents</p>
        </div>
      );
    }
    
    // New message form
    if (selectedMessage.id === null) {
      return (
        <div className="p-3">
          <h5 className="mb-3">New Message</h5>
          <form>
            <div className="mb-3">
              <label htmlFor="messageTo" className="form-label">To</label>
              <input 
                type="text" 
                className="form-control" 
                id="messageTo" 
                value={selectedMessage.to} 
                onChange={(e) => setSelectedMessage({...selectedMessage, to: e.target.value})}
                required
              />
            </div>
            
            <div className="mb-3">
              <label htmlFor="contactMethod" className="form-label">Contact Method</label>
              <select 
                className="form-control"
                id="contactMethod"
                value={replyMethod}
                onChange={(e) => {
                  setReplyMethod(e.target.value);
                  setSelectedMessage({...selectedMessage, contactMethod: e.target.value});
                }}
              >
                <option value="email">Email</option>
                <option value="sms">SMS</option>
              </select>
            </div>
            
            {replyMethod === 'email' && (
              <div className="mb-3">
                <label htmlFor="messageEmail" className="form-label">Email Address</label>
                <input 
                  type="email" 
                  className="form-control" 
                  id="messageEmail" 
                  value={selectedMessage.email || ''} 
                  onChange={(e) => setSelectedMessage({...selectedMessage, email: e.target.value})}
                  required={replyMethod === 'email'}
                />
              </div>
            )}
            
            {replyMethod === 'sms' && (
              <div className="mb-3">
                <label htmlFor="messagePhone" className="form-label">Phone Number</label>
                <input 
                  type="tel" 
                  className="form-control" 
                  id="messagePhone" 
                  value={selectedMessage.phone || ''} 
                  onChange={(e) => setSelectedMessage({...selectedMessage, phone: e.target.value})}
                  placeholder="09XXXXXXXXX"
                  required={replyMethod === 'sms'}
                />
                <small className="text-muted">Format: 09XXXXXXXXX</small>
              </div>
            )}
            
            <div className="mb-3">
              <label htmlFor="messageSubject" className="form-label">Subject</label>
              <input 
                type="text" 
                className="form-control" 
                id="messageSubject" 
                value={selectedMessage.subject || ''} 
                onChange={(e) => setSelectedMessage({...selectedMessage, subject: e.target.value})}
                required
              />
            </div>
            
            <div className="mb-3">
              <label htmlFor="messageContent" className="form-label">Message</label>
              <textarea 
                className="form-control" 
                id="messageContent" 
                rows="5"
                value={replyText}
                onChange={(e) => setReplyText(e.target.value)}
                required
              ></textarea>
            </div>
            
            <div className="d-grid">
              <button 
                type="button" 
                className="btn btn-primary" 
                onClick={handleSendNewMessage}
              >
                {replyMethod === 'email' ? 
                  <><i className="fas fa-envelope me-2"></i>Send Email</> : 
                  <><i className="fas fa-sms me-2"></i>Send SMS</>
                }
              </button>
            </div>
          </form>
        </div>
      );
    }
    
    // View existing message
    return (
      <div className="p-3">
        <div className="d-flex justify-content-between align-items-center mb-3">
          <h5 className="mb-0">{selectedMessage.subject}</h5>
          <small className="text-muted">{selectedMessage.date}</small>
        </div>
        <div className="mb-3">
          <strong>
            {activeTab === 'inbox' ? 'From: ' : 'To: '}
          </strong>
          {activeTab === 'inbox' ? selectedMessage.from : selectedMessage.to}
          {selectedMessage.email && (
            <span className="text-muted ms-2">
              <i className="fas fa-envelope me-1"></i>
              {selectedMessage.email}
            </span>
          )}
          {selectedMessage.phone && (
            <span className="text-muted ms-2">
              <i className="fas fa-sms me-1"></i>
              {selectedMessage.phone}
            </span>
          )}
        </div>
        <div className="p-3 bg-light rounded mb-4">
          <p style={{ whiteSpace: 'pre-wrap' }}>{selectedMessage.message}</p>
        </div>
        
        {activeTab === 'inbox' && (
          <div>
            <div className="mb-3">
              <div className="d-flex justify-content-between align-items-center mb-2">
                <label className="form-label mb-0">Reply Method:</label>
                <div className="btn-group" role="group">
                  <input 
                    type="radio" 
                    className="btn-check" 
                    name="replyMethod" 
                    id="emailReply" 
                    value="email" 
                    checked={replyMethod === 'email'} 
                    onChange={handleReplyMethodChange}
                    autoComplete="off"
                  />
                  <label className="btn btn-outline-primary" htmlFor="emailReply">
                    <i className="fas fa-envelope me-1"></i> Email
                  </label>
                  
                  <input 
                    type="radio" 
                    className="btn-check" 
                    name="replyMethod" 
                    id="smsReply" 
                    value="sms" 
                    checked={replyMethod === 'sms'} 
                    onChange={handleReplyMethodChange}
                    autoComplete="off"
                    disabled={!selectedMessage.phone}
                  />
                  <label className={`btn btn-outline-primary ${!selectedMessage.phone ? 'disabled' : ''}`} htmlFor="smsReply">
                    <i className="fas fa-sms me-1"></i> SMS
                  </label>
                </div>
              </div>
              {!selectedMessage.phone && replyMethod === 'email' && (
                <div className="alert alert-warning py-1 small">
                  <i className="fas fa-info-circle me-1"></i> SMS not available: No phone number provided
                </div>
              )}
              <textarea 
                className="form-control" 
                rows="4" 
                placeholder="Write your reply here..."
                value={replyText}
                onChange={(e) => setReplyText(e.target.value)}
              ></textarea>
            </div>
            <div className="d-flex justify-content-end">
              <button 
                className="btn btn-primary"
                onClick={handleReply}
                disabled={!replyText.trim()}
              >
                {replyMethod === 'email' ? 
                  <><i className="fas fa-envelope me-1"></i> Reply via Email</> : 
                  <><i className="fas fa-sms me-1"></i> Reply via SMS</>
                }
              </button>
            </div>
          </div>
        )}
      </div>
    );
  };

  // Main component render for Services
  const renderServicesContent = () => {
    if (role !== "employee") {
      return (
        <div className="alert alert-danger">
          You don't have permission to access this page.
        </div>
      );
    }

    return (
      <div className="services-content">
        <h1 className="mb-4">Messages</h1>
        
        <div className="row">
          <div className="col-md-4 mb-4 mb-md-0">
            <div className="card">
              <div className="card-header d-flex justify-content-between align-items-center">
                <ul className="nav nav-tabs card-header-tabs">
                  <li className="nav-item">
                    <button 
                      className={`nav-link ${activeTab === 'inbox' ? 'active' : ''}`}
                      onClick={() => setActiveTab('inbox')}
                    >
                      Inbox
                      {messages.inbox.filter(m => m.status === 'unread').length > 0 && (
                        <span className="badge bg-primary rounded-pill ms-1">
                          {messages.inbox.filter(m => m.status === 'unread').length}
                        </span>
                      )}
                    </button>
                  </li>
                  <li className="nav-item">
                    <button 
                      className={`nav-link ${activeTab === 'outbox' ? 'active' : ''}`}
                      onClick={() => setActiveTab('outbox')}
                    >
                      Sent
                    </button>
                  </li>
                </ul>
              </div>
              <div className="card-body">
                <div className="d-flex justify-content-between align-items-center mb-3">
                  <div className="input-group">
                    <input
                      type="text"
                      className="form-control"
                      placeholder="Search messages..."
                      value={searchQuery}
                      onChange={handleSearchChange}
                    />
                    <button className="btn btn-outline-secondary">
                      <i className="fas fa-search"></i>
                    </button>
                  </div>
                  <div className="ms-2">
                    <button 
                      className="btn btn-sm btn-primary"
                      onClick={handleNewMessage}
                    >
                      <i className="fas fa-plus"></i>
                    </button>
                  </div>
                </div>
                <div className="mb-3">
                  <select
                    className="form-select form-select-sm"
                    value={filterStatus}
                    onChange={handleStatusFilterChange}
                  >
                    <option value="all">All Status</option>
                    <option value="unread">Unread</option>
                    <option value="read">Read</option>
                    <option value="sent">Sent</option>
                  </select>
                </div>
                {renderMessagesList()}
              </div>
            </div>
          </div>
          <div className="col-md-8">
            <div className="card">
              <div className="card-body">
                {renderMessageDetails()}
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  };

  return (
    <RoleLayout role={role}>
      {renderServicesContent()}
    </RoleLayout>
  );
};

export default Services;
