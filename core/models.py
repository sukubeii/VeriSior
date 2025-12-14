# core/models.py - Complete Core Models with Content Management and Team Members

from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.validators import RegexValidator

User = get_user_model()

class AuditLog(models.Model):
    """Model for tracking all system activities and changes for compliance"""
    
    ACTION_CHOICES = [
        ('CREATE', 'Create'),
        ('READ', 'Read'),
        ('UPDATE', 'Update'),
        ('DELETE', 'Delete'),
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
        ('APPROVE', 'Approve'),
        ('REJECT', 'Reject'),
        ('ARCHIVE', 'Archive'),
        ('RESTORE', 'Restore'),
        ('EXPORT', 'Export'),
        ('BACKUP', 'Backup'),
        ('OTHER', 'Other'),
    ]
    
    # User and Action Information
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs')
    action = models.CharField(max_length=10, choices=ACTION_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # Object Information
    content_type = models.CharField(max_length=50, help_text="Type of object being acted upon")
    object_id = models.PositiveIntegerField(null=True, blank=True, help_text="ID of the object")
    
    # Detailed Information
    description = models.TextField(help_text="Detailed description of the action")
    
    # Technical Information
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, null=True)
    
    # Additional Metadata
    extra_data = models.JSONField(default=dict, blank=True, help_text="Additional metadata in JSON format")
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Audit Log'
        verbose_name_plural = 'Audit Logs'
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action', 'timestamp']),
            models.Index(fields=['content_type', 'object_id']),
            models.Index(fields=['-timestamp']),
        ]
    
    def __str__(self):
        return f"{self.user} - {self.action} - {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
    
    @property
    def username(self):
        return self.user.username if self.user else 'Anonymous'


class ContactMessage(models.Model):
    """Model for contact form messages from the public portal"""
    
    STATUS_CHOICES = [
        ('NEW', 'New'),
        ('READ', 'Read'),
        ('REPLIED', 'Replied'),
        ('CLOSED', 'Closed'),
    ]
    
    SUBJECT_CHOICES = [
        ('technical-support', 'Technical Support'),
        ('general-inquiry', 'General Inquiry'),
        ('establishment-partnership', 'Partnership'),
        ('feedback', 'Feedback'),
        ('verification-issue', 'Verification Issue'),
        ('account-help', 'Account Help'),
        ('other', 'Other'),
    ]
    
    # Contact Information
    name = models.CharField(max_length=100, help_text="Full name of the person contacting")
    email = models.EmailField(help_text="Email address for response")
    phone = models.CharField(
        max_length=20, 
        blank=True, 
        null=True,
        validators=[RegexValidator(
            regex=r'^\+?1?\d{9,15}$',
            message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
        )],
        help_text="Optional phone number"
    )
    
    # Message Details
    subject = models.CharField(max_length=50, choices=SUBJECT_CHOICES, help_text="Subject category")
    custom_subject = models.CharField(max_length=200, blank=True, null=True, help_text="Custom subject if 'other' is selected")
    message = models.TextField(help_text="The actual message content")
    
    # Status and Management
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='NEW')
    priority = models.CharField(
        max_length=10,
        choices=[
            ('LOW', 'Low'),
            ('NORMAL', 'Normal'),
            ('HIGH', 'High'),
            ('URGENT', 'Urgent'),
        ],
        default='NORMAL'
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Reply Information
    replied_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='replied_messages'
    )
    replied_at = models.DateTimeField(null=True, blank=True)
    reply_content = models.TextField(blank=True, null=True)
    
    # Assignment
    assigned_to = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_messages',
        help_text="User assigned to handle this message"
    )
    
    # Metadata
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, null=True)
    referrer = models.URLField(blank=True, null=True, help_text="Page where the contact form was submitted")
    
    # Privacy Consent
    privacy_consent = models.BooleanField(default=False, help_text="User agreed to privacy policy")
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Contact Message'
        verbose_name_plural = 'Contact Messages'
        indexes = [
            models.Index(fields=['status', '-created_at']),
            models.Index(fields=['assigned_to', 'status']),
            models.Index(fields=['-created_at']),
            models.Index(fields=['email']),
        ]
    
    def __str__(self):
        subject_display = self.custom_subject if self.subject == 'other' and self.custom_subject else self.get_subject_display()
        return f"Message from {self.name} - {subject_display}"
    
    @property
    def is_new(self):
        return self.status == 'NEW'
    
    @property
    def is_replied(self):
        return self.status == 'REPLIED'
    
    @property
    def is_overdue(self):
        """Check if message is older than 3 days without reply"""
        if self.status in ['REPLIED', 'CLOSED']:
            return False
        
        from datetime import timedelta
        return timezone.now() - self.created_at > timedelta(days=3)
    
    @property
    def display_subject(self):
        """Return the appropriate subject for display"""
        if self.subject == 'other' and self.custom_subject:
            return self.custom_subject
        return self.get_subject_display()
    
    def mark_as_read(self, user=None):
        """Mark message as read"""
        if self.status == 'NEW':
            self.status = 'READ'
            self.save(update_fields=['status', 'updated_at'])
            
            # Create audit log
            if user:
                AuditLog.objects.create(
                    user=user,
                    action='READ',
                    content_type='ContactMessage',
                    object_id=self.id,
                    description=f'Marked contact message from {self.name} as read'
                )
    
    def assign_to_user(self, user, assigned_by=None):
        """Assign message to a user"""
        self.assigned_to = user
        self.save(update_fields=['assigned_to', 'updated_at'])
        
        # Create audit log
        if assigned_by:
            AuditLog.objects.create(
                user=assigned_by,
                action='UPDATE',
                content_type='ContactMessage',
                object_id=self.id,
                description=f'Assigned contact message from {self.name} to {user.username}'
            )


class SystemConfiguration(models.Model):
    """Model for storing system-wide configuration settings"""
    
    # System Information
    system_name = models.CharField(max_length=100, default='VeriSior')
    system_version = models.CharField(max_length=20, default='1.0.0')
    maintenance_mode = models.BooleanField(default=False, help_text="Enable to put system in maintenance mode")
    
    # ID Generation Settings
    next_global_count = models.PositiveIntegerField(default=1, help_text="Next sequential number for ID generation")
    id_prefix = models.CharField(max_length=10, blank=True, help_text="Optional prefix for all IDs")
    
    # Security Settings
    force_mfa = models.BooleanField(default=False, help_text="Require MFA for all new users")
    password_expiry_days = models.PositiveIntegerField(default=90, help_text="Days before password expires")
    session_timeout_minutes = models.PositiveIntegerField(default=60, help_text="Session timeout in minutes")
    max_login_attempts = models.PositiveIntegerField(default=5, help_text="Max failed login attempts before lockout")
    
    # Audit Settings
    audit_all_actions = models.BooleanField(default=True, help_text="Log all user actions")
    audit_retention_days = models.PositiveIntegerField(default=365, help_text="Days to retain audit logs")
    
    # Email Settings
    email_notifications_enabled = models.BooleanField(default=True)
    admin_email = models.EmailField(blank=True, help_text="Admin email for system notifications")
    smtp_host = models.CharField(max_length=255, blank=True)
    smtp_port = models.PositiveIntegerField(default=587)
    smtp_use_tls = models.BooleanField(default=True)
    
    # Content Settings
    homepage_banner_text = models.TextField(
        default="VeriSior - Secure Senior Citizen ID Verification System",
        help_text="Main banner text for homepage"
    )
    system_announcements = models.TextField(blank=True, help_text="System-wide announcements")
    contact_info = models.TextField(
        default="Email: support@verisior.gov.ph\nPhone: +63 (2) 8123-4567",
        help_text="Contact information displayed on site"
    )
    
    # Backup Settings
    auto_backup_enabled = models.BooleanField(default=False)
    backup_frequency_hours = models.PositiveIntegerField(default=24)
    backup_retention_days = models.PositiveIntegerField(default=30)
    
    # System Limits
    max_file_upload_size_mb = models.PositiveIntegerField(default=10, help_text="Maximum file upload size in MB")
    max_batch_upload_records = models.PositiveIntegerField(default=1000, help_text="Maximum records per batch upload")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    class Meta:
        verbose_name = 'System Configuration'
        verbose_name_plural = 'System Configurations'
    
    def __str__(self):
        return f"{self.system_name} Configuration"
    
    @classmethod
    def get_config(cls):
        """Get or create the system configuration"""
        config, created = cls.objects.get_or_create(pk=1)
        return config
    
    def get_next_id_number(self, barangay_code):
        """Generate the next ID number for a senior citizen"""
        current_count = self.next_global_count
        self.next_global_count += 1
        self.save(update_fields=['next_global_count'])
        
        # Format: XXX0000YYYYYY (barangay + padding + sequential)
        if self.id_prefix:
            return f"{self.id_prefix}{barangay_code}0000{current_count:06d}"
        else:
            return f"{barangay_code}0000{current_count:06d}"


class SystemNotification(models.Model):
    """Model for system-wide notifications"""
    
    NOTIFICATION_TYPES = [
        ('INFO', 'Information'),
        ('WARNING', 'Warning'),
        ('ERROR', 'Error'),
        ('SUCCESS', 'Success'),
        ('MAINTENANCE', 'Maintenance'),
        ('SECURITY', 'Security Alert'),
    ]
    
    title = models.CharField(max_length=200)
    message = models.TextField()
    notification_type = models.CharField(max_length=12, choices=NOTIFICATION_TYPES, default='INFO')
    
    # Display Settings
    is_active = models.BooleanField(default=True)
    show_on_dashboard = models.BooleanField(default=True)
    show_on_login = models.BooleanField(default=False)
    auto_dismiss = models.BooleanField(default=False, help_text="Auto-dismiss after display")
    
    # Targeting
    target_roles = models.JSONField(
        default=list, 
        blank=True, 
        help_text="List of roles this notification targets (empty = all roles)"
    )
    
    # Scheduling
    start_date = models.DateTimeField(default=timezone.now)
    end_date = models.DateTimeField(null=True, blank=True)
    
    # Metadata
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_notifications')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'System Notification'
        verbose_name_plural = 'System Notifications'
    
    def __str__(self):
        return f"{self.get_notification_type_display()}: {self.title}"
    
    @property
    def is_current(self):
        """Check if notification is currently active"""
        now = timezone.now()
        if not self.is_active:
            return False
        if now < self.start_date:
            return False
        if self.end_date and now > self.end_date:
            return False
        return True
    
    def is_visible_to_user(self, user):
        """Check if notification should be visible to the given user"""
        if not self.is_current:
            return False
        
        # Check role targeting
        if self.target_roles and user.role not in self.target_roles:
            return False
        
        return True


class UserNotificationRead(models.Model):
    """Track which notifications have been read by which users"""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    notification = models.ForeignKey(SystemNotification, on_delete=models.CASCADE)
    read_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['user', 'notification']
        verbose_name = 'User Notification Read'
        verbose_name_plural = 'User Notifications Read'
    
    def __str__(self):
        return f"{self.user.username} read {self.notification.title}"


class FileUpload(models.Model):
    """Track file uploads in the system"""
    
    UPLOAD_TYPES = [
        ('PROFILE_PHOTO', 'Profile Photo'),
        ('SENIOR_PHOTO', 'Senior Citizen Photo'),
        ('TEAM_PHOTO', 'Team Member Photo'),
        ('DOCUMENT', 'Document'),
        ('BATCH_UPLOAD', 'Batch Upload File'),
        ('BACKUP', 'Backup File'),
        ('OTHER', 'Other'),
    ]
    
    # File Information
    original_filename = models.CharField(max_length=255)
    file_path = models.CharField(max_length=500)
    file_size = models.PositiveIntegerField(help_text="File size in bytes")
    file_type = models.CharField(max_length=100, help_text="MIME type")
    upload_type = models.CharField(max_length=20, choices=UPLOAD_TYPES, default='OTHER')
    
    # Upload Information
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='uploaded_files')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
    # Associated Object (generic foreign key would be better, but keeping simple)
    related_object_type = models.CharField(max_length=50, blank=True)
    related_object_id = models.PositiveIntegerField(null=True, blank=True)
    
    # Metadata
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    is_processed = models.BooleanField(default=False, help_text="Whether file has been processed")
    processing_notes = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-uploaded_at']
        verbose_name = 'File Upload'
        verbose_name_plural = 'File Uploads'
        indexes = [
            models.Index(fields=['uploaded_by', '-uploaded_at']),
            models.Index(fields=['upload_type', '-uploaded_at']),
            models.Index(fields=['-uploaded_at']),
        ]
    
    def __str__(self):
        return f"{self.original_filename} - {self.uploaded_by.username}"
    
    @property
    def file_size_mb(self):
        """Return file size in MB"""
        return round(self.file_size / (1024 * 1024), 2)
    
    @property
    def is_image(self):
        """Check if file is an image"""
        return self.file_type.startswith('image/')
    
    @property
    def is_document(self):
        """Check if file is a document"""
        document_types = ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']
        return self.file_type in document_types


# CONTENT MANAGEMENT MODELS

class LandingPageContent(models.Model):
    """Single model to manage all landing page content with character limits"""
    
    # Hero Section (UPDATED)
    hero_title = models.CharField(
        max_length=15,  # Changed from 60
        default="VeriSior",
        help_text="Main title (3-15 characters)"
    )
    hero_subtitle = models.CharField(
        max_length=100,  # Changed from 120
        default="Your trusted platform for senior citizen ID verification and discount tracking.",
        help_text="Subtitle text (10-100 characters)"
    )
    
    # Features Section Header (UPDATED)
    features_title = models.CharField(
        max_length=50,  # Changed from 80
        default="Practical Solutions for Government Needs",
        help_text="Features section title (10-50 characters)"
    )
    features_subtitle = models.CharField(
        max_length=100,  # Changed from 120
        default="Secure and reliable verification system designed for government processes.",
        help_text="Features section subtitle (10-100 characters)"
    )
    
    # Carousel Slide 1 - Secure ID Verification (UPDATED)
    slide1_title = models.CharField(
        max_length=30,  # Changed from 50
        default="Secure ID Verification",
        help_text="First slide title (10-30 characters)"
    )
    slide1_subtitle = models.CharField(
        max_length=20,  # Changed from 50
        default="Reliable Security",
        help_text="First slide subtitle (10-20 characters)"
    )
    slide1_description = models.CharField(
        max_length=150,  # Changed from 200
        default="Validates ID numbers through encrypted database checks with status indicators to support secure and trusted verification.",
        help_text="First slide description (10-150 characters)"
    )
    
    # Carousel Slide 2 - Discount Tracking (UPDATED)
    slide2_title = models.CharField(
        max_length=30,  # Changed from 50
        default="Discount Tracking",
        help_text="Second slide title (10-30 characters)"
    )
    slide2_subtitle = models.CharField(
        max_length=20,  # Changed from 50
        default="Smart Monitoring",
        help_text="Second slide subtitle (10-20 characters)"
    )
    slide2_description = models.CharField(
        max_length=150,  # Changed from 200
        default="Monitors senior discounts with real-time validation, preventing misuse and ensuring accurate, transparent benefit tracking for establishments.",
        help_text="Second slide description (10-150 characters)"
    )
    
    # Carousel Slide 3 - Advanced Security (UPDATED)
    slide3_title = models.CharField(
        max_length=30,  # Changed from 50
        default="Advanced Security",
        help_text="Third slide title (10-30 characters)"
    )
    slide3_subtitle = models.CharField(
        max_length=20,  # Changed from 50
        default="Reliable Protection",
        help_text="Third slide subtitle (10-20 characters)"
    )
    slide3_description = models.CharField(
        max_length=150,  # Changed from 200
        default="Uses AES-256 encryption with role-based access and activity logs to provide a secure and trustworthy system.",
        help_text="Third slide description (10-150 characters)"
    )
    
    # About Us Section (UPDATED)
    about_title = models.CharField(
        max_length=15,  # Changed from 50
        default="About VeriSior",
        help_text="About section title (3-15 characters)"
    )
    about_description = models.TextField(
        max_length=300,  # Changed from 400
        default="Designed specifically to address the unique challenges of senior citizen ID verification and discount tracking in the digital age, VeriSior is a web-based application designed by a team of BSIT students from STI College - Novaliches.",
        help_text="About section description (10-300 characters)"
    )
    
    # FAQ Section (UPDATED)
    faq_title = models.CharField(
        max_length=30,  # Changed from 60
        default="Frequently Asked Questions",
        help_text="FAQ section title (10-30 characters)"
    )
    faq_subtitle = models.CharField(
        max_length=100,  # Changed from 120
        default="Find answers to common questions about VeriSior and senior citizen verification",
        help_text="FAQ section subtitle (10-100 characters)"
    )
    
    # Contact Section (UPDATED)
    contact_title = models.CharField(
        max_length=15,  # Changed from 50
        default="Contact Us",
        help_text="Contact section title (3-15 characters)"
    )
    contact_subtitle = models.CharField(
        max_length=100,  # Changed from 120
        default="We're here to help. Get in touch with our support team for any questions or assistance.",
        help_text="Contact section subtitle (10-100 characters)"
    )
    
    # Contact Information (UPDATED)
    office_name = models.CharField(
        max_length=30,  # Changed from 80
        default="STI College - Novaliches",
        help_text="Office name (10-30 characters)"
    )
    office_address = models.CharField(
        max_length=100,  # Changed from 150
        default="Corner, Quirino Highway\nQuezon City, Metro Manila 1126",
        help_text="Office address (10-100 characters)"
    )
    phone_number = models.CharField(
        max_length=11,  # Changed from 30
        default="09776513490",
        validators=[RegexValidator(
            regex=r'^\d{11}$',
            message='Phone number must be exactly 11 digits'
        )],
        help_text="Phone number (11 digits only)"
    )
    email_address = models.EmailField(
        max_length=30,  # Changed from 80
        default="verisior.gov@gmail.com",
        help_text="Email address (10-30 characters)"
    )
    
    # Metadata
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    class Meta:
        verbose_name = "Landing Page Content"
        verbose_name_plural = "Landing Page Content"
    
    def __str__(self):
        return f"Landing Page Content - Last updated: {self.updated_at.strftime('%Y-%m-%d %H:%M')}"
    
    @classmethod
    def get_content(cls):
        """Get or create the landing page content"""
        content, created = cls.objects.get_or_create(pk=1)
        return content


class TeamMember(models.Model):
    """Team member information for About Us section"""
    
    name = models.CharField(
        max_length=50, 
        help_text="Full name (max 50 characters)"
    )
    role = models.CharField(
        max_length=60, 
        help_text="Role/Position (max 60 characters)"
    )
    photo = models.ImageField(
        upload_to='team_photos/', 
        help_text="Team member photo (recommended: 200x200px)",
        blank=True,
        null=True
    )
    technical_skills = models.CharField(
        max_length=300,
        help_text="Technical skills (max 300 characters)"
    )
    soft_skills = models.CharField(
        max_length=200,
        help_text="Soft skills (max 200 characters)"
    )
    order = models.PositiveIntegerField(default=0, help_text="Display order")
    is_active = models.BooleanField(default=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    class Meta:
        ordering = ['order', 'name']
        verbose_name = "Team Member"
        verbose_name_plural = "Team Members"
    
    def __str__(self):
        return f"{self.name} - {self.role}"


class FAQItem(models.Model):
    """FAQ items for the FAQ section"""

    question = models.CharField(
        max_length=120,
        help_text="FAQ question (max 120 characters)"
    )
    answer = models.TextField(
        max_length=500,
        help_text="Detailed answer (max 500 characters)"
    )
    icon_class = models.CharField(
        max_length=50,
        default="fas fa-question-circle",
        help_text="Font Awesome icon class (e.g., 'fas fa-question-circle')"
    )
    order = models.PositiveIntegerField(default=0, help_text="Display order")
    is_active = models.BooleanField(default=True)

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        ordering = ['order', 'created_at']
        verbose_name = "FAQ Item"
        verbose_name_plural = "FAQ Items"

    def __str__(self):
        return f"FAQ: {self.question[:50]}..."


class PrivacyPolicy(models.Model):
    """Privacy Policy content management"""

    title = models.CharField(
        max_length=100,
        default="Privacy Policy",
        help_text="Privacy policy title (max 100 characters)"
    )

    # Privacy Policy Sections
    introduction = models.TextField(
        max_length=1000,
        default="At VeriSior, we are committed to protecting your privacy and ensuring the security of your personal information. This Privacy Policy explains how we collect, use, and protect your information when you use our senior citizen ID verification system.",
        help_text="Introduction section (max 1000 characters)"
    )

    information_collected = models.TextField(
        max_length=1500,
        default="We collect information necessary to provide our verification services, including: personal identification details, contact information, verification requests, and system usage data. All data collection is limited to what is necessary for service provision and compliance with government regulations.",
        help_text="What information we collect (max 1500 characters)"
    )

    information_usage = models.TextField(
        max_length=1500,
        default="Your information is used to: verify senior citizen IDs, process discount validations, maintain system security, comply with legal requirements, and improve our services. We do not sell or share personal information with third parties except as required by law.",
        help_text="How we use your information (max 1500 characters)"
    )

    information_protection = models.TextField(
        max_length=1200,
        default="We implement industry-standard security measures including AES-256 encryption, secure data transmission, role-based access controls, regular security audits, and strict access policies to protect your personal information from unauthorized access or misuse.",
        help_text="How we protect your information (max 1200 characters)"
    )

    data_retention = models.TextField(
        max_length=800,
        default="We retain personal information only as long as necessary for service provision and legal compliance. Verification records are kept according to government retention requirements, typically 7 years for audit purposes.",
        help_text="Data retention policy (max 800 characters)"
    )

    user_rights = models.TextField(
        max_length=1000,
        default="You have the right to access your personal information, request corrections, withdraw consent where applicable, and file complaints with appropriate authorities. Contact us to exercise these rights or for privacy-related concerns.",
        help_text="User rights and choices (max 1000 characters)"
    )

    contact_information = models.TextField(
        max_length=500,
        default="For privacy-related questions or concerns, contact us at: verisior.gov@gmail.com or +63 977 651 3490. Our Data Protection Officer is available to address your privacy concerns and requests.",
        help_text="Privacy contact information (max 500 characters)"
    )

    effective_date = models.DateField(
        default=timezone.now,
        help_text="When this privacy policy becomes effective"
    )

    last_updated = models.DateField(
        auto_now=True,
        help_text="Last update date"
    )

    version = models.CharField(
        max_length=10,
        default="1.0",
        help_text="Policy version number"
    )

    is_active = models.BooleanField(
        default=True,
        help_text="Whether this privacy policy version is active"
    )

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        ordering = ['-version', '-last_updated']
        verbose_name = "Privacy Policy"
        verbose_name_plural = "Privacy Policies"

    def __str__(self):
        return f"Privacy Policy v{self.version} - {self.last_updated.strftime('%Y-%m-%d')}"

    @classmethod
    def get_active_policy(cls):
        """Get the currently active privacy policy"""
        return cls.objects.filter(is_active=True).first()

    def activate(self):
        """Set this policy as the active one and deactivate others"""
        cls = self.__class__
        cls.objects.filter(is_active=True).update(is_active=False)
        self.is_active = True
        self.save(update_fields=['is_active', 'updated_at'])


# Signals to automatically create audit logs
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver

@receiver(post_save, sender=ContactMessage)
def log_contact_message_save(sender, instance, created, **kwargs):
    """Create audit log when contact message is saved"""
    if created:
        AuditLog.objects.create(
            user=None,  # Public contact form
            action='CREATE',
            content_type='ContactMessage',
            object_id=instance.id,
            description=f'New contact message received from {instance.name} - {instance.display_subject}',
            ip_address=instance.ip_address
        )

@receiver(post_save, sender=SystemConfiguration)
def log_system_config_change(sender, instance, created, **kwargs):
    """Create audit log when system configuration is changed"""
    action = 'CREATE' if created else 'UPDATE'
    description = 'System configuration created' if created else 'System configuration updated'
    
    AuditLog.objects.create(
        user=instance.updated_by,
        action=action,
        content_type='SystemConfiguration',
        object_id=instance.id,
        description=description
    )

@receiver(post_save, sender=LandingPageContent)
def log_landing_page_content_change(sender, instance, created, **kwargs):
    """Create audit log when landing page content is changed"""
    action = 'CREATE' if created else 'UPDATE'
    description = 'Landing page content created' if created else 'Landing page content updated'
    
    AuditLog.objects.create(
        user=instance.updated_by,
        action=action,
        content_type='LandingPageContent',
        object_id=instance.id,
        description=description
    )

@receiver(post_save, sender=TeamMember)
def log_team_member_change(sender, instance, created, **kwargs):
    """Create audit log when team member is changed"""
    action = 'CREATE' if created else 'UPDATE'
    description = f'Team member {instance.name} {"created" if created else "updated"}'
    
    AuditLog.objects.create(
        user=instance.updated_by,
        action=action,
        content_type='TeamMember',
        object_id=instance.id,
        description=description
    )

@receiver(post_delete, sender=TeamMember)
def log_team_member_delete(sender, instance, **kwargs):
    """Create audit log when team member is deleted"""
    AuditLog.objects.create(
        user=None,  # Can't get user in post_delete
        action='DELETE',
        content_type='TeamMember',
        object_id=instance.id,
        description=f'Team member {instance.name} deleted'
    )

@receiver(post_save, sender=FAQItem)
def log_faq_item_change(sender, instance, created, **kwargs):
    """Create audit log when FAQ item is changed"""
    action = 'CREATE' if created else 'UPDATE'
    description = f'FAQ item {"created" if created else "updated"}: {instance.question[:50]}'
    
    AuditLog.objects.create(
        user=instance.updated_by,
        action=action,
        content_type='FAQItem',
        object_id=instance.id,
        description=description
    )

@receiver(post_delete, sender=FAQItem)
def log_faq_item_delete(sender, instance, **kwargs):
    """Create audit log when FAQ item is deleted"""
    AuditLog.objects.create(
        user=None,  # Can't get user in post_delete
        action='DELETE',
        content_type='FAQItem',
        object_id=instance.id,
        description=f'FAQ item deleted: {instance.question[:50]}'
    )

@receiver(post_save, sender=PrivacyPolicy)
def log_privacy_policy_change(sender, instance, created, **kwargs):
    """Create audit log when privacy policy is changed"""
    action = 'CREATE' if created else 'UPDATE'
    description = f'Privacy policy v{instance.version} {"created" if created else "updated"}'

    AuditLog.objects.create(
        user=instance.updated_by,
        action=action,
        content_type='PrivacyPolicy',
        object_id=instance.id,
        description=description
    )

@receiver(post_delete, sender=PrivacyPolicy)
def log_privacy_policy_delete(sender, instance, **kwargs):
    """Create audit log when privacy policy is deleted"""
    AuditLog.objects.create(
        user=None,  # Can't get user in post_delete
        action='DELETE',
        content_type='PrivacyPolicy',
        object_id=instance.id,
        description=f'Privacy policy v{instance.version} deleted'
    )
