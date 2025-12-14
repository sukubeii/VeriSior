from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from django.core.validators import FileExtensionValidator
from datetime import timedelta
import os

class UserType(models.TextChoices):
    GOVERNMENT = 'GOV', 'Government'
    ESTABLISHMENT = 'EST', 'Establishment'

class UserRole(models.TextChoices):
    ROOT_ADMIN = 'RA', 'Root Administrator'
    SYSTEM_ADMIN = 'SA', 'System Administrator'
    ADMINISTRATOR = 'AD', 'Administrator'
    EMPLOYEE = 'EM', 'Employee'

class UserStatus(models.TextChoices):
    ACTIVE = 'ACTIVE', 'Active'
    INACTIVE = 'INACTIVE', 'Inactive (Archived)'
    DELETED = 'DELETED', 'Deleted'

class CustomUser(AbstractUser):
    user_type = models.CharField(max_length=3, choices=UserType.choices, default='GOV')
    role = models.CharField(max_length=2, choices=UserRole.choices, default='EM')
    status = models.CharField(max_length=10, choices=UserStatus.choices, default='ACTIVE', help_text='User account status')
    mfa_enabled = models.BooleanField(default=False)
    must_change_password = models.BooleanField(default=True)

    # Status tracking fields
    inactivated_at = models.DateTimeField(null=True, blank=True, help_text='Date and time when user was inactivated')
    inactivated_by = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='inactivated_users',
        help_text='User who inactivated this account'
    )
    deleted_at = models.DateTimeField(null=True, blank=True, help_text='Date and time when user was moved to deleted status')
    deleted_by = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='deleted_users',
        help_text='User who deleted this account'
    )

    # Profile picture field
    profile_picture = models.ImageField(
        upload_to='profile_pictures/',
        null=True,
        blank=True,
        validators=[FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png', 'gif'])],
        help_text="Profile picture (JPG, PNG, GIF - Max 5MB)"
    )
    
    # ============ CORE NAVIGATION PERMISSIONS ============
    
    # Dashboard Access & Permissions
    can_access_dashboard = models.BooleanField(default=False, help_text="Access to Dashboard")
    can_view_dashboard_statistics = models.BooleanField(default=False, help_text="View dashboard statistics and overview")
    can_export_dashboard_reports = models.BooleanField(default=False, help_text="Export dashboard reports and analytics")
    
    # Active Records Access & CRUD Permissions
    can_access_active_records = models.BooleanField(default=False, help_text="Access to Active Records")
    can_view_active_records = models.BooleanField(default=False, help_text="View active senior citizen records")
    can_create_active_records = models.BooleanField(default=False, help_text="Create new senior citizen records")
    can_edit_active_records = models.BooleanField(default=False, help_text="Edit existing active records")
    can_delete_active_records = models.BooleanField(default=False, help_text="Delete active records")
    can_approve_active_records = models.BooleanField(default=False, help_text="Approve/reject senior citizen applications")
    can_export_active_records = models.BooleanField(default=False, help_text="Export active records data")
    
    # Archived Records Access & Permissions
    can_access_archived_records = models.BooleanField(default=False, help_text="Access to Archived Records")
    can_view_archived_records = models.BooleanField(default=False, help_text="View archived/historical records")
    can_restore_archived_records = models.BooleanField(default=False, help_text="Restore archived records to active")
    can_permanently_delete_archived = models.BooleanField(default=False, help_text="Permanently delete archived records")
    can_export_archived_records = models.BooleanField(default=False, help_text="Export archived records data")
    
    # Batch Upload Access & Permissions
    can_access_batch_upload = models.BooleanField(default=False, help_text="Access to Batch Upload")
    can_perform_batch_upload = models.BooleanField(default=False, help_text="Perform bulk data uploads")
    can_download_batch_templates = models.BooleanField(default=False, help_text="Download batch upload templates")
    can_view_batch_history = models.BooleanField(default=False, help_text="View batch upload history")
    can_manage_batch_operations = models.BooleanField(default=False, help_text="Manage and monitor batch operations")
    
    # Messages Access & Permissions
    can_access_messages = models.BooleanField(default=False, help_text="Access to Messages")
    can_view_messages = models.BooleanField(default=False, help_text="View contact messages and communications")
    can_respond_to_messages = models.BooleanField(default=False, help_text="Respond to messages")
    can_send_bulk_messages = models.BooleanField(default=False, help_text="Send bulk SMS/Email messages")
    can_delete_messages = models.BooleanField(default=False, help_text="Delete messages")
    can_export_message_data = models.BooleanField(default=False, help_text="Export message data and reports")
    
    # Settings Access & Permissions
    can_access_settings = models.BooleanField(default=False, help_text="Access to Settings")
    can_modify_personal_settings = models.BooleanField(default=True, help_text="Modify personal account settings")
    can_modify_system_settings = models.BooleanField(default=False, help_text="Modify system-wide settings")
    can_manage_backup_settings = models.BooleanField(default=False, help_text="Manage backup and restore settings")
    can_view_audit_logs = models.BooleanField(default=False, help_text="View system audit logs")
    can_export_audit_logs = models.BooleanField(default=False, help_text="Export audit logs")
    
    # Reports Access & Permissions
    can_access_reports = models.BooleanField(default=False, help_text="Access to Reports")
    can_view_reports = models.BooleanField(default=False, help_text="View system reports")
    can_generate_reports = models.BooleanField(default=False, help_text="Generate and download reports")
    can_export_reports = models.BooleanField(default=False, help_text="Export reports to various formats")
    
    # ============ ADMINISTRATIVE NAVIGATION PERMISSIONS ============
    
    # Pending Approvals Access & Permissions
    can_access_pending_approvals = models.BooleanField(default=False, help_text="Access to Pending Approvals")
    can_view_pending_applications = models.BooleanField(default=False, help_text="View pending applications")
    can_approve_applications = models.BooleanField(default=False, help_text="Approve applications")
    can_reject_applications = models.BooleanField(default=False, help_text="Reject applications")
    can_bulk_process_approvals = models.BooleanField(default=False, help_text="Bulk process multiple approvals")
    can_export_approval_reports = models.BooleanField(default=False, help_text="Export approval reports and statistics")
    
    # Verification Requests Access & Permissions
    can_access_verification_requests = models.BooleanField(default=False, help_text="Access to Verification Requests")
    can_view_verification_requests = models.BooleanField(default=False, help_text="View public verification requests")
    can_respond_to_verifications = models.BooleanField(default=False, help_text="Respond to verification requests")
    can_manage_verification_queue = models.BooleanField(default=False, help_text="Manage verification request queue")
    can_export_verification_data = models.BooleanField(default=False, help_text="Export verification request data")
    
    # User Management Access & Permissions
    can_access_user_management = models.BooleanField(default=False, help_text="Access to User Management")
    can_view_users = models.BooleanField(default=False, help_text="View user accounts")
    can_create_users = models.BooleanField(default=False, help_text="Create new user accounts")
    can_edit_users = models.BooleanField(default=False, help_text="Edit existing user accounts")
    can_delete_users = models.BooleanField(default=False, help_text="Delete user accounts")
    can_manage_user_permissions = models.BooleanField(default=False, help_text="Manage user permissions and roles")
    can_reset_user_passwords = models.BooleanField(default=False, help_text="Reset user passwords")
    can_disable_user_mfa = models.BooleanField(default=False, help_text="Disable MFA for users")
    
    # Content Management Access & Permissions
    can_access_content_management = models.BooleanField(default=False, help_text="Access to Content Management")
    can_view_content = models.BooleanField(default=False, help_text="View homepage content preview")
    can_edit_landing_page_content = models.BooleanField(default=False, help_text="Edit landing page content (hero, features, about, contact)")
    can_manage_team_members = models.BooleanField(default=False, help_text="Add, edit, delete team members")
    can_manage_faq_items = models.BooleanField(default=False, help_text="Add, edit, delete FAQ items")
    can_manage_privacy_policy = models.BooleanField(default=False, help_text="Edit privacy policy content")
    can_export_content = models.BooleanField(default=False, help_text="Export content data")
    can_backup_restore_content = models.BooleanField(default=False, help_text="Create and restore content backups")
    
    # Profile Access & Permissions
    can_access_profile = models.BooleanField(default=True, help_text="Access to Profile")
    can_edit_personal_profile = models.BooleanField(default=True, help_text="Edit personal profile information")
    can_change_password = models.BooleanField(default=True, help_text="Change account password")
    can_setup_mfa = models.BooleanField(default=True, help_text="Setup/modify multi-factor authentication")
    can_view_login_history = models.BooleanField(default=True, help_text="View personal login history")
    
    # Profile Fields
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    department = models.CharField(max_length=100, blank=True, null=True)
    
    # Add related_name attributes to resolve the clash
    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name='groups',
        blank=True,
        help_text='The groups this user belongs to.',
        related_name='custom_user_set',
        related_query_name='user'
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name='user permissions',
        blank=True,
        help_text='Specific permissions for this user.',
        related_name='custom_user_set',
        related_query_name='user'
    )
    
    class Meta:
        permissions = [
            ("manage_users", "Can manage users"),
            ("manage_senior_records", "Can manage senior records"),
            ("view_audit_logs", "Can view audit logs"),
            ("download_audit_logs", "Can download audit logs"),
            ("create_backups", "Can create system backups"),
            ("system_settings", "Can modify system settings"),
            ("root_access", "Can access root administrator functions"),
            ("content_management", "Can manage homepage content"),
            ("send_messages", "Can send SMS/Email messages"),
        ]

    def save(self, *args, **kwargs):
        """FIXED: Simple save method that doesn't interfere with manual permission setting"""
        # Set Django superuser/staff status based on role
        if self.role == 'RA':
            self.is_superuser = True
            self.is_staff = True
        elif self.role == 'SA':
            self.is_staff = True
            self.is_superuser = False
        else:
            self.is_staff = False
            self.is_superuser = False
        
        # Only set default permissions for brand new users created without explicit permission setting
        is_new_user = not self.pk
        
        # Call parent save method
        super().save(*args, **kwargs)
        
        # Set default permissions for new users based on role
        if is_new_user and not hasattr(self, '_permissions_manually_set'):
            if self.role == 'RA':
                print(f"Setting full permissions for Root Administrator: {self.username}")
                self.set_full_permissions()
            elif self.role == 'SA':
                print(f"Setting full permissions for System Administrator: {self.username}")
                self.set_full_permissions()  # SA gets same permissions as RA
            elif self.role == 'AD':
                print(f"Setting administrator permissions for: {self.username}")
                self.set_administrator_permissions()
            elif self.role == 'EM':
                print(f"Setting employee permissions for: {self.username}")
                self.set_employee_permissions()

            # Save again with permissions but mark as manually set to avoid recursion
            self._permissions_manually_set = True
            permission_fields = [f.name for f in self._meta.fields if f.name.startswith('can_')]
            super().save(update_fields=permission_fields)
    
    def delete_profile_picture(self):
        """Helper method to safely delete profile picture"""
        if self.profile_picture:
            try:
                if os.path.isfile(self.profile_picture.path):
                    os.remove(self.profile_picture.path)
            except Exception as e:
                print(f"Error deleting profile picture: {e}")
    
    def get_profile_picture_url(self):
        """Get profile picture URL or return None"""
        if self.profile_picture and hasattr(self.profile_picture, 'url'):
            return self.profile_picture.url
        return None
    
    def set_full_permissions(self):
        """Set all permissions to True - used only for RA accounts"""
        # Dashboard
        self.can_access_dashboard = True
        self.can_view_dashboard_statistics = True
        self.can_export_dashboard_reports = True

        # Active Records
        self.can_access_active_records = True
        self.can_view_active_records = True
        self.can_create_active_records = True
        self.can_edit_active_records = True
        self.can_delete_active_records = True
        self.can_approve_active_records = True
        self.can_export_active_records = True

        # Archived Records
        self.can_access_archived_records = True
        self.can_view_archived_records = True
        self.can_restore_archived_records = True
        self.can_permanently_delete_archived = True
        self.can_export_archived_records = True

        # Batch Upload
        self.can_access_batch_upload = True
        self.can_perform_batch_upload = True
        self.can_download_batch_templates = True
        self.can_view_batch_history = True
        self.can_manage_batch_operations = True

        # Messages
        self.can_access_messages = True
        self.can_view_messages = True
        self.can_respond_to_messages = True
        self.can_send_bulk_messages = True
        self.can_delete_messages = True
        self.can_export_message_data = True

        # Settings
        self.can_access_settings = True
        self.can_modify_personal_settings = True
        self.can_modify_system_settings = True
        self.can_manage_backup_settings = True
        self.can_view_audit_logs = True
        self.can_export_audit_logs = True

        # Reports
        self.can_access_reports = True
        self.can_view_reports = True
        self.can_generate_reports = True
        self.can_export_reports = True

        # Administrative - All permissions
        self.can_access_pending_approvals = True
        self.can_view_pending_applications = True
        self.can_approve_applications = True
        self.can_reject_applications = True
        self.can_bulk_process_approvals = True
        self.can_export_approval_reports = True

        self.can_access_verification_requests = True
        self.can_view_verification_requests = True
        self.can_respond_to_verifications = True
        self.can_manage_verification_queue = True
        self.can_export_verification_data = True

        self.can_access_user_management = True
        self.can_view_users = True
        self.can_create_users = True
        self.can_edit_users = True
        self.can_delete_users = True
        self.can_manage_user_permissions = True
        self.can_reset_user_passwords = True
        self.can_disable_user_mfa = True

        self.can_access_content_management = True
        self.can_view_content = True
        self.can_edit_landing_page_content = True
        self.can_manage_team_members = True
        self.can_manage_faq_items = True
        self.can_manage_privacy_policy = True
        self.can_export_content = True
        self.can_backup_restore_content = True

        # Profile permissions are always True by default

    def set_administrator_permissions(self):
        """Set permissions for AD (Administrator) role
        Access to everything EXCEPT:
        - Content Management
        - System Configuration (in Settings)
        - Backup & Data Management (in Settings)
        """
        # Dashboard - Full access
        self.can_access_dashboard = True
        self.can_view_dashboard_statistics = True
        self.can_export_dashboard_reports = True

        # Active Records - Full access
        self.can_access_active_records = True
        self.can_view_active_records = True
        self.can_create_active_records = True
        self.can_edit_active_records = True
        self.can_delete_active_records = True
        self.can_approve_active_records = True
        self.can_export_active_records = True

        # Archived Records - Full access
        self.can_access_archived_records = True
        self.can_view_archived_records = True
        self.can_restore_archived_records = True
        self.can_permanently_delete_archived = True
        self.can_export_archived_records = True

        # Batch Upload - Full access
        self.can_access_batch_upload = True
        self.can_perform_batch_upload = True
        self.can_download_batch_templates = True
        self.can_view_batch_history = True
        self.can_manage_batch_operations = True

        # Messages - Full access
        self.can_access_messages = True
        self.can_view_messages = True
        self.can_respond_to_messages = True
        self.can_send_bulk_messages = True
        self.can_delete_messages = True
        self.can_export_message_data = True

        # Settings - LIMITED (no system settings, no backup)
        self.can_access_settings = True
        self.can_modify_personal_settings = True
        self.can_modify_system_settings = False  # EXCLUDED
        self.can_manage_backup_settings = False  # EXCLUDED
        self.can_view_audit_logs = True
        self.can_export_audit_logs = True

        # Reports - Full access
        self.can_access_reports = True
        self.can_view_reports = True
        self.can_generate_reports = True
        self.can_export_reports = True

        # Pending Approvals - Full access
        self.can_access_pending_approvals = True
        self.can_view_pending_applications = True
        self.can_approve_applications = True
        self.can_reject_applications = True
        self.can_bulk_process_approvals = True
        self.can_export_approval_reports = True

        # Verification Requests - Full access
        self.can_access_verification_requests = True
        self.can_view_verification_requests = True
        self.can_respond_to_verifications = True
        self.can_manage_verification_queue = True
        self.can_export_verification_data = True

        # User Management - Full access
        self.can_access_user_management = True
        self.can_view_users = True
        self.can_create_users = True
        self.can_edit_users = True
        self.can_delete_users = True
        self.can_manage_user_permissions = True
        self.can_reset_user_passwords = True
        self.can_disable_user_mfa = True

        # Content Management - EXCLUDED
        self.can_access_content_management = False
        self.can_view_content = False
        self.can_edit_landing_page_content = False
        self.can_manage_team_members = False
        self.can_manage_faq_items = False
        self.can_manage_privacy_policy = False
        self.can_export_content = False
        self.can_backup_restore_content = False

        # Profile - Always enabled
        self.can_access_profile = True
        self.can_edit_personal_profile = True
        self.can_change_password = True
        self.can_setup_mfa = True
        self.can_view_login_history = True

    def set_employee_permissions(self):
        """Set permissions for EM (Employee) role
        Access to everything EXCEPT:
        - System Configuration (in Settings)
        - Backup & Data Management (in Settings)
        - Reports
        - Pending Approvals
        - Verification Requests
        - User Management
        - Content Management
        """
        # Dashboard - Full access
        self.can_access_dashboard = True
        self.can_view_dashboard_statistics = True
        self.can_export_dashboard_reports = True

        # Active Records - Full access
        self.can_access_active_records = True
        self.can_view_active_records = True
        self.can_create_active_records = True
        self.can_edit_active_records = True
        self.can_delete_active_records = True
        self.can_approve_active_records = True
        self.can_export_active_records = True

        # Archived Records - Full access
        self.can_access_archived_records = True
        self.can_view_archived_records = True
        self.can_restore_archived_records = True
        self.can_permanently_delete_archived = True
        self.can_export_archived_records = True

        # Batch Upload - Full access
        self.can_access_batch_upload = True
        self.can_perform_batch_upload = True
        self.can_download_batch_templates = True
        self.can_view_batch_history = True
        self.can_manage_batch_operations = True

        # Messages - Full access
        self.can_access_messages = True
        self.can_view_messages = True
        self.can_respond_to_messages = True
        self.can_send_bulk_messages = True
        self.can_delete_messages = True
        self.can_export_message_data = True

        # Settings - LIMITED (no system settings, no backup)
        self.can_access_settings = True
        self.can_modify_personal_settings = True
        self.can_modify_system_settings = False  # EXCLUDED
        self.can_manage_backup_settings = False  # EXCLUDED
        self.can_view_audit_logs = True
        self.can_export_audit_logs = True

        # Reports - EXCLUDED
        self.can_access_reports = False
        self.can_view_reports = False
        self.can_generate_reports = False
        self.can_export_reports = False

        # Pending Approvals - EXCLUDED
        self.can_access_pending_approvals = False
        self.can_view_pending_applications = False
        self.can_approve_applications = False
        self.can_reject_applications = False
        self.can_bulk_process_approvals = False
        self.can_export_approval_reports = False

        # Verification Requests - EXCLUDED
        self.can_access_verification_requests = False
        self.can_view_verification_requests = False
        self.can_respond_to_verifications = False
        self.can_manage_verification_queue = False
        self.can_export_verification_data = False

        # User Management - EXCLUDED
        self.can_access_user_management = False
        self.can_view_users = False
        self.can_create_users = False
        self.can_edit_users = False
        self.can_delete_users = False
        self.can_manage_user_permissions = False
        self.can_reset_user_passwords = False
        self.can_disable_user_mfa = False

        # Content Management - EXCLUDED
        self.can_access_content_management = False
        self.can_view_content = False
        self.can_edit_landing_page_content = False
        self.can_manage_team_members = False
        self.can_manage_faq_items = False
        self.can_manage_privacy_policy = False
        self.can_export_content = False
        self.can_backup_restore_content = False

        # Profile - Always enabled
        self.can_access_profile = True
        self.can_edit_personal_profile = True
        self.can_change_password = True
        self.can_setup_mfa = True
        self.can_view_login_history = True

    def get_manageable_roles(self):
        """Get roles that this user can manage - based on role hierarchy"""
        # Must have user management access permission
        if not getattr(self, 'can_access_user_management', False) or not getattr(self, 'can_create_users', False):
            return []
        
        # Role hierarchy - can only create accounts at same level or below
        if self.role == 'RA':
            return ['SA', 'AD', 'EM']
        elif self.role == 'SA':
            return ['SA', 'AD', 'EM']
        elif self.role == 'AD':
            return ['AD', 'EM']
        elif self.role == 'EM':
            # Employee can only create other employee accounts
            return ['EM']
        else:
            return []
    
    def can_manage_user(self, target_user):
        """Check if this user can manage the target user"""
        if self.pk == target_user.pk:
            return False  # Cannot manage yourself
        
        if target_user.role == 'RA':
            return False  # No one can manage RA except RA themselves
            
        # Must have permission to edit users
        if not getattr(self, 'can_edit_users', False):
            return False
            
        manageable_roles = self.get_manageable_roles()
        return target_user.role in manageable_roles
    
    def get_permission_summary(self):
        """Get a summary of user's permissions for debugging"""
        permissions = {}
        
        # Get all permission fields
        for field in self._meta.fields:
            if field.name.startswith('can_'):
                permissions[field.name] = getattr(self, field.name, False)
        
        granted = [name for name, value in permissions.items() if value]
        revoked = [name for name, value in permissions.items() if not value]
        
        return {
            'total_permissions': len(permissions),
            'granted_count': len(granted),
            'revoked_count': len(revoked),
            'granted_permissions': granted,
            'revoked_permissions': revoked
        }
    
    def has_any_administrative_access(self):
        """Check if user has any administrative navigation access"""
        admin_permissions = [
            'can_access_pending_approvals',
            'can_access_verification_requests', 
            'can_access_user_management',
            'can_access_content_management'
        ]
        
        return any(getattr(self, perm, False) for perm in admin_permissions)
    
    def has_any_core_navigation_access(self):
        """Check if user has any core navigation access"""
        core_permissions = [
            'can_access_dashboard',
            'can_access_active_records',
            'can_access_archived_records',
            'can_access_batch_upload',
            'can_access_messages',
            'can_access_settings',
            'can_access_reports'
        ]
        
        return any(getattr(self, perm, False) for perm in core_permissions)
    
    def validate_permission_coherence(self):
        """Validate that permissions are coherent (dependent permissions have prerequisites)"""
        issues = []
        
        # Check navigation access prerequisites
        navigation_checks = [
            ('can_view_dashboard_statistics', 'can_access_dashboard', 'Dashboard statistics requires dashboard access'),
            ('can_export_dashboard_reports', 'can_access_dashboard', 'Dashboard reports requires dashboard access'),
            ('can_view_active_records', 'can_access_active_records', 'View active records requires active records access'),
            ('can_create_active_records', 'can_access_active_records', 'Create active records requires active records access'),
            ('can_edit_active_records', 'can_view_active_records', 'Edit active records requires view access'),
            ('can_delete_active_records', 'can_view_active_records', 'Delete active records requires view access'),
            ('can_view_users', 'can_access_user_management', 'View users requires user management access'),
            ('can_create_users', 'can_access_user_management', 'Create users requires user management access'),
            ('can_edit_users', 'can_view_users', 'Edit users requires view users permission'),
            ('can_delete_users', 'can_view_users', 'Delete users requires view users permission'),
            ('can_view_reports', 'can_access_reports', 'View reports requires reports access'),
            ('can_generate_reports', 'can_access_reports', 'Generate reports requires reports access'),
        ]
        
        for dependent, required, description in navigation_checks:
            if getattr(self, dependent, False) and not getattr(self, required, False):
                issues.append(f"{description} ({dependent} requires {required})")
        
        return issues
    
    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"


# Import security models
from .security_models import LoginAttempt, SecurityAlert


class PasswordResetCode(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def is_valid(self):
        return timezone.now() < self.expires_at

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=15)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Reset code for {self.user.username} (expires: {self.expires_at})"


class PasswordResetRequest(models.Model):
    """Model for tracking password reset requests that require admin approval"""

    STATUS_CHOICES = [
        ('PENDING', 'Pending Approval'),
        ('APPROVED', 'Approved'),
        ('REJECTED', 'Rejected'),
    ]

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='password_reset_requests')
    requested_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='PENDING')

    # Approval/Rejection fields
    processed_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='processed_reset_requests',
        help_text='Admin who approved or rejected this request'
    )
    processed_at = models.DateTimeField(null=True, blank=True)
    admin_notes = models.TextField(blank=True, null=True, help_text='Admin notes/reason for approval or rejection')

    # Temporary password (only set when approved)
    temporary_password = models.CharField(max_length=128, blank=True, null=True, help_text='Temporary password sent to user')
    temp_password_sent = models.BooleanField(default=False)
    temp_password_used = models.BooleanField(default=False)

    class Meta:
        ordering = ['-requested_at']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['status', 'requested_at']),
        ]

    def __str__(self):
        return f"Password reset request for {self.user.username} - {self.status}"

    def approve(self, admin_user, temporary_password, notes=''):
        """Approve the password reset request"""
        self.status = 'APPROVED'
        self.processed_by = admin_user
        self.processed_at = timezone.now()
        self.admin_notes = notes
        self.temporary_password = temporary_password
        self.save()

    def reject(self, admin_user, notes=''):
        """Reject the password reset request"""
        self.status = 'REJECTED'
        self.processed_by = admin_user
        self.processed_at = timezone.now()
        self.admin_notes = notes
        self.save()


# Signal to clean up profile pictures when user is deleted
from django.db.models.signals import pre_delete
from django.dispatch import receiver

@receiver(pre_delete, sender=CustomUser)
def delete_user_profile_picture(sender, instance, **kwargs):
    """Delete profile picture file when user is deleted"""
    instance.delete_profile_picture()
