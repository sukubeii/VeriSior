from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.hashers import make_password
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import JsonResponse
from django.db import transaction
import string
import random

from .models import CustomUser, UserRole, UserType, PasswordResetRequest
from .forms import UserForm
from .decorators import admin_required, system_admin_required
from .permission_decorators import requires_permission, _get_safe_redirect_url

def generate_secure_password(length=12):
    """Generate a secure random password"""
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choice(characters) for _ in range(length))

def send_welcome_email(user, password):
    """Send welcome email with login credentials"""
    try:
        subject = 'Welcome to VeriSior - Your Account Details'
        
        html_message = f"""
        <h2>Welcome to VeriSior!</h2>
        <p>Your account has been created successfully. Here are your login details:</p>
        <ul>
            <li><strong>Username:</strong> {user.username}</li>
            <li><strong>Temporary Password:</strong> {password}</li>
            <li><strong>Login URL:</strong> {getattr(settings, 'SITE_URL', 'http://127.0.0.1:8000')}/auth/</li>
        </ul>
        <p>For security reasons, you will be required to:</p>
        <ol>
            <li>Change your password on first login</li>
            <li>Set up Two-Factor Authentication</li>
        </ol>
        <p>If you have any questions, please contact your system administrator.</p>
        <p>Best regards,<br>The VeriSior Team</p>
        """
        
        plain_message = f"""
Welcome to VeriSior!

Your account has been created successfully. Here are your login details:

Username: {user.username}
Temporary Password: {password}
Login URL: www.verisior.com

For security reasons, you will be required to:
1. Change your password on first login
2. Set up Two-Factor Authentication

If you have any questions, please contact your system administrator.

Best regards,
The VeriSior Team
        """
        
        send_mail(
            subject=subject,
            message=plain_message,
            html_message=html_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False
        )
        return True
    except Exception as e:
        print(f"Failed to send welcome email: {str(e)}")
        return False

def get_manageable_users(current_user):
    """Get ACTIVE users that current user can VIEW based on role hierarchy and permissions"""
    # Check if user has permission to view users
    if not getattr(current_user, 'can_view_users', False):
        return CustomUser.objects.none()

    if current_user.role == 'RA':
        # Root Admin can see all ACTIVE users except other Root Admins
        return CustomUser.objects.filter(
            user_type=current_user.user_type,
            status='ACTIVE'
        ).exclude(
            Q(pk=current_user.pk) | Q(role='RA')
        ).order_by('-date_joined')
    elif current_user.role == 'SA':
        # System Admin can see ACTIVE SA, AD, EM (not RA)
        return CustomUser.objects.filter(
            user_type=current_user.user_type,
            role__in=['SA', 'AD', 'EM'],
            status='ACTIVE'
        ).order_by('-date_joined')
    elif current_user.role == 'AD':
        # Administrator can see ACTIVE AD, EM (not RA, SA)
        return CustomUser.objects.filter(
            user_type=current_user.user_type,
            role__in=['AD', 'EM'],
            status='ACTIVE'
        ).order_by('-date_joined')
    else:
        # Employee with user management permissions can see other ACTIVE employees
        if getattr(current_user, 'can_access_user_management', False) and getattr(current_user, 'can_view_users', False):
            return CustomUser.objects.filter(
                user_type=current_user.user_type,
                role='EM',
                status='ACTIVE'
            ).exclude(pk=current_user.pk).order_by('-date_joined')
        return CustomUser.objects.none()

def apply_permission_updates(user_obj, post_data, current_user=None):
    """Apply ALL permission updates from POST data - COMPREHENSIVE VERSION

    Args:
        user_obj: The user whose permissions are being updated
        post_data: POST data containing permission checkboxes
        current_user: The user making the changes (optional, for permission restrictions)
    """
    print(f"\n=== APPLYING PERMISSIONS FOR {user_obj.username} ===")
    if current_user:
        print(f"Permissions being set by: {current_user.username} (Role: {current_user.role})")

    # Track which permissions are being set
    permissions_granted = []
    permissions_revoked = []

    if current_user:
        print(f"Permissions being set by: {current_user.username} (Role: {current_user.role}) for {user_obj.username} (Role: {user_obj.role})")

    # Core Navigation - Dashboard
    dashboard_perms = {
        'can_access_dashboard': 'Dashboard Access',
        'can_view_dashboard_statistics': 'View Dashboard Statistics',
        'can_export_dashboard_reports': 'Export Dashboard Reports'
    }

    for perm, desc in dashboard_perms.items():
        old_value = getattr(user_obj, perm, False)
        new_value = perm in post_data
        setattr(user_obj, perm, new_value)

        if new_value and not old_value:
            permissions_granted.append(desc)
        elif not new_value and old_value:
            permissions_revoked.append(desc)

    # Core Navigation - Active Records (CRUD) - RESTRICTED for SA->SA
    active_records_perms = {
        'can_access_active_records': 'Active Records Access',
        'can_view_active_records': 'View Active Records',
        'can_create_active_records': 'Create Active Records',
        'can_edit_active_records': 'Edit Active Records',
        'can_delete_active_records': 'Delete Active Records',
        'can_approve_active_records': 'Approve Active Records',
        'can_export_active_records': 'Export Active Records'
    }

    for perm, desc in active_records_perms.items():
        old_value = getattr(user_obj, perm, False)
        new_value = perm in post_data

        setattr(user_obj, perm, new_value)

        if new_value and not old_value:
            permissions_granted.append(desc)
        elif not new_value and old_value:
            permissions_revoked.append(desc)

    # Core Navigation - Archived Records - RESTRICTED for SA->SA
    archived_records_perms = {
        'can_access_archived_records': 'Archived Records Access',
        'can_view_archived_records': 'View Archived Records',
        'can_restore_archived_records': 'Restore Archived Records',
        'can_permanently_delete_archived': 'Permanently Delete Archived',
        'can_export_archived_records': 'Export Archived Records'
    }

    for perm, desc in archived_records_perms.items():
        old_value = getattr(user_obj, perm, False)
        new_value = perm in post_data

        setattr(user_obj, perm, new_value)

        if new_value and not old_value:
            permissions_granted.append(desc)
        elif not new_value and old_value:
            permissions_revoked.append(desc)
    
    # Core Navigation - Batch Upload
    batch_upload_perms = {
        'can_access_batch_upload': 'Batch Upload Access',
        'can_perform_batch_upload': 'Perform Batch Upload',
        'can_download_batch_templates': 'Download Batch Templates',
        'can_view_batch_history': 'View Batch History',
        'can_manage_batch_operations': 'Manage Batch Operations'
    }
    
    for perm, desc in batch_upload_perms.items():
        old_value = getattr(user_obj, perm, False)
        new_value = perm in post_data
        setattr(user_obj, perm, new_value)
        
        if new_value and not old_value:
            permissions_granted.append(desc)
        elif not new_value and old_value:
            permissions_revoked.append(desc)
    
    # Core Navigation - Messages
    messages_perms = {
        'can_access_messages': 'Messages Access',
        'can_view_messages': 'View Messages',
        'can_respond_to_messages': 'Respond to Messages',
        'can_delete_messages': 'Delete Messages'
    }
    
    for perm, desc in messages_perms.items():
        old_value = getattr(user_obj, perm, False)
        new_value = perm in post_data
        setattr(user_obj, perm, new_value)
        
        if new_value and not old_value:
            permissions_granted.append(desc)
        elif not new_value and old_value:
            permissions_revoked.append(desc)
    
    # Core Navigation - Settings
    settings_perms = {
        'can_access_settings': 'Settings Access',
        'can_modify_personal_settings': 'Modify Personal Settings',
        'can_modify_system_settings': 'Modify System Settings',
        'can_manage_backup_settings': 'Manage Backup Settings',
        'can_view_audit_logs': 'View Audit Logs',
        'can_export_audit_logs': 'Export Audit Logs'
    }
    
    for perm, desc in settings_perms.items():
        old_value = getattr(user_obj, perm, False)
        new_value = perm in post_data
        setattr(user_obj, perm, new_value)
        
        if new_value and not old_value:
            permissions_granted.append(desc)
        elif not new_value and old_value:
            permissions_revoked.append(desc)
    
    # Core Navigation - Reports
    reports_perms = {
        'can_access_reports': 'Reports Access',
        'can_view_reports': 'View Reports',
        'can_generate_reports': 'Generate Reports',
        'can_export_reports': 'Export Reports'
    }
    
    for perm, desc in reports_perms.items():
        old_value = getattr(user_obj, perm, False)
        new_value = perm in post_data
        setattr(user_obj, perm, new_value)
        
        if new_value and not old_value:
            permissions_granted.append(desc)
        elif not new_value and old_value:
            permissions_revoked.append(desc)
    
    # Administrative Navigation - Pending Approvals
    pending_approvals_perms = {
        'can_access_pending_approvals': 'Pending Approvals Access',
        'can_view_pending_applications': 'View Pending Applications',
        'can_approve_applications': 'Approve Applications',
        'can_reject_applications': 'Reject Applications',
        'can_bulk_process_approvals': 'Bulk Process Approvals',
        'can_export_approval_reports': 'Export Approval Reports'
    }
    
    for perm, desc in pending_approvals_perms.items():
        old_value = getattr(user_obj, perm, False)
        new_value = perm in post_data
        setattr(user_obj, perm, new_value)
        
        if new_value and not old_value:
            permissions_granted.append(desc)
        elif not new_value and old_value:
            permissions_revoked.append(desc)
    
    # Administrative Navigation - Verification Requests
    verification_requests_perms = {
        'can_access_verification_requests': 'Verification Requests Access',
        'can_view_verification_requests': 'View Verification Requests',
        'can_respond_to_verifications': 'Respond to Verifications',
        'can_manage_verification_queue': 'Manage Verification Queue',
        'can_export_verification_data': 'Export Verification Data'
    }
    
    for perm, desc in verification_requests_perms.items():
        old_value = getattr(user_obj, perm, False)
        new_value = perm in post_data
        setattr(user_obj, perm, new_value)
        
        if new_value and not old_value:
            permissions_granted.append(desc)
        elif not new_value and old_value:
            permissions_revoked.append(desc)
    
    # Administrative Navigation - User Management
    user_management_perms = {
        'can_access_user_management': 'User Management Access',
        'can_view_users': 'View Users',
        'can_create_users': 'Create Users',
        'can_edit_users': 'Edit Users',
        'can_delete_users': 'Delete Users',
        'can_manage_user_permissions': 'Manage User Permissions',
        'can_reset_user_passwords': 'Reset User Passwords',
        'can_disable_user_mfa': 'Disable User MFA'
    }
    
    for perm, desc in user_management_perms.items():
        old_value = getattr(user_obj, perm, False)
        new_value = perm in post_data
        setattr(user_obj, perm, new_value)
        
        if new_value and not old_value:
            permissions_granted.append(desc)
        elif not new_value and old_value:
            permissions_revoked.append(desc)
    
    # Administrative Navigation - Content Management
    content_management_perms = {
        'can_access_content_management': 'Content Management Access',
        'can_view_content': 'View Content Preview',
        'can_edit_landing_page_content': 'Edit Landing Page Content',
        'can_manage_team_members': 'Manage Team Members',
        'can_manage_faq_items': 'Manage FAQ Items',
        'can_manage_privacy_policy': 'Manage Privacy Policy',
        'can_export_content': 'Export Content Data',
        'can_backup_restore_content': 'Backup & Restore Content'
    }
    
    for perm, desc in content_management_perms.items():
        old_value = getattr(user_obj, perm, False)
        new_value = perm in post_data
        setattr(user_obj, perm, new_value)
        
        if new_value and not old_value:
            permissions_granted.append(desc)
        elif not new_value and old_value:
            permissions_revoked.append(desc)
    
    # Profile Access (always keep these enabled for basic functionality)
    profile_perms = {
        'can_access_profile': 'Profile Access',
        'can_edit_personal_profile': 'Edit Personal Profile',
        'can_change_password': 'Change Password',
        'can_setup_mfa': 'Setup MFA',
        'can_view_login_history': 'View Login History'
    }
    
    for perm, desc in profile_perms.items():
        old_value = getattr(user_obj, perm, False)
        new_value = perm in post_data
        setattr(user_obj, perm, new_value)
        
        if new_value and not old_value:
            permissions_granted.append(desc)
        elif not new_value and old_value:
            permissions_revoked.append(desc)
    
    # Log the permission changes
    if permissions_granted:
        print(f"GRANTED PERMISSIONS: {', '.join(permissions_granted)}")
    if permissions_revoked:
        print(f"REVOKED PERMISSIONS: {', '.join(permissions_revoked)}")
    
    print(f"=== PERMISSIONS UPDATE COMPLETE ===\n")
    
    return permissions_granted, permissions_revoked

def get_user_permissions_data(user_obj):
    """Get user's current permissions as a dictionary for form population"""
    return {
        # Core Navigation - Dashboard
        'can_access_dashboard': getattr(user_obj, 'can_access_dashboard', False),
        'can_view_dashboard_statistics': getattr(user_obj, 'can_view_dashboard_statistics', False),
        'can_export_dashboard_reports': getattr(user_obj, 'can_export_dashboard_reports', False),
        
        # Core Navigation - Active Records (CRUD)
        'can_access_active_records': getattr(user_obj, 'can_access_active_records', False),
        'can_view_active_records': getattr(user_obj, 'can_view_active_records', False),
        'can_create_active_records': getattr(user_obj, 'can_create_active_records', False),
        'can_edit_active_records': getattr(user_obj, 'can_edit_active_records', False),
        'can_delete_active_records': getattr(user_obj, 'can_delete_active_records', False),
        'can_approve_active_records': getattr(user_obj, 'can_approve_active_records', False),
        'can_export_active_records': getattr(user_obj, 'can_export_active_records', False),
        
        # Core Navigation - Archived Records
        'can_access_archived_records': getattr(user_obj, 'can_access_archived_records', False),
        'can_view_archived_records': getattr(user_obj, 'can_view_archived_records', False),
        'can_restore_archived_records': getattr(user_obj, 'can_restore_archived_records', False),
        'can_permanently_delete_archived': getattr(user_obj, 'can_permanently_delete_archived', False),
        'can_export_archived_records': getattr(user_obj, 'can_export_archived_records', False),
        
        # Core Navigation - Batch Upload
        'can_access_batch_upload': getattr(user_obj, 'can_access_batch_upload', False),
        'can_perform_batch_upload': getattr(user_obj, 'can_perform_batch_upload', False),
        'can_download_batch_templates': getattr(user_obj, 'can_download_batch_templates', False),
        'can_view_batch_history': getattr(user_obj, 'can_view_batch_history', False),
        'can_manage_batch_operations': getattr(user_obj, 'can_manage_batch_operations', False),
        
        # Core Navigation - Messages
        'can_access_messages': getattr(user_obj, 'can_access_messages', False),
        'can_view_messages': getattr(user_obj, 'can_view_messages', False),
        'can_respond_to_messages': getattr(user_obj, 'can_respond_to_messages', False),
        'can_delete_messages': getattr(user_obj, 'can_delete_messages', False),
        
        # Core Navigation - Settings
        'can_access_settings': getattr(user_obj, 'can_access_settings', False),
        'can_modify_personal_settings': getattr(user_obj, 'can_modify_personal_settings', False),
        'can_modify_system_settings': getattr(user_obj, 'can_modify_system_settings', False),
        'can_manage_backup_settings': getattr(user_obj, 'can_manage_backup_settings', False),
        'can_view_audit_logs': getattr(user_obj, 'can_view_audit_logs', False),
        'can_export_audit_logs': getattr(user_obj, 'can_export_audit_logs', False),
        
        # Core Navigation - Reports
        'can_access_reports': getattr(user_obj, 'can_access_reports', False),
        'can_view_reports': getattr(user_obj, 'can_view_reports', False),
        'can_generate_reports': getattr(user_obj, 'can_generate_reports', False),
        'can_export_reports': getattr(user_obj, 'can_export_reports', False),
        
        # Administrative Navigation - Pending Approvals
        'can_access_pending_approvals': getattr(user_obj, 'can_access_pending_approvals', False),
        'can_view_pending_applications': getattr(user_obj, 'can_view_pending_applications', False),
        'can_approve_applications': getattr(user_obj, 'can_approve_applications', False),
        'can_reject_applications': getattr(user_obj, 'can_reject_applications', False),
        'can_bulk_process_approvals': getattr(user_obj, 'can_bulk_process_approvals', False),
        'can_export_approval_reports': getattr(user_obj, 'can_export_approval_reports', False),
        
        # Administrative Navigation - Verification Requests
        'can_access_verification_requests': getattr(user_obj, 'can_access_verification_requests', False),
        'can_view_verification_requests': getattr(user_obj, 'can_view_verification_requests', False),
        'can_respond_to_verifications': getattr(user_obj, 'can_respond_to_verifications', False),
        'can_manage_verification_queue': getattr(user_obj, 'can_manage_verification_queue', False),
        'can_export_verification_data': getattr(user_obj, 'can_export_verification_data', False),
        
        # Administrative Navigation - User Management
        'can_access_user_management': getattr(user_obj, 'can_access_user_management', False),
        'can_view_users': getattr(user_obj, 'can_view_users', False),
        'can_create_users': getattr(user_obj, 'can_create_users', False),
        'can_edit_users': getattr(user_obj, 'can_edit_users', False),
        'can_delete_users': getattr(user_obj, 'can_delete_users', False),
        'can_manage_user_permissions': getattr(user_obj, 'can_manage_user_permissions', False),
        'can_reset_user_passwords': getattr(user_obj, 'can_reset_user_passwords', False),
        'can_disable_user_mfa': getattr(user_obj, 'can_disable_user_mfa', False),
        
        # Administrative Navigation - Content Management
        'can_access_content_management': getattr(user_obj, 'can_access_content_management', False),
        'can_view_content': getattr(user_obj, 'can_view_content', False),
        'can_edit_landing_page_content': getattr(user_obj, 'can_edit_landing_page_content', False),
        'can_manage_team_members': getattr(user_obj, 'can_manage_team_members', False),
        'can_manage_faq_items': getattr(user_obj, 'can_manage_faq_items', False),
        'can_manage_privacy_policy': getattr(user_obj, 'can_manage_privacy_policy', False),
        'can_export_content': getattr(user_obj, 'can_export_content', False),
        'can_backup_restore_content': getattr(user_obj, 'can_backup_restore_content', False),
        
        # Profile Access
        'can_access_profile': getattr(user_obj, 'can_access_profile', False),
        'can_edit_personal_profile': getattr(user_obj, 'can_edit_personal_profile', False),
        'can_change_password': getattr(user_obj, 'can_change_password', False),
        'can_setup_mfa': getattr(user_obj, 'can_setup_mfa', False),
        'can_view_login_history': getattr(user_obj, 'can_view_login_history', False),
    }

@login_required
@requires_permission('can_access_user_management')
def user_list_view(request):
    """Enhanced user list with proper role-based filtering and pagination"""
    print(f"\n=== USER LIST VIEW ===")
    print(f"User: {request.user.username}")
    print(f"Can access user management: {request.user.can_access_user_management}")
    print(f"Can view users: {getattr(request.user, 'can_view_users', 'MISSING')}")
    
    # Check view permission specifically
    if not getattr(request.user, 'can_view_users', False):
        print("User lacks can_view_users permission")
        messages.error(request, 'You do not have permission to view users.')
        return redirect(_get_safe_redirect_url(request.user))
    
    # Get users based on role hierarchy and permissions
    users = get_manageable_users(request.user)

    # Exclude the current user from the list (they can edit their profile directly)
    users = users.exclude(pk=request.user.pk)

    # Add filtering
    role_filter = request.GET.get('role', '')
    search_query = request.GET.get('search', '')
    status_filter = request.GET.get('status', '')
    
    if role_filter:
        users = users.filter(role=role_filter)
    
    if search_query:
        users = users.filter(
            Q(username__icontains=search_query) |
            Q(first_name__icontains=search_query) |
            Q(last_name__icontains=search_query) |
            Q(email__icontains=search_query)
        )
    
    if status_filter == 'active':
        users = users.filter(is_active=True)
    elif status_filter == 'inactive':
        users = users.filter(is_active=False)
    
    # Add additional properties to each user for template
    for user in users:
        user.can_be_managed_by_current_user = request.user.can_manage_user(user)
    
    # Pagination
    paginator = Paginator(users, 10)
    page_number = request.GET.get('page', 1)
    users_page = paginator.get_page(page_number)
    
    # Get role choices that current user can manage
    manageable_roles = request.user.get_manageable_roles()
    role_choices = [(role, display) for role, display in UserRole.choices if role in manageable_roles]
    
    context = {
        'users': users_page,
        'role_choices': role_choices,
        'current_role_filter': role_filter,
        'current_search': search_query,
        'current_status_filter': status_filter,
        'can_create_users': getattr(request.user, 'can_create_users', False) and len(manageable_roles) > 0,
        'manageable_roles': manageable_roles,
    }
    
    return render(request, 'accounts/user_list.html', context)

@login_required
@requires_permission('can_access_user_management')
def user_detail_view(request, pk):
    """View for displaying user details with proper data loading"""
    print(f"\n=== USER DETAIL VIEW ===")
    print(f"User: {request.user.username}")
    print(f"Target User PK: {pk}")
    
    # Check view permission specifically
    if not getattr(request.user, 'can_view_users', False):
        print("User lacks can_view_users permission")
        messages.error(request, 'You do not have permission to view user details.')
        return redirect('user_list')
    
    # Get manageable users and find the target user
    try:
        user_obj = CustomUser.objects.get(pk=pk)
    except CustomUser.DoesNotExist:
        messages.error(request, 'User not found.')
        return redirect('user_list')
    
    # Check if current user can manage this user
    if not request.user.can_manage_user(user_obj):
        messages.error(request, 'You do not have permission to view this user.')
        return redirect('user_list')
    
    # Get user statistics
    try:
        user_stats = {
            'total_seniors_created': 0,
            'pending_seniors': 0,
            'approved_seniors': 0,
            'recent_activity': [],
        }
    except:
        user_stats = {
            'total_seniors_created': 0,
            'pending_seniors': 0,
            'approved_seniors': 0,
            'recent_activity': [],
        }
    
    # Get password reset requests for this user
    password_reset_requests = user_obj.password_reset_requests.all().order_by('-requested_at')
    pending_reset_requests = user_obj.password_reset_requests.filter(status='PENDING')

    # Log the action
    try:
        from core.models import AuditLog
        AuditLog.objects.create(
            user=request.user,
            action='READ',
            content_type='User',
            object_id=user_obj.id,
            description=f'Viewed user details: {user_obj.username}',
            ip_address=request.META.get('REMOTE_ADDR')
        )
    except:
        pass

    context = {
        'user_obj': user_obj,
        'user_stats': user_stats,
        'password_reset_requests': password_reset_requests,
        'pending_reset_count': pending_reset_requests.count(),
        'can_modify': request.user.can_manage_user(user_obj) and getattr(request.user, 'can_edit_users', False),
        'can_delete': request.user.can_manage_user(user_obj) and getattr(request.user, 'can_delete_users', False) and user_obj.pk != request.user.pk,
    }

    return render(request, 'accounts/user_detail.html', context)

@login_required
@requires_permission('can_access_user_management')
@transaction.atomic
def user_create_view(request):
    """FIXED: Enhanced user creation with proper permission handling"""
    print(f"\n=== USER CREATE VIEW ===")
    print(f"User: {request.user.username}")
    print(f"User Role: {request.user.role}")
    print(f"Can create users: {getattr(request.user, 'can_create_users', 'MISSING')}")
    
    # Check create permission specifically
    if not getattr(request.user, 'can_create_users', False):
        print("User lacks can_create_users permission")
        messages.error(request, 'You do not have permission to create users.')
        return redirect('user_list')
    
    manageable_roles = request.user.get_manageable_roles()
    print(f"Manageable roles for {request.user.username}: {manageable_roles}")
    
    if not manageable_roles:
        messages.error(request, 'You do not have permission to create users')
        return redirect('user_list')
    
    if request.method == 'POST':
        # Get form data
        form_data = {
            'first_name': request.POST.get('first_name', '').strip(),
            'last_name': request.POST.get('last_name', '').strip(),
            'username': request.POST.get('username', '').strip(),
            'email': request.POST.get('email', '').strip(),
            'role': request.POST.get('role', ''),
            'phone_number': request.POST.get('phone_number', '').strip(),
            'department': request.POST.get('department', '').strip(),
        }
        
        print(f"Creating user with data: {form_data}")

        # Validate required fields
        errors = {}
        if not form_data['first_name']:
            errors['first_name'] = 'First name is required'
        if not form_data['last_name']:
            errors['last_name'] = 'Last name is required'
        if not form_data['username']:
            errors['username'] = 'Username is required'
        if not form_data['email']:
            errors['email'] = 'Email is required'
        else:
            # Validate email format
            from django.core.validators import validate_email
            from django.core.exceptions import ValidationError
            try:
                validate_email(form_data['email'])
            except ValidationError:
                errors['email'] = 'Please enter a valid email address'
        if not form_data['role']:
            errors['role'] = 'Role is required'
        
        # Check if username is unique
        if form_data['username'] and CustomUser.objects.filter(username=form_data['username']).exists():
            errors['username'] = 'Username already exists'
        
        # Check if email is unique
        if form_data['email'] and CustomUser.objects.filter(email=form_data['email']).exists():
            errors['email'] = 'Email already exists'
        
        # Validate role permissions
        if form_data['role'] and form_data['role'] not in manageable_roles:
            errors['role'] = f'You do not have permission to create {dict(UserRole.choices).get(form_data["role"], form_data["role"])} users'
        
        # Prevent creation of multiple RA accounts
        if form_data['role'] == 'RA':
            existing_ra_count = CustomUser.objects.filter(role='RA').count()
            if existing_ra_count >= 1:
                errors['role'] = 'Only one Root Administrator account is allowed per system.'

        if errors:
            for field, error in errors.items():
                messages.error(request, f'{field.replace("_", " ").title()}: {error}')
        else:
            try:
                print("Creating new user...")

                # Always generate a secure temporary password
                password = generate_secure_password()
                print(f"Generated temporary password for new user")

                # Create user object - DON'T SAVE YET
                user_obj = CustomUser(
                    username=form_data['username'],
                    email=form_data['email'],
                    first_name=form_data['first_name'],
                    last_name=form_data['last_name'],
                    role=form_data['role'],
                    user_type=request.user.user_type,
                    phone_number=form_data['phone_number'],
                    department=form_data['department'],
                    must_change_password=True,
                    is_active='is_active' in request.POST,
                )

                # Set password
                user_obj.set_password(password)
                print(f"Password set for new user")

                # Apply permissions BEFORE saving - this is crucial
                print("Applying permissions to new user...")
                permissions_granted, permissions_revoked = apply_permission_updates(user_obj, request.POST, request.user)

                # Now save the user with all permissions set
                user_obj.save()
                print(f"User {user_obj.username} created and saved successfully")

                # Always send welcome email with temporary password
                email_sent = False
                if user_obj.email:
                    email_sent = send_welcome_email(user_obj, password)
                    print(f"Welcome email sent to {user_obj.email}: {email_sent}")
                
                # Log the action with permission details
                try:
                    from core.models import AuditLog
                    description_parts = [f'Created user: {user_obj.username} with role {user_obj.get_role_display()}']
                    if permissions_granted:
                        description_parts.append(f'Granted permissions: {", ".join(permissions_granted[:5])}{"..." if len(permissions_granted) > 5 else ""}')
                    
                    AuditLog.objects.create(
                        user=request.user,
                        action='CREATE',
                        content_type='User',
                        object_id=user_obj.id,
                        description='; '.join(description_parts),
                        ip_address=request.META.get('REMOTE_ADDR')
                    )
                    print("Audit log created")
                except Exception as e:
                    print(f"Failed to create audit log: {e}")
                
                # Success message with permission summary
                success_msg_parts = [f'User "{user_obj.username}" created successfully!']

                if permissions_granted:
                    success_msg_parts.append(f'Granted {len(permissions_granted)} permissions')

                # Always show email status
                if user_obj.email:
                    if email_sent:
                        success_msg_parts.append(f'Welcome email with temporary password sent to {user_obj.email}')
                    else:
                        success_msg_parts.append(f'WARNING: Failed to send welcome email. Temporary password: {password}')
                else:
                    success_msg_parts.append(f'WARNING: No email provided. Temporary password: {password}')

                messages.success(request, ' | '.join(success_msg_parts))
                
                print(f"User creation complete. Redirecting to user list.")
                return redirect('user_list')
                
            except Exception as e:
                print(f"Error creating user: {str(e)}")
                messages.error(request, f'Error creating user: {str(e)}')
    
    # GET request - show form
    available_roles = [(role, display) for role, display in UserRole.choices if role in manageable_roles]
    
    context = {
        'action': 'Create',
        'available_roles': available_roles,
        'manageable_roles': manageable_roles,
        'permission_data': {},  # Empty for create
    }
    
    return render(request, 'accounts/user_form.html', context)

@login_required
@requires_permission('can_access_user_management')
@transaction.atomic
def user_update_view(request, pk):
    """FIXED: Enhanced user update with proper permission handling"""
    print(f"\n=== USER UPDATE VIEW ===")
    print(f"User: {request.user.username}")
    print(f"Target User PK: {pk}")
    print(f"Method: {request.method}")
    
    # Check edit permission specifically
    if not getattr(request.user, 'can_edit_users', False):
        print("User lacks can_edit_users permission")
        messages.error(request, 'You do not have permission to edit users.')
        return redirect('user_list')
    
    # Get the user object first
    try:
        user_obj = CustomUser.objects.get(pk=pk)
        print(f"Found target user: {user_obj.username}")
    except CustomUser.DoesNotExist:
        print("Target user not found")
        messages.error(request, 'User not found.')
        return redirect('user_list')
    
    # Check if current user can manage this user
    if not request.user.can_manage_user(user_obj):
        print(f"Permission denied: {request.user.username} cannot manage {user_obj.username}")
        messages.error(request, 'You do not have permission to modify this user.')
        return redirect('user_list')
    
    manageable_roles = request.user.get_manageable_roles()
    print(f"Manageable roles: {manageable_roles}")
    
    if request.method == 'POST':
        print("Processing POST request for user update")
        
        # Get original permissions for comparison
        original_permissions = get_user_permissions_data(user_obj)
        
        # Handle form submission
        form_data = {
            'first_name': request.POST.get('first_name', '').strip(),
            'last_name': request.POST.get('last_name', '').strip(),
            'username': request.POST.get('username', '').strip(),
            'email': request.POST.get('email', '').strip(),
            'role': request.POST.get('role', ''),
            'phone_number': request.POST.get('phone_number', '').strip(),
            'department': request.POST.get('department', '').strip(),
        }
        
        print(f"Form data: {form_data}")

        # Validate required fields
        errors = {}
        if not form_data['first_name']:
            errors['first_name'] = 'First name is required'
        if not form_data['last_name']:
            errors['last_name'] = 'Last name is required'
        if not form_data['username']:
            errors['username'] = 'Username is required'
        if not form_data['email']:
            errors['email'] = 'Email is required'
        else:
            # Validate email format
            from django.core.validators import validate_email
            from django.core.exceptions import ValidationError
            try:
                validate_email(form_data['email'])
            except ValidationError:
                errors['email'] = 'Please enter a valid email address'
        if not form_data['role']:
            errors['role'] = 'Role is required'
        
        # Check if username is unique (excluding current user)
        if form_data['username'] and CustomUser.objects.filter(
            username=form_data['username']
        ).exclude(pk=user_obj.pk).exists():
            errors['username'] = 'Username already exists'
        
        # Check if email is unique (excluding current user)
        if form_data['email'] and CustomUser.objects.filter(
            email=form_data['email']
        ).exclude(pk=user_obj.pk).exists():
            errors['email'] = 'Email already exists'
        
        # Validate role permissions
        if form_data['role'] and form_data['role'] not in manageable_roles:
            # Allow keeping current role even if not in manageable roles
            if form_data['role'] != user_obj.role:
                errors['role'] = f'You do not have permission to assign {dict(UserRole.choices).get(form_data["role"], form_data["role"])} role'
        
        if errors:
            print(f"Validation errors: {errors}")
            for field, error in errors.items():
                messages.error(request, f'{field.replace("_", " ").title()}: {error}')
        else:
            try:
                print("Updating user...")
                
                # Update user basic information
                user_obj.first_name = form_data['first_name']
                user_obj.last_name = form_data['last_name']
                user_obj.username = form_data['username']
                user_obj.email = form_data['email']
                user_obj.role = form_data['role']
                user_obj.phone_number = form_data['phone_number']
                user_obj.department = form_data['department']
                user_obj.is_active = 'is_active' in request.POST
                
                # Handle password if provided
                new_password = request.POST.get('password', '').strip()
                if new_password:
                    user_obj.set_password(new_password)
                    user_obj.must_change_password = True
                    print("Password updated")
                
                # Force password change option
                if 'force_password_change' in request.POST:
                    user_obj.must_change_password = True
                    print("Force password change enabled")
                
                # Apply permission updates and track changes
                print("Updating permissions...")
                permissions_granted, permissions_revoked = apply_permission_updates(user_obj, request.POST, request.user)
                
                # Save the user with all updates
                user_obj.save()
                print("User saved successfully")
                
                # Log the action with detailed permission changes
                try:
                    from core.models import AuditLog
                    description_parts = [f'Updated user: {user_obj.username}']
                    
                    if permissions_granted:
                        description_parts.append(f'Granted: {", ".join(permissions_granted[:3])}{"..." if len(permissions_granted) > 3 else ""}')
                    if permissions_revoked:
                        description_parts.append(f'Revoked: {", ".join(permissions_revoked[:3])}{"..." if len(permissions_revoked) > 3 else ""}')
                    
                    AuditLog.objects.create(
                        user=request.user,
                        action='UPDATE',
                        content_type='User',
                        object_id=user_obj.id,
                        description='; '.join(description_parts),
                        ip_address=request.META.get('REMOTE_ADDR')
                    )
                    print("Audit log created")
                except Exception as e:
                    print(f"Failed to create audit log: {e}")
                
                # Success message with permission summary
                success_parts = [f'User "{user_obj.username}" updated successfully!']
                if permissions_granted:
                    success_parts.append(f'Granted {len(permissions_granted)} new permissions')
                if permissions_revoked:
                    success_parts.append(f'Revoked {len(permissions_revoked)} permissions')
                
                messages.success(request, ' | '.join(success_parts))
                print("Redirecting to user detail page")
                return redirect('user_detail', pk=user_obj.pk)
                
            except Exception as e:
                print(f"Error updating user: {e}")
                messages.error(request, f'Error updating user: {str(e)}')
    
    # GET request - prepare context
    print("Preparing GET response...")
    
    # Get current permissions
    permission_data = get_user_permissions_data(user_obj)
    
    # Create available roles list (include current role even if not manageable)
    available_roles = [(role, display) for role, display in UserRole.choices 
                      if role in manageable_roles or role == user_obj.role]
    
    print(f"Available roles: {available_roles}")
    print(f"Permission data loaded: {len(permission_data)} permissions")
    
    context = {
        'action': 'Update',
        'user_obj': user_obj,
        'permission_data': permission_data,
        'manageable_roles': manageable_roles,
        'available_roles': available_roles,
    }
    
    print("Rendering user form template")
    return render(request, 'accounts/user_form.html', context)

@login_required
@requires_permission('can_access_user_management')
def user_delete_view(request, pk):
    """Enhanced user deactivation with role hierarchy validation"""
    print(f"\n=== USER DEACTIVATE VIEW ===")
    print(f"User: {request.user.username}")
    print(f"Target User PK: {pk}")
    print(f"Can delete users: {getattr(request.user, 'can_delete_users', 'MISSING')}")
    
    # Check delete permission specifically
    if not getattr(request.user, 'can_delete_users', False):
        print("User lacks can_delete_users permission")
        messages.error(request, 'You do not have permission to deactivate users.')
        return redirect('user_list')
    
    # Get the user object
    try:
        user_obj = CustomUser.objects.get(pk=pk)
    except CustomUser.DoesNotExist:
        messages.error(request, 'User not found.')
        return redirect('user_list')
    
    # Prevent deactivating Root Administrator
    if user_obj.role == 'RA':
        messages.error(request, 'Root Administrator accounts cannot be deactivated')
        return redirect('user_list')
    
    # Prevent deactivating yourself
    if user_obj.pk == request.user.pk:
        messages.error(request, 'You cannot deactivate your own account')
        return redirect('user_list')
    
    # Check if current user can manage this user
    if not request.user.can_manage_user(user_obj):
        messages.error(request, 'You do not have permission to deactivate this user')
        return redirect('user_list')
    
    if request.method == 'POST':
        # Get confirmation input
        confirmation = request.POST.get('confirmation', '').strip().upper()
        deactivation_reason = request.POST.get('deactivation_reason', '').strip()
        reason_category = request.POST.get('reason_category', '').strip()
        
        if confirmation != 'DEACTIVATE':
            messages.error(request, 'Please type DEACTIVATE to confirm deactivation')
            return render(request, 'accounts/user_confirm_delete.html', {
                'user_to_delete': user_obj
            })
        
        if not deactivation_reason or not reason_category:
            messages.error(request, 'Please provide both a category and detailed reason for deactivation')
            return render(request, 'accounts/user_confirm_delete.html', {
                'user_to_delete': user_obj
            })
        
        # Log before deactivation
        try:
            from core.models import AuditLog
            AuditLog.objects.create(
                user=request.user,
                action='DEACTIVATE',
                content_type='User',
                object_id=user_obj.id,
                description=f'Deactivated user: {user_obj.username}. Category: {reason_category}. Reason: {deactivation_reason}',
                ip_address=request.META.get('REMOTE_ADDR')
            )
        except Exception as e:
            print(f"Failed to create audit log: {str(e)}")
        
        # Store username for success message
        deactivated_username = user_obj.username

        # Set to INACTIVE status (archived)
        from django.utils import timezone
        user_obj.status = 'INACTIVE'
        user_obj.is_active = False
        user_obj.inactivated_at = timezone.now()
        user_obj.inactivated_by = request.user
        user_obj.save()

        messages.success(request, f'User "{deactivated_username}" has been moved to Inactive (Archived) list!')
        return redirect('user_list')
    
    context = {
        'user_to_delete': user_obj
    }
    
    return render(request, 'accounts/user_confirm_delete.html', context)

def send_account_deletion_email(user, reason):
    """Send email notification for account deletion"""
    try:
        subject = 'VeriSior - Account Deleted'
        
        plain_message = f"""
Your VeriSior account has been deleted by an administrator.

Username: {user.username}
Reason: {reason}

If you believe this was done in error, please contact your system administrator.

Best regards,
The VeriSior Team
        """
        
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=True
        )
    except Exception as e:
        print(f"Failed to send account deletion email: {str(e)}")

@login_required
def check_user_permissions(request):
    """AJAX endpoint to check user's current permissions"""
    if request.method == 'GET':
        permissions = {
            'core_navigation': {
                # Dashboard
                'dashboard_access': getattr(request.user, 'can_access_dashboard', False),
                'dashboard_statistics': getattr(request.user, 'can_view_dashboard_statistics', False),
                'dashboard_reports': getattr(request.user, 'can_export_dashboard_reports', False),
                
                # Active Records
                'active_records_access': getattr(request.user, 'can_access_active_records', False),
                'active_records_view': getattr(request.user, 'can_view_active_records', False),
                'active_records_create': getattr(request.user, 'can_create_active_records', False),
                'active_records_edit': getattr(request.user, 'can_edit_active_records', False),
                'active_records_delete': getattr(request.user, 'can_delete_active_records', False),
                'active_records_approve': getattr(request.user, 'can_approve_active_records', False),
                'active_records_export': getattr(request.user, 'can_export_active_records', False),
                
                # Archived Records
                'archived_records_access': getattr(request.user, 'can_access_archived_records', False),
                'archived_records_view': getattr(request.user, 'can_view_archived_records', False),
                'archived_records_restore': getattr(request.user, 'can_restore_archived_records', False),
                'archived_records_delete': getattr(request.user, 'can_permanently_delete_archived', False),
                'archived_records_export': getattr(request.user, 'can_export_archived_records', False),
                
                # Batch Upload
                'batch_upload_access': getattr(request.user, 'can_access_batch_upload', False),
                'batch_upload_perform': getattr(request.user, 'can_perform_batch_upload', False),
                'batch_upload_templates': getattr(request.user, 'can_download_batch_templates', False),
                'batch_upload_history': getattr(request.user, 'can_view_batch_history', False),
                'batch_upload_manage': getattr(request.user, 'can_manage_batch_operations', False),
                
                # Messages
                'messages_access': getattr(request.user, 'can_access_messages', False),
                'messages_view': getattr(request.user, 'can_view_messages', False),
                'messages_respond': getattr(request.user, 'can_respond_to_messages', False),
                'messages_delete': getattr(request.user, 'can_delete_messages', False),
                
                # Settings
                'settings_access': getattr(request.user, 'can_access_settings', False),
                'settings_personal': getattr(request.user, 'can_modify_personal_settings', False),
                'settings_system': getattr(request.user, 'can_modify_system_settings', False),
                'settings_backup': getattr(request.user, 'can_manage_backup_settings', False),
                'settings_audit': getattr(request.user, 'can_view_audit_logs', False),
                'settings_export_audit': getattr(request.user, 'can_export_audit_logs', False),
                
                # Reports
                'reports_access': getattr(request.user, 'can_access_reports', False),
                'reports_view': getattr(request.user, 'can_view_reports', False),
                'reports_generate': getattr(request.user, 'can_generate_reports', False),
                'reports_export': getattr(request.user, 'can_export_reports', False),
            },
            'administrative_navigation': {
                # Pending Approvals
                'pending_approvals_access': getattr(request.user, 'can_access_pending_approvals', False),
                'pending_approvals_view': getattr(request.user, 'can_view_pending_applications', False),
                'pending_approvals_approve': getattr(request.user, 'can_approve_applications', False),
                'pending_approvals_reject': getattr(request.user, 'can_reject_applications', False),
                'pending_approvals_bulk': getattr(request.user, 'can_bulk_process_approvals', False),
                'pending_approvals_export': getattr(request.user, 'can_export_approval_reports', False),
                
                # Verification Requests
                'verification_requests_access': getattr(request.user, 'can_access_verification_requests', False),
                'verification_requests_view': getattr(request.user, 'can_view_verification_requests', False),
                'verification_requests_respond': getattr(request.user, 'can_respond_to_verifications', False),
                'verification_requests_manage': getattr(request.user, 'can_manage_verification_queue', False),
                'verification_requests_export': getattr(request.user, 'can_export_verification_data', False),
                
                # User Management
                'user_management_access': getattr(request.user, 'can_access_user_management', False),
                'user_management_view': getattr(request.user, 'can_view_users', False),
                'user_management_create': getattr(request.user, 'can_create_users', False),
                'user_management_edit': getattr(request.user, 'can_edit_users', False),
                'user_management_delete': getattr(request.user, 'can_delete_users', False),
                'user_management_permissions': getattr(request.user, 'can_manage_user_permissions', False),
                'user_management_passwords': getattr(request.user, 'can_reset_user_passwords', False),
                'user_management_mfa': getattr(request.user, 'can_disable_user_mfa', False),
                
                # Content Management
                'content_management_access': getattr(request.user, 'can_access_content_management', False),
                'content_management_view': getattr(request.user, 'can_view_content', False),
                'content_management_edit_landing': getattr(request.user, 'can_edit_landing_page_content', False),
                'content_management_team': getattr(request.user, 'can_manage_team_members', False),
                'content_management_faq': getattr(request.user, 'can_manage_faq_items', False),
                'content_management_privacy': getattr(request.user, 'can_manage_privacy_policy', False),
                'content_management_export': getattr(request.user, 'can_export_content', False),
                'content_management_backup': getattr(request.user, 'can_backup_restore_content', False),
                
                # Profile
                'profile_access': getattr(request.user, 'can_access_profile', False),
                'profile_edit': getattr(request.user, 'can_edit_personal_profile', False),
                'profile_password': getattr(request.user, 'can_change_password', False),
                'profile_mfa': getattr(request.user, 'can_setup_mfa', False),
                'profile_history': getattr(request.user, 'can_view_login_history', False),
            },
            'role': request.user.role,
            'manageable_roles': request.user.get_manageable_roles(),
        }
        
        return JsonResponse(permissions)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@login_required
@requires_permission('can_access_user_management')
def user_reactivate_view(request, pk):
    """Reactivate a deactivated user"""
    if not getattr(request.user, 'can_edit_users', False):
        messages.error(request, 'You do not have permission to reactivate users.')
        return redirect('user_list')
    
    try:
        user_obj = CustomUser.objects.get(pk=pk)
    except CustomUser.DoesNotExist:
        messages.error(request, 'User not found.')
        return redirect('user_list')
    
    if request.user.can_manage_user(user_obj):
        user_obj.is_active = True
        user_obj.save()
        
        # Log the reactivation
        try:
            from core.models import AuditLog
            AuditLog.objects.create(
                user=request.user,
                action='REACTIVATE',
                content_type='User',
                object_id=user_obj.id,
                description=f'Reactivated user: {user_obj.username}',
                ip_address=request.META.get('REMOTE_ADDR')
            )
        except:
            pass
        
        messages.success(request, f'User "{user_obj.username}" has been reactivated successfully!')
    else:
        messages.error(request, 'You do not have permission to reactivate this user.')

    return redirect('user_list')

@login_required
@requires_permission('can_access_user_management')
def inactive_users_list_view(request):
    """List of inactive (archived) users"""
    if not getattr(request.user, 'can_view_users', False):
        messages.error(request, 'You do not have permission to view inactive users.')
        return redirect(_get_safe_redirect_url(request.user))

    # Get INACTIVE users based on role hierarchy
    if request.user.role == 'RA':
        users = CustomUser.objects.filter(
            user_type=request.user.user_type,
            status='INACTIVE'
        ).exclude(role='RA').order_by('-inactivated_at')
    elif request.user.role == 'SA':
        users = CustomUser.objects.filter(
            user_type=request.user.user_type,
            role__in=['SA', 'AD', 'EM'],
            status='INACTIVE'
        ).order_by('-inactivated_at')
    elif request.user.role == 'AD':
        users = CustomUser.objects.filter(
            user_type=request.user.user_type,
            role__in=['AD', 'EM'],
            status='INACTIVE'
        ).order_by('-inactivated_at')
    else:
        users = CustomUser.objects.none()

    # Search filter
    search_query = request.GET.get('search', '')
    if search_query:
        users = users.filter(
            Q(username__icontains=search_query) |
            Q(first_name__icontains=search_query) |
            Q(last_name__icontains=search_query) |
            Q(email__icontains=search_query)
        )

    # Pagination
    paginator = Paginator(users, 10)
    page_number = request.GET.get('page', 1)
    users_page = paginator.get_page(page_number)

    context = {
        'users': users_page,
        'current_search': search_query,
    }

    return render(request, 'accounts/inactive_users_list.html', context)

@login_required
@requires_permission('can_access_user_management')
def delete_inactive_user_view(request, pk):
    """Soft-delete inactive user (moves to DELETED status)"""
    if not getattr(request.user, 'can_delete_users', False):
        messages.error(request, 'You do not have permission to delete users.')
        return redirect('inactive_users_list')

    try:
        user_obj = CustomUser.objects.get(pk=pk, status='INACTIVE')
    except CustomUser.objects.DoesNotExist:
        messages.error(request, 'Inactive user not found.')
        return redirect('inactive_users_list')

    if not request.user.can_manage_user(user_obj):
        messages.error(request, 'You do not have permission to delete this user.')
        return redirect('inactive_users_list')

    if request.method == 'POST':
        from django.utils import timezone
        from core.models import AuditLog

        username = user_obj.username

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='DELETE',
            content_type='User',
            object_id=user_obj.id,
            description=f'Moved inactive user to deleted list: {username}',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        # Move to DELETED status
        user_obj.status = 'DELETED'
        user_obj.deleted_at = timezone.now()
        user_obj.deleted_by = request.user
        user_obj.save()

        messages.success(request, f'User "{username}" has been moved to the Deleted list.')
        return redirect('inactive_users_list')

    return redirect('inactive_users_list')

@login_required
@requires_permission('can_access_user_management')
def deleted_users_list_view(request):
    """List of deleted users (ready for permanent deletion)"""
    if not getattr(request.user, 'can_delete_users', False):
        messages.error(request, 'You do not have permission to view deleted users.')
        return redirect(_get_safe_redirect_url(request.user))

    # Get DELETED users based on role hierarchy
    if request.user.role == 'RA':
        users = CustomUser.objects.filter(
            user_type=request.user.user_type,
            status='DELETED'
        ).exclude(role='RA').order_by('-deleted_at')
    elif request.user.role == 'SA':
        users = CustomUser.objects.filter(
            user_type=request.user.user_type,
            role__in=['SA', 'AD', 'EM'],
            status='DELETED'
        ).order_by('-deleted_at')
    elif request.user.role == 'AD':
        users = CustomUser.objects.filter(
            user_type=request.user.user_type,
            role__in=['AD', 'EM'],
            status='DELETED'
        ).order_by('-deleted_at')
    else:
        users = CustomUser.objects.none()

    # Search filter
    search_query = request.GET.get('search', '')
    if search_query:
        users = users.filter(
            Q(username__icontains=search_query) |
            Q(first_name__icontains=search_query) |
            Q(last_name__icontains=search_query) |
            Q(email__icontains=search_query)
        )

    # Pagination
    paginator = Paginator(users, 10)
    page_number = request.GET.get('page', 1)
    users_page = paginator.get_page(page_number)

    context = {
        'users': users_page,
        'current_search': search_query,
    }

    return render(request, 'accounts/deleted_users_list.html', context)

@login_required
@requires_permission('can_access_user_management')
def permanent_delete_user_view(request, pk):
    """Permanently delete a user from DELETED status (NO confirmation)"""
    if not getattr(request.user, 'can_delete_users', False):
        messages.error(request, 'You do not have permission to permanently delete users.')
        return redirect('deleted_users_list')

    try:
        user_obj = CustomUser.objects.get(pk=pk, status='DELETED')
    except CustomUser.DoesNotExist:
        messages.error(request, 'Deleted user not found.')
        return redirect('deleted_users_list')

    if not request.user.can_manage_user(user_obj):
        messages.error(request, 'You do not have permission to permanently delete this user.')
        return redirect('deleted_users_list')

    if request.method == 'POST':
        from core.models import AuditLog

        username = user_obj.username
        user_id = user_obj.id

        # Log before deletion
        AuditLog.objects.create(
            user=request.user,
            action='DELETE',
            content_type='User',
            object_id=user_id,
            description=f'PERMANENT DELETE: User {username} (ID: {user_id})',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        # Delete profile picture if exists
        if user_obj.profile_picture:
            try:
                import os
                if os.path.isfile(user_obj.profile_picture.path):
                    os.remove(user_obj.profile_picture.path)
            except:
                pass

        # Permanently delete
        user_obj.delete()

        messages.success(request, f'User "{username}" has been permanently deleted.')
        return redirect('deleted_users_list')

    return redirect('deleted_users_list')


# ==================== PASSWORD RESET REQUEST FUNCTIONALITY ====================

def send_temporary_password_email(user, temporary_password):
    """Send email with temporary password to user"""
    try:
        subject = 'VeriSior - Temporary Password for Password Reset'

        html_message = f"""
        <h2>Password Reset Approved</h2>
        <p>Your password reset request has been approved by an administrator.</p>
        <p>Here is your temporary password:</p>
        <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <strong style="font-size: 18px; color: #2c3e50;">{temporary_password}</strong>
        </div>
        <p><strong>Important Security Instructions:</strong></p>
        <ul>
            <li>Use this temporary password to log in</li>
            <li>You will be required to change your password immediately after login</li>
            <li>You will need to set up Two-Factor Authentication again</li>
            <li>This temporary password will expire after first use</li>
            <li>Do not share this password with anyone</li>
        </ul>
        <p><strong>Login URL:</strong> <a href="https://www.verisior.com">www.verisior.com</a></p>
        <p>If you did not request this password reset, please contact your system administrator immediately.</p>
        <p>Best regards,<br>The VeriSior Team</p>
        """

        plain_message = f"""
Password Reset Approved

Your password reset request has been approved by an administrator.

Here is your temporary password: {temporary_password}

Important Security Instructions:
- Use this temporary password to log in
- You will be required to change your password immediately after login
- You will need to set up Two-Factor Authentication again
- This temporary password will expire after first use
- Do not share this password with anyone

Login URL: www.verisior.com

If you did not request this password reset, please contact your system administrator immediately.

Best regards,
The VeriSior Team
        """

        send_mail(
            subject,
            plain_message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            html_message=html_message,
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Error sending temporary password email: {e}")
        return False


def request_password_reset(request):
    """Public view for users to request password reset (from login page)"""
    if request.method == 'POST':
        username_or_email = request.POST.get('username_or_email', '').strip()

        if not username_or_email:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'error': 'Please enter your username or email address.'}, status=400)
            messages.error(request, 'Please enter your username or email address.')
            return redirect('request_password_reset')

        # Find user by username or email
        user = None
        try:
            user = CustomUser.objects.get(Q(username=username_or_email) | Q(email=username_or_email))
        except CustomUser.DoesNotExist:
            # Don't reveal if user exists or not (security)
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'success': True,
                    'message': 'If an account with that username/email exists, a password reset request has been submitted. An administrator will review your request.'
                })
            messages.success(request, 'If an account with that username/email exists, a password reset request has been submitted. An administrator will review your request.')
            return redirect('login')
        except CustomUser.MultipleObjectsReturned:
            # This shouldn't happen, but handle it gracefully
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'error': 'Multiple accounts found. Please contact your system administrator.'}, status=400)
            messages.error(request, 'Multiple accounts found. Please contact your system administrator.')
            return redirect('request_password_reset')

        # Check if user already has a pending request
        pending_requests = PasswordResetRequest.objects.filter(
            user=user,
            status='PENDING'
        ).exists()

        if pending_requests:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'success': True,
                    'message': 'You already have a pending password reset request. Please wait for administrator approval.'
                })
            messages.info(request, 'You already have a pending password reset request. Please wait for administrator approval.')
            return redirect('login')

        # Ensure user has an email address
        if not user.email:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'error': 'Your account does not have an email address. Please contact your system administrator.'}, status=400)
            messages.error(request, 'Your account does not have an email address. Please contact your system administrator.')
            return redirect('login')

        # Create new password reset request
        try:
            PasswordResetRequest.objects.create(user=user)

            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'success': True,
                    'message': 'Password reset request submitted successfully. An administrator will review your request and you will receive an email if approved.'
                })
            messages.success(request, 'Password reset request submitted successfully. An administrator will review your request and you will receive an email if approved.')
            return redirect('login')
        except Exception as e:
            print(f"Error creating password reset request: {str(e)}")
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'error': 'An error occurred while processing your request. Please try again later.'}, status=500)
            messages.error(request, 'An error occurred while processing your request. Please try again later.')
            return redirect('login')

    return render(request, 'accounts/request_password_reset.html')


@login_required
@requires_permission('can_edit_users')
def approve_password_reset(request, request_id):
    """Approve a password reset request and send temporary password"""
    reset_request = get_object_or_404(PasswordResetRequest, pk=request_id)

    if reset_request.status != 'PENDING':
        messages.error(request, 'This password reset request has already been processed.')
        return redirect('user_detail', pk=reset_request.user.pk)

    if request.method == 'POST':
        admin_notes = request.POST.get('admin_notes', '').strip()

        # Generate temporary password
        temporary_password = generate_secure_password(length=12)

        # Hash the temporary password for storage
        hashed_password = make_password(temporary_password)

        # Update user's password and set must_change_password flag
        user = reset_request.user
        user.password = hashed_password
        user.must_change_password = True
        user.mfa_enabled = False  # Disable MFA so they can log in and set it up again
        user.save()

        # Approve the request
        reset_request.approve(
            admin_user=request.user,
            temporary_password=temporary_password,  # Store plain text for email
            notes=admin_notes
        )

        # Send email with temporary password
        email_sent = send_temporary_password_email(user, temporary_password)

        if email_sent:
            reset_request.temp_password_sent = True
            reset_request.save()
            messages.success(request, f'Password reset approved for {user.username}. Temporary password has been sent to {user.email}.')
        else:
            messages.warning(request, f'Password reset approved for {user.username}, but there was an error sending the email. Temporary password: {temporary_password}')

        # Log the action
        from core.models import AuditLog
        AuditLog.objects.create(
            user=request.user,
            action='UPDATE',
            content_type='User',
            object_id=user.id,
            description=f'Approved password reset request for {user.username}',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        return redirect('user_detail', pk=user.pk)

    context = {
        'reset_request': reset_request,
    }
    return render(request, 'accounts/approve_password_reset.html', context)


@login_required
@requires_permission('can_edit_users')
def reject_password_reset(request, request_id):
    """Reject a password reset request"""
    reset_request = get_object_or_404(PasswordResetRequest, pk=request_id)

    if reset_request.status != 'PENDING':
        messages.error(request, 'This password reset request has already been processed.')
        return redirect('user_detail', pk=reset_request.user.pk)

    if request.method == 'POST':
        admin_notes = request.POST.get('admin_notes', '').strip()

        if not admin_notes:
            messages.error(request, 'Please provide a reason for rejecting this password reset request.')
            return redirect('reject_password_reset', request_id=request_id)

        # Reject the request
        reset_request.reject(
            admin_user=request.user,
            notes=admin_notes
        )

        messages.success(request, f'Password reset request for {reset_request.user.username} has been rejected.')

        # Log the action
        from core.models import AuditLog
        AuditLog.objects.create(
            user=request.user,
            action='UPDATE',
            content_type='User',
            object_id=reset_request.user.id,
            description=f'Rejected password reset request for {reset_request.user.username}',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        return redirect('user_detail', pk=reset_request.user.pk)

    context = {
        'reset_request': reset_request,
    }
    return render(request, 'accounts/reject_password_reset.html', context)


@login_required
@requires_permission('can_edit_users')
def delete_password_reset_request(request, request_id):
    """Delete a single password reset request"""
    if request.method == 'POST':
        try:
            reset_request = get_object_or_404(PasswordResetRequest, pk=request_id)
            user_pk = reset_request.user.pk
            username = reset_request.user.username

            # Log the action
            from core.models import AuditLog
            AuditLog.objects.create(
                user=request.user,
                action='DELETE',
                content_type='User',
                object_id=user_pk,
                description=f'Deleted password reset request for user {username}',
                ip_address=request.META.get('REMOTE_ADDR')
            )

            reset_request.delete()
            messages.success(request, f'Password reset request deleted successfully.')
            return redirect('user_detail', pk=user_pk)

        except Exception as e:
            messages.error(request, f'Failed to delete password reset request: {str(e)}')
            return redirect('user_list')

    return redirect('user_list')


@login_required
@requires_permission('can_edit_users')
def delete_all_password_reset_requests(request, user_id):
    """Delete all password reset requests for a specific user"""
    if request.method == 'POST':
        try:
            user = get_object_or_404(CustomUser, pk=user_id)
            count = PasswordResetRequest.objects.filter(user=user).count()

            # Log the action
            from core.models import AuditLog
            AuditLog.objects.create(
                user=request.user,
                action='DELETE',
                content_type='User',
                object_id=user.id,
                description=f'Deleted all ({count}) password reset requests for user {user.username}',
                ip_address=request.META.get('REMOTE_ADDR')
            )

            PasswordResetRequest.objects.filter(user=user).delete()
            messages.success(request, f'All {count} password reset request(s) deleted successfully.')
            return redirect('user_detail', pk=user_id)

        except Exception as e:
            messages.error(request, f'Failed to delete password reset requests: {str(e)}')
            return redirect('user_list')

    return redirect('user_list')
