# authentication/templatetags/permission_tags.py - RBAC ONLY VERSION
from django import template

register = template.Library()

@register.filter
def has_permission(user, permission_name):
    """
    Check if user has a specific permission.
    Usage in template: {% if user|has_permission:"can_access_dashboard" %}
    """
    if not user or not user.is_authenticated:
        return False
    
    return getattr(user, permission_name, False)

@register.filter
def has_navigation_access(user, navigation_name):
    """
    Check if user has access to a specific navigation item.
    Usage in template: {% if user|has_navigation_access:"dashboard" %}
    """
    if not user or not user.is_authenticated:
        return False
    
    permission_name = f'can_access_{navigation_name}'
    return getattr(user, permission_name, False)

@register.filter
def has_subcategory_permission(user, subcategory_permission):
    """
    Check if user has a specific subcategory permission.
    Usage in template: {% if user|has_subcategory_permission:"view_dashboard_statistics" %}
    """
    if not user or not user.is_authenticated:
        return False
    
    permission_name = f'can_{subcategory_permission}'
    return getattr(user, permission_name, False)

@register.filter
def has_crud_permission(user, crud_action):
    """
    Check if user has CRUD permissions for active records.
    Usage in template: {% if user|has_crud_permission:"create_active_records" %}
    """
    if not user or not user.is_authenticated:
        return False
    
    permission_name = f'can_{crud_action}'
    return getattr(user, permission_name, False)

@register.filter
def can_manage_role(user, target_role):
    """
    Check if user can manage accounts of a specific role.
    Usage in template: {% if user|can_manage_role:"SA" %}
    """
    if not user or not user.is_authenticated:
        return False
    
    manageable_roles = user.get_manageable_roles()
    return target_role in manageable_roles

@register.filter
def can_manage_user_account(current_user, target_user):
    """
    Check if current user can manage a specific target user.
    Usage in template: {% if user|can_manage_user_account:target_user %}
    """
    if not current_user or not current_user.is_authenticated:
        return False
    
    if not target_user:
        return False
    
    return current_user.can_manage_user(target_user)

@register.filter
def has_any_crud_permission(user, record_type):
    """
    Check if user has any CRUD permission for a specific record type.
    Usage in template: {% if user|has_any_crud_permission:"active_records" %}
    """
    if not user or not user.is_authenticated:
        return False
    
    crud_permissions = {
        'active_records': ['can_view_active_records', 'can_create_active_records', 
                          'can_edit_active_records', 'can_delete_active_records'],
        'archived_records': ['can_view_archived_records', 'can_restore_archived_records', 
                           'can_permanently_delete_archived'],
        'users': ['can_view_users', 'can_create_users', 'can_edit_users', 'can_delete_users'],
    }
    
    if record_type not in crud_permissions:
        return False
    
    return any(getattr(user, perm, False) for perm in crud_permissions[record_type])

@register.filter
def has_export_permission(user, export_type):
    """
    Check if user has export permission for a specific type.
    Usage in template: {% if user|has_export_permission:"dashboard_reports" %}
    """
    if not user or not user.is_authenticated:
        return False
    
    export_permissions = {
        'dashboard_reports': 'can_export_dashboard_reports',
        'active_records': 'can_export_active_records',
        'archived_records': 'can_export_archived_records',
        'message_data': 'can_export_message_data',
        'audit_logs': 'can_export_audit_logs',
        'approval_reports': 'can_export_approval_reports',
        'verification_data': 'can_export_verification_data',
    }
    
    permission_name = export_permissions.get(export_type)
    if not permission_name:
        return False
    
    return getattr(user, permission_name, False)

@register.filter
def has_management_permission(user, management_type):
    """
    Check if user has management permission for a specific type.
    Usage in template: {% if user|has_management_permission:"batch_operations" %}
    """
    if not user or not user.is_authenticated:
        return False
    
    management_permissions = {
        'batch_operations': 'can_manage_batch_operations',
        'verification_queue': 'can_manage_verification_queue',
        'user_permissions': 'can_manage_user_permissions',
        'announcements': 'can_manage_announcements',
        'backup_settings': 'can_manage_backup_settings',
        'site_configuration': 'can_manage_site_configuration',
    }
    
    permission_name = management_permissions.get(management_type)
    if not permission_name:
        return False
    
    return getattr(user, permission_name, False)

@register.filter
def has_administrative_access(user):
    """
    Check if user has any administrative navigation access.
    Usage in template: {% if user|has_administrative_access %}
    """
    if not user or not user.is_authenticated:
        return False
    
    admin_permissions = [
        'can_access_pending_approvals',
        'can_access_verification_requests', 
        'can_access_user_management',
        'can_access_content_management'
    ]
    
    return any(getattr(user, perm, False) for perm in admin_permissions)

@register.filter
def has_core_navigation_access(user):
    """
    Check if user has any core navigation access.
    Usage in template: {% if user|has_core_navigation_access %}
    """
    if not user or not user.is_authenticated:
        return False
    
    core_permissions = [
        'can_access_dashboard',
        'can_access_active_records',
        'can_access_archived_records',
        'can_access_batch_upload',
        'can_access_messages',
        'can_access_settings'
    ]
    
    return any(getattr(user, perm, False) for perm in core_permissions)

@register.filter
def has_full_category_access(user, category):
    """
    Check if user has full access to a category.
    Usage in template: {% if user|has_full_category_access:"dashboard" %}
    """
    if not user or not user.is_authenticated:
        return False
    
    categories = {
        'dashboard': ['can_access_dashboard', 'can_view_dashboard_statistics', 'can_export_dashboard_reports'],
        'active_records': ['can_access_active_records', 'can_view_active_records', 'can_create_active_records', 
                          'can_edit_active_records', 'can_delete_active_records', 'can_approve_active_records', 'can_export_active_records'],
        'archived_records': ['can_access_archived_records', 'can_view_archived_records', 'can_restore_archived_records',
                           'can_permanently_delete_archived', 'can_export_archived_records'],
        'user_management': ['can_access_user_management', 'can_view_users', 'can_create_users', 'can_edit_users', 
                          'can_delete_users', 'can_manage_user_permissions', 'can_reset_user_passwords', 'can_disable_user_mfa'],
        'batch_upload': ['can_access_batch_upload', 'can_perform_batch_upload', 'can_download_batch_templates',
                        'can_view_batch_history', 'can_manage_batch_operations'],
        'messages': ['can_access_messages', 'can_view_messages', 'can_respond_to_messages', 
                    'can_send_bulk_messages', 'can_delete_messages', 'can_export_message_data'],
        'settings': ['can_access_settings', 'can_modify_personal_settings', 'can_modify_system_settings',
                    'can_manage_backup_settings', 'can_view_audit_logs', 'can_export_audit_logs'],
        'pending_approvals': ['can_access_pending_approvals', 'can_view_pending_applications', 'can_approve_applications',
                             'can_reject_applications', 'can_bulk_process_approvals', 'can_export_approval_reports'],
        'verification_requests': ['can_access_verification_requests', 'can_view_verification_requests', 'can_respond_to_verifications',
                                'can_manage_verification_queue', 'can_export_verification_data'],
        'content_management': ['can_access_content_management', 'can_view_content', 'can_edit_landing_page_content',
                             'can_manage_team_members', 'can_manage_faq_items', 'can_manage_privacy_policy', 'can_export_content', 'can_backup_restore_content'],
        'profile': ['can_access_profile', 'can_edit_personal_profile', 'can_change_password', 'can_setup_mfa', 'can_view_login_history']
    }
    
    if category not in categories:
        return False
    
    permissions = categories[category]
    return all(getattr(user, perm, False) for perm in permissions)

@register.filter
def has_partial_category_access(user, category):
    """
    Check if user has partial access to a category.
    Usage in template: {% if user|has_partial_category_access:"dashboard" %}
    """
    if not user or not user.is_authenticated:
        return False
    
    categories = {
        'dashboard': ['can_access_dashboard', 'can_view_dashboard_statistics', 'can_export_dashboard_reports'],
        'active_records': ['can_access_active_records', 'can_view_active_records', 'can_create_active_records', 
                          'can_edit_active_records', 'can_delete_active_records', 'can_approve_active_records', 'can_export_active_records'],
        'archived_records': ['can_access_archived_records', 'can_view_archived_records', 'can_restore_archived_records',
                           'can_permanently_delete_archived', 'can_export_archived_records'],
        'user_management': ['can_access_user_management', 'can_view_users', 'can_create_users', 'can_edit_users', 
                          'can_delete_users', 'can_manage_user_permissions', 'can_reset_user_passwords', 'can_disable_user_mfa'],
        'batch_upload': ['can_access_batch_upload', 'can_perform_batch_upload', 'can_download_batch_templates',
                        'can_view_batch_history', 'can_manage_batch_operations'],
        'messages': ['can_access_messages', 'can_view_messages', 'can_respond_to_messages', 
                    'can_send_bulk_messages', 'can_delete_messages', 'can_export_message_data'],
        'settings': ['can_access_settings', 'can_modify_personal_settings', 'can_modify_system_settings',
                    'can_manage_backup_settings', 'can_view_audit_logs', 'can_export_audit_logs'],
        'pending_approvals': ['can_access_pending_approvals', 'can_view_pending_applications', 'can_approve_applications',
                             'can_reject_applications', 'can_bulk_process_approvals', 'can_export_approval_reports'],
        'verification_requests': ['can_access_verification_requests', 'can_view_verification_requests', 'can_respond_to_verifications',
                                'can_manage_verification_queue', 'can_export_verification_data'],
        'content_management': ['can_access_content_management', 'can_view_content', 'can_edit_landing_page_content',
                             'can_manage_team_members', 'can_manage_faq_items', 'can_manage_privacy_policy', 'can_export_content', 'can_backup_restore_content'],
        'profile': ['can_access_profile', 'can_edit_personal_profile', 'can_change_password', 'can_setup_mfa', 'can_view_login_history']
    }
    
    if category not in categories:
        return False
    
    permissions = categories[category]
    granted = sum(1 for perm in permissions if getattr(user, perm, False))
    total = len(permissions)
    
    # Has some but not all permissions
    return 0 < granted < total

@register.filter
def has_any_permission_in_category(user, category):
    """
    Check if user has any permission in a category.
    Usage in template: {% if user|has_any_permission_in_category:"dashboard" %}
    """
    if not user or not user.is_authenticated:
        return False
    
    categories = {
        'dashboard': ['can_access_dashboard', 'can_view_dashboard_statistics', 'can_export_dashboard_reports'],
        'active_records': ['can_access_active_records', 'can_view_active_records', 'can_create_active_records', 
                          'can_edit_active_records', 'can_delete_active_records', 'can_approve_active_records', 'can_export_active_records'],
        'archived_records': ['can_access_archived_records', 'can_view_archived_records', 'can_restore_archived_records',
                           'can_permanently_delete_archived', 'can_export_archived_records'],
        'user_management': ['can_access_user_management', 'can_view_users', 'can_create_users', 'can_edit_users', 
                          'can_delete_users', 'can_manage_user_permissions', 'can_reset_user_passwords', 'can_disable_user_mfa'],
        'batch_upload': ['can_access_batch_upload', 'can_perform_batch_upload', 'can_download_batch_templates',
                        'can_view_batch_history', 'can_manage_batch_operations'],
        'messages': ['can_access_messages', 'can_view_messages', 'can_respond_to_messages', 
                    'can_send_bulk_messages', 'can_delete_messages', 'can_export_message_data'],
        'settings': ['can_access_settings', 'can_modify_personal_settings', 'can_modify_system_settings',
                    'can_manage_backup_settings', 'can_view_audit_logs', 'can_export_audit_logs'],
        'pending_approvals': ['can_access_pending_approvals', 'can_view_pending_applications', 'can_approve_applications',
                             'can_reject_applications', 'can_bulk_process_approvals', 'can_export_approval_reports'],
        'verification_requests': ['can_access_verification_requests', 'can_view_verification_requests', 'can_respond_to_verifications',
                                'can_manage_verification_queue', 'can_export_verification_data'],
        'content_management': ['can_access_content_management', 'can_view_content', 'can_edit_landing_page_content',
                             'can_manage_team_members', 'can_manage_faq_items', 'can_manage_privacy_policy', 'can_export_content', 'can_backup_restore_content'],
        'profile': ['can_access_profile', 'can_edit_personal_profile', 'can_change_password', 'can_setup_mfa', 'can_view_login_history']
    }
    
    if category not in categories:
        return False
    
    permissions = categories[category]
    return any(getattr(user, perm, False) for perm in permissions)
