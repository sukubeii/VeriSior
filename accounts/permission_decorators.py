# authentication/permission_decorators.py - FIXED VERSION
from functools import wraps
from django.http import HttpResponseRedirect, HttpResponseForbidden
from django.urls import reverse
from django.contrib import messages
from django.shortcuts import redirect

def requires_permission(permission_name, redirect_url=None):
    """
    FIXED: Decorator that checks if the user has a specific permission with smart fallback redirects.
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return HttpResponseRedirect(reverse('login'))

            # CRITICAL: Validate permission exists and is True
            try:
                permission_value = getattr(request.user, permission_name, None)
                if permission_value is None:
                    # Permission field doesn't exist - log this
                    print(f"WARNING: Permission field '{permission_name}' not found for user {request.user.username}")
                    messages.error(request, f'System error: Missing permission configuration.')
                    return redirect(_get_safe_redirect_url(request.user, redirect_url))

                if bool(permission_value):
                    return view_func(request, *args, **kwargs)

            except AttributeError:
                print(f"ERROR: Permission field '{permission_name}' does not exist")
                messages.error(request, f'System error: Invalid permission check.')
                return redirect(_get_safe_redirect_url(request.user, redirect_url))

            # User doesn't have permission
            messages.error(request, f'You do not have permission to access this section.')
            return redirect(_get_safe_redirect_url(request.user, redirect_url))
        return _wrapped_view
    return decorator

def _get_safe_redirect_url(user, default_redirect=None):
    """
    Get a safe redirect URL based on user permissions and type.
    This prevents redirect loops when users don't have dashboard access.
    """
    # If a specific redirect is provided, use it first
    if default_redirect:
        return default_redirect

    # Check if user has any accessible areas, in order of preference
    if getattr(user, 'can_access_dashboard', False):
        return 'government_dashboard'
    elif getattr(user, 'can_access_active_records', False):
        return 'senior_list'
    elif getattr(user, 'can_access_content_management', False):
        return 'simple_content_management'
    elif getattr(user, 'can_access_user_management', False):
        return 'user_list'
    elif getattr(user, 'can_access_settings', False):
        return 'settings'
    elif getattr(user, 'can_access_profile', True):  # Profile access is default True
        return 'profile'
    else:
        # If user has absolutely no permissions, send to a "no access" page
        return 'no_access_page'

def requires_navigation_access(navigation_name):
    """
    Decorator specifically for navigation access permissions.
    
    Usage: @requires_navigation_access('user_management')
    """
    permission_name = f'can_access_{navigation_name}'
    return requires_permission(permission_name)

def requires_functional_permission(function_name):
    """
    Decorator specifically for functional permissions.
    
    Usage: @requires_functional_permission('approve_seniors')
    """
    permission_name = f'can_{function_name}'
    return requires_permission(permission_name)

def requires_user_management_permission(action):
    """
    Decorator specifically for user management actions.
    
    Usage: @requires_user_management_permission('create')
    """
    # FIXED: Map action names to actual permission field names
    action_mapping = {
        'create': 'can_create_users',
        'edit': 'can_edit_users',
        'modify': 'can_edit_users',  # Keep backward compatibility
        'update': 'can_edit_users',
        'delete': 'can_delete_users',
        'view': 'can_view_users',
        'manage_permissions': 'can_manage_user_permissions',
        'reset_passwords': 'can_reset_user_passwords',
        'disable_mfa': 'can_disable_user_mfa'
    }
    
    permission_name = action_mapping.get(action, f'can_{action}_users')
    return requires_permission(permission_name)

def role_hierarchy_required(*allowed_roles):
    """
    SIMPLIFIED: Role hierarchy decorator that ONLY checks role, not specific permissions.
    This allows custom permission assignment regardless of role.
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return HttpResponseRedirect(reverse('login'))

            user_role = request.user.role

            # Check if user's role is in allowed roles
            if user_role in allowed_roles:
                return view_func(request, *args, **kwargs)

            messages.error(request, 'You do not have sufficient privileges to access this section.')
            return redirect(_get_safe_redirect_url(request.user))
        return _wrapped_view
    return decorator

def check_can_manage_target_user(view_func):
    """
    Decorator to check if current user can manage the target user.
    Used for user update/delete views.
    
    Usage: @check_can_manage_target_user
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return HttpResponseRedirect(reverse('login'))
        
        # Get target user ID from URL kwargs
        target_user_id = kwargs.get('pk')
        if target_user_id:
            try:
                from accounts.models import CustomUser
                target_user = CustomUser.objects.get(pk=target_user_id)
                
                # Check if current user can manage this target user
                if not request.user.can_manage_user(target_user):
                    messages.error(request, 'You do not have permission to manage this user.')
                    return redirect('user_list')
                    
            except CustomUser.DoesNotExist:
                messages.error(request, 'User not found.')
                return redirect('user_list')
        
        return view_func(request, *args, **kwargs)
    return _wrapped_view
