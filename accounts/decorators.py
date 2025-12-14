from functools import wraps
from django.http import HttpResponseRedirect
from django.urls import reverse

def role_required(*roles):
    """
    Decorator that checks if the user has one of the specified roles.
    Usage: @role_required('SA', 'AD')
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if request.user.is_authenticated and request.user.role in roles:
                return view_func(request, *args, **kwargs)
            return HttpResponseRedirect(reverse('login'))
        return _wrapped_view
    return decorator

def role_hierarchy_required(*allowed_roles):
    """
    Decorator that checks role hierarchy.
    RA can access everything
    SA can access SA, AD, EM functions  
    AD can access AD, EM functions
    EM can only access EM functions
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return HttpResponseRedirect(reverse('login'))
                
            user_role = request.user.role
            
            # Define role hierarchy - higher roles can access lower role functions
            hierarchy = {
                'RA': ['RA', 'SA', 'AD', 'EM'],  # Root Admin can access everything
                'SA': ['SA', 'AD', 'EM'],        # System Admin can access SA, AD, EM
                'AD': ['AD', 'EM'],              # Admin can access AD, EM  
                'EM': ['EM']                     # Employee can only access EM
            }
            
            user_allowed_roles = hierarchy.get(user_role, [])
            
            # Check if any of the required roles are in user's allowed roles
            if any(role in user_allowed_roles for role in allowed_roles):
                return view_func(request, *args, **kwargs)
                
            return HttpResponseRedirect(reverse('login'))
        return _wrapped_view
    return decorator

def admin_required(view_func):
    """
    Decorator for admin-only views (RA, SA, AD)
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if request.user.is_authenticated and request.user.role in ['RA', 'SA', 'AD']:
            return view_func(request, *args, **kwargs)
        return HttpResponseRedirect(reverse('login'))
    return _wrapped_view

def system_admin_required(view_func):
    """
    Decorator for system admin-only views (RA, SA)
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if request.user.is_authenticated and request.user.role in ['RA', 'SA']:
            return view_func(request, *args, **kwargs)
        return HttpResponseRedirect(reverse('login'))
    return _wrapped_view

def root_admin_required(view_func):
    """
    Decorator for root admin-only views (RA only)
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if request.user.is_authenticated and request.user.role == 'RA':
            return view_func(request, *args, **kwargs)
        return HttpResponseRedirect(reverse('login'))
    return _wrapped_view
