# authentication/urls.py - FIXED VERSION
from django.urls import path
from . import views
from . import user_management
from . import password_reset

urlpatterns = [
    # Authentication URLs
    path('', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('change-password/', views.change_password_view, name='change_password'),
    path('mfa-setup/', views.mfa_setup_view, name='mfa_setup'),
    path('mfa-verify/', views.mfa_verify_view, name='mfa_verify'),
    path('mfa-setup-info/', views.mfa_setup_info_view, name='mfa_setup_info'),
    path('mfa-disable/', views.mfa_disable_view, name='mfa_disable'),
    path('mfa-disable-user/<int:user_id>/', views.mfa_disable_user_view, name='mfa_disable_user'),
    path('mfa-enable-user/<int:user_id>/', views.mfa_enable_user_view, name='mfa_enable_user'),

    # Profile URLs
    path('profile/', views.profile_view, name='profile'),
    path('profile/update/', views.profile_update_view, name='profile_update'),
    
    # Settings URLs
    path('settings/', views.settings_view, name='settings'),
    path('notification-settings/', views.notification_settings_view, name='notification_settings'),
    path('system-settings/', views.system_settings_view, name='system_settings'),
    path('audit-logs/', views.audit_logs_view, name='audit_logs_view'),
    
    # Password reset URLs (Old system - keep for compatibility)
    path('password-reset-request/', password_reset.password_reset_request, name='password_reset_request'),
    path('password-reset-verify/', password_reset.password_reset_verify, name='password_reset_verify'),
    path('password-reset-complete/', password_reset.password_reset_complete, name='password_reset_complete'),

    # New Password Reset Request System (Admin Approval Required)
    path('forgot-password/', user_management.request_password_reset, name='request_password_reset'),
    path('password-reset-requests/<int:request_id>/approve/', user_management.approve_password_reset, name='approve_password_reset'),
    path('password-reset-requests/<int:request_id>/reject/', user_management.reject_password_reset, name='reject_password_reset'),
    path('password-reset-requests/<int:request_id>/delete/', user_management.delete_password_reset_request, name='delete_password_reset_request'),
    path('password-reset-requests/delete-all/<int:user_id>/', user_management.delete_all_password_reset_requests, name='delete_all_password_reset_requests'),
    
    # Secure password change URLs
    path('verify-current-password/', views.verify_current_password, name='verify_current_password'),
    path('verify-mfa-code/', views.verify_mfa_code, name='verify_mfa_code'),
    path('change-password-secure/', views.change_password_secure_view, name='change_password_secure'),
    path('cancel-password-change/', views.cancel_password_change, name='cancel_password_change'),
    
    # User Management URLs - FIXED: Moved specific paths BEFORE generic path
    path('users/', user_management.user_list_view, name='user_list'),
    path('users/create/', user_management.user_create_view, name='user_create'),
    path('users/<int:pk>/edit/', user_management.user_update_view, name='user_update'),  # MOVED BEFORE detail
    path('users/<int:pk>/delete/', user_management.user_delete_view, name='user_delete'),
    path('users/<int:pk>/reactivate/', user_management.user_reactivate_view, name='user_reactivate'),  # NEW
    path('users/<int:pk>/', user_management.user_detail_view, name='user_detail'),  # MOVED TO END

    # Inactive (Archived) Users Management
    path('users/inactive/', user_management.inactive_users_list_view, name='inactive_users_list'),
    path('users/<int:pk>/delete-inactive/', user_management.delete_inactive_user_view, name='delete_inactive_user'),

    # Deleted Users Management
    path('users/deleted/', user_management.deleted_users_list_view, name='deleted_users_list'),
    path('users/<int:pk>/permanent-delete/', user_management.permanent_delete_user_view, name='permanent_delete_user'),
    
    # Permission checking endpoint
    path('check-permissions/', user_management.check_user_permissions, name='check_user_permissions'),

    # No access page for users without permissions
    path('no-access/', views.no_access_view, name='no_access_page'),


]
