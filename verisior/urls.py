from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from accounts.views import login_view
from accounts import views as auth_views
from accounts import password_reset
from core.contact import contact_form_view

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', login_view, name='landing_page'),  # Landing page
    path('auth/', include('accounts.urls')),  # Authentication URLs
    path('verify/', include('verifications.urls')),  # Public verification portal
    path('government/', include('seniors.urls')),  # Government module
    path('core/', include('core.urls')),  # Core module (audit, backup)
    
    # Contact form
    path('contact/', contact_form_view, name='contact_form'),
    
    # Password reset URLs at root level (for AJAX calls from login page)
    path('password-reset-request/', password_reset.password_reset_request, name='password_reset_request'),
    path('password-reset-verify/', password_reset.password_reset_verify, name='password_reset_verify'),
    path('password-reset-complete/', password_reset.password_reset_complete, name='password_reset_complete'),
    
    # MFA URLs at root level (for AJAX calls from login page)
    path('mfa-setup-info/', auth_views.mfa_setup_info_view, name='mfa_setup_info'),
    path('mfa-verify/', auth_views.mfa_verify_view, name='mfa_verify'),
    path('mfa-setup/', auth_views.mfa_setup_view, name='mfa_setup'),
    path('change-password/', auth_views.change_password_view, name='change_password'),
]

# Serve media files during development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
