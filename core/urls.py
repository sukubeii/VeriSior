# core/urls.py - Complete URL patterns for Core app with Reports and Team Member Management

from django.urls import path
from . import views
from . import backup
from . import report_generator
from . import contact
from . import dashboard_api
from . import reports
from accounts.views import settings_view

urlpatterns = [
    # Settings (use authentication app's settings view)
    path('settings/', settings_view, name='settings'),
    
    # Messages management
    path('messages/', contact.messages_list_view, name='messages_list'),
    path('messages/<int:pk>/', contact.message_detail_view, name='message_detail'), 
    path('messages/<int:pk>/reply/', contact.message_reply_view, name='message_reply'), 
    path('messages/<int:pk>/delete/', contact.message_delete_view, name='message_delete'),  
    
    # Reports management - UPDATED FOR PDF PREVIEW
    path('reports/', reports.reports_dashboard, name='reports_dashboard'),
    path('reports/api/preview/', reports.get_report_preview, name='get_report_preview'),
    path('reports/download/', reports.download_filtered_report, name='download_filtered_report'),
    
    # Legacy report generation (kept for backward compatibility)
    path('generate-report/', report_generator.generate_report, name='generate_report'),
    
    # Audit logs (download only)
    path('audit-logs/export/', views.export_audit_logs_view, name='export_audit_logs'),
    
    # CONTENT MANAGEMENT URLS - TEXT AND TEAM EDITING
    
    # Main content management dashboard
    path('content-management/', views.simple_content_management, name='simple_content_management'),
    path('content/', views.content_management, name='content_management'),  # Redirect to simple content management
    
    # Landing page content editing
    path('content/landing-page/edit/', views.edit_landing_page_content, name='edit_landing_page_content'),
    path('content/landing-page/preview/', views.preview_landing_page, name='preview_landing_page'),
    
    # Team member management
    path('content/team-members/', views.team_members_list, name='team_members_list'),
    path('content/team-member/add/', views.edit_team_member, name='edit_team_member'),
    path('content/team-member/<int:pk>/edit/', views.edit_team_member, name='edit_team_member'),
    path('content/team-member/<int:pk>/delete/', views.delete_team_member, name='delete_team_member'),
    path('content/team-member/<int:pk>/toggle-status/', views.toggle_team_member_status, name='toggle_team_member_status'),

    # FAQ management
    path('content/faq-items/', views.faq_items_list, name='faq_items_list'),
    path('content/faq-item/add/', views.edit_faq_item, name='edit_faq_item'),
    path('content/faq-item/<int:pk>/edit/', views.edit_faq_item, name='edit_faq_item'),
    path('content/faq-item/<int:pk>/delete/', views.delete_faq_item, name='delete_faq_item'),
    path('content/faq-item/<int:pk>/toggle-status/', views.toggle_faq_status, name='toggle_faq_status'),

    # Privacy policy management
    path('content/privacy-policy/edit/', views.edit_privacy_policy, name='edit_privacy_policy'),
    path('content/privacy-policy/<int:policy_id>/activate/', views.activate_privacy_policy, name='activate_privacy_policy'),
    
    # Content ordering
    path('content/update-order/', views.update_content_order, name='update_content_order'),
    
    # Content export/import
    path('content/export/', views.export_content, name='export_content'),
    
    # AJAX endpoints for content management
    path('api/update-content/', views.update_content_ajax, name='update_content_ajax'),
    path('api/get-content/', views.get_content_ajax, name='get_content_ajax'),
    path('api/backup-content/', views.backup_content, name='backup_content'),
    path('api/restore-content/', views.restore_content, name='restore_content'),
    
    # Backup and restore (accessible from settings)
    path('backup/', backup.backup_view, name='backup'),
    path('backup/download/', backup.download_backup, name='download_backup'),
    path('backup/keys/', backup.download_keys, name='download_keys'),
    path('backup/restore/', backup.restore_backup_view, name='restore_backup'),
    path('cleanup-media/', backup.cleanup_media_view, name='cleanup_media'),
    
    # Dashboard API endpoints
    path('api/system-status/', dashboard_api.system_status_api, name='api_system_status'),
    path('api/new-seniors/', dashboard_api.new_seniors_api, name='api_new_seniors'),
    path('api/deceased-seniors/', dashboard_api.deceased_seniors_api, name='api_deceased_seniors'),
    path('api/discount-applications/', dashboard_api.discount_applications_api, name='api_discount_applications'),
    path('api/renewals-status/', dashboard_api.renewals_status_api, name='api_renewals_status'),
    path('api/dashboard-stats/', dashboard_api.dashboard_stats_api, name='api_dashboard_stats'),
]
