from django.urls import path
from . import views
from . import views

urlpatterns = [
    # Dashboard
    path('dashboard/', views.dashboard_view, name='government_dashboard'),
    
    # Senior Citizens Management
    path('seniors/', views.senior_list_view, name='senior_list'),
    path('seniors/create/', views.senior_create_view, name='senior_create'),
    path('seniors/<int:pk>/', views.senior_detail_view, name='senior_detail'),
    path('seniors/<int:pk>/update/', views.senior_update_view, name='senior_update'),
    path('seniors/<int:pk>/delete/', views.senior_delete_view, name='senior_delete'),
    path('seniors/<int:pk>/archive/', views.senior_archive_view, name='senior_archive'),
    path('seniors/<int:pk>/restore/', views.restore_senior_view, name='restore_senior'),
    path('seniors/<int:pk>/qr-code/', views.download_qr_code_view, name='download_qr_code'),
    path('seniors/<int:pk>/print-id/', views.print_senior_id_view, name='print_senior_id'),
    
    # Archive Management
    path('archived-seniors/', views.archived_seniors_list_view, name='archived_seniors_list'),
    path('archived-seniors/<int:pk>/', views.archived_senior_detail_view, name='archived_senior_detail'),
    path('bulk-restore/', views.bulk_restore_seniors_view, name='bulk_restore_seniors'),
    path('seniors/<int:pk>/delete-archived/', views.delete_archived_senior_view, name='delete_archived_senior'),

    # Deleted Seniors Management
    path('deleted-seniors/', views.deleted_seniors_list_view, name='deleted_seniors_list'),
    path('seniors/<int:pk>/permanent-delete/', views.permanent_delete_senior_view, name='permanent_delete_senior'),
    
    # Approval System
    path('approvals/', views.approval_list_view, name='approval_list'),
    path('approvals/<int:pk>/', views.approve_senior_view, name='approve_senior'),
    
    # Document Management
    path('seniors/<int:pk>/upload-document/', views.upload_document_view, name='upload_document'),
    path('documents/<int:pk>/delete/', views.delete_document_view, name='delete_document'),

    # Required Documents and Photo Upload
    path('seniors/<int:pk>/upload-photo/', views.upload_senior_photo_view, name='upload_senior_photo'),
    path('seniors/<int:pk>/upload-birth-certificate/', views.upload_birth_certificate_view, name='upload_birth_certificate'),
    path('seniors/<int:pk>/upload-certificate-of-indigency/', views.upload_certificate_of_indigency_view, name='upload_certificate_of_indigency'),
    path('seniors/<int:pk>/upload-marriage-certificate/', views.upload_marriage_certificate_view, name='upload_marriage_certificate'),

    # Required Documents and Photo Deletion
    path('seniors/<int:pk>/delete-photo/', views.delete_senior_photo_view, name='delete_senior_photo'),
    path('seniors/<int:pk>/delete-birth-certificate/', views.delete_birth_certificate_view, name='delete_birth_certificate'),
    path('seniors/<int:pk>/delete-certificate-of-indigency/', views.delete_certificate_of_indigency_view, name='delete_certificate_of_indigency'),
    path('seniors/<int:pk>/delete-marriage-certificate/', views.delete_marriage_certificate_view, name='delete_marriage_certificate'),
    
    # Batch Upload
    path('batch-upload/', views.batch_upload_view, name='batch_upload'),
    path('batch-upload/process/', views.batch_upload_process_view, name='batch_upload_process'),
    path('batch-upload/action/', views.batch_upload_action_view, name='batch_upload_action'),
    path('download-template/', views.download_template_view, name='download_template'),
    
    # Export Functions
    path('export/csv/', views.export_csv_view, name='export_csv'),
    path('export/pdf/', views.export_pdf_view, name='export_pdf'),
]
