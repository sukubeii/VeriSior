from django.urls import path
from . import views

urlpatterns = [
    # Main verification page
    path('', views.verification_page, name='verification_page'),

    # ID verification and discount management
    path('api/verify-id/', views.verify_id, name='verify_id'),
    path('api/check-discounts/', views.check_discounts, name='check_discounts'),
    path('api/apply-discount/', views.apply_discount, name='apply_discount'),

    # Transaction management
    path('api/transactions/', views.get_transactions, name='get_transactions'),

    # Session management for establishment info
    path('api/save-establishment/', views.save_establishment_info, name='save_establishment_info'),
    path('api/get-establishment/', views.get_establishment_info, name='get_establishment_info'),
    path('api/clear-establishment/', views.clear_establishment_info, name='clear_establishment_info'),

    # Additional endpoint for verification requests
    path('api/request-verification/', views.request_verification, name='request_verification'),

    # Admin views for verification requests
    path('requests/', views.verification_requests_list_view, name='verification_requests'),
    path('requests/archived/', views.archived_verification_requests_view, name='archived_verification_requests'),
    path('requests/archive/', views.archive_verification_requests_view, name='archive_verification_requests'),
]
