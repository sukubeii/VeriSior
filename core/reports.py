# core/reports.py - Complete Reports Dashboard with PDF Generation - REAL DATA ONLY

from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from django.db.models import Count, Q
from datetime import datetime, timedelta
from accounts.decorators import role_required
from accounts.permission_decorators import requires_navigation_access
from .models import AuditLog
from django.contrib.auth import get_user_model

# PDF Generation imports
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
import io

User = get_user_model()

try:
    from seniors.models import SeniorCitizen
    SENIORS_APP_AVAILABLE = True
except ImportError:
    SENIORS_APP_AVAILABLE = False

try:
    from verifications.models import VerificationRequest, DiscountTransaction
    VERIFICATIONS_APP_AVAILABLE = True
except ImportError:
    VERIFICATIONS_APP_AVAILABLE = False


@login_required
@role_required('SA', 'AD', 'RA')
@requires_navigation_access('reports')
def reports_dashboard(request):
    """Reports dashboard with preview and PDF download"""
    
    # Get report categories
    report_categories = [
        {
            'id': 'senior_citizens',
            'name': 'Senior Citizens Reports',
            'icon': 'fa-users',
            'color': 'primary',
            'reports': [
                {'value': 'senior_citizen_comprehensive', 'label': 'Complete Senior Citizens Report'},
                {'value': 'senior_citizen_list', 'label': 'Senior Citizen List'},
                {'value': 'pending_approval', 'label': 'Pending Approvals'},
                {'value': 'id_expiry_renewal', 'label': 'ID Expiry & Renewals'},
                {'value': 'id_validation', 'label': 'Public Verification Report'},
                {'value': 'discount_application', 'label': 'Discount Applications'},
                {'value': 'id_usage', 'label': 'ID Usage Analysis'},
            ]
        },
        {
            'id': 'system_admin',
            'name': 'System Administration Reports',
            'icon': 'fa-cogs',
            'color': 'warning',
            'reports': [
                {'value': 'system_administration_comprehensive', 'label': 'Complete Administration Report'},
                {'value': 'role_based_user', 'label': 'Role-based User Report'},
                {'value': 'failed_login', 'label': 'Failed Login Report'},
                {'value': 'admin_activity', 'label': 'Admin Activity Report'},
                {'value': 'system_uptime', 'label': 'System Uptime Report'},
                {'value': 'validation_latency', 'label': 'Validation Latency Report'},
            ]
        },
        {
            'id': 'comprehensive',
            'name': 'Complete System Report',
            'icon': 'fa-file-alt',
            'color': 'success',
            'reports': [
                {'value': 'comprehensive', 'label': 'All-in-One System Report'},
            ]
        }
    ]
    
    context = {
        'report_categories': report_categories,
        'current_date': timezone.now(),
    }
    
    return render(request, 'core/reports_dashboard.html', context)


@login_required
@role_required('SA', 'AD', 'RA')
def get_report_preview(request):
    """API endpoint to get HTML preview of report content - REAL DATA ONLY"""
    
    report_type = request.GET.get('report_type', 'senior_citizen_list')
    filter_type = request.GET.get('filter_type', 'month')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    # Parse dates based on filter type
    today = timezone.now().date()
    
    if filter_type == 'today':
        date_from = today
        date_to = today
        date_label = f"Today ({today.strftime('%B %d, %Y')})"
    elif filter_type == 'month':
        month = request.GET.get('month', today.month)
        year = request.GET.get('year', today.year)
        date_from = datetime(int(year), int(month), 1).date()
        if int(month) == 12:
            date_to = datetime(int(year), 12, 31).date()
        else:
            date_to = (datetime(int(year), int(month) + 1, 1) - timedelta(days=1)).date()
        date_label = date_from.strftime('%B %Y')
    elif filter_type == 'year':
        year = request.GET.get('year', today.year)
        date_from = datetime(int(year), 1, 1).date()
        date_to = datetime(int(year), 12, 31).date()
        date_label = str(year)
    elif filter_type == 'date':
        specific_date = request.GET.get('date', str(today))
        date_from = datetime.strptime(specific_date, '%Y-%m-%d').date()
        date_to = date_from
        date_label = date_from.strftime('%B %d, %Y')
    elif filter_type == 'range':
        date_from = datetime.strptime(start_date, '%Y-%m-%d').date() if start_date else today - timedelta(days=30)
        date_to = datetime.strptime(end_date, '%Y-%m-%d').date() if end_date else today
        date_label = f"{date_from.strftime('%B %d, %Y')} - {date_to.strftime('%B %d, %Y')}"
    else:
        date_from = today - timedelta(days=30)
        date_to = today
        date_label = "Last 30 Days"
    
    # Generate HTML content for preview
    html_content = generate_report_html(report_type, date_from, date_to, date_label, request.user)
    
    return JsonResponse({
        'success': True,
        'html': html_content,
        'date_label': date_label
    })


def generate_report_html(report_type, date_from, date_to, date_label, user):
    """Generate HTML content for report preview - REAL DATA ONLY"""
    
    # Report title mapping
    report_titles = {
        'comprehensive': 'VeriSior Complete System Report',
        'senior_citizen_comprehensive': 'VeriSior Senior Citizens Report',
        'system_administration_comprehensive': 'VeriSior System Administration Report',
        'senior_citizen_list': 'VeriSior Senior Citizen List Report',
        'pending_approval': 'VeriSior Pending Approval Report',
        'id_validation': 'VeriSior Public Verification Report',
        'id_expiry_renewal': 'VeriSior ID Expiry & Renewal Report',
        'discount_application': 'VeriSior Discount Application Report',
        'role_based_user': 'VeriSior Role-based User Report',
        'failed_login': 'VeriSior Failed Login Report',
        'admin_activity': 'VeriSior Admin Activity Report',
        'system_uptime': 'VeriSior System Uptime Report',
        'validation_latency': 'VeriSior Validation Latency Report',
        'id_usage': 'VeriSior ID Usage Report'
    }
    
    report_title = report_titles.get(report_type, 'VeriSior System Report')
    user_name = user.get_full_name() or user.username
    user_role = user.get_role_display()
    
    # Start building HTML
    html = f"""
    <div class="report-preview">
        <div class="report-header text-center mb-4">
            <h2 class="fw-bold text-primary mb-2">{report_title}</h2>
            <p class="text-muted mb-1">Generated on: {timezone.now().strftime("%B %d, %Y at %I:%M %p")}</p>
            <p class="text-muted mb-1">Generated by: {user_name} ({user_role})</p>
            <p class="text-muted mb-3">Report Period: {date_label}</p>
            <hr class="my-4">
        </div>
    """
    
    # Generate report content based on type
    if report_type == 'comprehensive':
        html += generate_comprehensive_report_html(date_from, date_to)
    elif report_type == 'senior_citizen_comprehensive':
        html += generate_senior_citizen_comprehensive_html(date_from, date_to)
    elif report_type == 'system_administration_comprehensive':
        html += generate_system_admin_comprehensive_html(date_from, date_to)
    elif report_type == 'senior_citizen_list':
        html += generate_senior_citizen_list_html(date_from, date_to)
    elif report_type == 'pending_approval':
        html += generate_pending_approval_html(date_from, date_to)
    elif report_type == 'id_validation':
        html += generate_id_validation_html(date_from, date_to)
    elif report_type == 'id_expiry_renewal':
        html += generate_id_expiry_renewal_html(date_from, date_to)
    elif report_type == 'discount_application':
        html += generate_discount_application_html(date_from, date_to)
    elif report_type == 'role_based_user':
        html += generate_role_based_user_html(date_from, date_to)
    elif report_type == 'failed_login':
        html += generate_failed_login_html(date_from, date_to)
    elif report_type == 'admin_activity':
        html += generate_admin_activity_html(date_from, date_to)
    elif report_type == 'system_uptime':
        html += generate_system_uptime_html(date_from, date_to)
    elif report_type == 'validation_latency':
        html += generate_validation_latency_html(date_from, date_to)
    elif report_type == 'id_usage':
        html += generate_id_usage_html(date_from, date_to)
    else:
        html += "<p>Report type not found.</p>"
    
    html += "</div>"
    
    return html


def generate_comprehensive_report_html(date_from, date_to):
    """Generate comprehensive report HTML - REAL DATA ONLY"""
    html = "<div class='report-section'>"
    html += "<h4 class='fw-bold text-primary mb-3'>Executive Summary</h4>"
    html += "<ul class='list-unstyled'>"
    html += f"<li><i class='fas fa-calendar me-2'></i>Report Period: {date_from.strftime('%B %d, %Y')} - {date_to.strftime('%B %d, %Y')}</li>"
    html += f"<li><i class='fas fa-users me-2'></i>Total Users: {User.objects.count()}</li>"
    html += f"<li><i class='fas fa-user-check me-2'></i>Active Users: {User.objects.filter(is_active=True).count()}</li>"
    html += f"<li><i class='fas fa-list me-2'></i>System Activity Logs: {AuditLog.objects.count()}</li>"
    html += "</ul>"
    html += "</div>"
    
    # Add senior citizen data
    html += generate_senior_citizen_comprehensive_html(date_from, date_to)
    
    # Add system administration data
    html += generate_system_admin_comprehensive_html(date_from, date_to)
    
    return html


def generate_senior_citizen_comprehensive_html(date_from, date_to):
    """Generate COMPLETE senior citizen comprehensive report HTML - ALL SECTIONS - REAL DATA ONLY"""
    html = ""
    
    # Include ALL senior citizen report sections
    html += generate_senior_citizen_list_html(date_from, date_to)
    html += generate_pending_approval_html(date_from, date_to)
    html += generate_id_expiry_renewal_html(date_from, date_to)
    html += generate_id_validation_html(date_from, date_to)
    html += generate_discount_application_html(date_from, date_to)
    html += generate_id_usage_html(date_from, date_to)
    
    return html


def generate_system_admin_comprehensive_html(date_from, date_to):
    """Generate COMPLETE system administration comprehensive report HTML - ALL SECTIONS - REAL DATA ONLY"""
    html = ""
    
    # Include ALL system administration report sections
    html += generate_role_based_user_html(date_from, date_to)
    html += generate_failed_login_html(date_from, date_to)
    html += generate_admin_activity_html(date_from, date_to)
    html += generate_system_uptime_html(date_from, date_to)
    html += generate_validation_latency_html(date_from, date_to)
    
    return html


def generate_senior_citizen_list_html(date_from, date_to):
    """Generate senior citizen list report HTML - REAL DATA ONLY"""
    html = "<div class='report-section'>"
    html += "<h4 class='fw-bold text-primary mb-3'>Summary Statistics</h4>"
    
    if SENIORS_APP_AVAILABLE:
        total_seniors = SeniorCitizen.objects.count()
        active_seniors = SeniorCitizen.objects.filter(status='APPROVED').count()
        archived_seniors = SeniorCitizen.objects.filter(status='ARCHIVED').count()
        seniors_in_period = SeniorCitizen.objects.filter(
            created_at__date__gte=date_from,
            created_at__date__lte=date_to
        ).count()
        
        html += "<table class='table table-bordered'>"
        html += "<thead class='table-light'><tr><th>Metric</th><th>Count</th></tr></thead>"
        html += "<tbody>"
        html += f"<tr><td>Total Senior Citizens</td><td>{total_seniors}</td></tr>"
        html += f"<tr><td>Active Records</td><td>{active_seniors}</td></tr>"
        html += f"<tr><td>Archived Records</td><td>{archived_seniors}</td></tr>"
        html += f"<tr><td>Records in Selected Period</td><td>{seniors_in_period}</td></tr>"
        html += "</tbody></table>"
    else:
        html += "<p class='text-muted fst-italic'>Senior Citizen module is not available.</p>"
    
    html += "</div>"
    return html


def generate_pending_approval_html(date_from, date_to):
    """Generate pending approval report HTML - REAL DATA ONLY"""
    html = "<div class='report-section'>"
    html += "<h4 class='fw-bold text-primary mb-3'>Pending Approval Statistics</h4>"
    
    if SENIORS_APP_AVAILABLE:
        pending_total = SeniorCitizen.objects.filter(status='PENDING').count()
        pending_over_week = SeniorCitizen.objects.filter(
            status='PENDING',
            created_at__lt=timezone.now() - timedelta(days=7)
        ).count()
        approved_in_period = SeniorCitizen.objects.filter(
            status='APPROVED',
            updated_at__date__gte=date_from,
            updated_at__date__lte=date_to
        ).count()
        
        html += "<table class='table table-bordered'>"
        html += "<thead class='table-light'><tr><th>Category</th><th>Count</th></tr></thead>"
        html += "<tbody>"
        html += f"<tr><td>Total Pending Approvals</td><td>{pending_total}</td></tr>"
        html += f"<tr><td>Pending > 7 Days</td><td>{pending_over_week}</td></tr>"
        html += f"<tr><td>Approved in Period</td><td>{approved_in_period}</td></tr>"
        html += "</tbody></table>"
    else:
        html += "<p class='text-muted fst-italic'>Senior Citizen module is not available.</p>"
    
    html += "</div>"
    return html


def generate_id_validation_html(date_from, date_to):
    """Generate ID validation report HTML - REAL DATA ONLY"""
    html = "<div class='report-section'>"
    html += "<h4 class='fw-bold text-primary mb-3'>Public Verification Statistics</h4>"
    
    if VERIFICATIONS_APP_AVAILABLE:
        successful = DiscountTransaction.objects.filter(
            created_at__date__gte=date_from,
            created_at__date__lte=date_to,
            status='APPLIED'
        ).count()
        
        failed = VerificationRequest.objects.filter(
            created_at__date__gte=date_from,
            created_at__date__lte=date_to,
            is_archived=False
        ).count()
        
        html += "<table class='table table-bordered'>"
        html += "<thead class='table-light'><tr><th>Verification Metric</th><th>Count</th></tr></thead>"
        html += "<tbody>"
        html += f"<tr><td>Successful Verifications</td><td>{successful}</td></tr>"
        html += f"<tr><td>Failed Verifications</td><td>{failed}</td></tr>"
        html += f"<tr><td>Total Attempts</td><td>{successful + failed}</td></tr>"
        html += "</tbody></table>"
    else:
        html += "<p class='text-muted fst-italic'>Verification module is not available.</p>"
    
    html += "</div>"
    return html


def generate_id_expiry_renewal_html(date_from, date_to):
    """Generate ID expiry and renewal report HTML - REAL DATA ONLY"""
    html = "<div class='report-section'>"
    html += "<h4 class='fw-bold text-primary mb-3'>Expiry and Renewal Statistics</h4>"
    
    if SENIORS_APP_AVAILABLE:
        today = timezone.now().date()
        expired = SeniorCitizen.objects.filter(
            status='APPROVED',
            expiration_date__lt=today
        ).count()
        
        expiring_30 = SeniorCitizen.objects.filter(
            status='APPROVED',
            expiration_date__gte=today,
            expiration_date__lte=today + timedelta(days=30)
        ).count()
        
        renewals_in_period = SeniorCitizen.objects.filter(
            last_renewed_date__gte=date_from,
            last_renewed_date__lte=date_to
        ).count()
        
        html += "<table class='table table-bordered'>"
        html += "<thead class='table-light'><tr><th>Category</th><th>Count</th></tr></thead>"
        html += "<tbody>"
        html += f"<tr><td>Currently Expired IDs</td><td>{expired}</td></tr>"
        html += f"<tr><td>Expiring Within 30 Days</td><td>{expiring_30}</td></tr>"
        html += f"<tr><td>Renewals in Period</td><td>{renewals_in_period}</td></tr>"
        html += "</tbody></table>"
    else:
        html += "<p class='text-muted fst-italic'>Senior Citizen module is not available.</p>"
    
    html += "</div>"
    return html


def generate_discount_application_html(date_from, date_to):
    """Generate discount application report HTML - REAL DATA ONLY"""
    html = "<div class='report-section'>"
    html += "<h4 class='fw-bold text-primary mb-3'>Discount Application Statistics</h4>"
    
    if VERIFICATIONS_APP_AVAILABLE:
        transactions = DiscountTransaction.objects.filter(
            created_at__date__gte=date_from,
            created_at__date__lte=date_to,
            status='APPLIED'
        )
        
        cinema = transactions.filter(category='OTHER').count()
        restaurant = transactions.filter(category='RESTAURANT').count()
        grocery = transactions.filter(category='GROCERY').count()
        pharmacy = transactions.filter(category='MEDICINE').count()
        
        html += "<table class='table table-bordered'>"
        html += "<thead class='table-light'><tr><th>Discount Category</th><th>Count</th></tr></thead>"
        html += "<tbody>"
        html += f"<tr><td>Cinema Discounts</td><td>{cinema}</td></tr>"
        html += f"<tr><td>Restaurant Discounts</td><td>{restaurant}</td></tr>"
        html += f"<tr><td>Grocery Discounts</td><td>{grocery}</td></tr>"
        html += f"<tr><td>Pharmacy Discounts</td><td>{pharmacy}</td></tr>"
        html += f"<tr><td>Total Applications</td><td>{transactions.count()}</td></tr>"
        html += "</tbody></table>"
    else:
        html += "<p class='text-muted fst-italic'>Verification module is not available.</p>"
    
    html += "</div>"
    return html


def generate_role_based_user_html(date_from, date_to):
    """Generate role-based user report HTML - REAL DATA ONLY"""
    html = "<div class='report-section'>"
    html += "<h4 class='fw-bold text-primary mb-3'>User Statistics by Role</h4>"
    
    role_choices = getattr(User, 'ROLE_CHOICES', [
        ('RA', 'Root Administrator'),
        ('SA', 'System Administrator'), 
        ('AD', 'Administrator'),
        ('EM', 'Employee')
    ])
    
    html += "<table class='table table-bordered'>"
    html += "<thead class='table-light'><tr><th>Role</th><th>Active Users</th><th>Total Users</th></tr></thead>"
    html += "<tbody>"
    
    for role_code, role_display in role_choices:
        active_count = User.objects.filter(role=role_code, is_active=True).count()
        total_count = User.objects.filter(role=role_code).count()
        html += f"<tr><td>{role_display}</td><td>{active_count}</td><td>{total_count}</td></tr>"
    
    html += "</tbody></table></div>"
    return html


def generate_failed_login_html(date_from, date_to):
    """Generate failed login report HTML - REAL DATA ONLY"""
    html = "<div class='report-section'>"
    html += "<h4 class='fw-bold text-primary mb-3'>Failed Login Statistics</h4>"
    
    failed_logins = AuditLog.objects.filter(
        Q(action='LOGIN') & 
        (Q(description__icontains='failed') | 
         Q(description__icontains='invalid') |
         Q(description__icontains='incorrect') |
         Q(description__icontains='Failed')),
        timestamp__date__gte=date_from,
        timestamp__date__lte=date_to
    )
    
    html += "<table class='table table-bordered'>"
    html += "<thead class='table-light'><tr><th>Period</th><th>Failed Attempts</th></tr></thead>"
    html += "<tbody>"
    html += f"<tr><td>Selected Period</td><td>{failed_logins.count()}</td></tr>"
    html += "</tbody></table></div>"
    
    # Show recent failed login details
    recent_failures = failed_logins.order_by('-timestamp')[:20]
    
    if recent_failures.exists():
        html += "<div class='report-section mt-4'>"
        html += "<h5 class='fw-bold mb-3'>Recent Failed Login Attempts (Last 20)</h5>"
        html += "<table class='table table-bordered table-sm'>"
        html += "<thead class='table-light'><tr><th>Timestamp</th><th>Username</th><th>IP Address</th><th>Details</th></tr></thead>"
        html += "<tbody>"
        
        for log in recent_failures:
            username = "Unknown"
            if log.user:
                username = log.user.username
            
            ip_address = log.ip_address or "Unknown"
            description = log.description[:100] + "..." if len(log.description) > 100 else log.description
            timestamp = log.timestamp.strftime("%m/%d/%Y %H:%M:%S")
            
            html += f"<tr><td>{timestamp}</td><td>{username}</td><td>{ip_address}</td><td>{description}</td></tr>"
        
        html += "</tbody></table></div>"
    
    return html


def generate_admin_activity_html(date_from, date_to):
    """Generate admin activity report HTML - REAL DATA ONLY"""
    html = "<div class='report-section'>"
    html += "<h4 class='fw-bold text-primary mb-3'>Administrative Activity Statistics</h4>"
    
    admin_actions = AuditLog.objects.filter(
        user__role__in=['RA', 'SA', 'AD'],
        timestamp__date__gte=date_from,
        timestamp__date__lte=date_to
    )
    
    html += "<table class='table table-bordered'>"
    html += "<thead class='table-light'><tr><th>Action Type</th><th>Count</th></tr></thead>"
    html += "<tbody>"
    html += f"<tr><td>Create Actions</td><td>{admin_actions.filter(action='CREATE').count()}</td></tr>"
    html += f"<tr><td>Update Actions</td><td>{admin_actions.filter(action='UPDATE').count()}</td></tr>"
    html += f"<tr><td>Delete Actions</td><td>{admin_actions.filter(action='DELETE').count()}</td></tr>"
    html += f"<tr><td>Login Actions</td><td>{admin_actions.filter(action='LOGIN').count()}</td></tr>"
    html += f"<tr><td>Total Admin Actions</td><td>{admin_actions.count()}</td></tr>"
    html += "</tbody></table></div>"
    
    return html


def generate_system_uptime_html(date_from, date_to):
    """Generate system uptime report HTML - REAL DATA ONLY"""
    html = "<div class='report-section'>"
    html += "<h4 class='fw-bold text-primary mb-3'>System Activity Statistics</h4>"
    
    total_actions = AuditLog.objects.filter(
        timestamp__date__gte=date_from,
        timestamp__date__lte=date_to
    ).count()
    
    active_users = AuditLog.objects.filter(
        timestamp__date__gte=date_from,
        timestamp__date__lte=date_to,
        user__isnull=False
    ).values('user').distinct().count()
    
    first_log = AuditLog.objects.order_by('timestamp').first()
    system_start_date = first_log.timestamp.strftime("%B %d, %Y") if first_log else "No logs available"
    
    html += "<table class='table table-bordered'>"
    html += "<thead class='table-light'><tr><th>Metric</th><th>Value</th></tr></thead>"
    html += "<tbody>"
    html += f"<tr><td>Total System Actions in Period</td><td>{total_actions}</td></tr>"
    html += f"<tr><td>Active Users in Period</td><td>{active_users}</td></tr>"
    html += f"<tr><td>Total Users in System</td><td>{User.objects.count()}</td></tr>"
    html += f"<tr><td>System Start Date</td><td>{system_start_date}</td></tr>"
    html += "</tbody></table></div>"
    
    return html


def generate_validation_latency_html(date_from, date_to):
    """Generate validation latency report HTML - REAL DATA ONLY"""
    html = "<div class='report-section'>"
    html += "<h4 class='fw-bold text-primary mb-3'>Validation Performance</h4>"
    
    if VERIFICATIONS_APP_AVAILABLE:
        total_verifications = DiscountTransaction.objects.filter(
            created_at__date__gte=date_from,
            created_at__date__lte=date_to,
            status='APPLIED'
        ).count()
        
        days_in_period = (date_to - date_from).days + 1
        avg_daily = total_verifications / max(1, days_in_period)
        
        html += "<table class='table table-bordered'>"
        html += "<thead class='table-light'><tr><th>Performance Metric</th><th>Value</th></tr></thead>"
        html += "<tbody>"
        html += f"<tr><td>Total Verifications in Period</td><td>{total_verifications}</td></tr>"
        html += f"<tr><td>Average Daily Verifications</td><td>{avg_daily:.1f}</td></tr>"
        html += f"<tr><td>Days in Period</td><td>{days_in_period}</td></tr>"
        html += "</tbody></table>"
    else:
        html += "<p class='text-muted fst-italic'>Verification module is not available.</p>"
    
    html += "</div>"
    return html


def generate_id_usage_html(date_from, date_to):
    """Generate ID usage report HTML - REAL DATA ONLY"""
    html = "<div class='report-section'>"
    html += "<h4 class='fw-bold text-primary mb-3'>ID Usage Statistics</h4>"
    
    if VERIFICATIONS_APP_AVAILABLE:
        transactions = DiscountTransaction.objects.filter(
            created_at__date__gte=date_from,
            created_at__date__lte=date_to,
            status='APPLIED'
        )
        
        cinema = transactions.filter(category='OTHER').count()
        restaurant = transactions.filter(category='RESTAURANT').count()
        grocery = transactions.filter(category='GROCERY').count()
        pharmacy = transactions.filter(category='MEDICINE').count()
        
        unique_establishments = transactions.filter(
            ip_address__isnull=False
        ).values('ip_address').distinct().count()
        
        html += "<table class='table table-bordered'>"
        html += "<thead class='table-light'><tr><th>Location/Category</th><th>Usage Count</th></tr></thead>"
        html += "<tbody>"
        html += f"<tr><td>Cinema Verifications</td><td>{cinema}</td></tr>"
        html += f"<tr><td>Restaurant Verifications</td><td>{restaurant}</td></tr>"
        html += f"<tr><td>Grocery Verifications</td><td>{grocery}</td></tr>"
        html += f"<tr><td>Pharmacy Verifications</td><td>{pharmacy}</td></tr>"
        html += f"<tr><td>Total Verifications</td><td>{transactions.count()}</td></tr>"
        html += f"<tr><td>Unique Establishments</td><td>{unique_establishments}</td></tr>"
        html += "</tbody></table>"
    else:
        html += "<p class='text-muted fst-italic'>Verification module is not available.</p>"
    
    html += "</div>"
    return html


# PDF GENERATION FUNCTIONS

@login_required
@role_required('SA', 'AD', 'RA')
def download_filtered_report(request):
    """Download report as PDF with date filtering applied"""
    
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    
    report_type = request.POST.get('report_type', 'comprehensive')
    filter_type = request.POST.get('filter_type', 'month')
    start_date = request.POST.get('start_date')
    end_date = request.POST.get('end_date')
    
    # Parse dates
    today = timezone.now().date()
    
    if filter_type == 'today':
        date_from = today
        date_to = today
        date_label = f"Today ({today.strftime('%B %d, %Y')})"
    elif filter_type == 'month':
        month = int(request.POST.get('month', today.month))
        year = int(request.POST.get('year', today.year))
        date_from = datetime(year, month, 1).date()
        if month == 12:
            date_to = datetime(year, 12, 31).date()
        else:
            date_to = (datetime(year, month + 1, 1) - timedelta(days=1)).date()
        date_label = date_from.strftime('%B %Y')
    elif filter_type == 'year':
        year = int(request.POST.get('year', today.year))
        date_from = datetime(year, 1, 1).date()
        date_to = datetime(year, 12, 31).date()
        date_label = str(year)
    elif filter_type == 'date':
        specific_date = request.POST.get('date', str(today))
        date_from = datetime.strptime(specific_date, '%Y-%m-%d').date()
        date_to = date_from
        date_label = date_from.strftime('%B %d, %Y')
    elif filter_type == 'range':
        date_from = datetime.strptime(start_date, '%Y-%m-%d').date() if start_date else today - timedelta(days=30)
        date_to = datetime.strptime(end_date, '%Y-%m-%d').date() if end_date else today
        date_label = f"{date_from.strftime('%B %d, %Y')} - {date_to.strftime('%B %d, %Y')}"
    else:
        date_from = today - timedelta(days=30)
        date_to = today
        date_label = "Last 30 Days"
    
    try:
        # Generate PDF
        pdf_buffer = generate_pdf_report(report_type, date_from, date_to, date_label, request.user)
        
        # Create response
        response = HttpResponse(pdf_buffer.getvalue(), content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="{report_type}_report_{timezone.now().strftime("%Y%m%d_%H%M%S")}.pdf"'
        
        # Log the report generation
        AuditLog.objects.create(
            user=request.user,
            action='READ',
            content_type='Report',
            description=f'Generated {report_type} report as PDF',
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        return response
        
    except Exception as e:
        return JsonResponse({'error': f'Error generating report: {str(e)}'}, status=500)


def generate_pdf_report(report_type, date_from, date_to, date_label, user):
    """Generate PDF report using ReportLab - REAL DATA ONLY"""
    
    # Create a buffer to hold the PDF
    buffer = io.BytesIO()
    
    # Create the PDF document
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.75*inch, bottomMargin=0.75*inch)
    
    # Container for the 'Flowable' objects
    elements = []
    
    # Define styles
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#1e40af'),
        spaceAfter=12,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#1e40af'),
        spaceAfter=10,
        spaceBefore=15,
        fontName='Helvetica-Bold'
    )
    
    info_style = ParagraphStyle(
        'InfoStyle',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.grey,
        alignment=TA_CENTER,
        spaceAfter=6
    )
    
    # Report title mapping
    report_titles = {
        'comprehensive': 'VeriSior Complete System Report',
        'senior_citizen_comprehensive': 'VeriSior Senior Citizens Report',
        'system_administration_comprehensive': 'VeriSior System Administration Report',
        'senior_citizen_list': 'VeriSior Senior Citizen List Report',
        'pending_approval': 'VeriSior Pending Approval Report',
        'id_validation': 'VeriSior Public Verification Report',
        'id_expiry_renewal': 'VeriSior ID Expiry & Renewal Report',
        'discount_application': 'VeriSior Discount Application Report',
        'role_based_user': 'VeriSior Role-based User Report',
        'failed_login': 'VeriSior Failed Login Report',
        'admin_activity': 'VeriSior Admin Activity Report',
        'system_uptime': 'VeriSior System Uptime Report',
        'validation_latency': 'VeriSior Validation Latency Report',
        'id_usage': 'VeriSior ID Usage Report'
    }
    
    report_title = report_titles.get(report_type, 'VeriSior System Report')
    user_name = user.get_full_name() or user.username
    user_role = user.get_role_display()
    
    # Add header
    elements.append(Paragraph(report_title, title_style))
    elements.append(Paragraph(f"Generated on: {timezone.now().strftime('%B %d, %Y at %I:%M %p')}", info_style))
    elements.append(Paragraph(f"Generated by: {user_name} ({user_role})", info_style))
    elements.append(Paragraph(f"Report Period: {date_label}", info_style))
    elements.append(Spacer(1, 0.3*inch))
    
    # Generate report content based on type
    if report_type == 'comprehensive':
        add_comprehensive_report_pdf(elements, date_from, date_to, styles, heading_style)
    elif report_type == 'senior_citizen_comprehensive':
        add_senior_citizen_comprehensive_pdf(elements, date_from, date_to, styles, heading_style)
    elif report_type == 'system_administration_comprehensive':
        add_system_admin_comprehensive_pdf(elements, date_from, date_to, styles, heading_style)
    elif report_type == 'senior_citizen_list':
        add_senior_citizen_list_pdf(elements, date_from, date_to, styles, heading_style)
    elif report_type == 'pending_approval':
        add_pending_approval_pdf(elements, date_from, date_to, styles, heading_style)
    elif report_type == 'id_validation':
        add_id_validation_pdf(elements, date_from, date_to, styles, heading_style)
    elif report_type == 'id_expiry_renewal':
        add_id_expiry_renewal_pdf(elements, date_from, date_to, styles, heading_style)
    elif report_type == 'discount_application':
        add_discount_application_pdf(elements, date_from, date_to, styles, heading_style)
    elif report_type == 'role_based_user':
        add_role_based_user_pdf(elements, date_from, date_to, styles, heading_style)
    elif report_type == 'failed_login':
        add_failed_login_pdf(elements, date_from, date_to, styles, heading_style)
    elif report_type == 'admin_activity':
        add_admin_activity_pdf(elements, date_from, date_to, styles, heading_style)
    elif report_type == 'system_uptime':
        add_system_uptime_pdf(elements, date_from, date_to, styles, heading_style)
    elif report_type == 'validation_latency':
        add_validation_latency_pdf(elements, date_from, date_to, styles, heading_style)
    elif report_type == 'id_usage':
        add_id_usage_pdf(elements, date_from, date_to, styles, heading_style)
    
    # Build PDF
    doc.build(elements)
    
    # Get the value of the BytesIO buffer and return it
    buffer.seek(0)
    return buffer


def create_table(data, col_widths=None):
    """Helper function to create a styled table"""
    table = Table(data, colWidths=col_widths)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
    ]))
    return table


def add_comprehensive_report_pdf(elements, date_from, date_to, styles, heading_style):
    """Add comprehensive report content to PDF - REAL DATA ONLY"""
    elements.append(Paragraph("Executive Summary", heading_style))
    elements.append(Spacer(1, 0.1*inch))
    
    summary_data = [
        ['Metric', 'Value'],
        ['Report Period', f"{date_from.strftime('%B %d, %Y')} - {date_to.strftime('%B %d, %Y')}"],
        ['Total Users', str(User.objects.count())],
        ['Active Users', str(User.objects.filter(is_active=True).count())],
        ['System Activity Logs', str(AuditLog.objects.count())],
    ]
    
    elements.append(create_table(summary_data, col_widths=[3*inch, 3*inch]))
    elements.append(Spacer(1, 0.2*inch))
    
    # Add senior citizen data
    add_senior_citizen_comprehensive_pdf(elements, date_from, date_to, styles, heading_style)
    
    # Add system administration data
    add_system_admin_comprehensive_pdf(elements, date_from, date_to, styles, heading_style)


def add_senior_citizen_comprehensive_pdf(elements, date_from, date_to, styles, heading_style):
    """Add COMPLETE senior citizen comprehensive content to PDF - ALL SECTIONS - REAL DATA ONLY"""
    # Include ALL senior citizen report sections
    add_senior_citizen_list_pdf(elements, date_from, date_to, styles, heading_style)
    add_pending_approval_pdf(elements, date_from, date_to, styles, heading_style)
    add_id_expiry_renewal_pdf(elements, date_from, date_to, styles, heading_style)
    add_id_validation_pdf(elements, date_from, date_to, styles, heading_style)
    add_discount_application_pdf(elements, date_from, date_to, styles, heading_style)
    add_id_usage_pdf(elements, date_from, date_to, styles, heading_style)


def add_system_admin_comprehensive_pdf(elements, date_from, date_to, styles, heading_style):
    """Add system administration comprehensive content to PDF - REAL DATA ONLY"""
    elements.append(Paragraph("1. User Management by Role", heading_style))
    elements.append(Spacer(1, 0.1*inch))
    
    role_choices = getattr(User, 'ROLE_CHOICES', [
        ('RA', 'Root Administrator'),
        ('SA', 'System Administrator'), 
        ('AD', 'Administrator'),
        ('EM', 'Employee')
    ])
    
    data = [['Role', 'Active Users', 'Total Users']]
    
    for role_code, role_display in role_choices:
        active_count = User.objects.filter(role=role_code, is_active=True).count()
        total_count = User.objects.filter(role=role_code).count()
        data.append([role_display, str(active_count), str(total_count)])
    
    elements.append(create_table(data, col_widths=[3*inch, 1.5*inch, 1.5*inch]))
    elements.append(Spacer(1, 0.2*inch))
    
    # Security monitoring
    elements.append(Paragraph("2. Security Monitoring", heading_style))
    elements.append(Spacer(1, 0.1*inch))
    
    failed_logins = AuditLog.objects.filter(
        Q(action='LOGIN') & 
        (Q(description__icontains='failed') | 
         Q(description__icontains='invalid') |
         Q(description__icontains='incorrect') |
         Q(description__icontains='Failed')),
        timestamp__date__gte=date_from,
        timestamp__date__lte=date_to
    )
    
    data = [
        ['Security Metric', 'Count'],
        ['Failed Login Attempts in Period', str(failed_logins.count())],
    ]
    
    elements.append(create_table(data, col_widths=[4*inch, 2*inch]))
    elements.append(Spacer(1, 0.2*inch))


def add_senior_citizen_list_pdf(elements, date_from, date_to, styles, heading_style):
    """Add senior citizen list content to PDF - REAL DATA ONLY"""
    elements.append(Paragraph("Summary Statistics", heading_style))
    elements.append(Spacer(1, 0.1*inch))
    
    if SENIORS_APP_AVAILABLE:
        total_seniors = SeniorCitizen.objects.count()
        active_seniors = SeniorCitizen.objects.filter(status='APPROVED').count()
        archived_seniors = SeniorCitizen.objects.filter(status='ARCHIVED').count()
        seniors_in_period = SeniorCitizen.objects.filter(
            created_at__date__gte=date_from,
            created_at__date__lte=date_to
        ).count()
        
        data = [
            ['Metric', 'Count'],
            ['Total Senior Citizens', str(total_seniors)],
            ['Active Records', str(active_seniors)],
            ['Archived Records', str(archived_seniors)],
            ['Records in Selected Period', str(seniors_in_period)],
        ]
        
        elements.append(create_table(data, col_widths=[4*inch, 2*inch]))
    else:
        elements.append(Paragraph("Senior Citizen module is not available.", styles['Italic']))
    
    elements.append(Spacer(1, 0.2*inch))


def add_pending_approval_pdf(elements, date_from, date_to, styles, heading_style):
    """Add pending approval content to PDF - REAL DATA ONLY"""
    elements.append(Paragraph("Pending Approval Statistics", heading_style))
    elements.append(Spacer(1, 0.1*inch))
    
    if SENIORS_APP_AVAILABLE:
        pending_total = SeniorCitizen.objects.filter(status='PENDING').count()
        pending_over_week = SeniorCitizen.objects.filter(
            status='PENDING',
            created_at__lt=timezone.now() - timedelta(days=7)
        ).count()
        approved_in_period = SeniorCitizen.objects.filter(
            status='APPROVED',
            updated_at__date__gte=date_from,
            updated_at__date__lte=date_to
        ).count()
        
        data = [
            ['Category', 'Count'],
            ['Total Pending Approvals', str(pending_total)],
            ['Pending > 7 Days', str(pending_over_week)],
            ['Approved in Period', str(approved_in_period)],
        ]
        
        elements.append(create_table(data, col_widths=[4*inch, 2*inch]))
    else:
        elements.append(Paragraph("Senior Citizen module is not available.", styles['Italic']))
    
    elements.append(Spacer(1, 0.2*inch))


def add_id_validation_pdf(elements, date_from, date_to, styles, heading_style):
    """Add ID validation content to PDF - REAL DATA ONLY"""
    elements.append(Paragraph("Public Verification Statistics", heading_style))
    elements.append(Spacer(1, 0.1*inch))
    
    if VERIFICATIONS_APP_AVAILABLE:
        successful = DiscountTransaction.objects.filter(
            created_at__date__gte=date_from,
            created_at__date__lte=date_to,
            status='APPLIED'
        ).count()
        
        failed = VerificationRequest.objects.filter(
            created_at__date__gte=date_from,
            created_at__date__lte=date_to,
            is_archived=False
        ).count()
        
        data = [
            ['Verification Metric', 'Count'],
            ['Successful Verifications', str(successful)],
            ['Failed Verifications', str(failed)],
            ['Total Attempts', str(successful + failed)],
        ]
        
        elements.append(create_table(data, col_widths=[4*inch, 2*inch]))
    else:
        elements.append(Paragraph("Verification module is not available.", styles['Italic']))
    
    elements.append(Spacer(1, 0.2*inch))


def add_id_expiry_renewal_pdf(elements, date_from, date_to, styles, heading_style):
    """Add ID expiry and renewal content to PDF - REAL DATA ONLY"""
    elements.append(Paragraph("Expiry and Renewal Statistics", heading_style))
    elements.append(Spacer(1, 0.1*inch))
    
    if SENIORS_APP_AVAILABLE:
        today = timezone.now().date()
        expired = SeniorCitizen.objects.filter(
            status='APPROVED',
            expiration_date__lt=today
        ).count()
        
        expiring_30 = SeniorCitizen.objects.filter(
            status='APPROVED',
            expiration_date__gte=today,
            expiration_date__lte=today + timedelta(days=30)
        ).count()
        
        renewals_in_period = SeniorCitizen.objects.filter(
            last_renewed_date__gte=date_from,
            last_renewed_date__lte=date_to
        ).count()
        
        data = [
            ['Category', 'Count'],
            ['Currently Expired IDs', str(expired)],
            ['Expiring Within 30 Days', str(expiring_30)],
            ['Renewals in Period', str(renewals_in_period)],
        ]
        
        elements.append(create_table(data, col_widths=[4*inch, 2*inch]))
    else:
        elements.append(Paragraph("Senior Citizen module is not available.", styles['Italic']))
    
    elements.append(Spacer(1, 0.2*inch))


def add_discount_application_pdf(elements, date_from, date_to, styles, heading_style):
    """Add discount application content to PDF - REAL DATA ONLY"""
    elements.append(Paragraph("Discount Application Statistics", heading_style))
    elements.append(Spacer(1, 0.1*inch))
    
    if VERIFICATIONS_APP_AVAILABLE:
        transactions = DiscountTransaction.objects.filter(
            created_at__date__gte=date_from,
            created_at__date__lte=date_to,
            status='APPLIED'
        )
        
        cinema = transactions.filter(category='OTHER').count()
        restaurant = transactions.filter(category='RESTAURANT').count()
        grocery = transactions.filter(category='GROCERY').count()
        pharmacy = transactions.filter(category='MEDICINE').count()
        
        data = [
            ['Discount Category', 'Count'],
            ['Cinema Discounts', str(cinema)],
            ['Restaurant Discounts', str(restaurant)],
            ['Grocery Discounts', str(grocery)],
            ['Pharmacy Discounts', str(pharmacy)],
            ['Total Applications', str(transactions.count())],
        ]
        
        elements.append(create_table(data, col_widths=[4*inch, 2*inch]))
    else:
        elements.append(Paragraph("Verification module is not available.", styles['Italic']))
    
    elements.append(Spacer(1, 0.2*inch))


def add_role_based_user_pdf(elements, date_from, date_to, styles, heading_style):
    """Add role-based user content to PDF - REAL DATA ONLY"""
    elements.append(Paragraph("User Statistics by Role", heading_style))
    elements.append(Spacer(1, 0.1*inch))
    
    role_choices = getattr(User, 'ROLE_CHOICES', [
        ('RA', 'Root Administrator'),
        ('SA', 'System Administrator'), 
        ('AD', 'Administrator'),
        ('EM', 'Employee')
    ])
    
    data = [['Role', 'Active Users', 'Total Users']]
    
    for role_code, role_display in role_choices:
        active_count = User.objects.filter(role=role_code, is_active=True).count()
        total_count = User.objects.filter(role=role_code).count()
        data.append([role_display, str(active_count), str(total_count)])
    
    elements.append(create_table(data, col_widths=[3*inch, 1.5*inch, 1.5*inch]))
    elements.append(Spacer(1, 0.2*inch))


def add_failed_login_pdf(elements, date_from, date_to, styles, heading_style):
    """Add failed login content to PDF - REAL DATA ONLY"""
    elements.append(Paragraph("Failed Login Statistics", heading_style))
    elements.append(Spacer(1, 0.1*inch))
    
    failed_logins = AuditLog.objects.filter(
        Q(action='LOGIN') & 
        (Q(description__icontains='failed') | 
         Q(description__icontains='invalid') |
         Q(description__icontains='incorrect') |
         Q(description__icontains='Failed')),
        timestamp__date__gte=date_from,
        timestamp__date__lte=date_to
    )
    
    data = [
        ['Period', 'Failed Attempts'],
        ['Selected Period', str(failed_logins.count())],
    ]
    
    elements.append(create_table(data, col_widths=[4*inch, 2*inch]))
    elements.append(Spacer(1, 0.2*inch))


def add_admin_activity_pdf(elements, date_from, date_to, styles, heading_style):
    """Add admin activity content to PDF - REAL DATA ONLY"""
    elements.append(Paragraph("Administrative Activity Statistics", heading_style))
    elements.append(Spacer(1, 0.1*inch))
    
    admin_actions = AuditLog.objects.filter(
        user__role__in=['RA', 'SA', 'AD'],
        timestamp__date__gte=date_from,
        timestamp__date__lte=date_to
    )
    
    data = [
        ['Action Type', 'Count'],
        ['Create Actions', str(admin_actions.filter(action='CREATE').count())],
        ['Update Actions', str(admin_actions.filter(action='UPDATE').count())],
        ['Delete Actions', str(admin_actions.filter(action='DELETE').count())],
        ['Login Actions', str(admin_actions.filter(action='LOGIN').count())],
        ['Total Admin Actions', str(admin_actions.count())],
    ]
    
    elements.append(create_table(data, col_widths=[4*inch, 2*inch]))
    elements.append(Spacer(1, 0.2*inch))


def add_system_uptime_pdf(elements, date_from, date_to, styles, heading_style):
    """Add system uptime content to PDF - REAL DATA ONLY"""
    elements.append(Paragraph("System Activity Statistics", heading_style))
    elements.append(Spacer(1, 0.1*inch))
    
    total_actions = AuditLog.objects.filter(
        timestamp__date__gte=date_from,
        timestamp__date__lte=date_to
    ).count()
    
    active_users = AuditLog.objects.filter(
        timestamp__date__gte=date_from,
        timestamp__date__lte=date_to,
        user__isnull=False
    ).values('user').distinct().count()
    
    first_log = AuditLog.objects.order_by('timestamp').first()
    system_start_date = first_log.timestamp.strftime("%B %d, %Y") if first_log else "No logs available"
    
    data = [
        ['Metric', 'Value'],
        ['Total System Actions in Period', str(total_actions)],
        ['Active Users in Period', str(active_users)],
        ['Total Users in System', str(User.objects.count())],
        ['System Start Date', system_start_date],
    ]
    
    elements.append(create_table(data, col_widths=[4*inch, 2*inch]))
    elements.append(Spacer(1, 0.2*inch))


def add_validation_latency_pdf(elements, date_from, date_to, styles, heading_style):
    """Add validation latency content to PDF - REAL DATA ONLY"""
    elements.append(Paragraph("Validation Performance", heading_style))
    elements.append(Spacer(1, 0.1*inch))
    
    if VERIFICATIONS_APP_AVAILABLE:
        total_verifications = DiscountTransaction.objects.filter(
            created_at__date__gte=date_from,
            created_at__date__lte=date_to,
            status='APPLIED'
        ).count()
        
        days_in_period = (date_to - date_from).days + 1
        avg_daily = total_verifications / max(1, days_in_period)
        
        data = [
            ['Performance Metric', 'Value'],
            ['Total Verifications in Period', str(total_verifications)],
            ['Average Daily Verifications', f"{avg_daily:.1f}"],
            ['Days in Period', str(days_in_period)],
        ]
        
        elements.append(create_table(data, col_widths=[4*inch, 2*inch]))
    else:
        elements.append(Paragraph("Verification module is not available.", styles['Italic']))
    
    elements.append(Spacer(1, 0.2*inch))


def add_id_usage_pdf(elements, date_from, date_to, styles, heading_style):
    """Add ID usage content to PDF - REAL DATA ONLY"""
    elements.append(Paragraph("ID Usage Statistics", heading_style))
    elements.append(Spacer(1, 0.1*inch))
    
    if VERIFICATIONS_APP_AVAILABLE:
        transactions = DiscountTransaction.objects.filter(
            created_at__date__gte=date_from,
            created_at__date__lte=date_to,
            status='APPLIED'
        )
        
        cinema = transactions.filter(category='OTHER').count()
        restaurant = transactions.filter(category='RESTAURANT').count()
        grocery = transactions.filter(category='GROCERY').count()
        pharmacy = transactions.filter(category='MEDICINE').count()
        
        unique_establishments = transactions.filter(
            ip_address__isnull=False
        ).values('ip_address').distinct().count()
        
        data = [
            ['Location/Category', 'Usage Count'],
            ['Cinema Verifications', str(cinema)],
            ['Restaurant Verifications', str(restaurant)],
            ['Grocery Verifications', str(grocery)],
            ['Pharmacy Verifications', str(pharmacy)],
            ['Total Verifications', str(transactions.count())],
            ['Unique Establishments', str(unique_establishments)],
        ]
        
        elements.append(create_table(data, col_widths=[4*inch, 2*inch]))
    else:
        elements.append(Paragraph("Verification module is not available.", styles['Italic']))
    
    elements.append(Spacer(1, 0.2*inch))
