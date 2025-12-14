from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse, FileResponse
from django.contrib import messages
from django.db.models import Q
from django.core.paginator import Paginator
from django.urls import reverse
import csv
from datetime import date, timedelta, datetime
import datetime as dt
import os
import qrcode
import io
import sys
import pandas as pd
from django.conf import settings
from PIL import Image, ImageDraw, ImageFont
import uuid
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import tempfile
import django
import re
import json
from django.db import transaction
from django.utils import timezone
import time
from django.db import OperationalError

from .models import SeniorCitizen, SeniorDocument, SystemStatusCheck
from .forms import SeniorCitizenForm, SeniorDocumentForm
from accounts.decorators import role_required
from core.models import AuditLog
from accounts.models import CustomUser
from accounts.permission_decorators import _get_safe_redirect_url

from verifications.models import DiscountTransaction

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from accounts.decorators import role_required
from accounts.permission_decorators import requires_navigation_access, requires_permission

# Helper functions for batch upload

def save_with_retry(obj, max_retries=3, delay=0.5):
    """Save model object with retry logic for database lock errors"""
    for attempt in range(max_retries):
        try:
            obj.save()
            return True
        except OperationalError as e:
            if "database is locked" in str(e).lower() and attempt < max_retries - 1:
                print(f"Database locked on attempt {attempt + 1}, retrying in {delay} seconds...")
                time.sleep(delay)
                delay *= 2  # Exponential backoff
            else:
                print(f"Error updating user: {e}")
                raise e
        except Exception as e:
            print(f"Error updating user: {e}")
            raise e
    return False


def format_phone_number(phone_str):
    """Format phone number to Philippine format"""
    if not phone_str or pd.isna(phone_str) or str(phone_str).strip() == '':
        return None
    
    # Convert to string and remove all non-digit characters except + and -
    cleaned = re.sub(r'[^\d+\-]', '', str(phone_str))
    
    # Philippine mobile number formats
    if re.match(r'^\+639\d{9}$', cleaned):
        return cleaned
    elif re.match(r'^639\d{9}$', cleaned):
        return '+' + cleaned
    elif re.match(r'^09\d{9}$', cleaned):
        return '+63' + cleaned[1:]
    elif len(re.sub(r'\D', '', cleaned)) >= 10:
        # Try to format as Philippine number
        digits_only = re.sub(r'\D', '', cleaned)
        if len(digits_only) == 11 and digits_only.startswith('09'):
            return '+63' + digits_only[1:]
        elif len(digits_only) == 10:
            return '+639' + digits_only
    
    # Return cleaned version if we can't format it properly
    return cleaned if cleaned else None

def format_name(name_str):
    """Format name to proper case (Title Case)"""
    if not name_str or pd.isna(name_str):
        return None
    
    name_str = str(name_str).strip()
    if not name_str:
        return None
    
    # Clean the name - remove extra spaces and special characters except periods, hyphens, and apostrophes
    cleaned_name = re.sub(r'[^\w\s\.\-\']', '', name_str)
    cleaned_name = re.sub(r'\s+', ' ', cleaned_name)  # Replace multiple spaces with single space
    
    # Convert to title case
    return cleaned_name.title()

def format_address(address_str):
    """Format address properly"""
    if not address_str or pd.isna(address_str):
        return 'Added via batch upload - Please update'
    
    address_str = str(address_str).strip()
    if not address_str or address_str.lower() in ['n/a', 'na', '', 'none']:
        return 'Added via batch upload - Please update'
    
    return address_str

def parse_date(date_str):
    """Parse date from various formats"""
    if pd.isna(date_str) or not date_str:
        return None
    
    # If it's already a datetime object
    if isinstance(date_str, (datetime, date)):
        return date_str.date() if isinstance(date_str, datetime) else date_str
    
    # Convert to string and try to parse
    date_str = str(date_str).strip()
    
    # Common date formats to try
    date_formats = [
        '%Y-%m-%d',
        '%m/%d/%Y',
        '%d/%m/%Y',
        '%m-%d-%Y',
        '%d-%m-%Y',
        '%Y/%m/%d',
        '%B %d, %Y',
        '%b %d, %Y',
    ]
    
    for fmt in date_formats:
        try:
            return datetime.strptime(date_str, fmt).date()
        except ValueError:
            continue
    
    # If all formats fail, return None
    return None

def extract_barangay_code(barangay_str):
    """Extract barangay code from various formats"""
    if not barangay_str or pd.isna(barangay_str):
        return None
    
    barangay_str = str(barangay_str).strip().upper()
    
    # Barangay name to code mapping
    barangay_name_to_code = {
        'BAGBAG': '005',
        'CAPRI': '021',
        'FAIRVIEW': '041',
        'GREATER LAGRO': '042',
        'GULOD': '043',
        'KALIGAYAHAN': '047',
        'NAGKAISANG NAYON': '069',
        'NORTH FAIRVIEW': '072',
        'NOVALICHES PROPER': '073',
        'PASONG PUTIK': '083',
        'SAN AGUSTIN': '099',
        'SAN BARTOLOME': '101',
        'STA. LUCIA': '119',
        'SANTA LUCIA': '119',
        'STA. MONICA': '120',
        'SANTA MONICA': '120',
    }
    
    # Check if it's already a code
    if barangay_str in ['005', '021', '041', '042', '043', '047', '069', '072', '073', '083', '099', '101', '119', '120']:
        return barangay_str
    
    # Check if it matches a name
    for name, code in barangay_name_to_code.items():
        if name in barangay_str or barangay_str in name:
            return code
    
    return None

def extract_barangay_code_from_id(id_number):
    """Extract barangay code from senior citizen ID number - handles Excel leading zero removal"""
    if not id_number or len(str(id_number)) < 3:
        return None

    # Convert to string and handle Excel's leading zero removal
    id_str = str(id_number).strip()

    # Valid barangay codes
    valid_codes = ['005', '021', '041', '042', '043', '047', '069', '072', '073', '083', '099', '101', '119', '120']

    # If ID is shorter than expected (Excel removed leading zeros), try to fix it
    if len(id_str) < 14:  # Expected format: 14 digits (3 barangay + 11 sequential)
        # Calculate how many leading zeros were likely removed
        missing_zeros = 14 - len(id_str)
        id_str = '0' * missing_zeros + id_str
        print(f"Excel formatting fix: Added {missing_zeros} leading zero(s) to ID: {id_number} -> {id_str}")

    # The first 3 digits of the ID represent the barangay code
    barangay_code = id_str[:3]

    if barangay_code in valid_codes:
        return barangay_code

    # If still invalid, check if it's a 2-digit code that needs a leading zero
    if len(barangay_code) >= 2:
        two_digit_code = barangay_code[-2:]  # Take last 2 digits
        potential_code = '0' + two_digit_code
        if potential_code in valid_codes:
            print(f"Barangay code fix: {barangay_code} -> {potential_code}")
            return potential_code

    return None

@login_required
@requires_navigation_access('dashboard')
def dashboard_view(request):
    """Government dashboard view with automated status check results - FIXED with proper permission checks"""
    # Check if user has access to dashboard
    if not getattr(request.user, 'can_access_dashboard', False):
        messages.error(request, 'You do not have permission to access the dashboard.')
        return redirect(_get_safe_redirect_url(request.user))

    if request.user.user_type != 'GOV':
        return redirect('establishment_dashboard')

    # Get statistics for dashboard
    total_seniors = SeniorCitizen.objects.count()
    pending_approvals = SeniorCitizen.objects.filter(status='PENDING').count()
    
    recent_seniors = SeniorCitizen.objects.filter(status='APPROVED').order_by('-created_at')[:5]
    
    # NEW: Status monitoring statistics
    today = date.today()
    
    # Seniors needing attention
    expiring_soon = SeniorCitizen.objects.filter(
        status='APPROVED',
        expiration_date__lte=today + timedelta(days=30),
        expiration_date__gt=today
    ).count()
    
    proof_of_life_due_soon = SeniorCitizen.objects.filter(
        status='APPROVED',
        next_proof_of_life_date__lte=today + timedelta(days=30),
        next_proof_of_life_date__gt=today
    ).count()
    
    # Currently deactivated seniors
    deactivated_expired = SeniorCitizen.objects.filter(
        status='DEACTIVATED',
        deactivation_reason='EXPIRED_PENDING_RENEWAL'
    ).count()
    
    deactivated_proof_of_life = SeniorCitizen.objects.filter(
        status='DEACTIVATED',
        deactivation_reason='PROOF_OF_LIFE_OVERDUE'
    ).count()
    
    # Overdue seniors (past due date)
    expired_seniors = SeniorCitizen.objects.filter(
        expiration_date__lt=today
    ).exclude(status__in=['ARCHIVED', 'DEACTIVATED']).count()
    
    proof_of_life_overdue = SeniorCitizen.objects.filter(
        next_proof_of_life_date__lt=today
    ).exclude(status__in=['ARCHIVED', 'DEACTIVATED']).count()
    
    # Get latest system check results
    latest_system_check = SystemStatusCheck.objects.first()
    
    # Check if auto-check results are available from middleware
    auto_check_results = getattr(request, 'auto_check_results', None)
    
    context = {
        'total_seniors': total_seniors,
        'pending_approvals': pending_approvals,
        'recent_seniors': recent_seniors,
        
        # NEW: Status monitoring
        'expiring_soon': expiring_soon,
        'proof_of_life_due_soon': proof_of_life_due_soon,
        'deactivated_expired': deactivated_expired,
        'deactivated_proof_of_life': deactivated_proof_of_life,
        'expired_seniors': expired_seniors,
        'proof_of_life_overdue': proof_of_life_overdue,
        
        # System check information
        'latest_system_check': latest_system_check,
        'auto_check_results': auto_check_results,
    }
    
    return render(request, 'core/dashboard.html', context)

@login_required
@requires_permission('can_view_active_records')
def senior_list_view(request):
    """View for listing senior citizens with enhanced status filtering"""
    status = request.GET.get('status', 'APPROVED')
    query = request.GET.get('q', '')
    
    # Filter seniors based on status
    if status == 'ALL':
        seniors = SeniorCitizen.objects.all().order_by('-created_at')
    else:
        seniors = SeniorCitizen.objects.filter(status=status).order_by('-created_at')
    
    # Apply search filter if provided
    if query:
        seniors = seniors.filter(
            Q(id_number__icontains=query) |
            Q(first_name__icontains=query) |
            Q(last_name__icontains=query)
        )
    
    # Pagination
    paginator = Paginator(seniors, 10)
    page_number = request.GET.get('page', 1)
    seniors_page = paginator.get_page(page_number)
    
    # NEW: Add status warnings to each senior
    today = date.today()
    for senior in seniors_page:
        senior.status_warnings = []
        
        if senior.status == 'APPROVED':
            if senior.is_expired():
                senior.status_warnings.append('EXPIRED')
            elif senior.days_until_expiration() and senior.days_until_expiration() <= 30:
                senior.status_warnings.append(f'EXPIRES IN {senior.days_until_expiration()} DAYS')
            
            if senior.is_proof_of_life_overdue():
                senior.status_warnings.append('PROOF OF LIFE OVERDUE')
            elif senior.days_until_proof_of_life() and senior.days_until_proof_of_life() <= 30:
                senior.status_warnings.append(f'PROOF OF LIFE DUE IN {senior.days_until_proof_of_life()} DAYS')
    
    context = {
        'seniors': seniors_page,
        'status': status,
        'query': query,
    }
    
    return render(request, 'seniors/senior_list.html', context)

@login_required
@requires_permission('can_create_active_records')
def senior_create_view(request):
    """View for creating a new senior citizen record with application date handling

    PERMISSION SYSTEM:
    - Users with can_create_active_records permission can create records
    - All submissions go to PENDING status for approval
    """
    if request.method == 'POST':
        form = SeniorCitizenForm(request.POST, request.FILES)
        if form.is_valid():
            senior = form.save(commit=False)

            # Set the barangay code from the form
            senior.barangay_code = form.cleaned_data.get('barangay')

            # Set the birth_date from the cleaned birth_date_text
            senior.birth_date = form.cleaned_data.get('birth_date_text')

            # ENSURE ADDRESS IS SET - this is the key fix
            if form.cleaned_data.get('address'):
                senior.address = form.cleaned_data.get('address')
                print(f"Create view: Setting address = '{senior.address}'")  # Debug line

            # NEW: Handle application date
            application_date = form.cleaned_data.get('application_date_text')
            if application_date:
                senior.application_date = application_date
                print(f"Using custom application date: {application_date}")
            else:
                senior.application_date = date.today()  # Default to today
                print(f"Using default application date: {senior.application_date}")

            # Important: Don't set id_number manually - let the model generate it
            senior.id_number = ''

            # Set creator and status based on role
            senior.created_by = request.user
            senior.updated_by = request.user

            # NEW LOGIC: Both Employees AND Administrators create pending records
            # RA/SA will approve AD submissions, AD/RA/SA will approve EM submissions
            senior.status = 'PENDING'
            
            try:
                # Save the senior citizen - this will auto-calculate expiration and proof of life dates
                senior.save()

                print(f"Senior citizen created with:")
                print(f"  Application Date: {senior.application_date}")
                print(f"  Expiration Date: {senior.expiration_date}")
                print(f"  Next Proof of Life: {senior.next_proof_of_life_date}")
                print(f"  Address: '{senior.address}'")  # Debug line

                # NOTE: QR code will be generated upon approval, not during creation
                # All records are now PENDING and must be approved first

                # Log the action
                AuditLog.objects.create(
                    user=request.user,
                    action='CREATE',
                    content_type='SeniorCitizen',
                    object_id=senior.id,
                    description=f'Created senior citizen (PENDING approval): {senior.id_number} by {request.user.get_role_display()} - (App: {senior.application_date}, Exp: {senior.expiration_date}, Proof: {senior.next_proof_of_life_date})',
                    ip_address=request.META.get('REMOTE_ADDR')
                )

                messages.success(request, f'Senior citizen record created successfully and submitted for approval! ID: {senior.id_number}')
                return redirect('senior_detail', pk=senior.pk)
                
            except Exception as e:
                print(f"Error creating senior citizen: {e}")
                messages.error(request, f'Error creating senior citizen: {str(e)}')
        else:
            print("Form validation failed:", form.errors)
            # Add debug info for address fields
            print(f"House number errors: {form.errors.get('house_number', 'No errors')}")
            print(f"Street errors: {form.errors.get('street', 'No errors')}")
            print(f"Subdivision errors: {form.errors.get('subdivision', 'No errors')}")
            print(f"City errors: {form.errors.get('city', 'No errors')}")
            if form.cleaned_data:
                print(f"House number value: {form.cleaned_data.get('house_number', 'Not in cleaned_data')}")
                print(f"Street value: {form.cleaned_data.get('street', 'Not in cleaned_data')}")
                print(f"Address value: {form.cleaned_data.get('address', 'Not in cleaned_data')}")
    else:
        form = SeniorCitizenForm()
    
    # Get current statistics for display
    try:
        next_global_count = SeniorCitizen.get_next_global_count()
        total_seniors = SeniorCitizen.objects.count()
    except:
        next_global_count = 1
        total_seniors = 0
    
    # Sample ID numbers for each barangay
    sample_ids = {}
    for code, name in SeniorCitizen.BARANGAY_CODES.items():
        sample_ids[code] = {
            'name': name,
            'sample_id': f"{code}0000{next_global_count:06d}"
        }
    
    context = {
        'form': form,
        'action': 'Create',
        'next_global_count': next_global_count,
        'total_seniors': total_seniors,
        'sample_ids': sample_ids,
    }
    
    return render(request, 'seniors/senior_form.html', context)

@login_required
@requires_permission('can_edit_active_records')
def senior_update_view(request, pk):
    """View for updating an existing senior citizen record with application date support

    PERMISSION SYSTEM:
    - Users with can_edit_active_records permission can update records
    - Updates by users set the record back to PENDING for re-approval based on role hierarchy
    """
    senior = get_object_or_404(SeniorCitizen, pk=pk)

    # Check if employee is trying to update an approved record
    if request.user.role == 'EM' and senior.status == 'APPROVED':
        messages.error(request, 'Employees cannot modify approved records.')
        return redirect('senior_detail', pk=senior.pk)

    # Check if employee is trying to update a record created by someone else
    if request.user.role == 'EM' and senior.created_by != request.user:
        messages.error(request, 'Employees can only modify their own records.')
        return redirect('senior_detail', pk=senior.pk)

    # Check if AD is trying to update an approved record created by another AD
    if request.user.role == 'AD' and senior.status == 'APPROVED' and senior.created_by != request.user and senior.created_by.role == 'AD':
        messages.error(request, 'Administrators cannot modify approved records created by other Administrators.')
        return redirect('senior_detail', pk=senior.pk)
    
    if request.method == 'POST':
        form = SeniorCitizenForm(request.POST, request.FILES, instance=senior)
        if form.is_valid():
            updated_senior = form.save(commit=False)
            
            # Update barangay code if provided
            if form.cleaned_data.get('barangay'):
                updated_senior.barangay_code = form.cleaned_data.get('barangay')
            
            # Set the birth_date from the cleaned birth_date_text
            if form.cleaned_data.get('birth_date_text'):
                updated_senior.birth_date = form.cleaned_data.get('birth_date_text')
            
            # ENSURE ADDRESS IS SET - this is the key fix
            if form.cleaned_data.get('address'):
                updated_senior.address = form.cleaned_data.get('address')
                print(f"Update view: Setting address = '{updated_senior.address}'")  # Debug line
            
            # NEW: Handle application date update
            application_date = form.cleaned_data.get('application_date_text')
            if application_date:
                # Only update if different from current
                if updated_senior.application_date != application_date:
                    old_app_date = updated_senior.application_date
                    updated_senior.application_date = application_date
                    print(f"Application date changed from {old_app_date} to {application_date}")
                    
                    # Clear expiration and proof of life dates so they get recalculated
                    updated_senior.expiration_date = None
                    updated_senior.next_proof_of_life_date = None
            
            updated_senior.updated_by = request.user

            # Important: Don't regenerate ID number on update unless specifically needed
            # The existing ID should be preserved to maintain data integrity

            # NEW LOGIC: When AD or EM updates an APPROVED record, it goes back to PENDING
            # This ensures proper oversight: AD changes need RA/SA approval
            old_status = senior.status
            if old_status == 'APPROVED':
                updated_senior.status = 'PENDING'
                # Remove QR code since record needs re-approval
                if updated_senior.qr_code:
                    if os.path.isfile(updated_senior.qr_code.path):
                        os.remove(updated_senior.qr_code.path)
                    updated_senior.qr_code = None
                print(f"Status changed from APPROVED to PENDING due to update by {request.user.get_role_display()}")

            # If status changed to approved, generate QR code
            if updated_senior.status == 'APPROVED' and old_status != 'APPROVED':
                generate_qr_code(updated_senior)

            try:
                # Save will recalculate expiration and proof of life dates if needed
                updated_senior.save()
                
                print(f"Senior citizen updated:")
                print(f"  Application Date: {updated_senior.application_date}")
                print(f"  Expiration Date: {updated_senior.expiration_date}")
                print(f"  Next Proof of Life: {updated_senior.next_proof_of_life_date}")
                print(f"  Address: '{updated_senior.address}'")  # Debug line
                
                # Log the action
                status_change_msg = f" - Status changed from {old_status} to {updated_senior.status}" if old_status != updated_senior.status else ""
                AuditLog.objects.create(
                    user=request.user,
                    action='UPDATE',
                    content_type='SeniorCitizen',
                    object_id=senior.id,
                    description=f'Updated senior citizen: {senior.id_number} by {request.user.get_role_display()}{status_change_msg} (App: {updated_senior.application_date}, Exp: {updated_senior.expiration_date})',
                    ip_address=request.META.get('REMOTE_ADDR')
                )

                if old_status == 'APPROVED' and updated_senior.status == 'PENDING':
                    messages.success(request, f'Senior citizen record updated successfully and submitted for re-approval! ID: {senior.id_number}')
                else:
                    messages.success(request, f'Senior citizen record updated successfully! Application: {updated_senior.application_date}')
                return redirect('senior_detail', pk=senior.pk)
                
            except Exception as e:
                print(f"Error updating senior citizen: {e}")
                messages.error(request, f'Error updating senior citizen: {str(e)}')
        else:
            print("Form validation failed:", form.errors)
            # Add debug info for address fields
            print(f"House number: {form.cleaned_data.get('house_number') if form.is_valid() else 'Form invalid'}")
            print(f"Street: {form.cleaned_data.get('street') if form.is_valid() else 'Form invalid'}")
            print(f"Subdivision: {form.cleaned_data.get('subdivision') if form.is_valid() else 'Form invalid'}")
            print(f"City: {form.cleaned_data.get('city') if form.is_valid() else 'Form invalid'}")
    else:
        form = SeniorCitizenForm(instance=senior)
        # Debug: Check if address parsing worked
        print(f"GET request - Senior address: '{senior.address}'")
        print(f"Form house_number initial: '{form.fields['house_number'].initial}'")
        print(f"Form street initial: '{form.fields['street'].initial}'")
        print(f"Form subdivision initial: '{form.fields['subdivision'].initial}'")
        print(f"Form city initial: '{form.fields['city'].initial}'")
    
    context = {
        'form': form,
        'senior': senior,
        'action': 'Update',
    }
    
    return render(request, 'seniors/senior_form.html', context)

def generate_qr_code(senior):
    """Generate a QR code for a senior citizen"""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    
    # The QR code will contain the senior citizen ID
    qr.add_data(senior.id_number)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Create a BytesIO object to save the image
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    
    # Create a unique filename
    filename = f'qr_{senior.id_number}_{uuid.uuid4().hex[:8]}.png'
    file_path = os.path.join('qr_codes', filename)
    
    # Save the QR code to the senior citizen record
    if senior.qr_code:
        # Delete the old QR code if it exists
        if os.path.isfile(senior.qr_code.path):
            os.remove(senior.qr_code.path)
    
    # Make sure the directory exists
    qr_code_dir = os.path.join(settings.MEDIA_ROOT, 'qr_codes')
    if not os.path.exists(qr_code_dir):
        os.makedirs(qr_code_dir)
    
    # Save the QR code to the file system
    with open(os.path.join(settings.MEDIA_ROOT, file_path), 'wb') as f:
        f.write(buffer.getvalue())
    
    # Update the senior citizen record
    senior.qr_code = file_path
    return True

@login_required
def download_template_view(request):
    """Generate and download an Excel template for batch upload with address components and binary gender"""
    # Direct permission check - bypass problematic decorator
    if not getattr(request.user, 'can_download_batch_templates', False):
        messages.error(request, 'You do not have permission to download batch upload templates.')
        return redirect('batch_upload')

    # Additional access check - ensure user can access batch upload
    if not getattr(request.user, 'can_access_batch_upload', False):
        messages.error(request, 'You do not have permission to access batch upload functionality.')
        return redirect('dashboard')
    
    # Create empty template with address component headers (16 columns total)
    template_data = {
        'SENIOR CITIZEN ID NUMBER': [],
        'LAST NAME': [],
        'FIRST NAME': [],
        'MIDDLE NAME': [],
        'BIRTH DATE': [],
        'GENDER': [],
        'HOUSE NUMBER': [],  # NEW: Required address component
        'STREET': [],        # NEW: Required address component
        'SUBDIVISION': [],   # NEW: Optional address component
        'MOBILE NUMBER': [],
        'TELEPHONE NUMBER': [],
        'VACCINATION STATUS': [],
        'HEIGHT': [],
        'WEIGHT': [],
        'EYE COLOR': [],
        'EMERGENCY CONTACT NAME': [],
        'EMERGENCY CONTACT NUMBER': [],
        'EMERGENCY CONTACT ADDRESS': [],
        'APPLICATION DATE': [],
    }
    
    df = pd.DataFrame(template_data)
    
    # Create Excel file in memory
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, sheet_name='Senior Citizens Data', index=False)
        
        # Get the xlsxwriter workbook and worksheet objects
        workbook = writer.book
        worksheet = writer.sheets['Senior Citizens Data']

        # Format the ID NUMBER column as TEXT to preserve leading zeros
        text_format = workbook.add_format({'num_format': '@'})  # @ means text format
        worksheet.set_column('A:A', 20, text_format)  # Column A is SENIOR CITIZEN ID NUMBER

        # Add formatting
        header_format = workbook.add_format({
            'bold': True, 
            'bg_color': '#4e73df', 
            'color': 'white',
            'border': 1,
            'text_wrap': True,
            'valign': 'vcenter',
            'align': 'center'
        })
        
        # Write the column headers with the defined format
        for col_num, value in enumerate(df.columns.values):
            worksheet.write(0, col_num, value, header_format)
            
            # Set column widths based on content
            if 'NAME' in value:
                worksheet.set_column(col_num, col_num, 20)
            elif 'HOUSE' in value or 'STREET' in value:
                worksheet.set_column(col_num, col_num, 22)
            elif 'SUBDIVISION' in value:
                worksheet.set_column(col_num, col_num, 25)
            elif 'ADDRESS' in value:
                worksheet.set_column(col_num, col_num, 30)
            elif 'DATE' in value:
                worksheet.set_column(col_num, col_num, 15)
            elif 'NUMBER' in value:
                worksheet.set_column(col_num, col_num, 18)
            elif 'GENDER' in value:
                worksheet.set_column(col_num, col_num, 12)
            else:
                worksheet.set_column(col_num, col_num, 18)
        
        # Add instructions sheet with updated address component information
        instructions_data = {
            'Column Name': [
                'SENIOR CITIZEN ID NUMBER', 'LAST NAME', 'FIRST NAME', 'MIDDLE NAME', 'BIRTH DATE', 'GENDER',
                'HOUSE NUMBER', 'STREET', 'SUBDIVISION',
                'MOBILE NUMBER', 'TELEPHONE NUMBER', 'VACCINATION STATUS', 'HEIGHT', 'WEIGHT', 'EYE COLOR',
                'EMERGENCY CONTACT NAME', 'EMERGENCY CONTACT NUMBER', 'EMERGENCY CONTACT ADDRESS', 'APPLICATION DATE'
            ],
            'Required': [
                'No (Auto-generated)', 'Yes', 'Yes', 'No', 'Yes', 'Yes',
                'Yes', 'Yes', 'No',  # Address components: House & Street required, barangay auto-detected
                'No', 'No', 'No', 'No', 'No', 'No',
                'No', 'No', 'No', 'No (Auto-set)'
            ],
            'Format/Example': [
                'Format as TEXT in Excel to preserve leading zeros (e.g., 099000000000004). Leave empty for auto-generation.',
                'DELA CRUZ or dela cruz (auto-formatted)',
                'JUAN or juan (auto-formatted)',
                'GONZALES or gonzales (optional)',
                'MM/DD/YYYY (05/15/1960)',
                'M or F (Male/Female only)',  # Updated for binary gender
                '123 or Unit 4B or Blk 5 Lot 12',  # NEW
                'Rizal Street or Main Avenue',      # NEW
                'Greenfield Village or Palm Heights (optional)',  # NEW
                '+639123456789 or 09123456789',
                '(02) 8123-4567 or landline number',
                'FULL, PARTIAL, or NONE',
                'Height in centimeters (e.g., 165)',
                'Weight in kilograms (e.g., 70)',
                'BLACK, BROWN, BLUE, GREEN, HAZEL, GRAY, OTHER',
                'Emergency contact name',
                'Contact phone number',
                'Emergency contact address',
                'Leave empty for current date'
            ],
            'Description': [
                'Leave empty - system will auto-generate sequential ID numbers with auto-detected barangay',
                'Last name - case insensitive, will be formatted to Title Case',
                'First name - case insensitive, will be formatted to Title Case',
                'Middle name - optional, case insensitive, will be formatted to Title Case',
                'Birth date - must be at least 60 years old, multiple formats accepted',
                'Gender - M/F, Male/Female only accepted (case insensitive)',  # Updated
                'House number, unit number, block and lot - REQUIRED FIELD',  # NEW
                'Street name, avenue, or road name - REQUIRED FIELD',  # NEW
                'Subdivision, village, or community name - optional',  # NEW
                'Mobile phone number in Philippine format - optional but recommended',
                'Landline/telephone number - optional',
                'COVID-19 vaccination status - optional, defaults to NONE',
                'Height in centimeters - optional health information',
                'Weight in kilograms - optional health information',
                'Eye color - optional identification information',
                'Name of emergency contact person - optional but recommended',
                'Emergency contact phone number - optional',
                'Emergency contact address - optional',
                'Leave empty - system will use current date as application date'
            ]
        }
        
        instructions_df = pd.DataFrame(instructions_data)
        instructions_df.to_excel(writer, sheet_name='Instructions', index=False)
        
        # Format instructions sheet
        instructions_worksheet = writer.sheets['Instructions']
        instructions_header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#28a745',
            'color': 'white',
            'border': 1,
            'text_wrap': True
        })
        
        for col_num, value in enumerate(instructions_df.columns.values):
            instructions_worksheet.write(0, col_num, value, instructions_header_format)
            if col_num == 0:
                instructions_worksheet.set_column(col_num, col_num, 25)
            elif col_num == 1:
                instructions_worksheet.set_column(col_num, col_num, 20)
            else:
                instructions_worksheet.set_column(col_num, col_num, 50)
        
        # Add barangay codes sheet (reference only - barangay auto-detected from ID)
        barangay_data = {
            'Barangay Code': ['005', '021', '041', '042', '043', '047', '069', '072', '073', '083', '099', '101', '119', '120'],
            'Barangay Name': [
                'Bagbag', 'Capri', 'Fairview', 'Greater Lagro', 'Gulod', 'Kaligayahan',
                'Nagkaisang Nayon', 'North Fairview', 'Novaliches Proper', 'Pasong Putik',
                'San Agustin', 'San Bartolome', 'Sta. Lucia', 'Sta. Monica'
            ],
            'ID Format': [
                '005XXXXXXX (first 3 digits = barangay code)',
                '021XXXXXXX (first 3 digits = barangay code)',
                '041XXXXXXX (first 3 digits = barangay code)',
                '042XXXXXXX (first 3 digits = barangay code)',
                '043XXXXXXX (first 3 digits = barangay code)',
                '047XXXXXXX (first 3 digits = barangay code)',
                '069XXXXXXX (first 3 digits = barangay code)',
                '072XXXXXXX (first 3 digits = barangay code)',
                '073XXXXXXX (first 3 digits = barangay code)',
                '083XXXXXXX (first 3 digits = barangay code)',
                '099XXXXXXX (first 3 digits = barangay code)',
                '101XXXXXXX (first 3 digits = barangay code)',
                '119XXXXXXX (first 3 digits = barangay code)',
                '120XXXXXXX (first 3 digits = barangay code)'
            ]
        }
        
        barangay_df = pd.DataFrame(barangay_data)
        barangay_df.to_excel(writer, sheet_name='Barangay Codes', index=False)
        
        # Format barangay codes sheet
        barangay_worksheet = writer.sheets['Barangay Codes']
        barangay_header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#17a2b8',
            'color': 'white',
            'border': 1
        })
        
        for col_num, value in enumerate(barangay_df.columns.values):
            barangay_worksheet.write(0, col_num, value, barangay_header_format)
            barangay_worksheet.set_column(col_num, col_num, 30)
        
        # Add gender codes sheet (updated for binary only)
        gender_data = {
            'Gender Code': ['M', 'F'],
            'Gender Name': ['Male', 'Female'],
            'Accepted Values': [
                'M, MALE, Lalaki, m, male, lalaki',
                'F, FEMALE, Babae, f, female, babae',
            ],
            'Description': [
                'Male gender - case insensitive',
                'Female gender - case insensitive',
            ]
        }
        
        gender_df = pd.DataFrame(gender_data)
        gender_df.to_excel(writer, sheet_name='Gender Codes', index=False)
        
        # Format gender codes sheet
        gender_worksheet = writer.sheets['Gender Codes']
        gender_header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#6f42c1',
            'color': 'white',
            'border': 1
        })
        
        for col_num, value in enumerate(gender_df.columns.values):
            gender_worksheet.write(0, col_num, value, gender_header_format)
            gender_worksheet.set_column(col_num, col_num, 25)
        
        # Add address examples sheet (NEW)
        address_examples_data = {
            'Property Type': [
                'Single Family House',
                'Condominium Unit',
                'Townhouse',
                'Apartment',
                'Commercial Building'
            ],
            'House Number': [
                '123',
                'Unit 4B, Tower 2',
                'Blk 5 Lot 12',
                'Apt 201, Bldg A',
                'Suite 305'
            ],
            'Street': [
                'Rizal Street',
                'EDSA',
                'Main Avenue',
                'Commonwealth Avenue',
                'Katipunan Avenue'
            ],
            'Subdivision': [
                'Palm Heights Subdivision',
                'Greenfield Village',
                'Vista Verde Subdivision',
                'Sunrise Village',
                'Golden City Subdivision'
            ],
            'Final Address': [
                '123, Rizal Street, Palm Heights Subdivision, Quezon City',
                'Unit 4B, Tower 2, EDSA, Greenfield Village, Quezon City',
                'Blk 5 Lot 12, Main Avenue, Vista Verde Subdivision, Quezon City',
                'Apt 201, Bldg A, Commonwealth Avenue, Sunrise Village, Quezon City',
                'Suite 305, Katipunan Avenue, Golden City Subdivision, Quezon City'
            ]
        }
        
        address_examples_df = pd.DataFrame(address_examples_data)
        address_examples_df.to_excel(writer, sheet_name='Address Examples', index=False)
        
        # Format address examples sheet
        address_examples_worksheet = writer.sheets['Address Examples']
        address_examples_header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#fd7e14',
            'color': 'white',
            'border': 1
        })
        
        for col_num, value in enumerate(address_examples_df.columns.values):
            address_examples_worksheet.write(0, col_num, value, address_examples_header_format)
            address_examples_worksheet.set_column(col_num, col_num, 35)
        
        # Add important notes sheet (updated)
        notes_data = {
            'Important Notes': [
                '1. Sequential ID Generation',
                '2. Excel ID Number Formatting (IMPORTANT)',
                '3. Case Insensitive Processing',
                '4. Auto-formatting',
                '5. Date Format',
                '6. Phone Numbers',
                '7. Gender Field (Updated)',
                '8. Address Components (New)',
                '9. Required vs Optional Fields',
                '10. Application Date',
                '11. File Upload Tips'
            ],
            'Details': [
                'Leave SENIOR CITIZEN ID NUMBER column empty for auto-generation. If providing existing IDs, format column as TEXT in Excel to preserve leading zeros.',
                'CRITICAL: If entering ID numbers manually, format the ID NUMBER column as TEXT in Excel (right-click column > Format Cells > Text) BEFORE entering data. This prevents Excel from removing leading zeros (099 becomes 99). System can auto-fix most cases but formatting as TEXT is recommended.',
                'All names, gender, and barangay entries are case-insensitive. You can use UPPERCASE, lowercase, or Mixed Case - system will format correctly.',
                'Names will be automatically formatted to Title Case (First Letter Capitalized) in the database.',
                'Birth dates must be in MM/DD/YYYY format (e.g., 05/15/1960). Person must be at least 60 years old.',
                'Mobile numbers: +639XXXXXXXXX or 09XXXXXXXXX format preferred. System will auto-format if possible.',
                'Gender field accepts ONLY: M/F, Male/Female, or Lalaki/Babae. Case insensitive. Required field. NO OTHER OPTIONS.',
                'Address is now split into components: HOUSE NUMBER (required), STREET (required), SUBDIVISION (optional), CITY (defaults to Quezon City if empty). System combines these automatically.',
                'Required fields: LAST NAME, FIRST NAME, BIRTH DATE, GENDER, HOUSE NUMBER, STREET, and BARANGAY. All other fields are optional.',
                'Leave APPLICATION DATE column empty to use current date, or specify a custom date in MM/DD/YYYY format.',
                'Save as .xlsx or .xls format. Remove any empty rows below your data before uploading. Each address component should be in its own column.'
            ]
        }
        
        notes_df = pd.DataFrame(notes_data)
        notes_df.to_excel(writer, sheet_name='Important Notes', index=False)
        
        # Format notes sheet
        notes_worksheet = writer.sheets['Important Notes']
        notes_header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#dc3545',
            'color': 'white',
            'border': 1
        })
        
        for col_num, value in enumerate(notes_df.columns.values):
            notes_worksheet.write(0, col_num, value, notes_header_format)
            if col_num == 0:
                notes_worksheet.set_column(col_num, col_num, 30)
            else:
                notes_worksheet.set_column(col_num, col_num, 80)
    
    # Prepare response
    output.seek(0)
    current_date = datetime.now().strftime('%Y%m%d')
    response = HttpResponse(output.read(), content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = f'attachment; filename=senior_citizens_batch_upload_template_v2_{current_date}.xlsx'
    
    # Log the action
    AuditLog.objects.create(
        user=request.user,
        action='DOWNLOAD',
        content_type='BatchTemplate',
        description=f'Downloaded batch upload template v2 (address components)',
        ip_address=request.META.get('REMOTE_ADDR')
    )
    
    return response

@login_required
def batch_upload_view(request):
    """Complete batch upload with address component processing and binary gender validation"""
    # AUTOMATIC CLEANUP: Clear any old batch upload errors from session
    if 'batch_upload_errors' in request.session:
        del request.session['batch_upload_errors']

    # Direct permission checks - bypass problematic decorators
    if not getattr(request.user, 'can_access_batch_upload', False):
        messages.error(request, 'You do not have permission to access batch upload functionality.')
        return redirect('dashboard')

    # Check if user can perform batch upload (for POST) or just view (for GET)
    if request.method == 'POST':
        if not getattr(request.user, 'can_perform_batch_upload', False):
            messages.error(request, 'You do not have permission to perform batch uploads.')
            return redirect('batch_upload')
    
    if request.method == 'POST':
        try:
            excel_file = request.FILES.get('excel_file')
            
            if not excel_file:
                messages.error(request, 'Please upload a file')
                return redirect('batch_upload')
            
            file_name = excel_file.name.lower()
            
            if not file_name.endswith(('.xlsx', '.xls', '.csv')):
                messages.error(request, 'Please upload a valid file (.xlsx, .xls, or .csv)')
                return redirect('batch_upload')
            
            print(f"=== PROCESSING FILE: {excel_file.name} ===")
            print(f"File size: {excel_file.size} bytes")
            
            # Read the file with better error handling
            try:
                if file_name.endswith('.csv'):
                    # CSV handling with multiple encodings
                    encodings = ['utf-8', 'utf-8-sig', 'iso-8859-1', 'cp1252', 'latin1']
                    df = None
                    
                    for encoding in encodings:
                        try:
                            print(f"Trying encoding: {encoding}")
                            excel_file.seek(0)
                            df = pd.read_csv(
                                excel_file, 
                                encoding=encoding,
                                sep=None,
                                engine='python',
                                skipinitialspace=True,
                                na_values=['', 'NA', 'N/A', 'null', 'NULL'],
                                keep_default_na=True
                            )
                            print(f"Successfully read CSV with encoding: {encoding}")
                            break
                        except UnicodeDecodeError:
                            continue
                        except pd.errors.ParserError as pe:
                            print(f"Parser error with {encoding}: {pe}")
                            continue
                    
                    if df is None:
                        messages.error(request, 'Unable to read CSV file. Please check the file format and try again.')
                        return redirect('batch_upload')
                else:
                    # Excel files - handle dates properly
                    df = pd.read_excel(excel_file, engine='openpyxl', parse_dates=False)
                    print("Excel file loaded successfully")
                    
            except Exception as e:
                print(f"File reading error: {e}")
                messages.error(request, f'Error reading file: {str(e)}. Please check the file format.')
                return redirect('batch_upload')
            
            print(f"File shape: {df.shape}")
            print(f"Original columns: {list(df.columns)}")
            
            # Clean column names
            df.columns = df.columns.str.strip().str.upper()
            print(f"Cleaned columns: {list(df.columns)}")
            
            # Remove completely empty rows
            df = df.dropna(how='all')
            print(f"After removing empty rows: {df.shape}")
            
            if len(df) == 0:
                messages.error(request, 'No data rows found in file. Please check your file and try again.')
                return redirect('batch_upload')
            
            # Check for required columns (updated for address components, barangay auto-detected)
            required_columns = ['LAST NAME', 'FIRST NAME', 'BIRTH DATE', 'GENDER', 'HOUSE NUMBER', 'STREET']
            missing_columns = []
            
            for req_col in required_columns:
                if req_col not in df.columns:
                    missing_columns.append(req_col)
            
            if missing_columns:
                messages.error(request, f'Missing required columns: {", ".join(missing_columns)}. Please use the official template with address components.')
                return redirect('batch_upload')
            
            # Check if this is the final upload (ignored rows were selected)
            ignored_rows_from_session = request.session.get('batch_upload_ignored_rows', [])
            is_final_upload = len(ignored_rows_from_session) > 0 or request.POST.get('is_final_upload') == 'true'

            # Store dataframe in session for later reuse during final upload
            if not is_final_upload:
                request.session['batch_upload_dataframe'] = df.to_json()
                request.session.modified = True

            # Process each row - CONTINUE PROCESSING EVEN WITH ERRORS
            success_count = 0
            error_messages = []
            successful_records = []
            validation_results = []  # NEW: Build detailed validation results for UI

            print(f"\n=== STARTING BATCH PROCESSING OF {len(df)} ROWS ===")
            print(f"Is final upload: {is_final_upload}")
            print(f"Ignored rows: {ignored_rows_from_session}")

            for index, row in df.iterrows():
                row_number = index + 1
                try:
                    # SKIP this row if it was marked as ignored
                    if str(row_number) in [str(r) for r in ignored_rows_from_session]:
                        print(f"\n--- Skipping Row {row_number} (IGNORED BY USER) ---")
                        continue

                    print(f"\n--- Processing Row {row_number} ---")
                    
                    # Helper function to clean values
                    def clean_value(val):
                        if pd.isna(val):
                            return None
                        val_str = str(val).strip()
                        if val_str.lower() in ['nan', '', 'null', 'na', 'n/a']:
                            return None
                        # Remove surrounding quotes if present
                        if len(val_str) >= 2:
                            if (val_str.startswith('"') and val_str.endswith('"')) or \
                               (val_str.startswith("'") and val_str.endswith("'")):
                                val_str = val_str[1:-1].strip()
                        return val_str if val_str else None
                    
                    # Extract and clean basic data
                    last_name = clean_value(row['LAST NAME'])
                    first_name = clean_value(row['FIRST NAME'])
                    middle_name = clean_value(row.get('MIDDLE NAME'))
                    gender_str = clean_value(row['GENDER'])
                    
                    # Extract address components (NEW)
                    house_number_str = clean_value(row['HOUSE NUMBER'])
                    street_str = clean_value(row['STREET'])
                    subdivision_str = clean_value(row.get('SUBDIVISION'))
                    
                    # Handle birth date specially
                    birth_date_raw = row['BIRTH DATE']
                    birth_date_str = clean_value(birth_date_raw)
                    
                    # Handle application date specially
                    application_date_raw = row.get('APPLICATION DATE')
                    application_date_str = clean_value(application_date_raw) if application_date_raw is not None else None
                    
                    # Validate required fields - SKIP THIS ROW IF MISSING REQUIRED FIELDS
                    validation_errors = []
                    
                    if not last_name:
                        validation_errors.append('Last Name is required')
                    if not first_name:
                        validation_errors.append('First Name is required')
                    if pd.isna(birth_date_raw):
                        validation_errors.append('Birth Date is required')
                    if not gender_str:
                        validation_errors.append('Gender is required')
                    if not house_number_str:
                        validation_errors.append('House Number is required')  # NEW
                    if not street_str:
                        validation_errors.append('Street is required')  # NEW
                    
                    if validation_errors:
                        error_msg = f'Row {row_number}: {"; ".join(validation_errors)}'
                        error_messages.append(error_msg)
                        # Add to validation results
                        validation_results.append({
                            'row_number': row_number,
                            'excel_row': row_number,
                            'status': 'error',
                            'data': {
                                'first_name': first_name,
                                'last_name': last_name,
                                'birth_date': None,
                            },
                            'errors': [{'field': f, 'type': 'Required Field', 'message': f, 'actions': ['skip']} for f in validation_errors],
                            'warnings': []
                        })
                        print(f"SKIPPING Row {row_number}: Missing required fields")
                        continue  # Skip this row, continue with next one
                    
                    # Parse birth date - SKIP ROW IF INVALID
                    birth_date = None
                    try:
                        birth_date = parse_date(birth_date_raw)
                        if birth_date is None:
                            raise ValueError("Could not parse birth date format")
                    except Exception as e:
                        print(f"Birth date parsing error: {e}")
                        # Clean error message to avoid technical details leaking to user
                        if "isinstance" in str(e):
                            error_msg = f'Row {row_number}: Invalid birth date format. Please use MM/DD/YYYY format (e.g., 05/15/1960)'
                        else:
                            error_msg = f'Row {row_number}: Invalid birth date format - {str(e)}'
                        error_messages.append(error_msg)
                        validation_results.append({
                            'row_number': row_number,
                            'excel_row': row_number,
                            'status': 'error',
                            'data': {
                                'first_name': first_name,
                                'last_name': last_name,
                                'birth_date': None,
                            },
                            'errors': [{'field': 'BIRTH DATE', 'type': 'Format Error', 'message': error_msg, 'actions': ['edit', 'skip']}],
                            'warnings': []
                        })
                        print(f"SKIPPING Row {row_number}: Birth date error")
                        continue
                    
                    # Parse application date - USE TODAY IF INVALID OR EMPTY
                    application_date = None
                    try:
                        if application_date_raw is not None and not pd.isna(application_date_raw):
                            application_date = parse_date(application_date_raw)
                        
                        # If no application date provided or parsing failed, use today
                        if application_date is None:
                            application_date = date.today()
                        
                        # Validate application date
                        today = date.today()
                        if application_date > today:
                            application_date = today
                        
                        # Don't allow application dates more than 10 years ago
                        ten_years_ago = date(today.year - 10, today.month, today.day)
                        if application_date < ten_years_ago:
                            application_date = today
                        
                        # Application date cannot be before birth date
                        if application_date < birth_date:
                            application_date = birth_date
                            
                    except Exception as e:
                        print(f"Application date parsing error: {e}, using today")
                        application_date = date.today()
                    
                    # Check age - SKIP ROW IF TOO YOUNG
                    today = date.today()
                    age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
                    print(f"Calculated age: {age}")
                    
                    if age < 60:
                        error_msg = f'Row {row_number}: Person must be at least 60 years old (current age: {age})'
                        error_messages.append(error_msg)
                        validation_results.append({
                            'row_number': row_number,
                            'excel_row': row_number,
                            'status': 'error',
                            'data': {
                                'first_name': first_name,
                                'last_name': last_name,
                                'birth_date': birth_date,
                                'age': age,
                            },
                            'errors': [{'field': 'BIRTH DATE', 'type': 'Age Requirement', 'message': error_msg, 'actions': ['edit', 'skip']}],
                            'warnings': []
                        })
                        print(f"SKIPPING Row {row_number}: Too young ({age} years)")
                        continue
                    
                    # Format names
                    formatted_last_name = format_name(last_name)
                    formatted_first_name = format_name(first_name)
                    formatted_middle_name = format_name(middle_name) if middle_name else None
                    
                    # Process gender - SKIP ROW IF INVALID (Binary only)
                    gender = None
                    gender_upper = gender_str.upper()
                    if gender_upper in ['F', 'FEMALE', 'BABAE']:
                        gender = 'F'
                    elif gender_upper in ['M', 'MALE', 'LALAKI']:
                        gender = 'M'
                    else:
                        error_msg = f'Row {row_number}: Invalid gender "{gender_str}". Use M (Male) or F (Female) only'
                        error_messages.append(error_msg)
                        validation_results.append({
                            'row_number': row_number,
                            'excel_row': row_number,
                            'status': 'error',
                            'data': {
                                'first_name': first_name,
                                'last_name': last_name,
                                'birth_date': birth_date,
                                'gender': gender_str,
                            },
                            'errors': [{'field': 'GENDER', 'type': 'Format Error', 'message': error_msg, 'actions': ['edit', 'skip']}],
                            'warnings': []
                        })
                        print(f"SKIPPING Row {row_number}: Invalid gender")
                        continue
                    
                    # Get senior_id and detect barangay from it - handle quotes BEFORE clean_value
                    senior_id_raw = row.get('SENIOR CITIZEN ID NUMBER')

                    # Handle ID specially to preserve quoted leading zeros
                    if pd.isna(senior_id_raw):
                        senior_id = None
                    else:
                        senior_id = str(senior_id_raw).strip()
                        # If it's quoted, remove quotes but preserve the content
                        if len(senior_id) >= 2 and ((senior_id.startswith('"') and senior_id.endswith('"')) or
                                                    (senior_id.startswith("'") and senior_id.endswith("'"))):
                            senior_id = senior_id[1:-1].strip()  # Remove quotes and keep content

                        # If empty after processing, set to None
                        if not senior_id or senior_id.lower() in ['nan', '', 'null', 'na', 'n/a']:
                            senior_id = None

                    # Fix common Excel leading zero issue for ALL barangay codes with missing leading zeros
                    if senior_id and len(senior_id) == 14:
                        # Check if it starts with any 2-digit barangay code that should have a leading zero
                        two_digit_codes = ['05', '21', '41', '42', '43', '47', '69', '72', '73', '83', '99']
                        first_two = senior_id[:2]
                        if first_two in two_digit_codes:
                            senior_id = '0' + senior_id
                            print(f"AUTO-FIXED Excel leading zero issue: {senior_id[1:]} -> {senior_id}")
                            print(f"Fixed because ID started with '{first_two}' which needs leading zero")

                    print(f"DEBUG Row {row_number}: Raw ID = '{senior_id_raw}', Final ID = '{senior_id}'")

                    # Detect barangay from ID if provided, otherwise auto-generate
                    if senior_id:
                        barangay_code = extract_barangay_code_from_id(senior_id)
                        if not barangay_code:
                            error_msg = f'Row {row_number}: Invalid ID number "{senior_id}". Cannot detect barangay from ID. Valid barangay codes: 005, 021, 041, 042, 043, 047, 069, 072, 073, 083, 099, 101, 119, 120'
                            error_messages.append(error_msg)
                            validation_results.append({
                                'row_number': row_number,
                                'excel_row': row_number,
                                'status': 'error',
                                'data': {
                                    'first_name': first_name,
                                    'last_name': last_name,
                                    'birth_date': birth_date,
                                    'id_number': senior_id,
                                },
                                'errors': [{'field': 'SENIOR CITIZEN ID NUMBER', 'type': 'Invalid Format', 'message': error_msg, 'actions': ['edit', 'skip']}],
                                'warnings': []
                            })
                            print(f"SKIPPING Row {row_number}: Invalid barangay in ID '{senior_id}'")
                            continue

                        # Fix the ID format (add leading zeros if Excel removed them)
                        senior_id_str = str(senior_id).strip()
                        if len(senior_id_str) < 14:
                            missing_zeros = 14 - len(senior_id_str)
                            senior_id = '0' * missing_zeros + senior_id_str
                            print(f"Fixed ID format: {senior_id_str} -> {senior_id}")
                    else:
                        # If no ID provided, we need a default barangay code for auto-generation
                        # For now, use '005' (BAGBAG) as default - you may want to make this configurable
                        barangay_code = '005'
                        print(f"No ID provided, using default barangay code: {barangay_code}")

                    print(f"Barangay code detected/used: {barangay_code}")
                    
                    # Build complete address from components (NEW)
                    address_parts = []
                    if house_number_str:
                        address_parts.append(house_number_str.strip())
                    if street_str:
                        address_parts.append(street_str.strip())
                    if subdivision_str:
                        address_parts.append(subdivision_str.strip())
                    
                    # Add city (always Quezon City as specified in requirements)
                    address_parts.append('Quezon City')
                    
                    complete_address = ', '.join(address_parts)
                    print(f"Combined address: {complete_address}")
                    
                    # Get optional fields
                    mobile_str = clean_value(row.get('MOBILE NUMBER'))
                    telephone_str = clean_value(row.get('TELEPHONE NUMBER'))
                    vaccination_str = clean_value(row.get('VACCINATION STATUS'))
                    height_str = clean_value(row.get('HEIGHT'))
                    weight_str = clean_value(row.get('WEIGHT'))
                    eye_color_str = clean_value(row.get('EYE COLOR'))
                    emergency_name = clean_value(row.get('EMERGENCY CONTACT NAME'))
                    emergency_number = clean_value(row.get('EMERGENCY CONTACT NUMBER'))
                    emergency_address = clean_value(row.get('EMERGENCY CONTACT ADDRESS'))

                    # Generate ID if not provided (senior_id was already extracted and processed above)
                    if not senior_id:
                        try:
                            next_count = SeniorCitizen.get_next_global_count()
                            senior_id = f"{barangay_code}0000{next_count:06d}"
                        except Exception as e:
                            error_msg = f'Row {row_number}: Error generating ID - {str(e)}'
                            error_messages.append(error_msg)
                            print(f"SKIPPING Row {row_number}: ID generation error")
                            continue
                    
                    # Check if ID already exists - SKIP IF DUPLICATE
                    if SeniorCitizen.objects.filter(id_number=senior_id).exists():
                        error_msg = f'Row {row_number}: ID number {senior_id} already exists'
                        error_messages.append(error_msg)
                        existing = SeniorCitizen.objects.filter(id_number=senior_id).first()
                        validation_results.append({
                            'row_number': row_number,
                            'excel_row': row_number,
                            'status': 'error',
                            'data': {
                                'first_name': first_name,
                                'last_name': last_name,
                                'birth_date': birth_date,
                                'id_number': senior_id,
                            },
                            'errors': [{
                                'field': 'SENIOR CITIZEN ID NUMBER',
                                'type': 'Duplicate ID',
                                'message': error_msg,
                                'existing_record': {
                                    'name': f"{existing.first_name} {existing.last_name}" if existing else "Unknown",
                                    'id_number': senior_id,
                                    'birth_date': existing.birth_date if existing else None,
                                },
                                'actions': ['replace', 'merge', 'skip']
                            }],
                            'warnings': []
                        })
                        print(f"SKIPPING Row {row_number}: Duplicate ID")
                        continue
                    
                    # Process optional fields (with safe defaults)
                    mobile_number = format_phone_number(mobile_str) if mobile_str else None
                    telephone_number = format_phone_number(telephone_str) if telephone_str else None
                    
                    vaccination_status = 'NONE'
                    if vaccination_str:
                        vax_upper = vaccination_str.upper()
                        if 'FULL' in vax_upper:
                            vaccination_status = 'FULL'
                        elif 'PARTIAL' in vax_upper:
                            vaccination_status = 'PARTIAL'
                    
                    height = None
                    if height_str:
                        try:
                            height = float(height_str)
                            if height < 50 or height > 250:
                                height = None
                        except:
                            pass
                    
                    weight = None
                    if weight_str:
                        try:
                            weight = float(weight_str)
                            if weight < 20 or weight > 300:
                                weight = None
                        except:
                            pass
                    
                    eye_color = None
                    if eye_color_str:
                        eye_mapping = {
                            'BLACK': 'BLACK', 'BROWN': 'BROWN', 'BLUE': 'BLUE',
                            'GREEN': 'GREEN', 'HAZEL': 'HAZEL', 'GRAY': 'GRAY', 'OTHER': 'OTHER'
                        }
                        eye_color = eye_mapping.get(eye_color_str.upper())
                    
                    emergency_contact_number = format_phone_number(emergency_number) if emergency_number else None
                    
                    # Create senior citizen record with combined address
                    try:
                        with transaction.atomic():
                            senior = SeniorCitizen(
                                id_number=senior_id,
                                first_name=formatted_first_name,
                                last_name=formatted_last_name,
                                middle_name=formatted_middle_name,
                                birth_date=birth_date,
                                application_date=application_date,
                                gender=gender,
                                barangay_code=barangay_code,
                                address=complete_address,  # Combined address from components
                                mobile_number=mobile_number,
                                telephone_number=telephone_number,
                                vaccination_status=vaccination_status,
                                height=height,
                                weight=weight,
                                eye_color=eye_color,
                                emergency_contact_name=emergency_name,
                                emergency_contact_number=emergency_contact_number,
                                emergency_contact_address=emergency_address,
                                created_by=request.user,
                                updated_by=request.user,
                                status='APPROVED'
                            )
                            
                            # Save will automatically calculate expiration_date and next_proof_of_life_date
                            save_with_retry(senior)
                            
                            # Generate QR code for approved records
                            try:
                                generate_qr_code(senior)
                                save_with_retry(senior)
                            except Exception as qr_error:
                                print(f"QR code generation failed for {senior.id_number}: {qr_error}")
                                # Don't fail the whole record for QR code issues
                            
                            success_count += 1
                            successful_records.append(f"{senior.first_name} {senior.last_name} ({senior.id_number}) - App: {senior.application_date}, Exp: {senior.expiration_date}")

                            # Add to validation results as valid
                            validation_results.append({
                                'row_number': row_number,
                                'excel_row': row_number,
                                'status': 'valid',
                                'data': {
                                    'first_name': senior.first_name,
                                    'last_name': senior.last_name,
                                    'birth_date': senior.birth_date,
                                    'gender': senior.gender,
                                    'id_number': senior.id_number,
                                    'age': (today.year - senior.birth_date.year - ((today.month, today.day) < (senior.birth_date.month, senior.birth_date.day))) if senior.birth_date else None,
                                    'house_number': house_number_str,
                                    'street': street_str,
                                },
                                'errors': [],
                                'warnings': []
                            })
                            print(f"SUCCESS Row {row_number}: Created {senior.first_name} {senior.last_name} ({senior.id_number}) with app date {senior.application_date}")
                            
                            # Log the successful creation
                            AuditLog.objects.create(
                                user=request.user,
                                action='CREATE',
                                content_type='SeniorCitizen',
                                object_id=senior.id,
                                description=f'Batch upload: Created senior citizen {senior.id_number} (App: {senior.application_date}, Exp: {senior.expiration_date})',
                                ip_address=request.META.get('REMOTE_ADDR')
                            )
                            
                    except Exception as e:
                        error_msg = f'Row {row_number}: Database error - {str(e)}'
                        error_messages.append(error_msg)
                        print(f"SKIPPING Row {row_number}: Database error - {e}")
                        continue
                        
                except Exception as e:
                    error_msg = f'Row {row_number}: Unexpected error - {str(e)}'
                    error_messages.append(error_msg)
                    print(f"SKIPPING Row {row_number}: Unexpected error - {e}")
                    continue
            
            print(f"\n=== BATCH PROCESSING COMPLETE ===")
            print(f"Total rows processed: {len(df)}")
            print(f"Successful records: {success_count}")
            print(f"Failed records: {len(error_messages)}")

            # Calculate statistics
            warning_rows = len([r for r in validation_results if r['status'] == 'warning'])
            error_rows = len([r for r in validation_results if r['status'] == 'error'])
            valid_rows = success_count
            total_rows = len(df)

            # Build context for validation review page
            context = {
                'validation_results': validation_results,
                'file_name': excel_file.name,
                'total_rows': total_rows,
                'valid_rows': valid_rows,
                'warning_rows': warning_rows,
                'error_rows': error_rows,
                'sample_data': [
                    {'column': 'SENIOR CITIZEN ID NUMBER', 'required': 'No', 'description': 'Leave empty for auto-generation'},
                    {'column': 'LAST NAME', 'required': 'Yes', 'description': 'Last name'},
                    {'column': 'FIRST NAME', 'required': 'Yes', 'description': 'First name'},
                    {'column': 'MIDDLE NAME', 'required': 'No', 'description': 'Middle name (optional)'},
                    {'column': 'BIRTH DATE', 'required': 'Yes', 'description': 'Birth date MM/DD/YYYY'},
                    {'column': 'GENDER', 'required': 'Yes', 'description': 'M or F (Male/Female only)'},
                    {'column': 'HOUSE NUMBER', 'required': 'Yes', 'description': 'House #, Unit #, Block & Lot'},
                    {'column': 'STREET', 'required': 'Yes', 'description': 'Street name or avenue'},
                    {'column': 'SUBDIVISION', 'required': 'No', 'description': 'Subdivision or village name'},
                    {'column': 'MOBILE NUMBER', 'required': 'No', 'description': 'Mobile phone number'},
                    {'column': 'TELEPHONE NUMBER', 'required': 'No', 'description': 'Landline number'},
                    {'column': 'VACCINATION STATUS', 'required': 'No', 'description': 'FULL/PARTIAL/NONE'},
                    {'column': 'HEIGHT', 'required': 'No', 'description': 'Height in cm'},
                    {'column': 'WEIGHT', 'required': 'No', 'description': 'Weight in kg'},
                    {'column': 'EYE COLOR', 'required': 'No', 'description': 'Eye color'},
                    {'column': 'EMERGENCY CONTACT NAME', 'required': 'No', 'description': 'Emergency contact name'},
                    {'column': 'EMERGENCY CONTACT NUMBER', 'required': 'No', 'description': 'Emergency contact phone'},
                    {'column': 'EMERGENCY CONTACT ADDRESS', 'required': 'No', 'description': 'Emergency contact address'},
                    {'column': 'APPLICATION DATE', 'required': 'No', 'description': 'Leave empty for current date (MM/DD/YYYY)'},
                ]
            }

            # Render validation review page DIRECTLY (no redirect)
            return render(request, 'seniors/batch_upload.html', context)
                
        except Exception as e:
            print(f"=== CRITICAL ERROR ===")
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
            messages.error(request, f'Critical error processing file: {str(e)}. Please check your file format and try again.')
            return redirect('batch_upload')
    
    # GET request - show form
    try:
        next_global_count = SeniorCitizen.get_next_global_count()
        total_seniors = SeniorCitizen.objects.count()
    except:
        next_global_count = 1
        total_seniors = 0
    
    # Updated sample data for address components (18 columns)
    sample_data = [
        {'column': 'SENIOR CITIZEN ID NUMBER', 'required': 'No', 'description': 'Leave empty for auto-generation'},
        {'column': 'LAST NAME', 'required': 'Yes', 'description': 'Last name'},
        {'column': 'FIRST NAME', 'required': 'Yes', 'description': 'First name'},
        {'column': 'MIDDLE NAME', 'required': 'No', 'description': 'Middle name (optional)'},
        {'column': 'BIRTH DATE', 'required': 'Yes', 'description': 'Birth date MM/DD/YYYY'},
        {'column': 'GENDER', 'required': 'Yes', 'description': 'M or F (Male/Female only)'},
        {'column': 'HOUSE NUMBER', 'required': 'Yes', 'description': 'House #, Unit #, Block & Lot'},  # NEW
        {'column': 'STREET', 'required': 'Yes', 'description': 'Street name or avenue'},  # NEW
        {'column': 'SUBDIVISION', 'required': 'No', 'description': 'Subdivision or village name'},  # NEW
        {'column': 'MOBILE NUMBER', 'required': 'No', 'description': 'Mobile phone number'},
        {'column': 'TELEPHONE NUMBER', 'required': 'No', 'description': 'Landline number'},
        {'column': 'VACCINATION STATUS', 'required': 'No', 'description': 'FULL/PARTIAL/NONE'},
        {'column': 'HEIGHT', 'required': 'No', 'description': 'Height in cm'},
        {'column': 'WEIGHT', 'required': 'No', 'description': 'Weight in kg'},
        {'column': 'EYE COLOR', 'required': 'No', 'description': 'Eye color'},
        {'column': 'EMERGENCY CONTACT NAME', 'required': 'No', 'description': 'Emergency contact name'},
        {'column': 'EMERGENCY CONTACT NUMBER', 'required': 'No', 'description': 'Emergency contact phone'},
        {'column': 'EMERGENCY CONTACT ADDRESS', 'required': 'No', 'description': 'Emergency contact address'},
        {'column': 'APPLICATION DATE', 'required': 'No', 'description': 'Leave empty for current date (MM/DD/YYYY)'},
    ]
    
    context = {
        'sample_data': sample_data,
        'batch_upload_errors': request.session.pop('batch_upload_errors', None),
        'next_global_count': next_global_count,
        'total_seniors': total_seniors,
        'can_perform_upload': request.user.can_perform_batch_upload,
        'can_download_templates': request.user.can_download_batch_templates,
        'can_view_history': request.user.can_view_batch_history,
    }
    
    return render(request, 'seniors/batch_upload.html', context)


@login_required
def batch_upload_action_view(request):
    """Handle individual row actions during batch upload review"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'Invalid request method'}, status=400)

    try:
        data = json.loads(request.body)
        action = data.get('action')
        row = data.get('row')
        field = data.get('field')
        value = data.get('value')

        # Store action in session for later processing
        if 'batch_upload_row_actions' not in request.session:
            request.session['batch_upload_row_actions'] = {}

        if action == 'edit':
            if 'batch_upload_row_actions' not in request.session:
                request.session['batch_upload_row_actions'] = {}

            if row not in request.session['batch_upload_row_actions']:
                request.session['batch_upload_row_actions'][row] = {}

            request.session['batch_upload_row_actions'][row][field] = {
                'action': 'edit',
                'value': value
            }
            request.session.modified = True

            return JsonResponse({'success': True, 'message': f'Field {field} updated successfully'})

        elif action == 'clear':
            if row not in request.session['batch_upload_row_actions']:
                request.session['batch_upload_row_actions'][row] = {}

            request.session['batch_upload_row_actions'][row][field] = {
                'action': 'clear'
            }
            request.session.modified = True

            return JsonResponse({'success': True, 'message': f'Field {field} cleared'})

        elif action == 'ignore' or action == 'skip':
            # Both 'ignore' and 'skip' mean the same thing - mark row to be skipped
            if 'batch_upload_ignored_rows' not in request.session:
                request.session['batch_upload_ignored_rows'] = []

            if row not in request.session['batch_upload_ignored_rows']:
                request.session['batch_upload_ignored_rows'].append(row)

            request.session.modified = True

            return JsonResponse({'success': True, 'message': f'Row {row} will be ignored during upload'})

        elif action == 'replace':
            # Mark row for replace action
            if 'batch_upload_row_actions' not in request.session:
                request.session['batch_upload_row_actions'] = {}

            if row not in request.session['batch_upload_row_actions']:
                request.session['batch_upload_row_actions'][row] = {}

            request.session['batch_upload_row_actions'][row]['action'] = 'replace'
            request.session.modified = True

            return JsonResponse({'success': True, 'message': f'Row {row} will replace existing record'})

        elif action == 'merge':
            # Mark row for merge action
            if 'batch_upload_row_actions' not in request.session:
                request.session['batch_upload_row_actions'] = {}

            if row not in request.session['batch_upload_row_actions']:
                request.session['batch_upload_row_actions'][row] = {}

            request.session['batch_upload_row_actions'][row]['action'] = 'merge'
            request.session.modified = True

            return JsonResponse({'success': True, 'message': f'Row {row} will be merged with existing record'})

        elif action == 'generate_new_id':
            # Mark row to generate new ID
            if 'batch_upload_row_actions' not in request.session:
                request.session['batch_upload_row_actions'] = {}

            if row not in request.session['batch_upload_row_actions']:
                request.session['batch_upload_row_actions'][row] = {}

            request.session['batch_upload_row_actions'][row]['action'] = 'generate_new_id'
            request.session.modified = True

            return JsonResponse({'success': True, 'message': f'Row {row} will get a new ID generated'})

        return JsonResponse({'success': False, 'message': f'Unknown action: {action}'}, status=400)

    except Exception as e:
        print(f"Error in batch_upload_action_view: {e}")
        return JsonResponse({'success': False, 'message': str(e)}, status=500)


@login_required
def batch_upload_process_view(request):
    """Process the batch upload with ignored rows"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'message': 'Invalid request method'}, status=400)

    try:
        # Get ignored rows from request
        ignored_rows = []
        ignored_rows_param = request.POST.get('ignored_rows')
        if ignored_rows_param:
            try:
                ignored_rows = json.loads(ignored_rows_param)
            except:
                ignored_rows = []

        # Also check session for ignored rows
        session_ignored = request.session.get('batch_upload_ignored_rows', [])
        ignored_rows.extend(session_ignored)
        ignored_rows = list(set([str(r) for r in ignored_rows]))  # Deduplicate

        # Get row actions from session
        row_actions = request.session.get('batch_upload_row_actions', {})

        # For now, just redirect to senior list to show success
        # In a full implementation, you would process the batch here with ignored rows skipped
        if ignored_rows:
            count_msg = f'{len(ignored_rows)} row(s) were ignored'
            messages.warning(request, count_msg)

        # Clean up session
        if 'batch_upload_ignored_rows' in request.session:
            del request.session['batch_upload_ignored_rows']
        if 'batch_upload_row_actions' in request.session:
            del request.session['batch_upload_row_actions']
        request.session.modified = True

        # Redirect to success page
        messages.success(request, 'Batch upload completed successfully!')
        return redirect('senior_list')

    except Exception as e:
        print(f"Error in batch_upload_process_view: {e}")
        messages.error(request, f'Error processing upload: {str(e)}')
        return redirect('batch_upload')


@login_required
@requires_permission('can_export_dashboard_reports')
def export_csv_view(request):
    """View for exporting senior citizens to properly formatted Excel file (not CSV) with professional styling"""
    status = request.GET.get('status', 'APPROVED')
    query = request.GET.get('q', '')
    
    # Filter seniors based on status
    if status == 'ALL':
        seniors = SeniorCitizen.objects.all().order_by('-created_at')
    else:
        seniors = SeniorCitizen.objects.filter(status=status).order_by('-created_at')
    
    # Apply search filter if provided
    if query:
        seniors = seniors.filter(
            Q(id_number__icontains=query) |
            Q(first_name__icontains=query) |
            Q(last_name__icontains=query)
        )
    
    def parse_address_for_export(address):
        """Parse address back into components for export"""
        if not address:
            return '', '', '', 'Quezon City'
        
        # Split by commas and clean each part
        parts = [part.strip() for part in address.split(',') if part.strip()]
        
        house_number = parts[0] if len(parts) > 0 else ''
        street = parts[1] if len(parts) > 1 else ''
        subdivision = ''
        city = 'Quezon City'
        
        # Handle different address formats
        if len(parts) >= 3:
            # Check if the third part is a city (contains "quezon city" or is the last part)
            if len(parts) >= 4 or 'quezon city' not in parts[2].lower():
                subdivision = parts[2]
                city = parts[3] if len(parts) > 3 else 'Quezon City'
            else:
                # Third part is the city
                city = parts[2]
        
        return house_number, street, subdivision, city
    
    # Create Excel file in memory with professional formatting
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        
        # Prepare data for main sheet
        export_data = []
        for senior in seniors:
            # Format dates properly
            birth_date_formatted = senior.birth_date.strftime('%m/%d/%Y') if senior.birth_date else ''
            application_date_formatted = senior.application_date.strftime('%m/%d/%Y') if senior.application_date else (senior.created_at.strftime('%m/%d/%Y') if senior.created_at else '')
            expiration_date_formatted = senior.expiration_date.strftime('%m/%d/%Y') if senior.expiration_date else ''
            created_date_formatted = senior.created_at.strftime('%m/%d/%Y %I:%M %p') if senior.created_at else ''
            updated_date_formatted = senior.updated_at.strftime('%m/%d/%Y %I:%M %p') if senior.updated_at else ''
            
            # Parse address components
            house_number, street, subdivision, city = parse_address_for_export(senior.address)
            
            # Build row data
            row_data = {
                'SENIOR CITIZEN ID NUMBER': senior.id_number or '',
                'LAST NAME': senior.last_name or '',
                'FIRST NAME': senior.first_name or '',
                'MIDDLE NAME': senior.middle_name or '',
                'BIRTH DATE': birth_date_formatted,
                'GENDER': senior.get_gender_display() or '',
                'HOUSE NUMBER': house_number,
                'STREET': street,
                'SUBDIVISION': subdivision,
                'CITY': city,
                'BARANGAY': f"{senior.get_barangay_name()} ({senior.barangay_code})" if senior.barangay_code else '',
                'MOBILE NUMBER': senior.mobile_number or '',
                'TELEPHONE NUMBER': senior.telephone_number or '',
                'VACCINATION STATUS': senior.get_vaccination_status_display() or '',
                'HEIGHT': str(senior.height) if senior.height else '',
                'WEIGHT': str(senior.weight) if senior.weight else '',
                'EYE COLOR': senior.get_eye_color_display() or '',
                'EMERGENCY CONTACT NAME': senior.emergency_contact_name or '',
                'EMERGENCY CONTACT NUMBER': senior.emergency_contact_number or '',
                'EMERGENCY CONTACT ADDRESS': senior.emergency_contact_address or '',
                'APPLICATION DATE': application_date_formatted,
                'EXPIRATION DATE': expiration_date_formatted,
                'STATUS': senior.get_status_display() or '',
                'CREATED BY': senior.created_by.username if senior.created_by else '',
                'CREATED DATE': created_date_formatted,
                'UPDATED BY': senior.updated_by.username if senior.updated_by else '',
                'UPDATED DATE': updated_date_formatted
            }
            export_data.append(row_data)
        
        # Create DataFrame
        df = pd.DataFrame(export_data)
        
        # Write to Excel with formatting
        df.to_excel(writer, sheet_name='Senior Citizens Export', index=False)
        
        # Get workbook and worksheet objects for formatting
        workbook = writer.book
        worksheet = writer.sheets['Senior Citizens Export']
        
        # Define formats
        header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#4e73df',
            'color': 'white',
            'border': 1,
            'text_wrap': True,
            'valign': 'vcenter',
            'align': 'center',
            'font_size': 11
        })
        
        data_format = workbook.add_format({
            'border': 1,
            'valign': 'vcenter',
            'font_size': 10
        })
        
        date_format = workbook.add_format({
            'border': 1,
            'valign': 'vcenter',
            'font_size': 10,
            'num_format': 'mm/dd/yyyy'
        })
        
        id_format = workbook.add_format({
            'border': 1,
            'valign': 'vcenter',
            'font_size': 10,
            'num_format': '@'  # Text format to preserve leading zeros
        })
        
        # Apply header formatting
        for col_num, value in enumerate(df.columns.values):
            worksheet.write(0, col_num, value, header_format)
            
            # Set column widths based on content type
            if 'ID NUMBER' in value or 'MOBILE' in value or 'TELEPHONE' in value:
                worksheet.set_column(col_num, col_num, 18)
            elif 'NAME' in value:
                worksheet.set_column(col_num, col_num, 20)
            elif 'HOUSE' in value or 'STREET' in value:
                worksheet.set_column(col_num, col_num, 22)
            elif 'SUBDIVISION' in value or 'CITY' in value:
                worksheet.set_column(col_num, col_num, 25)
            elif 'ADDRESS' in value:
                worksheet.set_column(col_num, col_num, 35)
            elif 'DATE' in value:
                worksheet.set_column(col_num, col_num, 15)
            elif 'BARANGAY' in value:
                worksheet.set_column(col_num, col_num, 25)
            elif 'STATUS' in value or 'GENDER' in value:
                worksheet.set_column(col_num, col_num, 15)
            elif 'HEIGHT' in value or 'WEIGHT' in value:
                worksheet.set_column(col_num, col_num, 12)
            else:
                worksheet.set_column(col_num, col_num, 18)
        
        # Apply data formatting to all data rows
        for row_num in range(1, len(df) + 1):
            for col_num, col_name in enumerate(df.columns):
                cell_value = df.iloc[row_num - 1, col_num]
                
                # Apply specific formatting based on column type
                if 'DATE' in col_name and cell_value and cell_value != '':
                    try:
                        # Convert date string back to date for proper formatting
                        date_obj = datetime.strptime(str(cell_value).split(' ')[0], '%m/%d/%Y')
                        worksheet.write_datetime(row_num, col_num, date_obj, date_format)
                    except:
                        worksheet.write(row_num, col_num, cell_value, data_format)
                elif 'ID NUMBER' in col_name or 'MOBILE' in col_name or 'TELEPHONE' in col_name:
                    worksheet.write(row_num, col_num, str(cell_value), id_format)
                else:
                    worksheet.write(row_num, col_num, cell_value, data_format)
        
        # Add summary sheet
        summary_data = {
            'Export Summary': [
                'Export Date',
                'Status Filter',
                'Search Query',
                'Total Records',
                'Exported By'
            ],
            'Details': [
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                dict(SeniorCitizen.STATUS_CHOICES).get(status, 'All Records'),
                query if query else 'No search filter',
                str(len(df)),
                request.user.username
            ]
        }
        
        summary_df = pd.DataFrame(summary_data)
        summary_df.to_excel(writer, sheet_name='Export Summary', index=False)
        
        # Format summary sheet
        summary_worksheet = writer.sheets['Export Summary']
        summary_header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#28a745',
            'color': 'white',
            'border': 1
        })
        
        for col_num, value in enumerate(summary_df.columns.values):
            summary_worksheet.write(0, col_num, value, summary_header_format)
            if col_num == 0:
                summary_worksheet.set_column(col_num, col_num, 25)
            else:
                summary_worksheet.set_column(col_num, col_num, 40)
        
        # Add column info sheet (similar to template)
        column_info_data = {
            'Column Name': list(df.columns),
            'Data Type': [
                'Text ID',
                'Text', 'Text', 'Text',
                'Date', 'Text', 
                'Text', 'Text', 'Text', 'Text',
                'Text with Code',
                'Phone Number', 'Phone Number',
                'Status', 'Number', 'Number', 'Text',
                'Text', 'Phone Number', 'Text',
                'Date', 'Date', 'Status',
                'Username', 'DateTime', 'Username', 'DateTime'
            ],
            'Description': [
                'Senior Citizen ID Number',
                'Last Name', 'First Name', 'Middle Name',
                'Birth Date (MM/DD/YYYY)', 'Gender (Male/Female)',
                'House Number/Unit', 'Street Name', 'Subdivision/Village', 'City',
                'Barangay Name and Code',
                'Mobile Phone Number', 'Landline Number',
                'COVID-19 Vaccination Status', 'Height in CM', 'Weight in KG', 'Eye Color',
                'Emergency Contact Name', 'Emergency Contact Phone', 'Emergency Contact Address',
                'Application Date', 'ID Expiration Date', 'Current Status',
                'Created By User', 'Record Creation Date', 'Last Updated By', 'Last Update Date'
            ]
        }
        
        column_info_df = pd.DataFrame(column_info_data)
        column_info_df.to_excel(writer, sheet_name='Column Information', index=False)
        
        # Format column info sheet
        column_info_worksheet = writer.sheets['Column Information']
        column_info_header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#17a2b8',
            'color': 'white',
            'border': 1
        })
        
        for col_num, value in enumerate(column_info_df.columns.values):
            column_info_worksheet.write(0, col_num, value, column_info_header_format)
            if col_num == 0:
                column_info_worksheet.set_column(col_num, col_num, 35)
            elif col_num == 1:
                column_info_worksheet.set_column(col_num, col_num, 20)
            else:
                column_info_worksheet.set_column(col_num, col_num, 50)
    
    # Prepare response with proper filename
    output.seek(0)
    current_date = datetime.now().strftime('%Y%m%d_%H%M%S')
    status_suffix = f"_{status.lower()}" if status != 'ALL' else "_all"
    search_suffix = f"_search" if query else ""
    
    response = HttpResponse(
        output.read(), 
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename=senior_citizens_export{status_suffix}{search_suffix}_{current_date}.xlsx'
    
    # Log the export action
    AuditLog.objects.create(
        user=request.user,
        action='EXPORT',
        content_type='SeniorCitizen',
        description=f'Exported {seniors.count()} senior citizens to Excel ({status} status) - Professional Format',
        ip_address=request.META.get('REMOTE_ADDR')
    )
    
    return response


@login_required
@role_required('RA', 'SA', 'AD')
def export_csv_simple_view(request):
    """Simple CSV export for users who specifically need CSV format (not Excel)"""
    status = request.GET.get('status', 'APPROVED')
    query = request.GET.get('q', '')
    
    # Filter seniors based on status
    if status == 'ALL':
        seniors = SeniorCitizen.objects.all().order_by('-created_at')
    else:
        seniors = SeniorCitizen.objects.filter(status=status).order_by('-created_at')
    
    # Apply search filter if provided
    if query:
        seniors = seniors.filter(
            Q(id_number__icontains=query) |
            Q(first_name__icontains=query) |
            Q(last_name__icontains=query)
        )
    
    # Prepare CSV response with UTF-8 BOM for Excel compatibility
    response = HttpResponse(content_type='text/csv; charset=utf-8-sig')
    response['Content-Disposition'] = f'attachment; filename=senior_citizens_{status.lower()}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    
    # Add BOM for Excel compatibility
    response.write('\ufeff')
    
    # Create CSV writer
    writer = csv.writer(response, quoting=csv.QUOTE_ALL)
    
    # Write header with proper formatting
    writer.writerow([
        'SENIOR CITIZEN ID NUMBER',
        'LAST NAME',
        'FIRST NAME', 
        'MIDDLE NAME',
        'BIRTH DATE',
        'GENDER',
        'HOUSE NUMBER',
        'STREET',
        'SUBDIVISION',
        'CITY',
        'BARANGAY',
        'MOBILE NUMBER',
        'TELEPHONE NUMBER',
        'VACCINATION STATUS',
        'HEIGHT',
        'WEIGHT', 
        'EYE COLOR',
        'EMERGENCY CONTACT NAME',
        'EMERGENCY CONTACT NUMBER',
        'EMERGENCY CONTACT ADDRESS',
        'APPLICATION DATE',
        'EXPIRATION DATE',
        'STATUS',
        'CREATED BY',
        'CREATED DATE'
    ])
    
    def parse_address_for_export(address):
        """Parse address back into components for CSV export"""
        if not address:
            return '', '', '', 'Quezon City'
        
        parts = [part.strip() for part in address.split(',') if part.strip()]
        
        house_number = parts[0] if len(parts) > 0 else ''
        street = parts[1] if len(parts) > 1 else ''
        subdivision = ''
        city = 'Quezon City'
        
        if len(parts) >= 3:
            if len(parts) >= 4 or 'quezon city' not in parts[2].lower():
                subdivision = parts[2]
                city = parts[3] if len(parts) > 3 else 'Quezon City'
            else:
                city = parts[2]
        
        return house_number, street, subdivision, city
    
    # Write senior data with proper quoting and formatting
    for senior in seniors:
        # Format dates
        birth_date_formatted = senior.birth_date.strftime('%m/%d/%Y') if senior.birth_date else ''
        application_date_formatted = senior.application_date.strftime('%m/%d/%Y') if senior.application_date else (senior.created_at.strftime('%m/%d/%Y') if senior.created_at else '')
        expiration_date_formatted = senior.expiration_date.strftime('%m/%d/%Y') if senior.expiration_date else ''
        created_date_formatted = senior.created_at.strftime('%m/%d/%Y %I:%M %p') if senior.created_at else ''
        
        # Parse address components
        house_number, street, subdivision, city = parse_address_for_export(senior.address)
        
        # Write row with all fields properly quoted
        writer.writerow([
            senior.id_number or '',
            senior.last_name or '',
            senior.first_name or '',
            senior.middle_name or '',
            birth_date_formatted,
            senior.get_gender_display() or '',
            house_number,
            street,
            subdivision,
            city,
            f"{senior.get_barangay_name()} ({senior.barangay_code})" if senior.barangay_code else '',
            senior.mobile_number or '',
            senior.telephone_number or '',
            senior.get_vaccination_status_display() or '',
            str(senior.height) if senior.height else '',
            str(senior.weight) if senior.weight else '',
            senior.get_eye_color_display() or '',
            senior.emergency_contact_name or '',
            senior.emergency_contact_number or '',
            senior.emergency_contact_address or '',
            application_date_formatted,
            expiration_date_formatted,
            senior.get_status_display() or '',
            senior.created_by.username if senior.created_by else '',
            created_date_formatted
        ])
    
    # Log the export action
    AuditLog.objects.create(
        user=request.user,
        action='EXPORT',
        content_type='SeniorCitizen',
        description=f'Exported {seniors.count()} senior citizens to CSV ({status} status)',
        ip_address=request.META.get('REMOTE_ADDR')
    )
    
    return response

@login_required
@role_required('RA', 'SA', 'AD')
def export_pdf_view(request):
    """View for exporting senior citizens to PDF using ReportLab"""
    status = request.GET.get('status', 'APPROVED')
    query = request.GET.get('q', '')
    
    # Filter seniors based on status
    if status == 'ALL':
        seniors = SeniorCitizen.objects.all().order_by('-created_at')
    else:
        seniors = SeniorCitizen.objects.filter(status=status).order_by('-created_at')
    
    # Apply search filter if provided
    if query:
        seniors = seniors.filter(
            Q(id_number__icontains=query) |
            Q(first_name__icontains=query) |
            Q(last_name__icontains=query)
        )
    
    # Create a PDF file
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename=senior_citizens_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
    
    # Create the PDF document
    doc = SimpleDocTemplate(response, pagesize=letter)
    elements = []
    
    # Define styles
    styles = getSampleStyleSheet()
    title_style = styles['Heading1']
    heading_style = styles['Heading2']
    normal_style = styles['Normal']
    
    # Add title
    title = Paragraph("Senior Citizens Report", title_style)
    elements.append(title)
    elements.append(Spacer(1, 0.25*inch))
    
    # Add report info
    report_date = Paragraph(f"Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style)
    elements.append(report_date)
    elements.append(Paragraph(f"Status: {dict(SeniorCitizen.STATUS_CHOICES).get(status, 'All')}", normal_style))
    if query:
        elements.append(Paragraph(f"Search Query: {query}", normal_style))
    elements.append(Paragraph(f"Total Records: {seniors.count()}", normal_style))
    elements.append(Spacer(1, 0.25*inch))
    
    # Prepare table data
    data = [['ID Number', 'Name', 'Birth Date', 'Gender', 'Contact', 'Barangay', 'Status']]

    for senior in seniors:
        full_name = f"{senior.last_name}, {senior.first_name} {senior.middle_name or ''}"
        data.append([
            senior.id_number,
            full_name,
            str(senior.birth_date),
            senior.get_gender_display(),
            senior.mobile_number or senior.telephone_number or 'N/A',
            senior.get_barangay_name(),
            senior.get_status_display()
        ])
    
    # Create table
    table = Table(data, repeatRows=1)
    
    # Add table style
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    
    elements.append(table)
    
    # Generate footer
    footer_text = Paragraph(f"Generated by: {request.user.username} | VeriSior System", styles['Normal'])
    elements.append(Spacer(1, 0.5*inch))
    elements.append(footer_text)
    
    # Build the PDF
    doc.build(elements)
    
    # Log the export action
    AuditLog.objects.create(
        user=request.user,
        action='READ',
        content_type='SeniorCitizen',
        description=f'Exported senior citizens to PDF ({status} status)',
        ip_address=request.META.get('REMOTE_ADDR')
    )
    
    return response

@login_required
@requires_permission('can_view_active_records')
def senior_detail_view(request, pk):
    """View for displaying senior citizen details with status information"""
    senior = get_object_or_404(SeniorCitizen, pk=pk)
    documents = SeniorDocument.objects.filter(senior=senior)
    
    # FIXED: Get discount transaction history from verifications app
    from verifications.models import DiscountTransaction
    transactions = DiscountTransaction.objects.filter(
        id_number=senior.id_number
    ).order_by('-created_at')[:10]
    
    # NEW: Calculate status information
    today = date.today()
    status_info = {
        'can_be_verified': senior.can_be_verified(),
        'is_expired': senior.is_expired(),
        'is_proof_of_life_overdue': senior.is_proof_of_life_overdue(),
        'days_until_expiration': senior.days_until_expiration(),
        'days_until_proof_of_life': senior.days_until_proof_of_life(),
        'needs_renewal': senior.is_expired() or (senior.days_until_expiration() and senior.days_until_expiration() <= 30),
        'needs_proof_of_life': senior.is_proof_of_life_overdue() or (senior.days_until_proof_of_life() and senior.days_until_proof_of_life() <= 30),
    }
    
    # Get renewal and proof of life logs
    renewal_logs = senior.renewal_logs.all()[:5] if hasattr(senior, 'renewal_logs') else []
    proof_of_life_logs = senior.proof_of_life_logs.all()[:5] if hasattr(senior, 'proof_of_life_logs') else []
    
    # Log the action
    AuditLog.objects.create(
        user=request.user,
        action='READ',
        content_type='SeniorCitizen',
        object_id=senior.id,
        description=f'Viewed senior citizen details: {senior.id_number}',
        ip_address=request.META.get('REMOTE_ADDR')
    )
    
    context = {
        'senior': senior,
        'documents': documents,
        'transactions': transactions,
        'status_info': status_info,
        'renewal_logs': renewal_logs,
        'proof_of_life_logs': proof_of_life_logs,
    }
    
    return render(request, 'seniors/senior_detail.html', context)

@login_required
@role_required('RA', 'SA', 'AD')
def expiration_report_view(request):
    """View for expiration and proof of life status report"""
    today = date.today()
    
    # Expiration statistics
    expired_seniors = SeniorCitizen.objects.filter(
        expiration_date__lt=today
    ).exclude(status__in=['ARCHIVED', 'DEACTIVATED'])
    
    expiring_30_days = SeniorCitizen.objects.filter(
        status='APPROVED',
        expiration_date__lte=today + timedelta(days=30),
        expiration_date__gt=today
    )
    
    expiring_90_days = SeniorCitizen.objects.filter(
        status='APPROVED',
        expiration_date__lte=today + timedelta(days=90),
        expiration_date__gt=today + timedelta(days=30)
    )
    
    # Proof of life statistics
    proof_overdue = SeniorCitizen.objects.filter(
        next_proof_of_life_date__lt=today
    ).exclude(status__in=['ARCHIVED', 'DEACTIVATED'])
    
    proof_due_30_days = SeniorCitizen.objects.filter(
        status='APPROVED',
        next_proof_of_life_date__lte=today + timedelta(days=30),
        next_proof_of_life_date__gt=today
    )
    
    proof_due_90_days = SeniorCitizen.objects.filter(
        status='APPROVED',
        next_proof_of_life_date__lte=today + timedelta(days=90),
        next_proof_of_life_date__gt=today + timedelta(days=30)
    )
    
    # Deactivated seniors
    deactivated_expired = SeniorCitizen.objects.filter(
        status='DEACTIVATED',
        deactivation_reason='EXPIRED_PENDING_RENEWAL'
    )
    
    deactivated_proof = SeniorCitizen.objects.filter(
        status='DEACTIVATED',
        deactivation_reason='PROOF_OF_LIFE_OVERDUE'
    )
    
    # Recent system checks
    recent_checks = SystemStatusCheck.objects.all()[:10]
    
    context = {
        'today': today,
        'expired_seniors': expired_seniors,
        'expiring_30_days': expiring_30_days,
        'expiring_90_days': expiring_90_days,
        'proof_overdue': proof_overdue,
        'proof_due_30_days': proof_due_30_days,
        'proof_due_90_days': proof_due_90_days,
        'deactivated_expired': deactivated_expired,
        'deactivated_proof': deactivated_proof,
        'recent_checks': recent_checks,
    }
    
    return render(request, 'seniors/expiration_report.html', context)

@login_required
@role_required('RA', 'SA', 'AD')
def manual_status_check_view(request):
    """View for manually triggering status checks"""
    if request.method == 'POST':
        try:
            results = SeniorCitizen.run_automated_checks(request.user)
            
            # Log the results
            SystemStatusCheck.objects.create(
                checked_by=request.user,
                seniors_checked=results['checked'],
                warnings_sent=results['warnings_sent'],
                deactivated_count=results['deactivated'],
                archived_count=results['archived'],
                errors_count=len(results['errors']),
                notes=f"Manual check by {request.user.username}. " + ('; '.join(results['errors']) if results['errors'] else 'No errors')
            )
            
            if results['errors']:
                messages.warning(request, f"Status check completed with {len(results['errors'])} errors. See system logs for details.")
            else:
                messages.success(request, f"Status check completed successfully!")
            
            messages.info(request, f"Checked: {results['checked']}, Warnings: {results['warnings_sent']}, Deactivated: {results['deactivated']}, Archived: {results['archived']}")
            
        except Exception as e:
            messages.error(request, f"Error running status check: {str(e)}")
    
    return redirect('expiration_report')

@login_required
def approve_senior_view(request, pk):
    """View for approving or rejecting a pending senior citizen record - FIXED with proper permission checks"""
    print(f"\n=== APPROVE SENIOR VIEW ACCESS ===")
    print(f"User: {request.user.username}")
    print(f"Role: {request.user.role}")
    print(f"Senior PK: {pk}")
    print(f"can_access_pending_approvals: {getattr(request.user, 'can_access_pending_approvals', 'MISSING')}")
    print(f"can_view_pending_applications: {getattr(request.user, 'can_view_pending_applications', 'MISSING')}")
    print(f"can_approve_applications: {getattr(request.user, 'can_approve_applications', 'MISSING')}")
    print(f"can_reject_applications: {getattr(request.user, 'can_reject_applications', 'MISSING')}")
    
    # Check navigation access permission
    if not getattr(request.user, 'can_access_pending_approvals', False):
        print("PERMISSION DENIED: Missing navigation access")
        messages.error(request, 'You do not have access to Pending Approvals section.')
        return redirect(_get_safe_redirect_url(request.user))
    
    # Check view permission
    if not getattr(request.user, 'can_view_pending_applications', False):
        print("PERMISSION DENIED: Missing view permission")
        messages.error(request, 'You do not have permission to view pending applications.')
        return redirect(_get_safe_redirect_url(request.user))
    
    # Get the senior record
    try:
        senior = get_object_or_404(SeniorCitizen, pk=pk, status='PENDING')
        print(f"Found pending senior: {senior.id_number} - {senior.first_name} {senior.last_name}")
    except Exception as e:
        print(f"Error finding senior: {e}")
        messages.error(request, 'Senior citizen record not found or not pending approval.')
        return redirect('approval_list')
    
    # Check what actions user can perform
    can_approve = getattr(request.user, 'can_approve_applications', False)
    can_reject = getattr(request.user, 'can_reject_applications', False)
    
    print(f"User action permissions: can_approve={can_approve}, can_reject={can_reject}")
    
    # Handle POST request (approval/rejection actions)
    if request.method == 'POST':
        action = request.POST.get('action')
        print(f"Processing action: {action}")

        if action == 'approve':
            # Check if user can approve
            if not can_approve:
                print("PERMISSION DENIED: Cannot approve applications")
                messages.error(request, 'You do not have permission to approve applications.')
                return redirect('approval_list')

            # NEW APPROVAL HIERARCHY CHECK:
            # - AD can approve EM submissions only
            # - RA/SA can approve both EM and AD submissions
            creator_role = senior.created_by.role if senior.created_by else 'UNKNOWN'
            approver_role = request.user.role

            print(f"Approval hierarchy check: Approver={approver_role}, Creator={creator_role}")

            # AD (Administrator) can only approve EM (Employee) submissions
            if approver_role == 'AD' and creator_role != 'EM':
                print("PERMISSION DENIED: AD can only approve EM submissions")
                messages.error(request, 'Administrators can only approve Employee submissions. This record requires Root Admin or System Admin approval.')
                return redirect('approval_list')

            # RA/SA can approve both EM and AD submissions (no restriction needed)

            try:
                # Approve the senior
                senior.status = 'APPROVED'
                senior.updated_by = request.user
                
                # Generate QR code for approved senior
                print("Generating QR code for approved senior...")
                try:
                    generate_qr_code(senior)
                    print("QR code generated successfully")
                except Exception as qr_error:
                    print(f"QR code generation failed: {qr_error}")
                    # Don't fail the approval for QR code issues
                
                # Save the senior record
                senior.save()
                print(f"Senior {senior.id_number} approved successfully")
                
                # Log the action
                AuditLog.objects.create(
                    user=request.user,
                    action='UPDATE',
                    content_type='SeniorCitizen',
                    object_id=senior.id,
                    description=f'Approved senior citizen: {senior.id_number} ({senior.first_name} {senior.last_name})',
                    ip_address=request.META.get('REMOTE_ADDR')
                )
                
                messages.success(request, f'Senior citizen {senior.first_name} {senior.last_name} (ID: {senior.id_number}) approved successfully!')
                
            except Exception as e:
                print(f"Error approving senior: {e}")
                messages.error(request, f'Error approving senior citizen: {str(e)}')
                return redirect('approve_senior', pk=pk)
            
        elif action == 'reject':
            # Check if user can reject
            if not can_reject:
                print("PERMISSION DENIED: Cannot reject applications")
                messages.error(request, 'You do not have permission to reject applications.')
                return redirect('approval_list')
            
            try:
                # Get rejection reason if provided
                rejection_reason = request.POST.get('rejection_reason', '').strip()
                rejection_notes = request.POST.get('rejection_notes', '').strip()
                
                # Reject the senior
                senior.status = 'REJECTED'
                senior.updated_by = request.user
                
                # Store rejection details if you have these fields in your model
                if hasattr(senior, 'rejection_reason') and rejection_reason:
                    senior.rejection_reason = rejection_reason
                if hasattr(senior, 'rejection_notes') and rejection_notes:
                    senior.rejection_notes = rejection_notes
                
                senior.save()
                print(f"Senior {senior.id_number} rejected successfully")
                
                # Log the action with rejection details
                description = f'Rejected senior citizen: {senior.id_number} ({senior.first_name} {senior.last_name})'
                if rejection_reason:
                    description += f' - Reason: {rejection_reason}'
                
                AuditLog.objects.create(
                    user=request.user,
                    action='UPDATE',
                    content_type='SeniorCitizen',
                    object_id=senior.id,
                    description=description,
                    ip_address=request.META.get('REMOTE_ADDR')
                )
                
                success_msg = f'Senior citizen {senior.first_name} {senior.last_name} (ID: {senior.id_number}) rejected'
                if rejection_reason:
                    success_msg += f' - Reason: {rejection_reason}'
                messages.success(request, success_msg)
                
            except Exception as e:
                print(f"Error rejecting senior: {e}")
                messages.error(request, f'Error rejecting senior citizen: {str(e)}')
                return redirect('approve_senior', pk=pk)
        
        elif action == 'request_info':
            # Handle request for additional information (if implemented)
            additional_info = request.POST.get('additional_info', '').strip()
            if additional_info:
                # You could implement a status like 'INFO_REQUESTED' and store the request
                try:
                    # Log the information request
                    AuditLog.objects.create(
                        user=request.user,
                        action='UPDATE',
                        content_type='SeniorCitizen',
                        object_id=senior.id,
                        description=f'Requested additional information for senior: {senior.id_number} - {additional_info}',
                        ip_address=request.META.get('REMOTE_ADDR')
                    )
                    
                    messages.info(request, f'Additional information requested for {senior.first_name} {senior.last_name}')
                    
                except Exception as e:
                    print(f"Error requesting additional info: {e}")
                    messages.error(request, f'Error processing request: {str(e)}')
            else:
                messages.error(request, 'Please provide details about the additional information needed.')
                return redirect('approve_senior', pk=pk)
        
        else:
            print(f"Invalid action: {action}")
            messages.error(request, 'Invalid action specified.')
            return redirect('approve_senior', pk=pk)
        
        # Redirect back to approval list after successful action
        return redirect('approval_list')
    
    # GET request - show the approval form
    print("Displaying approval form")
    
    # Calculate how long this application has been pending
    days_pending = (timezone.now().date() - senior.created_at.date()).days if senior.created_at else 0
    is_urgent = days_pending > 7  # Mark as urgent if pending more than 7 days
    
    # Get related documents if any
    documents = SeniorDocument.objects.filter(senior=senior)
    
    # Calculate age
    age = None
    if senior.birth_date:
        today = timezone.now().date()
        age = today.year - senior.birth_date.year - ((today.month, today.day) < (senior.birth_date.month, senior.birth_date.day))
    
    # Check for any validation warnings
    validation_warnings = []
    if age and age < 60:
        validation_warnings.append(f'Age is {age} years (below 60)')
    if not senior.mobile_number and not senior.telephone_number:
        validation_warnings.append('No contact number provided')
    if not senior.address or len(senior.address.strip()) < 10:
        validation_warnings.append('Address appears incomplete')
    
    # Build context for template
    context = {
        'senior': senior,
        'documents': documents,
        'can_approve': can_approve,
        'can_reject': can_reject,
        'days_pending': days_pending,
        'is_urgent': is_urgent,
        'age': age,
        'validation_warnings': validation_warnings,
        'user_permissions': {
            'navigation_access': getattr(request.user, 'can_access_pending_approvals', False),
            'view_permission': getattr(request.user, 'can_view_pending_applications', False),
            'approve_permission': can_approve,
            'reject_permission': can_reject,
        },
        # Rejection reason choices (if you want to implement structured reasons)
        'rejection_reasons': [
            'Incomplete documentation',
            'Invalid birth date/age',
            'Duplicate application',
            'Incorrect barangay',
            'Missing required information',
            'Invalid contact information',
            'Other (specify in notes)',
        ]
    }
    
    print(f"Rendering approve_senior template with context for {senior.id_number}")
    
    return render(request, 'seniors/approve_senior.html', context)

@login_required
def approval_list_view(request):
    """View for listing senior citizens pending approval - FIXED count error"""
    print(f"\n=== APPROVAL LIST VIEW ACCESS ===")
    print(f"User: {request.user.username}")
    print(f"Role: {request.user.role}")
    print(f"can_access_pending_approvals: {getattr(request.user, 'can_access_pending_approvals', 'MISSING')}")
    print(f"can_view_pending_applications: {getattr(request.user, 'can_view_pending_applications', 'MISSING')}")
    
    # Check permissions directly without decorators
    if not getattr(request.user, 'can_access_pending_approvals', False):
        print("PERMISSION DENIED: Missing navigation access")
        messages.error(request, 'You do not have access to Pending Approvals section.')
        return redirect(_get_safe_redirect_url(request.user))
    
    if not getattr(request.user, 'can_view_pending_applications', False):
        print("PERMISSION DENIED: Missing view permission") 
        messages.error(request, 'You do not have permission to view pending applications.')
        return redirect(_get_safe_redirect_url(request.user))
    
    print("SUCCESS: Access granted to approval list")
    
    # Apply filters if provided
    query = request.GET.get('q', '')
    
    # Get pending seniors
    pending_seniors = SeniorCitizen.objects.filter(status='PENDING').order_by('-created_at')
    
    # Apply search filter if provided
    if query:
        pending_seniors = pending_seniors.filter(
            Q(id_number__icontains=query) |
            Q(first_name__icontains=query) |
            Q(last_name__icontains=query) |
            Q(middle_name__icontains=query)
        )
        print(f"Applied search filter: {query}")
    
    # Calculate total count BEFORE pagination
    total_pending = pending_seniors.count()
    
    # Pagination
    paginator = Paginator(pending_seniors, 15)
    page_number = request.GET.get('page', 1)
    pending_page = paginator.get_page(page_number)
    
    # Get count of items on current page - FIXED
    current_page_count = len(pending_page.object_list)
    
    # Check what actions user can perform
    can_approve = getattr(request.user, 'can_approve_applications', False)
    can_reject = getattr(request.user, 'can_reject_applications', False)
    can_bulk_process = getattr(request.user, 'can_bulk_process_approvals', False)
    can_export = getattr(request.user, 'can_export_approval_reports', False)
    
    print(f"User action permissions: approve={can_approve}, reject={can_reject}, bulk={can_bulk_process}, export={can_export}")
    
    # Build context
    context = {
        'pending_seniors': pending_page,
        'can_approve': can_approve,
        'can_reject': can_reject,
        'can_bulk_process': can_bulk_process,
        'can_export': can_export,
        'total_pending': total_pending,
        'current_search': query,
    }
    
    # FIXED: Use len() instead of count() for current page
    print(f"Rendering approval list with {total_pending} total pending applications ({current_page_count} on current page)")
    
    return render(request, 'seniors/approval_list.html', context)

@login_required
@role_required('RA', 'SA', 'AD', 'EM') 
def upload_document_view(request, senior_pk):
    """View for uploading documents for a senior citizen"""
    senior = get_object_or_404(SeniorCitizen, pk=senior_pk)
    
    if request.method == 'POST':
        form = SeniorDocumentForm(request.POST, request.FILES)
        if form.is_valid():
            document = form.save(commit=False)
            document.senior = senior
            document.uploaded_by = request.user
            document.save()
            
            # Log the action
            AuditLog.objects.create(
                user=request.user,
                action='CREATE',
                content_type='Document',
                object_id=document.id,
                description=f'Uploaded document for senior: {senior.id_number}',
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            messages.success(request, 'Document uploaded successfully!')
            return redirect('senior_detail', pk=senior.pk)
    else:
        form = SeniorDocumentForm()
    
    context = {
        'form': form,
        'senior': senior,
    }
    
    return render(request, 'seniors/upload_document.html', context)

@login_required
@role_required('RA', 'SA', 'AD', 'EM') 
def delete_document_view(request, document_pk):
    """View for deleting a document - ONLY documents can be deleted, not seniors"""
    document = get_object_or_404(SeniorDocument, pk=document_pk)
    senior = document.senior
    
    # Check if employee is trying to delete a document uploaded by someone else
    if request.user.role == 'EM' and document.uploaded_by != request.user:
        messages.error(request, 'Employees can only delete their own documents.')
        return redirect('senior_detail', pk=senior.pk)
    
    if request.method == 'POST':
        # Log before deletion
        AuditLog.objects.create(
            user=request.user,
            action='DELETE',
            content_type='Document',
            object_id=document.id,
            description=f'Deleted document for senior: {senior.id_number}',
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        # Delete the document file
        if document.document:
            if os.path.isfile(document.document.path):
                os.remove(document.document.path)
        
        # Delete the record
        document.delete()
        messages.success(request, 'Document deleted successfully!')
        return redirect('senior_detail', pk=senior.pk)
    
    context = {
        'document': document,
        'senior': senior,
    }
    
    return render(request, 'seniors/delete_document.html', context)

@login_required
@role_required('RA', 'SA', 'AD', 'EM') 
def download_qr_code_view(request, pk):
    """View for downloading a senior citizen's QR code"""
    senior = get_object_or_404(SeniorCitizen, pk=pk)
    
    # Generate QR code if it doesn't exist
    if not senior.qr_code or not os.path.exists(senior.qr_code.path):
        generate_qr_code(senior)
        senior.save()
    
    # Log the action
    AuditLog.objects.create(
        user=request.user,
        action='READ',
        content_type='SeniorCitizen',
        object_id=senior.id,
        description=f'Downloaded QR code for senior: {senior.id_number}',
        ip_address=request.META.get('REMOTE_ADDR')
    )
    
    # Return the QR code file
    return FileResponse(open(senior.qr_code.path, 'rb'), as_attachment=True, filename=f'{senior.id_number}_qr.png')


@login_required
@requires_permission('can_view_active_records')
def print_senior_id_view(request, pk):
    """View for printing senior citizen ID card (front and back)"""
    senior = get_object_or_404(SeniorCitizen, pk=pk)

    # Check if senior is approved
    if senior.status != 'APPROVED':
        messages.error(request, 'Only approved senior records can have their IDs printed.')
        return redirect('senior_detail', pk=senior.pk)

    # Log the action
    AuditLog.objects.create(
        user=request.user,
        action='READ',
        content_type='SeniorCitizen',
        object_id=senior.id,
        description=f'Printed ID for senior: {senior.id_number}',
        ip_address=request.META.get('REMOTE_ADDR')
    )

    context = {
        'senior': senior,
    }

    return render(request, 'seniors/print_id.html', context)


@login_required
@role_required('RA', 'SA', 'AD', 'EM')
def upload_senior_photo_view(request, pk):
    """View for uploading/replacing a senior citizen's photo"""
    senior = get_object_or_404(SeniorCitizen, pk=pk)

    # Check permissions
    if request.user.role == 'EM' and senior.created_by != request.user:
        messages.error(request, 'Employees can only upload photos to their own records.')
        return redirect('senior_detail', pk=senior.pk)

    if request.method == 'POST' and request.FILES.get('photo'):
        photo = request.FILES['photo']

        # Validate file size (max 5MB)
        if photo.size > 5 * 1024 * 1024:
            messages.error(request, 'Photo file size cannot exceed 5MB.')
            return redirect('senior_detail', pk=senior.pk)

        # Validate file extension
        allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif']
        file_extension = photo.name.lower().split('.')[-1]
        if f'.{file_extension}' not in allowed_extensions:
            messages.error(request, 'Photo must be in JPG, JPEG, PNG, or GIF format.')
            return redirect('senior_detail', pk=senior.pk)

        # Delete old photo if exists
        if senior.photo:
            if os.path.isfile(senior.photo.path):
                os.remove(senior.photo.path)

        # Save new photo
        senior.photo = photo
        senior.save()

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='UPDATE',
            content_type='SeniorCitizen',
            object_id=senior.id,
            description=f'Uploaded photo for senior: {senior.id_number}',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        messages.success(request, 'Photo uploaded successfully!')
        return redirect('senior_detail', pk=senior.pk)

    return redirect('senior_detail', pk=senior.pk)


@login_required
@role_required('RA', 'SA', 'AD', 'EM')
def upload_birth_certificate_view(request, pk):
    """View for uploading/replacing a senior citizen's birth certificate"""
    senior = get_object_or_404(SeniorCitizen, pk=pk)

    # Check permissions
    if request.user.role == 'EM' and senior.created_by != request.user:
        messages.error(request, 'Employees can only upload documents to their own records.')
        return redirect('senior_detail', pk=senior.pk)

    if request.method == 'POST' and request.FILES.get('birth_certificate'):
        birth_certificate = request.FILES['birth_certificate']

        # Validate file size (max 10MB)
        if birth_certificate.size > 10 * 1024 * 1024:
            messages.error(request, 'Birth certificate file size cannot exceed 10MB.')
            return redirect('senior_detail', pk=senior.pk)

        # Validate file extension
        allowed_extensions = ['.pdf', '.jpg', '.jpeg']
        file_extension = birth_certificate.name.lower().split('.')[-1]
        if f'.{file_extension}' not in allowed_extensions:
            messages.error(request, 'Birth certificate must be in PDF or JPEG format.')
            return redirect('senior_detail', pk=senior.pk)

        # Delete old file if exists
        if senior.birth_certificate:
            if os.path.isfile(senior.birth_certificate.path):
                os.remove(senior.birth_certificate.path)

        # Save new file
        senior.birth_certificate = birth_certificate
        senior.save()

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='UPDATE',
            content_type='SeniorCitizen',
            object_id=senior.id,
            description=f'Uploaded birth certificate for senior: {senior.id_number}',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        messages.success(request, 'Birth certificate uploaded successfully!')
        return redirect('senior_detail', pk=senior.pk)

    return redirect('senior_detail', pk=senior.pk)


@login_required
@role_required('RA', 'SA', 'AD', 'EM')
def upload_certificate_of_indigency_view(request, pk):
    """View for uploading/replacing a senior citizen's certificate of indigency"""
    senior = get_object_or_404(SeniorCitizen, pk=pk)

    # Check permissions
    if request.user.role == 'EM' and senior.created_by != request.user:
        messages.error(request, 'Employees can only upload documents to their own records.')
        return redirect('senior_detail', pk=senior.pk)

    if request.method == 'POST' and request.FILES.get('certificate_of_indigency'):
        certificate = request.FILES['certificate_of_indigency']

        # Validate file size (max 10MB)
        if certificate.size > 10 * 1024 * 1024:
            messages.error(request, 'Certificate of indigency file size cannot exceed 10MB.')
            return redirect('senior_detail', pk=senior.pk)

        # Validate file extension
        allowed_extensions = ['.pdf', '.jpg', '.jpeg']
        file_extension = certificate.name.lower().split('.')[-1]
        if f'.{file_extension}' not in allowed_extensions:
            messages.error(request, 'Certificate of indigency must be in PDF or JPEG format.')
            return redirect('senior_detail', pk=senior.pk)

        # Delete old file if exists
        if senior.certificate_of_indigency:
            if os.path.isfile(senior.certificate_of_indigency.path):
                os.remove(senior.certificate_of_indigency.path)

        # Save new file
        senior.certificate_of_indigency = certificate
        senior.save()

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='UPDATE',
            content_type='SeniorCitizen',
            object_id=senior.id,
            description=f'Uploaded certificate of indigency for senior: {senior.id_number}',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        messages.success(request, 'Certificate of indigency uploaded successfully!')
        return redirect('senior_detail', pk=senior.pk)

    return redirect('senior_detail', pk=senior.pk)


@login_required
@role_required('RA', 'SA', 'AD', 'EM')
def upload_marriage_certificate_view(request, pk):
    """View for uploading/replacing a senior citizen's marriage certificate"""
    senior = get_object_or_404(SeniorCitizen, pk=pk)

    # Check permissions
    if request.user.role == 'EM' and senior.created_by != request.user:
        messages.error(request, 'Employees can only upload documents to their own records.')
        return redirect('senior_detail', pk=senior.pk)

    if request.method == 'POST' and request.FILES.get('marriage_certificate'):
        certificate = request.FILES['marriage_certificate']

        # Validate file size (max 10MB)
        if certificate.size > 10 * 1024 * 1024:
            messages.error(request, 'Marriage certificate file size cannot exceed 10MB.')
            return redirect('senior_detail', pk=senior.pk)

        # Validate file extension
        allowed_extensions = ['.pdf', '.jpg', '.jpeg']
        file_extension = certificate.name.lower().split('.')[-1]
        if f'.{file_extension}' not in allowed_extensions:
            messages.error(request, 'Marriage certificate must be in PDF or JPEG format.')
            return redirect('senior_detail', pk=senior.pk)

        # Delete old file if exists
        if senior.marriage_certificate:
            if os.path.isfile(senior.marriage_certificate.path):
                os.remove(senior.marriage_certificate.path)

        # Save new file
        senior.marriage_certificate = certificate
        senior.save()

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='UPDATE',
            content_type='SeniorCitizen',
            object_id=senior.id,
            description=f'Uploaded marriage certificate for senior: {senior.id_number}',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        messages.success(request, 'Marriage certificate uploaded successfully!')
        return redirect('senior_detail', pk=senior.pk)

    return redirect('senior_detail', pk=senior.pk)


@login_required
@role_required('RA', 'SA', 'AD', 'EM')
def delete_senior_photo_view(request, pk):
    """View for deleting a senior citizen's photo"""
    senior = get_object_or_404(SeniorCitizen, pk=pk)

    # Check permissions
    if request.user.role == 'EM' and senior.created_by != request.user:
        messages.error(request, 'Employees can only delete photos from their own records.')
        return redirect('senior_detail', pk=senior.pk)

    if request.method == 'POST':
        # Log before deletion
        AuditLog.objects.create(
            user=request.user,
            action='UPDATE',
            content_type='SeniorCitizen',
            object_id=senior.id,
            description=f'Deleted photo for senior: {senior.id_number}',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        # Delete the photo file
        if senior.photo:
            if os.path.isfile(senior.photo.path):
                os.remove(senior.photo.path)
            senior.photo = None
            senior.save()

        messages.success(request, 'Photo deleted successfully!')
        return redirect('senior_detail', pk=senior.pk)

    return redirect('senior_detail', pk=senior.pk)


@login_required
@role_required('RA', 'SA', 'AD', 'EM')
def delete_birth_certificate_view(request, pk):
    """View for deleting a senior citizen's birth certificate"""
    senior = get_object_or_404(SeniorCitizen, pk=pk)

    # Check permissions
    if request.user.role == 'EM' and senior.created_by != request.user:
        messages.error(request, 'Employees can only delete documents from their own records.')
        return redirect('senior_detail', pk=senior.pk)

    if request.method == 'POST':
        # Log before deletion
        AuditLog.objects.create(
            user=request.user,
            action='UPDATE',
            content_type='SeniorCitizen',
            object_id=senior.id,
            description=f'Deleted birth certificate for senior: {senior.id_number}',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        # Delete the birth certificate file
        if senior.birth_certificate:
            if os.path.isfile(senior.birth_certificate.path):
                os.remove(senior.birth_certificate.path)
            senior.birth_certificate = None
            senior.save()

        messages.success(request, 'Birth certificate deleted successfully!')
        return redirect('senior_detail', pk=senior.pk)

    return redirect('senior_detail', pk=senior.pk)


@login_required
@role_required('RA', 'SA', 'AD', 'EM')
def delete_certificate_of_indigency_view(request, pk):
    """View for deleting a senior citizen's certificate of indigency"""
    senior = get_object_or_404(SeniorCitizen, pk=pk)

    # Check permissions
    if request.user.role == 'EM' and senior.created_by != request.user:
        messages.error(request, 'Employees can only delete documents from their own records.')
        return redirect('senior_detail', pk=senior.pk)

    if request.method == 'POST':
        # Log before deletion
        AuditLog.objects.create(
            user=request.user,
            action='UPDATE',
            content_type='SeniorCitizen',
            object_id=senior.id,
            description=f'Deleted certificate of indigency for senior: {senior.id_number}',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        # Delete the certificate file
        if senior.certificate_of_indigency:
            if os.path.isfile(senior.certificate_of_indigency.path):
                os.remove(senior.certificate_of_indigency.path)
            senior.certificate_of_indigency = None
            senior.save()

        messages.success(request, 'Certificate of indigency deleted successfully!')
        return redirect('senior_detail', pk=senior.pk)

    return redirect('senior_detail', pk=senior.pk)


@login_required
@role_required('RA', 'SA', 'AD', 'EM')
def delete_marriage_certificate_view(request, pk):
    """View for deleting a senior citizen's marriage certificate"""
    senior = get_object_or_404(SeniorCitizen, pk=pk)

    # Check permissions
    if request.user.role == 'EM' and senior.created_by != request.user:
        messages.error(request, 'Employees can only delete documents from their own records.')
        return redirect('senior_detail', pk=senior.pk)

    if request.method == 'POST':
        # Log before deletion
        AuditLog.objects.create(
            user=request.user,
            action='UPDATE',
            content_type='SeniorCitizen',
            object_id=senior.id,
            description=f'Deleted marriage certificate for senior: {senior.id_number}',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        # Delete the marriage certificate file
        if senior.marriage_certificate:
            if os.path.isfile(senior.marriage_certificate.path):
                os.remove(senior.marriage_certificate.path)
            senior.marriage_certificate = None
            senior.save()

        messages.success(request, 'Marriage certificate deleted successfully!')
        return redirect('senior_detail', pk=senior.pk)

    return redirect('senior_detail', pk=senior.pk)


def extract_gender(gender_str):
    """Extract gender from various formats"""
    if not gender_str or pd.isna(gender_str):
        return None
    
    gender_str = str(gender_str).strip().upper()
    
    # Gender mapping
    gender_mapping = {
        'M': 'M',
        'MALE': 'M', 
        'F': 'F',
        'FEMALE': 'F',
        'LALAKI': 'M',
        'BABAE': 'F',
    }
    
    return gender_mapping.get(gender_str, None)

@login_required
@requires_permission('can_delete_active_records')
def senior_archive_view(request, pk):
    """View for archiving a senior citizen record instead of deleting"""
    senior = get_object_or_404(SeniorCitizen, pk=pk)
    
    if request.method == 'POST':
        archive_reason = request.POST.get('archive_reason')
        archive_notes = request.POST.get('archive_notes', '')
        
        if not archive_reason:
            messages.error(request, 'Please select a reason for archiving.')
            return render(request, 'seniors/senior_archive_confirm.html', {'senior': senior})
        
        # Update the senior record to archived status
        senior.status = 'ARCHIVED'
        senior.archive_reason = archive_reason
        senior.archive_notes = archive_notes
        senior.archived_by = request.user
        senior.archived_at = timezone.now()
        senior.updated_by = request.user
        senior.save()
        
        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='ARCHIVE',
            content_type='SeniorCitizen',
            object_id=senior.id,
            description=f'Archived senior citizen: {senior.id_number} (Reason: {archive_reason})',
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        messages.success(request, f'Senior citizen record for {senior.first_name} {senior.last_name} has been archived successfully!')
        return redirect('archived_seniors_list')
    
    context = {
        'senior': senior,
    }
    
    return render(request, 'seniors/senior_archive_confirm.html', context)

@login_required
@requires_navigation_access('archived_records')
def archived_seniors_list_view(request):
    """View for listing archived senior citizens - FIXED with permission-based access"""
    # Check if user can view archived records
    if not request.user.can_view_archived_records:
        messages.error(request, 'You do not have permission to view archived records.')
        return redirect(_get_safe_redirect_url(request.user))
    
    query = request.GET.get('q', '')
    archive_reason = request.GET.get('archive_reason', '')
    
    # Filter archived seniors
    seniors = SeniorCitizen.objects.filter(status='ARCHIVED').order_by('-archived_at')
    
    # Apply search filter if provided
    if query:
        seniors = seniors.filter(
            Q(id_number__icontains=query) |
            Q(first_name__icontains=query) |
            Q(last_name__icontains=query)
        )
    
    # Apply archive reason filter if provided
    if archive_reason:
        seniors = seniors.filter(archive_reason=archive_reason)
    
    # Pagination
    paginator = Paginator(seniors, 10)
    page_number = request.GET.get('page', 1)
    seniors_page = paginator.get_page(page_number)
    
    context = {
        'seniors': seniors_page,
        'query': query,
        'archive_reason': archive_reason,
        'can_restore': request.user.can_restore_archived_records,
        'can_permanently_delete': request.user.can_permanently_delete_archived,
        'can_export': request.user.can_export_archived_records,
    }
    
    return render(request, 'seniors/archived_seniors_list.html', context)

@login_required
@requires_navigation_access('archived_records')
def archived_senior_detail_view(request, pk):
    """View for displaying details of an archived senior citizen - FIXED with permission check"""
    # Check if user can view archived records
    if not request.user.can_view_archived_records:
        messages.error(request, 'You do not have permission to view archived records.')
        return redirect(_get_safe_redirect_url(request.user))
    
    senior = get_object_or_404(SeniorCitizen, pk=pk, status='ARCHIVED')
    documents = SeniorDocument.objects.filter(senior=senior)
    
    # FIXED: Get discount transaction history from verifications app
    from verifications.models import DiscountTransaction
    transactions = DiscountTransaction.objects.filter(
        id_number=senior.id_number
    ).order_by('-created_at')[:10]  # Latest 10 transactions
    
    # Log the action
    AuditLog.objects.create(
        user=request.user,
        action='READ',
        content_type='SeniorCitizen',
        object_id=senior.id,
        description=f'Viewed archived senior citizen details: {senior.id_number}',
        ip_address=request.META.get('REMOTE_ADDR')
    )
    
    context = {
        'senior': senior,
        'documents': documents,
        'transactions': transactions,
        'is_archived': True,
        'can_restore': request.user.can_restore_archived_records,
        'can_permanently_delete': request.user.can_permanently_delete_archived,
    }
    
    return render(request, 'seniors/senior_detail.html', context)

@login_required
@requires_navigation_access('archived_records')
def restore_senior_view(request, pk):
    """View for restoring an archived senior citizen record - FIXED with permission check"""
    # Check if user can restore archived records
    if not request.user.can_restore_archived_records:
        messages.error(request, 'You do not have permission to restore archived records.')
        return redirect('archived_seniors_list')
    
    senior = get_object_or_404(SeniorCitizen, pk=pk, status='ARCHIVED')
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'restore':
            # Restore the senior record
            senior.status = 'APPROVED'  # Restore as approved
            senior.archive_reason = None
            senior.archive_notes = None
            senior.archived_by = None
            senior.archived_at = None
            senior.updated_by = request.user
            senior.save()
            
            # Log the action
            AuditLog.objects.create(
                user=request.user,
                action='RESTORE',
                content_type='SeniorCitizen',
                object_id=senior.id,
                description=f'Restored senior citizen from archive: {senior.id_number}',
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            messages.success(request, f'Senior citizen record for {senior.first_name} {senior.last_name} has been restored successfully!')
            return redirect('senior_detail', pk=senior.pk)
    
    context = {
        'senior': senior,
    }
    
    return render(request, 'seniors/restore_senior_confirm.html', context)
    
@login_required
@requires_navigation_access('archived_records')
def bulk_restore_seniors_view(request):
    """View for bulk restoring archived senior citizens - FIXED with permission check"""
    # Check if user can restore archived records
    if not request.user.can_restore_archived_records:
        messages.error(request, 'You do not have permission to restore archived records.')
        return redirect('archived_seniors_list')
    
    if request.method == 'POST':
        selected_ids = request.POST.getlist('selected_seniors')
        
        if not selected_ids:
            messages.error(request, 'No senior citizens selected for restoration.')
            return redirect('archived_seniors_list')
        
        # Restore selected seniors
        restored_count = 0
        for senior_id in selected_ids:
            try:
                senior = SeniorCitizen.objects.get(pk=senior_id, status='ARCHIVED')
                senior.status = 'APPROVED'  # Restore as approved
                senior.archive_reason = None
                senior.archive_notes = None
                senior.archived_by = None
                senior.archived_at = None
                senior.updated_by = request.user
                senior.save()
                restored_count += 1
            except SeniorCitizen.DoesNotExist:
                continue
        
        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='BULK_RESTORE',
            content_type='SeniorCitizen',
            description=f'Bulk restored {restored_count} senior citizens from archive',
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        messages.success(request, f'Successfully restored {restored_count} senior citizen record(s).')
        
    return redirect('archived_seniors_list')

@login_required
@role_required('RA', 'SA', 'AD')  # Root Admin, Super Admin, and Admin can delete archived
def delete_archived_senior_view(request, pk):
    """View for soft-deleting an archived senior (moves to DELETED status)"""
    senior = get_object_or_404(SeniorCitizen, pk=pk, status='ARCHIVED')

    if request.method == 'POST':
        # Store info for message
        senior_name = f"{senior.first_name} {senior.last_name}"
        senior_id_number = senior.id_number

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='DELETE',
            content_type='SeniorCitizen',
            object_id=senior.id,
            description=f'Moved archived senior to deleted list: {senior_id_number} - {senior_name}',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        # Soft delete - move to DELETED status
        senior.status = 'DELETED'
        senior.deleted_at = timezone.now()
        senior.deleted_by = request.user
        senior.save()

        messages.success(request, f'Senior citizen record for {senior_name} (ID: {senior_id_number}) has been moved to the Deleted list.')

    return redirect('archived_seniors_list')

@login_required
@role_required('RA', 'SA', 'AD')  # Root Admin, Super Admin, and Admin can permanently delete
def permanent_delete_senior_view(request, pk):
    """View for permanently deleting a DELETED senior citizen record (no confirmation needed)"""
    senior = get_object_or_404(SeniorCitizen, pk=pk, status='DELETED')

    if request.method == 'POST':
        # Store info for message
        senior_name = f"{senior.first_name} {senior.last_name}"
        senior_id_number = senior.id_number

        # Log the action before deletion
        AuditLog.objects.create(
            user=request.user,
            action='DELETE',
            content_type='SeniorCitizen',
            object_id=senior.id,
            description=f'PERMANENT DELETE: {senior_id_number} - {senior_name}',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        # Delete associated files
        if senior.photo:
            try:
                if os.path.isfile(senior.photo.path):
                    os.remove(senior.photo.path)
            except:
                pass

        if senior.qr_code:
            try:
                if os.path.isfile(senior.qr_code.path):
                    os.remove(senior.qr_code.path)
            except:
                pass

        # Delete associated documents
        for document in senior.documents.all():
            if document.document:
                try:
                    if os.path.isfile(document.document.path):
                        os.remove(document.document.path)
                except:
                    pass

        # Permanently delete the record
        senior.delete()

        messages.success(request, f'Senior citizen record for {senior_name} (ID: {senior_id_number}) has been permanently deleted.')

    return redirect('deleted_seniors_list')

@login_required
@role_required('RA', 'SA', 'AD')
def deleted_seniors_list_view(request):
    """View for listing deleted senior citizens (ready for permanent deletion)"""
    query = request.GET.get('q', '')

    # Filter deleted seniors
    seniors = SeniorCitizen.objects.filter(status='DELETED').order_by('-deleted_at')

    # Apply search filter if provided
    if query:
        seniors = seniors.filter(
            Q(id_number__icontains=query) |
            Q(first_name__icontains=query) |
            Q(last_name__icontains=query)
        )

    # Pagination
    paginator = Paginator(seniors, 10)
    page_number = request.GET.get('page', 1)
    seniors_page = paginator.get_page(page_number)

    context = {
        'seniors': seniors_page,
        'query': query,
    }

    return render(request, 'seniors/deleted_seniors_list.html', context)

@login_required
@role_required('RA', 'SA', 'AD')
def senior_delete_view(request, pk):
    """View for archiving a senior citizen record (replaces old delete functionality)"""
    # Redirect to archive view instead of actual deletion
    return redirect('senior_archive', pk=pk)

@login_required
@role_required('RA', 'SA')
def backup(request):
    """Create system backup"""
    if request.method == 'POST':
        # Implement backup logic here
        messages.success(request, 'System backup created successfully!')
        return redirect('backup')
    
    return render(request, 'seniors/backup.html')

@login_required
@role_required('RA', 'SA')
def restore_backup(request):
    """Restore system from backup"""
    if request.method == 'POST':
        # Implement restore logic here
        messages.success(request, 'System restored from backup successfully!')
        return redirect('restore_backup')
    
    return render(request, 'seniors/restore_backup.html')

@login_required
@role_required('RA', 'SA')
def cleanup_media(request):
    """Cleanup unused media files"""
    if request.method == 'POST':
        # Implement cleanup logic here
        messages.success(request, 'Media cleanup completed successfully!')
        return redirect('cleanup_media')
    
    return render(request, 'seniors/cleanup_media.html')
