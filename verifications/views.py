from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.db import transaction
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.contrib import messages
import json
import logging
import io
from datetime import date

# External libraries for Excel generation
from openpyxl import Workbook
from openpyxl.styles import Font, Alignment

# Import from seniors app
from seniors.models import SeniorCitizen

# Import from local models
from .models import DiscountTransaction, VerificationRequest

# Import from accounts app
from accounts.decorators import role_required

# Set up logging
logger = logging.getLogger(__name__)

def verification_page(request):
    """Render the verification page"""
    return render(request, 'verifications/verification.html')


# ===============================
#   ID VERIFICATION
# ===============================
@csrf_exempt
@require_http_methods(["POST"])
def verify_id(request):
    """Verify a senior citizen ID"""
    try:
        data = json.loads(request.body)
        raw_id = data.get('id_number', '').strip()

        if not raw_id:
            return JsonResponse({'success': False, 'message': 'ID number is required'})

        # Normalize input (remove spaces/dashes)
        cleaned_id = raw_id.replace(' ', '').replace('-', '')

        # Query against seniors app
        senior = (
            SeniorCitizen.objects.filter(id_number=raw_id).first()
            or SeniorCitizen.objects.filter(id_number__iexact=raw_id).first()
            or SeniorCitizen.objects.filter(id_number=cleaned_id).first()
            or SeniorCitizen.objects.filter(id_number__iexact=cleaned_id).first()
        )

        if not senior:
            return JsonResponse({'success': False, 'message': 'ID number not found in our database'})

        # Calculate age using model's method
        senior_age = senior.get_age()

        # Build full name safely
        first_name = getattr(senior, "first_name", "")
        last_name = getattr(senior, "last_name", "")
        full_name = f"{first_name} {last_name}".strip()

        # Create response data
        response_data = {
            'success': True,
            'senior': {
                'id_number': senior.id_number,
                'full_name': full_name,
                'first_name': first_name,
                'last_name': last_name,
                'age': senior_age,
                'birth_date': (
                    senior.birth_date.strftime('%Y-%m-%d')
                    if getattr(senior, "birth_date", None)
                    else None
                ),
                'barangay_name': senior.get_barangay_name() if hasattr(senior, 'get_barangay_name') else None,
            }
        }

        # Log the response for debugging
        logger.info(f"Verification response for ID {raw_id}: {response_data}")

        return JsonResponse(response_data)

    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'message': 'Invalid JSON data'})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'message': 'Server error occurred during verification'})


# ===============================
#   DISCOUNTS
# ===============================
@csrf_exempt
@require_http_methods(["POST"])
def check_discounts(request):
    """Check what discounts have been used today at this location"""
    try:
        data = json.loads(request.body)
        id_number = data.get('id_number')

        if not id_number:
            return JsonResponse({'success': False, 'message': 'ID number is required'})

        # Get IP address
        ip_address = request.META.get('HTTP_X_FORWARDED_FOR')
        if ip_address:
            ip_address = ip_address.split(',')[0].strip()
        else:
            ip_address = request.META.get('REMOTE_ADDR', '127.0.0.1')

        today = timezone.now().date()
        
        # Check discounts used today at THIS location (IP)
        used_discounts = DiscountTransaction.objects.filter(
            id_number=id_number,
            created_at__date=today,
            ip_address=ip_address,
            status='APPLIED'
        )

        used_categories = list(used_discounts.values_list('category', flat=True))

        return JsonResponse({
            'success': True, 
            'used_categories': used_categories,
            'location': ip_address
        })

    except Exception as e:
        logger.error(f"Error checking discounts: {e}")
        return JsonResponse({'success': False, 'message': 'Server error occurred'})


@csrf_exempt
@require_http_methods(["POST"])
def apply_discount(request):
    """Apply a discount for a senior citizen with IP and GPS tracking + establishment details"""
    try:
        data = json.loads(request.body)
        id_number = data.get('id_number')
        category = data.get('category', '').upper()

        # Get discount amount from request
        discount_amount = data.get('discount_amount')

        # Get establishment information from session
        establishment_name = request.session.get('establishment_name', '').strip()
        establishment_contact = request.session.get('establishment_contact', '').strip()
        establishment_address = request.session.get('establishment_address', '').strip()

        # Location data from frontend
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        accuracy = data.get('accuracy')

        # Get IP address from request
        ip_address = request.META.get('HTTP_X_FORWARDED_FOR')
        if ip_address:
            ip_address = ip_address.split(',')[0].strip()
        else:
            ip_address = request.META.get('REMOTE_ADDR', '127.0.0.1')

        logger.info(f"Applying discount - ID: {id_number}, Category: {category}, Amount: {discount_amount}, Establishment: {establishment_name}")

        # Validation
        if not id_number or not category:
            return JsonResponse({'success': False, 'message': 'ID number and category are required'})

        if not discount_amount or float(discount_amount) <= 0:
            return JsonResponse({'success': False, 'message': 'Valid discount amount is required'})

        if not establishment_name or len(establishment_name) > 25:
            return JsonResponse({'success': False, 'message': 'Establishment name is required (max 25 characters)'})

        if not establishment_contact or len(establishment_contact) != 11 or not establishment_contact.isdigit():
            return JsonResponse({'success': False, 'message': 'Valid 11-digit contact number is required'})

        if not establishment_address or len(establishment_address) > 25:
            return JsonResponse({'success': False, 'message': 'Establishment address is required (max 25 characters)'})

        valid_categories = [choice[0] for choice in DiscountTransaction.CATEGORY_CHOICES]
        if category not in valid_categories:
            return JsonResponse({'success': False, 'message': 'Invalid discount category'})

        today = timezone.now().date()

        # Check if discount already used today at this location (IP-based)
        existing = DiscountTransaction.objects.filter(
            id_number=id_number,
            category=category,
            created_at__date=today,
            ip_address=ip_address,
            status='APPLIED'
        ).first()

        if existing:
            return JsonResponse({
                'success': False,
                'message': f'{category.lower()} discount already used today at this establishment'
            })

        try:
            senior = SeniorCitizen.objects.get(id_number=id_number)
            senior_name = f"{senior.first_name} {senior.last_name}"
        except SeniorCitizen.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'Invalid senior citizen ID'})

        with transaction.atomic():
            discount_transaction = DiscountTransaction.objects.create(
                id_number=id_number,
                senior_name=senior_name,
                category=category,
                discount_amount=discount_amount,
                establishment_name=establishment_name,
                establishment_contact=establishment_contact,
                establishment_address=establishment_address,
                ip_address=ip_address,
                latitude=latitude,
                longitude=longitude,
                location_accuracy=accuracy
            )

        return JsonResponse({
            'success': True,
            'message': f'{category.lower()} discount applied successfully',
            'transaction': {
                'id': discount_transaction.id,
                'transaction_number': discount_transaction.transaction_number,
                'category': category,
                'discount_amount': str(discount_amount),
                'senior_name': senior_name,
                'establishment_name': establishment_name,
                'created_at': discount_transaction.created_at.isoformat(),
                'location_captured': bool(latitude and longitude)
            }
        })

    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'message': 'Invalid JSON data'})
    except Exception as e:
        logger.error(f"Error applying discount: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'message': 'Server error occurred'})


# ===============================
#   TRANSACTIONS
# ===============================
@csrf_exempt
@require_http_methods(["POST"])
def get_transactions(request):
    """Get all transactions for today"""
    try:
        today = timezone.now().date()
        transactions = DiscountTransaction.objects.filter(
            created_at__date=today
        ).order_by('-created_at')

        transactions_data = [
            {
                'id': txn.id,
                'created_at': txn.created_at.isoformat(),
                'id_number': txn.id_number,
                'senior_name': txn.senior_name,
                'category': txn.category,
                'status': txn.status,
                'voided_at': txn.voided_at.isoformat() if txn.voided_at else None
            }
            for txn in transactions
        ]

        return JsonResponse({'success': True, 'transactions': transactions_data, 'total_count': len(transactions_data)})

    except Exception as e:
        logger.error(f"Error getting transactions: {e}")
        return JsonResponse({'success': False, 'message': 'Server error occurred'})


# ===============================
#   VERIFICATION REQUESTS
# ===============================
@csrf_exempt
@require_http_methods(["POST"])
def request_verification(request):
    """Handle verification requests for IDs not found in database"""
    try:
        data = json.loads(request.body)
        id_number = data.get('id_number')

        if not id_number:
            return JsonResponse({'success': False, 'message': 'ID number is required'})

        VerificationRequest.objects.create(
            id_number=id_number,
            ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )

        return JsonResponse({'success': True, 'message': 'Verification request submitted successfully'})

    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'message': 'Invalid JSON data'})
    except Exception as e:
        logger.error(f"Error processing verification request: {e}")
        return JsonResponse({'success': False, 'message': 'Server error occurred'})


@login_required
@role_required('RA', 'SA', 'AD', 'EM')
def verification_requests_list_view(request):
    """View for listing verification requests"""
    verification_requests = VerificationRequest.objects.filter(is_archived=False).order_by('-created_at')
    paginator = Paginator(verification_requests, 20)
    requests_page = paginator.get_page(request.GET.get('page', 1))

    context = {
        'requests': requests_page,
        'total_requests': verification_requests.count(),
        'pending_requests': verification_requests.count(),
        'status': request.GET.get('status', 'ALL'),
        'is_archived_view': False,
    }
    return render(request, 'verifications/verification_requests.html', context)


@login_required
@role_required('RA', 'SA', 'AD', 'EM')
def archived_verification_requests_view(request):
    """View for listing archived verification requests"""
    verification_requests = VerificationRequest.objects.filter(is_archived=True).order_by('-created_at')
    paginator = Paginator(verification_requests, 20)
    requests_page = paginator.get_page(request.GET.get('page', 1))

    context = {
        'requests': requests_page,
        'total_requests': verification_requests.count(),
        'pending_requests': 0,
        'is_archived_view': True,
    }
    return render(request, 'verifications/verification_requests.html', context)


@login_required
@role_required('RA', 'SA', 'AD')
def archive_verification_requests_view(request):
    """Archive selected verification requests"""
    if request.method == 'POST':
        selected_requests = request.POST.getlist('selected_requests')
        if not selected_requests:
            messages.error(request, 'No verification requests selected.')
            return redirect('verification_requests')

        VerificationRequest.objects.filter(id__in=selected_requests).update(is_archived=True)
        messages.success(request, f'Successfully archived {len(selected_requests)} verification requests.')

    return redirect('verification_requests')


# ===============================
#   SESSION MANAGEMENT
# ===============================
@csrf_exempt
@require_http_methods(["POST"])
def save_establishment_info(request):
    """Save establishment information to session for reuse"""
    try:
        data = json.loads(request.body)
        establishment_name = data.get('establishment_name', '').strip()
        establishment_contact = data.get('establishment_contact', '').strip()
        establishment_address = data.get('establishment_address', '').strip()

        # Validation
        if not establishment_name or len(establishment_name) > 25:
            return JsonResponse({'success': False, 'message': 'Invalid establishment name (max 25 characters)'})

        if not establishment_contact or len(establishment_contact) != 11 or not establishment_contact.isdigit():
            return JsonResponse({'success': False, 'message': 'Invalid contact number (must be 11 digits)'})

        if not establishment_address or len(establishment_address) > 25:
            return JsonResponse({'success': False, 'message': 'Invalid address (max 25 characters)'})

        # Save to session
        request.session['establishment_name'] = establishment_name
        request.session['establishment_contact'] = establishment_contact
        request.session['establishment_address'] = establishment_address

        logger.info(f"Establishment info saved to session: {establishment_name}")

        return JsonResponse({
            'success': True,
            'message': 'Establishment information saved successfully',
            'data': {
                'establishment_name': establishment_name,
                'establishment_contact': establishment_contact,
                'establishment_address': establishment_address
            }
        })

    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'message': 'Invalid JSON data'})
    except Exception as e:
        logger.error(f"Error saving establishment info: {e}")
        return JsonResponse({'success': False, 'message': 'Server error occurred'})


@csrf_exempt
@require_http_methods(["GET"])
def get_establishment_info(request):
    """Retrieve establishment information from session"""
    try:
        establishment_name = request.session.get('establishment_name', '')
        establishment_contact = request.session.get('establishment_contact', '')
        establishment_address = request.session.get('establishment_address', '')

        return JsonResponse({
            'success': True,
            'data': {
                'establishment_name': establishment_name,
                'establishment_contact': establishment_contact,
                'establishment_address': establishment_address
            }
        })

    except Exception as e:
        logger.error(f"Error retrieving establishment info: {e}")
        return JsonResponse({'success': False, 'message': 'Server error occurred'})


@csrf_exempt
@require_http_methods(["POST"])
def clear_establishment_info(request):
    """Clear establishment information from session (end session)"""
    try:
        # Remove establishment info from session
        request.session.pop('establishment_name', None)
        request.session.pop('establishment_contact', None)
        request.session.pop('establishment_address', None)

        logger.info("Establishment session cleared")

        return JsonResponse({
            'success': True,
            'message': 'Session ended successfully'
        })

    except Exception as e:
        logger.error(f"Error clearing establishment info: {e}")
        return JsonResponse({'success': False, 'message': 'Server error occurred'})
