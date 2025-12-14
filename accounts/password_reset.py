from django.http import JsonResponse
from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.contrib.auth.hashers import make_password
import random
import string
from datetime import timedelta

from .models import CustomUser, PasswordResetCode, PasswordResetRequest

def password_reset_request(request):
    """Handle the initial password reset request - NOW USES ADMIN APPROVAL SYSTEM"""
    if request.method == 'POST':
        email = request.POST.get('email')

        if not email:
            return JsonResponse({'error': 'Email is required'}, status=400)

        # Check if user exists
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            # For security, don't reveal if email exists
            return JsonResponse({
                'success': True,
                'message': 'If an account with that email exists, a password reset request has been submitted. An administrator will review your request.'
            })

        # Check if user already has a pending request
        pending_exists = PasswordResetRequest.objects.filter(
            user=user,
            status='PENDING'
        ).exists()

        if pending_exists:
            return JsonResponse({
                'success': True,
                'message': 'You already have a pending password reset request. Please wait for administrator approval.'
            })

        # Create new password reset request (requires admin approval)
        try:
            PasswordResetRequest.objects.create(user=user)

            return JsonResponse({
                'success': True,
                'message': 'Password reset request submitted successfully. An administrator will review your request and send you a temporary password via email if approved.'
            })
        except Exception as e:
            print(f"Error creating password reset request: {str(e)}")
            return JsonResponse({
                'error': 'An error occurred while processing your request. Please try again later.'
            }, status=500)

    return JsonResponse({'error': 'Invalid request'}, status=400)

def password_reset_verify(request):
    """Verify the reset code"""
    if request.method == 'POST':
        email = request.POST.get('email')
        code = request.POST.get('code')
        
        if not email or not code:
            return JsonResponse({'error': 'Email and code are required'}, status=400)
        
        # Check if user exists
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return JsonResponse({'error': 'No account found with this email address'}, status=404)
        
        # Verify the code
        try:
            reset_code = PasswordResetCode.objects.get(user=user, code=code)
            
            # Check if code is expired
            if reset_code.expires_at < timezone.now():
                return JsonResponse({'error': 'Verification code has expired'}, status=400)
            
            # Code is valid
            return JsonResponse({'success': True})
            
        except PasswordResetCode.DoesNotExist:
            return JsonResponse({'error': 'Invalid verification code'}, status=400)
    
    return JsonResponse({'error': 'Invalid request'}, status=400)

def password_reset_complete(request):
    """Complete the password reset process"""
    if request.method == 'POST':
        email = request.POST.get('email')
        code = request.POST.get('code')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        
        if not email or not code or not new_password or not confirm_password:
            return JsonResponse({'error': 'All fields are required'}, status=400)
        
        if new_password != confirm_password:
            return JsonResponse({'error': 'Passwords do not match'}, status=400)
        
        # Check if user exists
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return JsonResponse({'error': 'No account found with this email address'}, status=404)
        
        # Verify the code
        try:
            reset_code = PasswordResetCode.objects.get(user=user, code=code)
            
            # Check if code is expired
            if reset_code.expires_at < timezone.now():
                return JsonResponse({'error': 'Verification code has expired'}, status=400)
            
            # Reset the password
            user.password = make_password(new_password)
            user.must_change_password = False
            user.save()
            
            # Delete the reset code
            reset_code.delete()
            
            return JsonResponse({'success': True})
            
        except PasswordResetCode.DoesNotExist:
            return JsonResponse({'error': 'Invalid verification code'}, status=400)
    
    return JsonResponse({'error': 'Invalid request'}, status=400)
