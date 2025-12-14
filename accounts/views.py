from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.urls import reverse
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from django.views.decorators.http import require_http_methods
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.util import random_hex
from core.models import AuditLog, LandingPageContent, TeamMember, FAQItem, PrivacyPolicy
import qrcode
import io
import base64
import pyotp
from django.http import JsonResponse
from django.contrib import messages
from django.utils import timezone
from django.core.cache import cache
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
import json

from .forms import LoginForm, PasswordChangeForm, MFASetupForm, MFAVerifyForm
from .models import CustomUser
from .decorators import role_required, admin_required, system_admin_required, root_admin_required
from core.models import AuditLog

@ensure_csrf_cookie
def login_view(request):
    """
    ENHANCED: Handle user authentication with MFA support and detailed failed login tracking.
    """
    # IMPORTANT DEBUG OUTPUT
    print("\n\n=================== LOGIN VIEW CALLED ===================")
    print(f"Request method: {request.method}")
    print(f"Session data: {dict(request.session.items())}")
    
    # GET LANDING PAGE CONTENT FROM DATABASE - THIS IS THE FIX
    try:
        landing_page_content = LandingPageContent.get_content()
        print(f"Landing page content loaded: {landing_page_content.hero_title}")
    except Exception as e:
        print(f"Error loading landing page content: {str(e)}")
        # If content doesn't exist yet, create default content
        landing_page_content = LandingPageContent.objects.create()
        print("Created default landing page content")
    
    # Helper function to get client IP
    def get_client_ip(request):
        """Get the client's real IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    # Helper function to get user agent
    def get_user_agent(request):
        """Get the user agent string"""
        return request.META.get('HTTP_USER_AGENT', 'Unknown')
    
    # Helper function to log failed login attempt with detailed information
    def log_failed_login(username, ip_address, user_agent, error_message, user_obj=None):
        """Log failed login attempt with comprehensive details"""
        try:
            # Create detailed description
            description = f"Failed login attempt - Username: {username}, Error: {error_message}"
            
            # Log the failed attempt
            AuditLog.objects.create(
                user=user_obj,  # This will be None for non-existent users
                action='LOGIN',
                content_type='User',
                object_id=user_obj.id if user_obj else None,
                description=description,
                ip_address=ip_address,
                user_agent=user_agent,
                extra_data={
                    'login_attempt': True,
                    'success': False,
                    'username_attempted': username,
                    'error_type': error_message,
                    'timestamp': timezone.now().isoformat()
                }
            )
            print(f"Logged failed login attempt for username: {username} from IP: {ip_address}")
        except Exception as e:
            print(f"Error logging failed login attempt: {str(e)}")
    
    # Process login form
    if request.method == "POST":
        print("Processing POST request")
        # Clear partial login state only when processing a new login
        if 'partial_login_user_id' in request.session:
            print("Clearing existing partial login state")
            del request.session['partial_login_user_id']
            
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            print(f"Form valid, authenticating user: {username}")
            
            # Get IP address and user agent for logging
            client_ip = get_client_ip(request)
            user_agent = get_user_agent(request)
            
            print(f"Client IP: {client_ip}, User Agent: {user_agent[:100]}...")
            
            user = authenticate(request, username=username, password=password)
            
            if user is not None:
                print(f"Authentication successful for {username}")
                print(f"MFA enabled: {user.mfa_enabled}")



                # Get user's display name (first name + last name or fallback to username)
                display_name = f"{user.first_name} {user.last_name}".strip() or user.username
                print(f"Display name for user: {display_name}")

                # Check if MFA is enabled for this user
                if user.mfa_enabled:
                    print("MFA is enabled - storing user ID in session and redirecting to MFA verification")
                    # Store user ID in session for MFA verification
                    request.session['partial_login_user_id'] = user.id
                    request.session.save()  # Force save session
                    
                    # Return JSON for AJAX or redirect with parameters for form submit
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return JsonResponse({
                            'need_mfa': True,
                            'user_display_name': display_name  # Changed from 'username'
                        })
                    else:
                        # Redirect to same page with parameters to show MFA modal
                        return redirect(f'/auth/?need_mfa=true&username={display_name}')
                else:
                    print("MFA not enabled - completing login directly")
                    
                    # Complete login
                    login(request, user)


                    # Log the successful login with detailed information
                    AuditLog.objects.create(
                        user=user,
                        action='LOGIN',
                        content_type='User',
                        object_id=user.id,
                        description=f'User {display_name} ({username}) logged in successfully',
                        ip_address=client_ip,
                        user_agent=user_agent,
                        extra_data={
                            'login_attempt': True,
                            'success': True,
                            'username_attempted': username,
                            'display_name': display_name,
                            'mfa_required': False,
                            'timestamp': timezone.now().isoformat()
                        }
                    )
                    
                    # Check if user needs to change password
                    if user.must_change_password:
                        print("User must change password - redirecting")
                        # Return JSON for AJAX or redirect with parameters for form submit
                        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                            return JsonResponse({
                                'need_change_password': True
                            })
                        else:
                            # Redirect to same page with parameters to show password change modal
                            return redirect('/auth/?need_change_password=true')
                    
                    # Redirect based on user type
                    if user.user_type == 'GOV':
                        redirect_url = get_dashboard_redirect_url(user)
                    else:
                        # Redirect to landing page as the establishment module is now public portal
                        redirect_url = 'landing_page'
                        
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return JsonResponse({
                            'success': True,
                            'redirect_url': reverse(redirect_url)
                        })
                    else:
                        return redirect(redirect_url)
            else:
                print("Authentication failed - invalid credentials")
                
                # Try to find the user object to get more context for logging
                user_obj = None
                error_message = "Invalid username or password"
                
                try:
                    # Check if username exists to provide more specific error logging
                    user_obj = CustomUser.objects.get(username=username)
                    # User exists but password is wrong
                    error_message = "Invalid password for existing user"
                    print(f"Found existing user {username}, password incorrect")
                except CustomUser.DoesNotExist:
                    # Username doesn't exist
                    error_message = "Username does not exist"
                    print(f"Username {username} does not exist")
                except Exception as e:
                    # Some other error occurred
                    error_message = f"Authentication error: {str(e)}"
                    print(f"Authentication error for {username}: {str(e)}")
                
                # Log the failed login attempt with detailed information
                log_failed_login(username, client_ip, user_agent, error_message, user_obj)
                
                # Add form error
                form.add_error(None, 'Invalid username or password')
                
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({
                        'success': False,
                        'error': 'Invalid username or password'
                    }, status=400)
        else:
            print(f"Form validation failed: {form.errors}")
            
            # Log form validation failure if we have username
            username = request.POST.get('username', 'Unknown')
            if username and username != 'Unknown':
                client_ip = get_client_ip(request)
                user_agent = get_user_agent(request)
                log_failed_login(username, client_ip, user_agent, "Form validation failed", None)
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'success': False,
                    'errors': form.errors
                }, status=400)
    else:
        print("Displaying initial login form")
        form = LoginForm()
    
    # Handle 'next' parameter for redirecting after login
    next_url = request.GET.get('next', '/')
    if next_url:
        print(f"Found 'next' parameter: {next_url}")
    
    # Get team members for display on landing page
    try:
        team_members = TeamMember.objects.filter(is_active=True).order_by('order', 'name')
        print(f"Loaded {team_members.count()} active team members")
    except Exception as e:
        print(f"Error loading team members: {str(e)}")
        team_members = TeamMember.objects.none()

    # Get FAQ items for display on landing page
    try:
        faq_items = FAQItem.objects.filter(is_active=True).order_by('order', 'id')
        print(f"Loaded {faq_items.count()} active FAQ items")
    except Exception as e:
        print(f"Error loading FAQ items: {str(e)}")
        faq_items = FAQItem.objects.none()

    # GET PRIVACY POLICY FROM DATABASE
    try:
        privacy_policy = PrivacyPolicy.get_active_policy()
        print(f"Privacy policy loaded: {privacy_policy.title if privacy_policy else 'None'}")
    except Exception as e:
        print(f"Error loading privacy policy: {str(e)}")
        privacy_policy = None

    # Render the login template WITH LANDING PAGE CONTENT
    print("Rendering login template")
    context = {
        'form': form,
        'next': next_url,
        'landing_page_content': landing_page_content,  # THIS IS THE CRUCIAL FIX
        'team_members': team_members,  # Add team members from database
        'faq_items': faq_items,  # Add FAQ items from database
        'privacy_policy': privacy_policy,  # Add privacy policy from database
    }
    response = render(request, 'accounts/login.html', context)
    print("=============================================================\n\n")
    return response

def logout_view(request):
    """
    Handle user logout with proper logging and session cleanup.
    """
    print(f"\n=== LOGOUT VIEW ===")
    print(f"Request method: {request.method}")
    print(f"User authenticated: {request.user.is_authenticated}")
    
    if request.user.is_authenticated:
        # Get user info before logout for logging
        user = request.user
        username = user.username
        display_name = f"{user.first_name} {user.last_name}".strip() or user.username
        user_type = user.user_type
        
        print(f"Logging out user: {username} ({display_name})")
        
        # Log the logout action with display name
        try:
            AuditLog.objects.create(
                user=user,
                action='LOGOUT',
                content_type='User',
                description=f'User {display_name} ({username}) logged out',
                ip_address=request.META.get('REMOTE_ADDR')
            )
            print(f"Audit log created for logout")
        except Exception as e:
            print(f"Failed to create audit log: {str(e)}")
        
        # Clear any MFA-related session data
        session_keys_to_clear = [
            'partial_login_user_id',
            'totp_secret',
            'password_change_step1',
            'password_change_step2', 
            'password_change_timestamp',
            'password_change_mfa_timestamp',
            'notification_preferences'
        ]
        
        cleared_keys = []
        for key in session_keys_to_clear:
            if key in request.session:
                del request.session[key]
                cleared_keys.append(key)
        
        if cleared_keys:
            print(f"Cleared session keys: {cleared_keys}")
        
        # Force session save before logout
        request.session.save()
        
        # Perform the logout
        logout(request)
        print(f"User {display_name} successfully logged out")
        
        # Handle AJAX logout requests
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({
                'success': True,
                'message': f'Goodbye, {display_name}! You have been logged out successfully.',
                'redirect_url': '/'
            })
    else:
        print("Logout attempted by unauthenticated user")
        
        # Handle AJAX requests for unauthenticated users
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({
                'success': True,
                'message': 'You were already logged out.',
                'redirect_url': '/'
            })
    
    # For regular (non-AJAX) requests, redirect to the root URL (login page)
    print("Redirecting to login page")
    return redirect('/')  # Redirect to the root URL (login page)

@login_required
@ensure_csrf_cookie
def mfa_setup_info_view(request):
    """API endpoint to get MFA setup information"""
    # Get or create TOTP secret
    if 'totp_secret' not in request.session:
        totp_secret = pyotp.random_base32()
        request.session['totp_secret'] = totp_secret
    else:
        totp_secret = request.session['totp_secret']
    
    # Generate QR code
    totp = pyotp.TOTP(totp_secret)
    totp_uri = totp.provisioning_uri(name=request.user.username, issuer_name="VeriSior")
    
    img = qrcode.make(totp_uri)
    buffered = io.BytesIO()
    img.save(buffered)
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode()
    
    # Return data as JSON
    return JsonResponse({
        'qr_code': qr_code_base64,
        'secret_key': totp_secret
    })

@login_required
@csrf_protect
def change_password_view(request):
    """Change password view with AJAX support and proper CSRF protection"""
    print(f"\n=== CHANGE PASSWORD VIEW ===")
    print(f"Method: {request.method}")
    print(f"AJAX Request: {request.headers.get('X-Requested-With') == 'XMLHttpRequest'}")
    print(f"User: {request.user.username}")
    print(f"Session Keys: {list(request.session.keys())}")
    
    if request.method == 'POST':
        # For AJAX requests
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            print("Processing AJAX password change request")
            
            current_password = request.POST.get('current_password')
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')
            
            print(f"Received passwords - Current: {'*' * len(current_password) if current_password else 'None'}")
            print(f"New: {'*' * len(new_password) if new_password else 'None'}")
            print(f"Confirm: {'*' * len(confirm_password) if confirm_password else 'None'}")
            
            # Basic validation
            errors = {}
            if not current_password:
                errors['current_password'] = ['Current password is required']
            if not new_password:
                errors['new_password'] = ['New password is required']
            if not confirm_password:
                errors['confirm_password'] = ['Confirm password is required']
            if new_password and confirm_password and new_password != confirm_password:
                errors['confirm_password'] = ["Passwords don't match"]
            
            # Password strength validation
            if new_password:
                if len(new_password) < 8:
                    errors.setdefault('new_password', []).append('Password must be at least 8 characters long')
                if not any(c.isupper() for c in new_password):
                    errors.setdefault('new_password', []).append('Password must contain at least one uppercase letter')
                if not any(c.islower() for c in new_password):
                    errors.setdefault('new_password', []).append('Password must contain at least one lowercase letter')
                if not any(c.isdigit() for c in new_password):
                    errors.setdefault('new_password', []).append('Password must contain at least one number')
                if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in new_password):
                    errors.setdefault('new_password', []).append('Password must contain at least one special character')
            
            if errors:
                print(f"Validation errors: {errors}")
                return JsonResponse({'success': False, 'errors': errors}, status=400)
            
            # Verify current password
            if not request.user.check_password(current_password):
                print("Current password verification failed")
                return JsonResponse({
                    'success': False, 
                    'error': 'Current password is incorrect'
                }, status=400)
            
            print("Current password verified successfully")
            
            try:
                # Set new password
                user = request.user
                user.set_password(new_password)
                user.must_change_password = False
                user.save()
                
                print("Password updated successfully")
                
                # Update session authentication hash to prevent logout
                update_session_auth_hash(request, user)
                print("Session auth hash updated")
                
                # Log the action
                AuditLog.objects.create(
                    user=user,
                    action='UPDATE',
                    content_type='User',
                    description=f'User {user.username} changed password',
                    ip_address=request.META.get('REMOTE_ADDR')
                )
                
                # Return success with next steps
                response_data = {'success': True}
                if not user.mfa_enabled:
                    print("User needs MFA setup")
                    response_data['need_mfa_setup'] = True
                else:
                    print("Redirecting to dashboard")
                    # Redirect based on user type
                    if user.user_type == 'GOV':
                        redirect_url = reverse('government_dashboard')
                    else:
                        redirect_url = reverse('landing_page')
                        
                    response_data['redirect_url'] = redirect_url
                
                print(f"Returning response: {response_data}")
                return JsonResponse(response_data)
                
            except Exception as e:
                print(f"Error during password change: {str(e)}")
                return JsonResponse({
                    'success': False,
                    'error': f'An error occurred while changing password: {str(e)}'
                }, status=500)
        
        # For non-AJAX requests, process form and redirect appropriately
        print("Processing non-AJAX password change request")
        form = PasswordChangeForm(request.POST)
        if form.is_valid():
            current_password = form.cleaned_data.get('current_password')
            new_password = form.cleaned_data.get('new_password')
            
            # Verify current password
            if not request.user.check_password(current_password):
                form.add_error('current_password', 'Current password is incorrect')
                return redirect('/auth/?need_change_password=true')
            
            # Set new password
            user = request.user
            user.set_password(new_password)
            user.must_change_password = False
            user.save()
            
            # Update session authentication hash to prevent logout
            update_session_auth_hash(request, user)
            
            # Log the action
            AuditLog.objects.create(
                user=user,
                action='UPDATE',
                content_type='User',
                description=f'User {user.username} changed password',
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            # Redirect to MFA setup if not already enabled
            if not user.mfa_enabled:
                return redirect('/auth/?need_mfa_setup=true')
            
            # Redirect based on user type
            if user.user_type == 'GOV':
                return redirect('government_dashboard')
            else:
                return redirect('landing_page')
    
    # For GET requests, redirect to homepage with parameter
    return redirect('/auth/?need_change_password=true')

@login_required
@csrf_protect
def mfa_setup_view(request):
    """MFA setup view with AJAX support and proper CSRF protection"""
    print(f"\n=== MFA SETUP VIEW ===")
    print(f"Method: {request.method}")
    print(f"User: {request.user.username}")
    
    # Get or create TOTP secret from session
    if 'totp_secret' not in request.session:
        totp_secret = pyotp.random_base32()
        request.session['totp_secret'] = totp_secret
        print(f"Generated new TOTP secret: {totp_secret}")
    else:
        totp_secret = request.session['totp_secret']
        print(f"Using existing TOTP secret: {totp_secret}")
    
    # Generate QR code for Google Authenticator
    totp = pyotp.TOTP(totp_secret)
    totp_uri = totp.provisioning_uri(name=request.user.username, issuer_name="VeriSior")
    
    img = qrcode.make(totp_uri)
    buffered = io.BytesIO()
    img.save(buffered)
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode()
    
    if request.method == 'POST':
        # Keep original AJAX check and code verification logic
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            print("Processing AJAX MFA setup request")
            verification_code = request.POST.get('verification_code')
            
            if not verification_code:
                return JsonResponse({'success': False, 'error': 'Verification code is required'}, status=400)
            
            # For debugging - print the current code that should match
            current_code = totp.now()
            print(f"Entered code: {verification_code}")
            print(f"Expected code: {current_code}")
            print(f"Secret key used: {totp_secret}")
            
            # Verify with a window of 1 to allow for slight time skew
            if totp.verify(verification_code, valid_window=1):
                print("MFA code verified successfully")
                try:
                    device, created = TOTPDevice.objects.get_or_create(
                        user=request.user,
                        defaults={'name': f"{request.user.username}'s device"}
                    )
                    device.key = totp_secret
                    device.confirmed = True
                    device.save()
                    
                    print(f"TOTP device {'created' if created else 'updated'}")
                    
                    # Update user MFA status
                    request.user.mfa_enabled = True
                    request.user.save()
                    
                    # Clear the secret from session
                    if 'totp_secret' in request.session:
                        del request.session['totp_secret']
                    
                    # Log the action
                    AuditLog.objects.create(
                        user=request.user,
                        action='UPDATE',
                        content_type='User',
                        description=f'User {request.user.username} enabled MFA',
                        ip_address=request.META.get('REMOTE_ADDR')
                    )
                    
                    # Return success with redirect URL
                    if request.user.user_type == 'GOV':
                        redirect_url = reverse('government_dashboard')
                    else:
                        redirect_url = reverse('landing_page')
                        
                    print(f"MFA setup complete, redirecting to: {redirect_url}")
                    return JsonResponse({
                        'success': True,
                        'redirect_url': redirect_url
                    })
                except Exception as e:
                    print(f"Error setting up MFA: {str(e)}")
                    return JsonResponse({
                        'success': False,
                        'error': f'Error setting up MFA: {str(e)}'
                    }, status=500)
            else:
                print("MFA code verification failed")
                return JsonResponse({
                    'success': False, 
                    'error': 'Invalid verification code. Please try again with a new code.'
                }, status=400)
        else:
            # Original non-AJAX form submission - redirect to homepage with modal parameter
            print("Processing non-AJAX MFA setup request")
            form = MFASetupForm(request.POST)
            if form.is_valid():
                verification_code = form.cleaned_data.get('verification_code')
                
                # Verify with a window of 1 to allow for slight time skew
                if totp.verify(verification_code, valid_window=1):
                    # Save the secret key and update user MFA status
                    try:
                        device, created = TOTPDevice.objects.get_or_create(
                            user=request.user,
                            defaults={'name': f"{request.user.username}'s device"}
                        )
                        device.key = totp_secret
                        device.confirmed = True
                        device.save()
                        
                        # Update user MFA status
                        request.user.mfa_enabled = True
                        request.user.save()
                        
                        # Clear the secret from session
                        if 'totp_secret' in request.session:
                            del request.session['totp_secret']
                        
                        # Log the action
                        AuditLog.objects.create(
                            user=request.user,
                            action='UPDATE',
                            content_type='User',
                            description=f'User {request.user.username} enabled MFA',
                            ip_address=request.META.get('REMOTE_ADDR')
                        )
                        
                        # Redirect based on user type
                        if request.user.user_type == 'GOV':
                            return redirect('government_dashboard')
                        else:
                            return redirect('landing_page')
                    except Exception as e:
                        print(f"Error in non-AJAX MFA setup: {str(e)}")
                        return redirect('/auth/?need_mfa_setup=true&error=setup_failed')
                else:
                    return redirect('/auth/?need_mfa_setup=true&error=invalid_code')
    
    # For GET requests, redirect to homepage with parameter to show modal
    return redirect('/auth/?need_mfa_setup=true')

@csrf_protect
def mfa_verify_view(request):
    """
    MFA verification view for two-factor authentication with AJAX support and proper CSRF protection.
    """
    print(f"\n=== MFA VERIFY VIEW ===")
    print(f"Method: {request.method}")
    print(f"Session Keys: {list(request.session.keys())}")
    
    # Get user ID from session
    user_id = request.session.get('partial_login_user_id')
    print(f"Partial login user ID: {user_id}")
    
    # If no user ID in session, redirect to login
    if user_id is None:
        print("No partial login user ID found, redirecting to login")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'success': False, 'redirect_url': reverse('login')}, status=401)
        return redirect('login')
    
    # Get the user object
    try:
        user = CustomUser.objects.get(pk=user_id)
        print(f"Found user: {user.username}")
        # Get display name for user
        display_name = f"{user.first_name} {user.last_name}".strip() or user.username
        print(f"Display name: {display_name}")
    except CustomUser.DoesNotExist:
        print("User not found, clearing session and redirecting to login")
        if 'partial_login_user_id' in request.session:
            del request.session['partial_login_user_id']
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'success': False, 'redirect_url': reverse('login')}, status=401)
        return redirect('login')
    
    # Process the MFA verification
    if request.method == 'POST':
        # Handle AJAX requests
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            print("Processing AJAX MFA verification")
            verification_code = request.POST.get('verification_code')
            if not verification_code:
                return JsonResponse({'success': False, 'error': 'Verification code required'}, status=400)
            
            print(f"Verification code: {verification_code}")
            
            # Get the user's TOTP device
            try:
                device = TOTPDevice.objects.get(user=user, confirmed=True)
                print(f"Found TOTP device for user")
                
                # Verify the code
                totp = pyotp.TOTP(device.key)
                current_code = totp.now()
                print(f"Expected code: {current_code}")
                
                if totp.verify(verification_code, valid_window=1):
                    print("MFA verification successful")
                    
                    # CRITICAL FIX: Complete login BEFORE clearing session
                    from django.contrib.auth import get_backends
                    backend = get_backends()[0]
                    user.backend = f"{backend.__module__}.{backend.__class__.__name__}"
                    
                    # Log the user in
                    login(request, user)
                    print("User logged in successfully")
                    
                    # NOW clear partial login session data
                    if 'partial_login_user_id' in request.session:
                        del request.session['partial_login_user_id']
                    
                    # Force session save
                    request.session.modified = True
                    
                    # Log successful login with display name
                    AuditLog.objects.create(
                        user=user,
                        action='LOGIN',
                        content_type='User',
                        description=f'User {display_name} ({user.username}) logged in with MFA',
                        ip_address=request.META.get('REMOTE_ADDR')
                    )
                    
                    # Redirect based on user type and password status
                    if user.must_change_password:
                        print("User must change password")
                        return JsonResponse({
                            'need_change_password': True
                        })
                    else:
                        # Redirect based on user type
                        if user.user_type == 'GOV':
                            redirect_url = reverse(get_dashboard_redirect_url(user))
                        else:
                            redirect_url = reverse('landing_page')
                            
                        print(f"Redirecting to: {redirect_url}")
                        return JsonResponse({
                            'success': True,
                            'redirect_url': redirect_url
                        })
                else:
                    print("MFA verification failed")
                    # Log failed MFA attempt
                    try:
                        AuditLog.objects.create(
                            user=user,
                            action='LOGIN_FAILED',
                            content_type='User',
                            description=f'Failed MFA verification for {display_name} ({user.username})',
                            ip_address=request.META.get('REMOTE_ADDR')
                        )
                    except Exception as e:
                        print(f"Failed to log MFA failure: {str(e)}")
                    
                    return JsonResponse({'success': False, 'error': 'Invalid verification code'}, status=400)
            except TOTPDevice.DoesNotExist:
                print("TOTP device not found for user")
                return JsonResponse({'success': False, 'error': 'MFA device not found. Please contact your administrator.'}, status=400)
            except Exception as e:
                print(f"Error during MFA verification: {str(e)}")
                return JsonResponse({'success': False, 'error': 'An error occurred during verification. Please try again.'}, status=500)
        else:
            # Handle regular form submission - redirect to homepage with parameters
            print("Processing non-AJAX MFA verification")
            form = MFAVerifyForm(request.POST)
            if form.is_valid():
                verification_code = form.cleaned_data.get('verification_code')
                
                # Get the user's TOTP device
                try:
                    device = TOTPDevice.objects.get(user=user, confirmed=True)
                    
                    # Verify the code
                    totp = pyotp.TOTP(device.key)
                    if totp.verify(verification_code, valid_window=1):
                        # Complete the login process
                        from django.contrib.auth import get_backends
                        backend = get_backends()[0]
                        user.backend = f"{backend.__module__}.{backend.__class__.__name__}"
                        login(request, user)

                        # Clear partial login session data
                        if 'partial_login_user_id' in request.session:
                            del request.session['partial_login_user_id']
                        
                        # Force session save
                        request.session.modified = True
                        
                        # Log successful login with MFA and display name
                        AuditLog.objects.create(
                            user=user,
                            action='LOGIN',
                            content_type='User',
                            description=f'User {display_name} ({user.username}) logged in with MFA',
                            ip_address=request.META.get('REMOTE_ADDR')
                        )
                        
                        # Redirect based on user type and password requirements
                        if user.must_change_password:
                            return redirect('/auth/?need_change_password=true')
                        elif user.user_type == 'GOV':
                            return redirect(get_dashboard_redirect_url(user))
                        else:
                            return redirect('landing_page')
                    else:
                        # Log failed attempt
                        try:
                            AuditLog.objects.create(
                                user=user,
                                action='LOGIN_FAILED',
                                content_type='User',
                                description=f'Failed MFA verification for {display_name} ({user.username})',
                                ip_address=request.META.get('REMOTE_ADDR')
                            )
                        except Exception as e:
                            print(f"Failed to log MFA failure: {str(e)}")
                        
                        return redirect(f'/auth/?need_mfa=true&username={display_name}&error=invalid_code')
                except TOTPDevice.DoesNotExist:
                    print("TOTP device not found for user")
                    return redirect(f'/auth/?need_mfa=true&username={display_name}&error=device_not_found')
                except Exception as e:
                    print(f"Error in non-AJAX MFA verification: {str(e)}")
                    return redirect(f'/auth/?need_mfa=true&username={display_name}&error=verification_failed')
            else:
                print(f"Form validation failed: {form.errors}")
                return redirect(f'/auth/?need_mfa=true&username={display_name}&error=invalid_form')
    
    # For GET requests, redirect to homepage with parameters to show modal
    print(f"GET request - redirecting to show MFA modal for {display_name}")
    return redirect(f'/auth/?need_mfa=true&username={display_name}')

@login_required
def profile_view(request):
    return render(request, 'accounts/profile.html')

@login_required
def settings_view(request):
    """Enhanced settings view with reports and system configuration"""
    from core.models import AuditLog
    
    # Get some context data for the template
    context = {
        'next_global_count': cache.get('system_settings', {}).get('next_global_count', 1),
        # Statistics for reports section
        'total_seniors': 1247,  # Replace with actual query
        'active_users': CustomUser.objects.filter(is_active=True).count(),
        'pending_approvals': 23,  # Replace with actual query
        'total_verifications': 156,  # Replace with actual query
    }
    
    return render(request, 'core/settings.html', context)

@login_required
def profile_update_view(request):
    """Update user profile information - FIXED WITH FILE UPLOAD"""
    if request.method == 'POST':
        user = request.user
        
        # Validate and update basic profile fields
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        email = request.POST.get('email', '').strip()
        phone_number = request.POST.get('phone_number', '').strip()
        department = request.POST.get('department', '').strip()
        
        # Validate email format
        if email:
            try:
                validate_email(email)
                user.email = email
            except ValidationError:
                messages.error(request, 'Please enter a valid email address.')
                return redirect('profile')
        
        # Update text fields
        user.first_name = first_name
        user.last_name = last_name
        user.phone_number = phone_number
        user.department = department
        
        # Handle profile picture upload
        if 'profile_picture' in request.FILES:
            profile_picture = request.FILES['profile_picture']
            
            # Validate file size (max 5MB)
            if profile_picture.size > 5 * 1024 * 1024:
                messages.error(request, 'Profile picture must be less than 5MB.')
                return redirect('profile')
            
            # Validate file type
            allowed_types = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif']
            if profile_picture.content_type not in allowed_types:
                messages.error(request, 'Profile picture must be JPG, PNG, or GIF.')
                return redirect('profile')
            
            # Delete old profile picture if exists
            if user.profile_picture:
                try:
                    user.profile_picture.delete(save=False)
                except:
                    pass
            
            # Save new profile picture
            user.profile_picture = profile_picture
        
        # Save user
        user.save()
        
        # Log the action
        AuditLog.objects.create(
            user=user,
            action='UPDATE',
            content_type='User',
            object_id=user.id,
            description=f'Updated profile: {first_name} {last_name}, {email}' + (' with new profile picture' if 'profile_picture' in request.FILES else ''),
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        messages.success(request, 'Profile updated successfully!')
        return redirect('profile')
    
    return redirect('profile')

@login_required
def notification_settings_view(request):
    """Update notification preferences - REAL IMPLEMENTATION"""
    if request.method == 'POST':
        user = request.user
        
        # Get actual checkbox values
        email_new_applications = 'email_new_applications' in request.POST
        email_verification_requests = 'email_verification_requests' in request.POST
        email_system_alerts = 'email_system_alerts' in request.POST
        dashboard_pending_approvals = 'dashboard_pending_approvals' in request.POST
        dashboard_recent_activity = 'dashboard_recent_activity' in request.POST
        
        # Store in user session (since CustomUser doesn't have these fields)
        request.session['notification_preferences'] = {
            'email_new_applications': email_new_applications,
            'email_verification_requests': email_verification_requests,
            'email_system_alerts': email_system_alerts,
            'dashboard_pending_approvals': dashboard_pending_approvals,
            'dashboard_recent_activity': dashboard_recent_activity,
        }
        
        # Log what was actually changed
        preferences_summary = []
        if email_new_applications:
            preferences_summary.append('email notifications for new applications')
        if email_verification_requests:
            preferences_summary.append('email notifications for verification requests')
        if email_system_alerts:
            preferences_summary.append('email system alerts')
        
        AuditLog.objects.create(
            user=user,
            action='UPDATE',
            content_type='NotificationSettings',
            object_id=user.id,
            description=f'Updated notification preferences: {", ".join(preferences_summary)}',
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        messages.success(request, 'Notification preferences saved successfully!')
        return redirect('settings')
    
    return redirect('settings')

@login_required
@role_required('SA', 'RA')
def system_settings_view(request):
    """Handle system settings updates"""
    if request.method == 'POST':
        # Get actual form values
        force_mfa = 'force_mfa' in request.POST
        password_expiry = 'password_expiry' in request.POST
        audit_all_actions = 'audit_all_actions' in request.POST
        
        # Store system settings in cache
        system_settings = {
            'force_mfa': force_mfa,
            'password_expiry': password_expiry,
            'audit_all_actions': audit_all_actions,
            'updated_by': request.user.username,
            'updated_at': timezone.now().isoformat(),
        }
        
        # Store in cache
        cache.set('system_settings', system_settings, timeout=None)
        
        # Log the actual changes
        changes = []
        changes.append(f'Force MFA: {"enabled" if force_mfa else "disabled"}')
        changes.append(f'Password expiry: {"enabled" if password_expiry else "disabled"}')
        changes.append(f'Audit all actions: {"enabled" if audit_all_actions else "disabled"}')
        
        from core.models import AuditLog
        AuditLog.objects.create(
            user=request.user,
            action='UPDATE',
            content_type='SystemSettings',
            description=f'System settings updated: {", ".join(changes)}',
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        messages.success(request, f'System settings updated successfully! Changes: {", ".join(changes)}')
        return redirect('settings')
    
    return redirect('settings')

@login_required
@role_required('SA', 'AD', 'RA')
def audit_logs_view(request):
    """View audit logs - REAL IMPLEMENTATION"""
    # Get actual audit logs from database
    logs = AuditLog.objects.filter(
        user__user_type=request.user.user_type
    ).order_by('-timestamp')
    
    # Apply filters if provided
    action_filter = request.GET.get('action', '')
    date_filter = request.GET.get('date', '')
    user_filter = request.GET.get('user', '')
    
    if action_filter:
        logs = logs.filter(action=action_filter)
    
    if date_filter:
        try:
            from datetime import datetime
            filter_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
            logs = logs.filter(timestamp__date=filter_date)
        except ValueError:
            pass
    
    if user_filter:
        logs = logs.filter(user__username__icontains=user_filter)
    
    # Paginate results
    from django.core.paginator import Paginator
    paginator = Paginator(logs, 25)  # 25 logs per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get real statistics
    total_actions = logs.count()
    today_actions = logs.filter(timestamp__date=timezone.now().date()).count()
    failed_logins = logs.filter(action='LOGIN', description__icontains='failed').count()
    
    context = {
        'logs': page_obj,
        'total_actions': total_actions,
        'today_actions': today_actions,
        'failed_logins': failed_logins,
        'current_action_filter': action_filter,
        'current_date_filter': date_filter,
        'current_user_filter': user_filter,
        'action_choices': AuditLog.ACTION_CHOICES,
    }
    
    return render(request, 'core/audit_logs.html', context)

# Import password reset views from separate file
from .password_reset import password_reset_request, password_reset_verify, password_reset_complete

def get_dashboard_redirect_url(user):
    """
    Get the appropriate dashboard URL based on user role and type
    """
    if user.user_type == 'GOV':
        # All government users go to government dashboard
        return 'government_dashboard'
    else:
        # Establishment users go to public portal
        return 'landing_page'
    
@login_required
@root_admin_required
def mfa_disable_view(request):
    """
    Disable MFA for the current user (Root Admin only)
    Only Root Administrators can disable their own MFA
    """
    if request.method == 'POST':
        user = request.user
        
        # Verify user is Root Admin
        if user.role != 'RA':
            messages.error(request, 'Only Root Administrators can disable MFA')
            return redirect('settings')
        
        try:
            # Find and delete the user's TOTP device
            device = TOTPDevice.objects.get(user=user, confirmed=True)
            device.delete()
            
            # Update user MFA status
            user.mfa_enabled = False
            user.save()
            
            # Log the action
            AuditLog.objects.create(
                user=user,
                action='UPDATE',
                content_type='User',
                object_id=user.id,
                description=f'Root Administrator {user.username} disabled MFA',
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            messages.success(request, 'Two-Factor Authentication has been disabled successfully')
            
        except TOTPDevice.DoesNotExist:
            messages.warning(request, 'MFA was not enabled for your account')
        except Exception as e:
            messages.error(request, f'Failed to disable MFA: {str(e)}')
            
        return redirect('settings')
    
    # For GET requests, redirect to settings
    return redirect('settings')

@login_required
def mfa_disable_user_view(request, user_id):
    """
    Disable MFA for another user (Root Admin only)
    Allows Root Admin to disable MFA for any user
    """
    if request.method == 'POST':
        current_user = request.user

        # Verify current user is Root Admin
        if current_user.role != 'RA':
            messages.error(request, 'Only Root Administrators can disable MFA for other users')
            return redirect('user_detail', pk=user_id)

        try:
            # Get the target user
            target_user = CustomUser.objects.get(pk=user_id)

            # Check if user has MFA enabled
            if not target_user.mfa_enabled:
                messages.warning(request, f'MFA is already disabled for user {target_user.username}')
                return redirect('user_detail', pk=user_id)

            # Disable MFA (but keep the TOTP device for re-enabling later)
            target_user.mfa_enabled = False
            target_user.save()

            # Log the action
            AuditLog.objects.create(
                user=current_user,
                action='UPDATE',
                content_type='User',
                object_id=target_user.id,
                description=f'Root Administrator {current_user.username} disabled MFA for user {target_user.username}',
                ip_address=request.META.get('REMOTE_ADDR')
            )

            messages.success(request, f'Two-Factor Authentication disabled for user {target_user.username}. The MFA setup will be preserved and can be re-enabled.')

        except CustomUser.DoesNotExist:
            messages.error(request, 'User not found')
            return redirect('user_list')
        except Exception as e:
            messages.error(request, f'Failed to disable MFA: {str(e)}')

        return redirect('user_detail', pk=user_id)

    # For GET requests, redirect to user detail page
    return redirect('user_detail', pk=user_id)

@login_required
def mfa_enable_user_view(request, user_id):
    """
    Re-enable MFA for another user (Root Admin only)
    Allows Root Admin to re-enable MFA using the previously saved TOTP device
    """
    if request.method == 'POST':
        current_user = request.user

        # Verify current user is Root Admin
        if current_user.role != 'RA':
            messages.error(request, 'Only Root Administrators can enable MFA for other users')
            return redirect('user_detail', pk=user_id)

        try:
            # Get the target user
            target_user = CustomUser.objects.get(pk=user_id)

            # Check if user already has MFA enabled
            if target_user.mfa_enabled:
                messages.warning(request, f'MFA is already enabled for user {target_user.username}')
                return redirect('user_detail', pk=user_id)

            # Check if user has a TOTP device (from previous setup)
            try:
                device = TOTPDevice.objects.get(user=target_user, confirmed=True)

                # Re-enable MFA using the existing device
                target_user.mfa_enabled = True
                target_user.save()

                # Log the action
                AuditLog.objects.create(
                    user=current_user,
                    action='UPDATE',
                    content_type='User',
                    object_id=target_user.id,
                    description=f'Root Administrator {current_user.username} re-enabled MFA for user {target_user.username}',
                    ip_address=request.META.get('REMOTE_ADDR')
                )

                messages.success(request, f'Two-Factor Authentication re-enabled for user {target_user.username}. They can now use their previous MFA setup.')

            except TOTPDevice.DoesNotExist:
                messages.error(request, f'No MFA setup found for user {target_user.username}. They need to set up MFA first.')

        except CustomUser.DoesNotExist:
            messages.error(request, 'User not found')
            return redirect('user_list')
        except Exception as e:
            messages.error(request, f'Failed to enable MFA: {str(e)}')

        return redirect('user_detail', pk=user_id)

    # For GET requests, redirect to user detail page
    return redirect('user_detail', pk=user_id)

@login_required
def change_password_page_view(request):
    """Dedicated change password page for logged-in users"""
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        
        # Validation
        errors = {}
        if not current_password:
            errors['current_password'] = 'Current password is required'
        if not new_password:
            errors['new_password'] = 'New password is required'
        if not confirm_password:
            errors['confirm_password'] = 'Confirm password is required'
        if new_password and confirm_password and new_password != confirm_password:
            errors['confirm_password'] = "Passwords don't match"
        
        # Password strength validation
        if new_password:
            if len(new_password) < 8:
                errors.setdefault('new_password', []).append('Password must be at least 8 characters long')
            if not any(c.isupper() for c in new_password):
                errors.setdefault('new_password', []).append('Password must contain at least one uppercase letter')
            if not any(c.islower() for c in new_password):
                errors.setdefault('new_password', []).append('Password must contain at least one lowercase letter')
            if not any(c.isdigit() for c in new_password):
                errors.setdefault('new_password', []).append('Password must contain at least one number')
        
        if errors:
            for field, error_list in errors.items():
                if isinstance(error_list, list):
                    for error in error_list:
                        messages.error(request, f"{field.replace('_', ' ').title()}: {error}")
                else:
                    messages.error(request, f"{field.replace('_', ' ').title()}: {error_list}")
            return render(request, 'accounts/change_password.html')
        
        # Verify current password
        if not request.user.check_password(current_password):
            messages.error(request, 'Current password is incorrect')
            return render(request, 'accounts/change_password.html')
        
        try:
            # Update password
            user = request.user
            user.set_password(new_password)
            user.save()
            
            # Update session to prevent logout
            update_session_auth_hash(request, user)
            
            # Log the action
            AuditLog.objects.create(
                user=user,
                action='UPDATE',
                content_type='User',
                description=f'User {user.username} changed password via settings',
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            messages.success(request, 'Password changed successfully!')
            return redirect('settings')
            
        except Exception as e:
            messages.error(request, f'Error changing password: {str(e)}')
            return render(request, 'accounts/change_password.html')
    
    return render(request, 'accounts/change_password.html')

@login_required
def force_change_password_view(request):
    """Force change password for first-time login (keep the existing modal logic)"""
    # This is the existing change_password_view logic for first-time logins
    # Keep all the AJAX and modal logic here
    return change_password_view(request)

# Add these functions to your authentication/views.py file

@login_required
@csrf_protect
def verify_current_password(request):
    """AJAX endpoint to verify current password"""
    print(f"verify_current_password called - Method: {request.method}")
    print(f"Is AJAX: {request.headers.get('X-Requested-With') == 'XMLHttpRequest'}")
    
    if request.method == 'POST' and request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        current_password = request.POST.get('current_password')
        print(f"Current password provided: {bool(current_password)}")
        
        if not current_password:
            return JsonResponse({'success': False, 'error': 'Current password is required'}, status=400)
        
        # Verify current password
        password_valid = request.user.check_password(current_password)
        print(f"Password valid: {password_valid}")
        
        if password_valid:
            # Store verification in session temporarily
            request.session['password_change_step1'] = True
            request.session['password_change_timestamp'] = timezone.now().timestamp()
            print("Session updated with step1 verification")
            return JsonResponse({'success': True})
        else:
            return JsonResponse({'success': False, 'error': 'Current password is incorrect'}, status=400)
    
    return JsonResponse({'success': False, 'error': 'Invalid request'}, status=400)

@login_required
@csrf_protect
def verify_mfa_code(request):
    """AJAX endpoint to verify MFA code for password change"""
    print(f"verify_mfa_code called - Method: {request.method}")
    print(f"Is AJAX: {request.headers.get('X-Requested-With') == 'XMLHttpRequest'}")
    
    if request.method == 'POST' and request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        mfa_code = request.POST.get('mfa_code')
        print(f"MFA code provided: {bool(mfa_code)}")
        
        if not mfa_code:
            return JsonResponse({'success': False, 'error': 'MFA code is required'}, status=400)
        
        # Check if step 1 was completed
        step1_completed = request.session.get('password_change_step1')
        print(f"Step 1 completed: {step1_completed}")
        
        if not step1_completed:
            return JsonResponse({'success': False, 'error': 'Please verify your current password first'}, status=400)
        
        # Check if MFA is enabled for user
        if not request.user.mfa_enabled:
            return JsonResponse({'success': False, 'error': 'MFA is not enabled for your account'}, status=400)
        
        try:
            # Get user's TOTP device
            device = TOTPDevice.objects.get(user=request.user, confirmed=True)
            print(f"TOTP device found: {device.name}")
            
            # Verify the code
            totp = pyotp.TOTP(device.key)
            current_code = totp.now()
            print(f"Current TOTP code should be: {current_code}")
            print(f"User provided code: {mfa_code}")
            
            code_valid = totp.verify(mfa_code, valid_window=1)
            print(f"MFA code valid: {code_valid}")
            
            if code_valid:
                # Store MFA verification in session
                request.session['password_change_step2'] = True
                request.session['password_change_mfa_timestamp'] = timezone.now().timestamp()
                print("Session updated with step2 verification")
                
                # Log MFA verification for password change
                AuditLog.objects.create(
                    user=request.user,
                    action='OTHER',
                    content_type='PasswordChange',
                    description=f'MFA verified for password change by {request.user.username}',
                    ip_address=request.META.get('REMOTE_ADDR')
                )
                
                return JsonResponse({'success': True})
            else:
                return JsonResponse({'success': False, 'error': 'Invalid MFA code'}, status=400)
                
        except TOTPDevice.DoesNotExist:
            print("TOTP device not found")
            return JsonResponse({'success': False, 'error': 'MFA device not found'}, status=400)
        except Exception as e:
            print(f"Error in MFA verification: {str(e)}")
            return JsonResponse({'success': False, 'error': f'Error verifying MFA: {str(e)}'}, status=500)
    
    return JsonResponse({'success': False, 'error': 'Invalid request'}, status=400)

@login_required
@csrf_protect
def change_password_secure_view(request):
    """Secure password change with MFA verification"""
    if request.method == 'POST':
        # Verify that both steps were completed
        step1_completed = request.session.get('password_change_step1', False)
        step2_completed = request.session.get('password_change_step2', False)
        
        if not step1_completed or not step2_completed:
            messages.error(request, 'Security verification incomplete. Please start over.')
            return redirect('profile')
        
        # Check timestamp to ensure verification is recent (within 10 minutes)
        password_timestamp = request.session.get('password_change_timestamp', 0)
        mfa_timestamp = request.session.get('password_change_mfa_timestamp', 0)
        current_timestamp = timezone.now().timestamp()
        
        if (current_timestamp - password_timestamp > 600 or  # 10 minutes
            current_timestamp - mfa_timestamp > 600):
            messages.error(request, 'Security verification expired. Please start over.')
            # Clear session data
            request.session.pop('password_change_step1', None)
            request.session.pop('password_change_step2', None)
            request.session.pop('password_change_timestamp', None)
            request.session.pop('password_change_mfa_timestamp', None)
            return redirect('profile')
        
        # Get form data
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        password_verified = request.POST.get('password_verified') == 'true'
        mfa_verified = request.POST.get('mfa_verified') == 'true'
        
        # Validation
        errors = []
        
        if not password_verified or not mfa_verified:
            errors.append('Security verification incomplete')
        
        if not new_password:
            errors.append('New password is required')
        
        if not confirm_password:
            errors.append('Password confirmation is required')
        
        if new_password != confirm_password:
            errors.append('Passwords do not match')
        
        # Password strength validation
        if new_password:
            if len(new_password) < 8:
                errors.append('Password must be at least 8 characters long')
            if not any(c.isupper() for c in new_password):
                errors.append('Password must contain at least one uppercase letter')
            if not any(c.islower() for c in new_password):
                errors.append('Password must contain at least one lowercase letter')
            if not any(c.isdigit() for c in new_password):
                errors.append('Password must contain at least one number')
            if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in new_password):
                errors.append('Password must contain at least one special character')
        
        # Double-check current password one more time
        if current_password and not request.user.check_password(current_password):
            errors.append('Current password is incorrect')
        
        if errors:
            for error in errors:
                messages.error(request, error)
            return redirect('profile')
        
        try:
            # Update password
            user = request.user
            user.set_password(new_password)
            user.must_change_password = False
            user.save()
            
            # Update session to prevent logout
            update_session_auth_hash(request, user)
            
            # Clear password change session data
            request.session.pop('password_change_step1', None)
            request.session.pop('password_change_step2', None)
            request.session.pop('password_change_timestamp', None)
            request.session.pop('password_change_mfa_timestamp', None)
            
            # Log the successful password change
            AuditLog.objects.create(
                user=user,
                action='UPDATE',
                content_type='User',
                object_id=user.id,
                description=f'Password changed securely with MFA verification by {user.username}',
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            messages.success(request, 'Password changed successfully! Your account security has been updated.')
            return redirect('profile')
            
        except Exception as e:
            messages.error(request, f'Error changing password: {str(e)}')
            return redirect('profile')
    
    return redirect('profile')

@login_required
def cancel_password_change(request):
    """Cancel password change process and clear session data"""
    # Clear all password change session data
    request.session.pop('password_change_step1', None)
    request.session.pop('password_change_step2', None)
    request.session.pop('password_change_timestamp', None)
    request.session.pop('password_change_mfa_timestamp', None)

    messages.info(request, 'Password change cancelled.')
    return redirect('profile')


@login_required
def no_access_view(request):
    """
    View for users who don't have any specific permissions.
    Displays a message asking them to contact their administrator.
    """
    # Get user's permission summary for debugging
    permission_summary = request.user.get_permission_summary()

    # Check if user has ANY permissions at all
    has_any_permissions = permission_summary['granted_count'] > 0

    context = {
        'user': request.user,
        'has_any_permissions': has_any_permissions,
        'permission_summary': permission_summary,
        'contact_admin_message': 'Please contact your system administrator to be granted appropriate permissions.',
    }

    return render(request, 'accounts/no_access.html', context)
