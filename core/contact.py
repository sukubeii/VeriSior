from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.core.paginator import Paginator
from django.db.models import Q
from django.contrib import messages
from .models import ContactMessage, AuditLog
from accounts.decorators import role_required
from accounts.permission_decorators import requires_permission
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
import json
import logging
import re

logger = logging.getLogger(__name__)

@csrf_protect
@require_http_methods(["POST"])
def contact_form_view(request):
    """Handle contact form submissions"""
    
    # Check if it's an AJAX request
    if not request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({'error': 'Invalid request'}, status=400)
    
    try:
        # Get form data - Use correct field names from JavaScript
        full_name = request.POST.get('full_name', '').strip()
        email = request.POST.get('email', '').strip()
        phone = request.POST.get('phone', '').strip()
        subject = request.POST.get('subject', '').strip()
        message = request.POST.get('message', '').strip()
        
        # Validate required fields
        if not all([full_name, email, subject, message]):
            return JsonResponse({
                'error': 'Please fill in all required fields (Name, Email, Subject, and Message)'
            }, status=400)
        
        # Validate email format
        email_pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
        if not re.match(email_pattern, email):
            return JsonResponse({
                'error': 'Please enter a valid email address'
            }, status=400)
        
        # Validate name length and characters
        if len(full_name) < 2 or len(full_name) > 100:
            return JsonResponse({
                'error': 'Name must be between 2 and 100 characters'
            }, status=400)
        
        # Validate name contains only allowed characters
        if not re.match(r'^[a-zA-Z\s\-\'\.]+$', full_name):
            return JsonResponse({
                'error': 'Name contains invalid characters. Only letters, spaces, hyphens, apostrophes, and periods are allowed.'
            }, status=400)
        
        # Validate message length
        if len(message) < 10:
            return JsonResponse({
                'error': 'Message must be at least 10 characters long'
            }, status=400)
        
        if len(message) > 2000:
            return JsonResponse({
                'error': 'Message must not exceed 2000 characters'
            }, status=400)
        
        # Validate phone if provided
        if phone:
            # Remove all non-digits for validation
            phone_clean = re.sub(r'\D', '', phone)
            if len(phone_clean) < 7 or len(phone_clean) > 15:
                return JsonResponse({
                    'error': 'Please enter a valid phone number (7-15 digits)'
                }, status=400)
            # Store the cleaned phone number
            phone = phone_clean
        
        # Validate subject
        valid_subjects = [
            'general-inquiry', 'establishment-partnership', 'technical-support',
            'feedback', 'verification-issue', 'account-help', 'other'
        ]
        if subject not in valid_subjects:
            return JsonResponse({
                'error': 'Please select a valid subject'
            }, status=400)
        
        # Get client info
        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')[:500]  # Limit length
        referrer = request.META.get('HTTP_REFERER', '')[:500]  # Limit length
        
        # Set custom subject if 'other' is selected
        custom_subject = None
        if subject == 'other':
            custom_subject = 'General Inquiry'  # Default for 'other'
        
        # Create contact message
        contact_message = ContactMessage.objects.create(
            name=full_name,
            email=email,
            phone=phone if phone else None,
            subject=subject,
            custom_subject=custom_subject,
            message=message,
            ip_address=ip_address,
            user_agent=user_agent,
            referrer=referrer,
            privacy_consent=True,  # Since form validates this
            status='NEW',
            priority=determine_priority(subject)
        )
        
        # NOTE: Audit log is automatically created by the post_save signal in models.py
        # DO NOT manually create AuditLog here - it causes duplicates
        
        # Send notification email to admin
        try:
            send_contact_notification(contact_message)
        except Exception as e:
            logger.error(f"Failed to send notification email: {str(e)}")
            # Don't fail the entire request if email fails
        
        # Send confirmation email to user
        try:
            send_user_confirmation(contact_message)
        except Exception as e:
            logger.error(f"Failed to send confirmation email: {str(e)}")
            # Don't fail the entire request if email fails
        
        logger.info(f"Contact message created: ID {contact_message.id} from {email}")
        
        return JsonResponse({
            'success': True,
            'message': 'Thank you for your message! We will get back to you within 24-48 hours.',
            'message_id': contact_message.id
        })
        
    except Exception as e:
        logger.error(f"Error processing contact form: {str(e)}")
        return JsonResponse({
            'error': 'An error occurred while sending your message. Please try again later.'
        }, status=500)


@login_required
@role_required('RA', 'SA', 'AD', 'EM')
def messages_list_view(request):
    """Admin view to manage contact messages"""
    # Get all contact messages
    contact_messages = ContactMessage.objects.all().order_by('-created_at')
    
    # Apply filters
    status_filter = request.GET.get('status', '')
    priority_filter = request.GET.get('priority', '')
    search_query = request.GET.get('search', '')
    
    if status_filter:
        contact_messages = contact_messages.filter(status=status_filter)
    
    if priority_filter:
        contact_messages = contact_messages.filter(priority=priority_filter)
    
    if search_query:
        contact_messages = contact_messages.filter(
            Q(name__icontains=search_query) |
            Q(email__icontains=search_query) |
            Q(message__icontains=search_query) |
            Q(display_subject__icontains=search_query)
        )
    
    # Pagination
    paginator = Paginator(contact_messages, 20)
    page_number = request.GET.get('page', 1)
    messages_page = paginator.get_page(page_number)
    
    # Get counts for dashboard
    total_messages = ContactMessage.objects.count()
    new_messages = ContactMessage.objects.filter(status='NEW').count()
    high_priority = ContactMessage.objects.filter(priority='HIGH').count()
    overdue_messages = ContactMessage.objects.filter(status__in=['NEW', 'READ']).count()
    
    # Log the action
    AuditLog.objects.create(
        user=request.user,
        action='READ',
        content_type='ContactMessage',
        description=f'Viewed contact messages list',
        ip_address=request.META.get('REMOTE_ADDR')
    )
    
    context = {
        'messages': messages_page,
        'status_filter': status_filter,
        'priority_filter': priority_filter,
        'search_query': search_query,
        'total_messages': total_messages,
        'new_messages': new_messages,
        'high_priority': high_priority,
        'overdue_messages': overdue_messages,
        'status_choices': ContactMessage.STATUS_CHOICES,
        'priority_choices': [
            ('LOW', 'Low'),
            ('NORMAL', 'Normal'),
            ('HIGH', 'High'),
            ('URGENT', 'Urgent'),
        ],
    }
    
    return render(request, 'core/messages_list.html', context)


@login_required
@role_required('RA', 'SA', 'AD', 'EM')
def message_detail_view(request, pk):
    """View individual contact message details"""
    contact_message = get_object_or_404(ContactMessage, pk=pk)
    
    # Mark as read if it's new
    if contact_message.status == 'NEW':
        contact_message.mark_as_read(request.user)
    
    # Log the action
    AuditLog.objects.create(
        user=request.user,
        action='READ',
        content_type='ContactMessage',
        object_id=contact_message.id,
        description=f'Viewed contact message from {contact_message.name}',
        ip_address=request.META.get('REMOTE_ADDR')
    )
    
    context = {
        'message': contact_message,
    }
    
    return render(request, 'core/message_detail.html', context)


@login_required
@requires_permission('can_respond_to_messages')
def message_reply_view(request, pk):
    """Reply to a contact message"""
    contact_message = get_object_or_404(ContactMessage, pk=pk)
    
    if request.method == 'POST':
        reply_content = request.POST.get('reply_content', '').strip()
        
        if not reply_content:
            messages.error(request, 'Reply content is required.')
            return render(request, 'core/message_reply.html', {'message': contact_message})
        
        try:
            # Send reply email
            send_message_reply(contact_message, reply_content, request.user)
            
            # Update message status
            contact_message.status = 'REPLIED'
            contact_message.replied_by = request.user
            contact_message.replied_at = timezone.now()
            contact_message.reply_content = reply_content
            contact_message.save()
            
            # Log the action
            AuditLog.objects.create(
                user=request.user,
                action='UPDATE',
                content_type='ContactMessage',
                object_id=contact_message.id,
                description=f'Replied to contact message from {contact_message.name}',
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            messages.success(request, f'Reply sent successfully to {contact_message.name}!')
            return redirect('message_detail', pk=contact_message.pk)
            
        except Exception as e:
            logger.error(f"Failed to send reply: {str(e)}")
            messages.error(request, f'Failed to send reply: {str(e)}')
    
    context = {
        'message': contact_message,
    }
    
    return render(request, 'core/message_reply.html', context)


def determine_priority(subject):
    """Determine message priority based on subject"""
    priority_mapping = {
        'technical-support': 'HIGH',
        'verification-issue': 'HIGH',
        'account-help': 'HIGH',
        'establishment-partnership': 'NORMAL',
        'general-inquiry': 'NORMAL',
        'feedback': 'LOW',
        'other': 'NORMAL'
    }
    return priority_mapping.get(subject, 'NORMAL')


def send_contact_notification(contact_message):
    """Send notification email to admin about new contact message"""
    
    subject = f'[VeriSior] New Contact Message - {contact_message.display_subject}'
    
    # HTML email template
    html_message = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
            <h2 style="color: #1e40af; border-bottom: 2px solid #1e40af; padding-bottom: 10px;">
                New Contact Message Received
            </h2>
            
            <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <h3 style="margin-top: 0; color: #495057;">Contact Information</h3>
                <p><strong>Name:</strong> {contact_message.name}</p>
                <p><strong>Email:</strong> {contact_message.email}</p>
                <p><strong>Phone:</strong> {contact_message.phone or 'Not provided'}</p>
                <p><strong>Subject:</strong> {contact_message.display_subject}</p>
                <p><strong>Priority:</strong> <span style="color: {'#dc3545' if contact_message.priority == 'HIGH' else '#ffc107' if contact_message.priority == 'NORMAL' else '#28a745'};">{contact_message.priority}</span></p>
                <p><strong>Submitted:</strong> {contact_message.created_at.strftime('%B %d, %Y at %I:%M %p')}</p>
            </div>
            
            <div style="background-color: #ffffff; padding: 15px; border: 1px solid #dee2e6; border-radius: 5px;">
                <h3 style="margin-top: 0; color: #495057;">Message</h3>
                <p style="white-space: pre-line;">{contact_message.message}</p>
            </div>
            
            <div style="margin-top: 20px; padding: 15px; background-color: #e7f3ff; border-radius: 5px;">
                <h4 style="margin-top: 0; color: #0056b3;">Technical Information</h4>
                <p><strong>IP Address:</strong> {contact_message.ip_address or 'Unknown'}</p>
                <p><strong>Referrer:</strong> {contact_message.referrer or 'Direct'}</p>
                <p><strong>Message ID:</strong> {contact_message.id}</p>
                <p><strong>Status:</strong> {contact_message.get_status_display()}</p>
            </div>
            
            <div style="margin-top: 20px; text-align: center;">
                <p style="color: #6c757d; font-size: 14px;">
                    Please respond to this message within 24-48 hours.<br>
                    Reply directly to this email to respond to {contact_message.name}.
                </p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Plain text version
    plain_message = f"""
New Contact Message Received

Contact Information:
Name: {contact_message.name}
Email: {contact_message.email}
Phone: {contact_message.phone or 'Not provided'}
Subject: {contact_message.display_subject}
Priority: {contact_message.priority}
Submitted: {contact_message.created_at.strftime('%B %d, %Y at %I:%M %p')}

Message:
{contact_message.message}

Technical Information:
IP Address: {contact_message.ip_address or 'Unknown'}
Referrer: {contact_message.referrer or 'Direct'}
Message ID: {contact_message.id}
Status: {contact_message.get_status_display()}

Please respond to this message within 24-48 hours.
"""
    
    # Get admin email from settings or use default
    admin_email = getattr(settings, 'ADMIN_EMAIL', 'verisior.admin@gmail.com')
    
    send_mail(
        subject=subject,
        message=plain_message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[admin_email],
        html_message=html_message,
        fail_silently=False,
    )


def send_user_confirmation(contact_message):
    """Send confirmation email to user"""
    
    subject = 'Thank you for contacting VeriSior - Message Received'
    
    # HTML email template
    html_message = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
            <div style="text-align: center; margin-bottom: 30px;">
                <h1 style="color: #1e40af; margin-bottom: 10px;">VeriSior</h1>
                <p style="color: #6c757d; margin: 0;">Senior Citizen ID Verification System</p>
            </div>
            
            <h2 style="color: #1e40af;">Thank You for Contacting Us!</h2>
            
            <p>Dear {contact_message.name},</p>
            
            <p>We have received your message regarding <strong>{contact_message.display_subject}</strong> 
            and want to thank you for taking the time to contact us.</p>
            
            <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <h3 style="margin-top: 0; color: #495057;">Your Message Summary</h3>
                <p><strong>Subject:</strong> {contact_message.display_subject}</p>
                <p><strong>Priority:</strong> {contact_message.priority}</p>
                <p><strong>Submitted:</strong> {contact_message.created_at.strftime('%B %d, %Y at %I:%M %p')}</p>
                <p><strong>Reference ID:</strong> #{contact_message.id}</p>
            </div>
            
            <div style="background-color: #e7f3ff; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <h3 style="margin-top: 0; color: #0056b3;">What Happens Next?</h3>
                <ul style="margin: 0; padding-left: 20px;">
                    <li>Our support team will review your message within 24 hours</li>
                    <li>You will receive a detailed response within 24-48 hours</li>
                    <li>For urgent matters, you may also contact us by phone</li>
                    <li>Please keep your reference ID #{contact_message.id} for future correspondence</li>
                </ul>
            </div>
            
            <div style="margin-top: 30px; padding: 20px; background-color: #f1f3f4; border-radius: 5px;">
                <h4 style="margin-top: 0; color: #495057;">Contact Information</h4>
                <p><strong>Email:</strong> verisior.gov@gmail.com</p>
                <p><strong>Phone:</strong> +63 977 651 3490</p>
                <p><strong>Office Hours:</strong> Monday - Friday: 8:00 AM - 5:00 PM</p>
                <p><strong>Address:</strong> STI College - Novaliches, Corner Quirino Highway, Quezon City, Metro Manila 1126</p>
            </div>
            
            <div style="margin-top: 30px; text-align: center; border-top: 1px solid #dee2e6; padding-top: 20px;">
                <p style="color: #6c757d; font-size: 14px; margin: 0;">
                    This is an automated message. Please do not reply to this email.<br>
                    For immediate assistance, please contact us using the information above.
                </p>
            </div>
            
            <div style="margin-top: 20px; text-align: center;">
                <p style="color: #6c757d; font-size: 12px; margin: 0;">
                    Best regards,<br>
                    VeriSior Support Team
                </p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Plain text version
    plain_message = f"""
Thank you for contacting VeriSior!

Dear {contact_message.name},

We have received your message regarding {contact_message.display_subject} and want to thank you for taking the time to contact us.

Your Message Summary:
Subject: {contact_message.display_subject}
Priority: {contact_message.priority}
Submitted: {contact_message.created_at.strftime('%B %d, %Y at %I:%M %p')}
Reference ID: #{contact_message.id}

What Happens Next?
- Our support team will review your message within 24 hours
- You will receive a detailed response within 24-48 hours
- For urgent matters, you may also contact us by phone
- Please keep your reference ID #{contact_message.id} for future correspondence

Contact Information:
Email: verisior.gov@gmail.com
Phone: +63 977 651 3490
Office Hours: Monday - Friday: 8:00 AM - 5:00 PM
Address: STI College - Novaliches, Corner Quirino Highway, Quezon City, Metro Manila 1126

This is an automated message. Please do not reply to this email.
For immediate assistance, please contact us using the information above.

Best regards,
VeriSior Support Team
"""
    
    send_mail(
        subject=subject,
        message=plain_message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[contact_message.email],
        html_message=html_message,
        fail_silently=False,
    )


def send_message_reply(contact_message, reply_content, replied_by):
    """Send reply email to the contact message sender"""
    
    subject = f'Re: {contact_message.display_subject} - VeriSior Support Response'
    
    # HTML email template
    html_message = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
            <div style="text-align: center; margin-bottom: 30px;">
                <h1 style="color: #1e40af; margin-bottom: 10px;">VeriSior</h1>
                <p style="color: #6c757d; margin: 0;">Senior Citizen ID Verification System</p>
            </div>
            
            <h2 style="color: #1e40af;">Response to Your Message</h2>
            
            <p>Dear {contact_message.name},</p>
            
            <p>Thank you for contacting VeriSior regarding <strong>{contact_message.display_subject}</strong>. 
            We have reviewed your message and are responding below:</p>
            
            <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <h3 style="margin-top: 0; color: #495057;">Our Response</h3>
                <p style="white-space: pre-line;">{reply_content}</p>
            </div>
            
            <div style="background-color: #e7f3ff; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <h3 style="margin-top: 0; color: #0056b3;">Your Original Message</h3>
                <p><strong>Subject:</strong> {contact_message.display_subject}</p>
                <p><strong>Submitted:</strong> {contact_message.created_at.strftime('%B %d, %Y at %I:%M %p')}</p>
                <p><strong>Reference ID:</strong> #{contact_message.id}</p>
                <p><strong>Message:</strong></p>
                <p style="white-space: pre-line; font-style: italic;">{contact_message.message}</p>
            </div>
            
            <div style="margin-top: 30px; padding: 20px; background-color: #f1f3f4; border-radius: 5px;">
                <h4 style="margin-top: 0; color: #495057;">Need Further Assistance?</h4>
                <p><strong>Email:</strong> verisior.gov@gmail.com</p>
                <p><strong>Phone:</strong> +63 977 651 3490</p>
                <p><strong>Office Hours:</strong> Monday - Friday: 8:00 AM - 5:00 PM</p>
                <p><strong>Address:</strong> STI College - Novaliches, Corner Quirino Highway, Quezon City, Metro Manila 1126</p>
            </div>
            
            <div style="margin-top: 20px; text-align: center;">
                <p style="color: #6c757d; font-size: 12px; margin: 0;">
                    Best regards,<br>
                    {replied_by.get_full_name() or replied_by.username}<br>
                    VeriSior Support Team
                </p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Plain text version
    plain_message = f"""
Response to Your Message - VeriSior Support

Dear {contact_message.name},

Thank you for contacting VeriSior regarding {contact_message.display_subject}. We have reviewed your message and are responding below:

OUR RESPONSE:
{reply_content}

YOUR ORIGINAL MESSAGE:
Subject: {contact_message.display_subject}
Submitted: {contact_message.created_at.strftime('%B %d, %Y at %I:%M %p')}
Reference ID: #{contact_message.id}
Message: {contact_message.message}

Need Further Assistance?
Email: verisior.gov@gmail.com
Phone: +63 977 651 3490
Office Hours: Monday - Friday: 8:00 AM - 5:00 PM
Address: STI College - Novaliches, Corner Quirino Highway, Quezon City, Metro Manila 1126

Best regards,
{replied_by.get_full_name() or replied_by.username}
VeriSior Support Team
"""
    
    send_mail(
        subject=subject,
        message=plain_message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[contact_message.email],
        html_message=html_message,
        fail_silently=False,
    )


def get_client_ip(request):
    """Get the client's IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

@login_required
@requires_permission('can_delete_messages')
def message_delete_view(request, pk):
    """Delete a contact message"""
    contact_message = get_object_or_404(ContactMessage, pk=pk)
    
    if request.method == 'POST':
        # Log the action before deletion
        AuditLog.objects.create(
            user=request.user,
            action='DELETE',
            content_type='ContactMessage',
            object_id=contact_message.id,
            description=f'Deleted contact message from {contact_message.name}',
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        contact_message.delete()
        messages.success(request, 'Message deleted successfully!')
        return redirect('messages_list')
    
    context = {
        'message': contact_message,
    }
    
    return render(request, 'core/message_delete_confirm.html', context)