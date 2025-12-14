# core/views.py - Complete Core Views with Content Management and Team Members

from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.db.models import Q
from django.contrib import messages
from django.views.decorators.http import require_POST, require_http_methods
from django.core.paginator import Paginator
from django.utils import timezone
from django.contrib.auth import get_user_model
import csv
import datetime
import json

from .models import AuditLog, LandingPageContent, TeamMember, FAQItem, PrivacyPolicy
from .forms import LandingPageContentForm, TeamMemberForm, FAQItemForm, PrivacyPolicyForm
from .reports import reports_dashboard, get_report_preview, download_filtered_report
from accounts.decorators import role_required
from accounts.permission_decorators import requires_navigation_access

User = get_user_model()

# EXISTING VIEWS

@login_required
def settings_view(request):
    """Main settings view with general settings and administrative tools"""
    if request.method == 'POST':
        # Handle general settings form submission
        user = request.user
        
        # Update notification preferences
        user.email_notifications = 'email_notifications' in request.POST
        user.sms_notifications = 'sms_notifications' in request.POST
        
        # Update language and timezone
        user.language = request.POST.get('language', 'en')
        user.timezone = request.POST.get('timezone', 'Asia/Manila')
        
        user.save()
        
        messages.success(request, 'Settings updated successfully!')
        return redirect('settings')
    
    return render(request, 'core/settings.html')


@login_required
@role_required('SA', 'AD')
def export_audit_logs_view(request):
    """Export audit logs to CSV - Direct download without viewing"""
    # Filter logs based on user organization type
    logs = AuditLog.objects.filter(user__user_type=request.user.user_type).order_by('-timestamp')
    
    # Prepare response
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename=audit_logs_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    
    # Create CSV writer
    writer = csv.writer(response)
    writer.writerow(['Timestamp', 'User', 'Action', 'Content Type', 'Object ID', 'Description', 'IP Address'])
    
    # Write log data
    for log in logs:
        writer.writerow([
            log.timestamp,
            log.user.username if log.user else 'Unknown',
            log.action,
            log.content_type,
            log.object_id if log.object_id else '',
            log.description,
            log.ip_address if log.ip_address else ''
        ])
    
    # Log the export action
    AuditLog.objects.create(
        user=request.user,
        action='READ',
        content_type='AuditLog',
        description='Downloaded audit logs CSV',
        ip_address=request.META.get('REMOTE_ADDR')
    )
    
    return response


@login_required
@requires_navigation_access('content_management')
def content_management(request):
    """Original content management for homepage - redirects to simplified version"""
    return redirect('simple_content_management')


# CONTENT MANAGEMENT VIEWS

@login_required
@requires_navigation_access('content_management')
def simple_content_management(request):
    """Simple content management dashboard with text content and team members"""
    content = LandingPageContent.get_content()
    team_members = TeamMember.objects.all().order_by('order', 'name')
    faq_items = FAQItem.objects.all().order_by('order', 'id')
    privacy_policy = PrivacyPolicy.get_active_policy()

    # Get counts for dashboard
    total_team_members = TeamMember.objects.count()
    active_team_members = TeamMember.objects.filter(is_active=True).count()
    total_faq_items = FAQItem.objects.count()
    active_faq_items = FAQItem.objects.filter(is_active=True).count()

    context = {
        'content': content,
        'team_members': team_members,
        'faq_items': faq_items,
        'privacy_policy': privacy_policy,
        'total_team_members': total_team_members,
        'active_team_members': active_team_members,
        'total_faq_items': total_faq_items,
        'active_faq_items': active_faq_items,
    }
    return render(request, 'core/simple_content_management.html', context)


@login_required
@requires_navigation_access('content_management')
def edit_landing_page_content(request):
    """Edit landing page content"""
    content = LandingPageContent.get_content()

    if request.method == 'POST':
        form = LandingPageContentForm(request.POST, instance=content)
        if form.is_valid():
            content = form.save(commit=False)
            content.updated_by = request.user
            content.save()

            # Log the action
            AuditLog.objects.create(
                user=request.user,
                action='UPDATE',
                content_type='LandingPageContent',
                object_id=content.id,
                description='Updated landing page content',
                ip_address=request.META.get('REMOTE_ADDR')
            )

            messages.success(request, 'Landing page content updated successfully!')
            return redirect('simple_content_management')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = LandingPageContentForm(instance=content)

    # Get team members for display
    team_members = TeamMember.objects.all().order_by('order', 'name')

    # Get FAQ items for display
    faq_items = FAQItem.objects.all().order_by('order', 'id')

    context = {
        'form': form,
        'content': content,
        'team_members': team_members,
        'faq_items': faq_items,
    }
    return render(request, 'core/edit_landing_page_content.html', context)


# PRIVACY POLICY MANAGEMENT VIEWS

@login_required
@requires_navigation_access('content_management')
def edit_privacy_policy(request):
    """Edit privacy policy content"""
    # Get or create privacy policy
    privacy_policy = PrivacyPolicy.get_active_policy()
    if not privacy_policy:
        # Create a new privacy policy if none exists
        privacy_policy = PrivacyPolicy()

    if request.method == 'POST':
        form = PrivacyPolicyForm(request.POST, instance=privacy_policy)
        if form.is_valid():
            privacy_policy = form.save(commit=False)
            privacy_policy.updated_by = request.user

            # Handle activation logic
            if privacy_policy.is_active:
                # Deactivate other policies before activating this one
                PrivacyPolicy.objects.filter(is_active=True).update(is_active=False)

            privacy_policy.save()

            # Log the action
            AuditLog.objects.create(
                user=request.user,
                action='UPDATE' if privacy_policy.pk else 'CREATE',
                content_type='PrivacyPolicy',
                object_id=privacy_policy.id,
                description=f'{"Updated" if privacy_policy.pk else "Created"} privacy policy v{privacy_policy.version}',
                ip_address=request.META.get('REMOTE_ADDR')
            )

            messages.success(request, f'Privacy policy v{privacy_policy.version} saved successfully!')
            return redirect('simple_content_management')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = PrivacyPolicyForm(instance=privacy_policy)

    context = {
        'form': form,
        'privacy_policy': privacy_policy,
    }
    return render(request, 'core/edit_privacy_policy.html', context)


@login_required
@requires_navigation_access('content_management')
@require_POST
def activate_privacy_policy(request, policy_id):
    """Activate a specific privacy policy version"""
    try:
        policy = get_object_or_404(PrivacyPolicy, id=policy_id)
        policy.activate()

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='UPDATE',
            content_type='PrivacyPolicy',
            object_id=policy.id,
            description=f'Activated privacy policy v{policy.version}',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        return JsonResponse({
            'success': True,
            'message': f'Privacy policy v{policy.version} activated successfully!'
        })

    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Error activating privacy policy: {str(e)}'
        })


# TEAM MEMBER MANAGEMENT VIEWS

@login_required
@requires_navigation_access('content_management')
def team_members_list(request):
    """List all team members with search and pagination"""
    team_members = TeamMember.objects.all().order_by('order', 'name')
    
    # Search functionality
    search_query = request.GET.get('search', '')
    if search_query:
        team_members = team_members.filter(
            Q(name__icontains=search_query) |
            Q(role__icontains=search_query) |
            Q(technical_skills__icontains=search_query) |
            Q(soft_skills__icontains=search_query)
        )
    
    # Status filter
    status_filter = request.GET.get('status', '')
    if status_filter == 'active':
        team_members = team_members.filter(is_active=True)
    elif status_filter == 'inactive':
        team_members = team_members.filter(is_active=False)
    
    # Pagination
    paginator = Paginator(team_members, 10)
    page_number = request.GET.get('page')
    team_members_page = paginator.get_page(page_number)
    
    context = {
        'team_members': team_members_page,
        'search_query': search_query,
        'status_filter': status_filter,
        'total_count': team_members.count(),
    }
    return render(request, 'core/team_members_list.html', context)


@login_required
@requires_navigation_access('content_management')
def edit_team_member(request, pk=None):
    """Edit or create team member"""
    if pk:
        team_member = get_object_or_404(TeamMember, pk=pk)
        action = 'Edit'
    else:
        team_member = None
        action = 'Add'
    
    if request.method == 'POST':
        form = TeamMemberForm(request.POST, request.FILES, instance=team_member)
        if form.is_valid():
            member = form.save(commit=False)
            member.updated_by = request.user
            member.save()
            
            # Log the action
            AuditLog.objects.create(
                user=request.user,
                action='CREATE' if not pk else 'UPDATE',
                content_type='TeamMember',
                object_id=member.id,
                description=f'{"Created" if not pk else "Updated"} team member: {member.name}',
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            messages.success(request, f'Team member {action.lower()}ed successfully!')
            return redirect('simple_content_management')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = TeamMemberForm(instance=team_member)
    
    context = {
        'form': form,
        'team_member': team_member,
        'action': action,
    }
    return render(request, 'core/edit_team_member.html', context)


@login_required
@requires_navigation_access('content_management')
def delete_team_member(request, pk):
    """Delete team member"""
    team_member = get_object_or_404(TeamMember, pk=pk)
    
    if request.method == 'POST':
        member_name = team_member.name
        team_member.delete()
        
        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='DELETE',
            content_type='TeamMember',
            object_id=pk,
            description=f'Deleted team member: {member_name}',
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        messages.success(request, f'Team member "{member_name}" deleted successfully!')
        return redirect('simple_content_management')
    
    context = {
        'team_member': team_member,
    }
    return render(request, 'core/delete_team_member.html', context)


# AJAX VIEWS FOR TOGGLE STATUS

@login_required
@requires_navigation_access('content_management')
@require_POST
def toggle_team_member_status(request, pk):
    """Toggle team member active status via AJAX"""
    try:
        team_member = get_object_or_404(TeamMember, pk=pk)
        team_member.is_active = not team_member.is_active
        team_member.updated_by = request.user
        team_member.save()
        
        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='UPDATE',
            content_type='TeamMember',
            object_id=team_member.id,
            description=f'{"Activated" if team_member.is_active else "Deactivated"} team member: {team_member.name}',
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        return JsonResponse({
            'success': True,
            'is_active': team_member.is_active,
            'message': f'Team member {"activated" if team_member.is_active else "deactivated"} successfully!'
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Error updating status: {str(e)}'
        }, status=500)


# FAQ MANAGEMENT VIEWS

@login_required
@requires_navigation_access('content_management')
def faq_items_list(request):
    """List all FAQ items"""
    faq_items = FAQItem.objects.all().order_by('order', 'created_at')

    context = {
        'faq_items': faq_items,
    }
    return render(request, 'core/faq_items_list.html', context)


@login_required
@requires_navigation_access('content_management')
def edit_faq_item(request, pk=None):
    """Add new or edit existing FAQ item"""
    if pk:
        faq_item = get_object_or_404(FAQItem, pk=pk)
        action = 'Edit'
    else:
        faq_item = FAQItem()
        action = 'Add'

    if request.method == 'POST':
        form = FAQItemForm(request.POST, instance=faq_item)
        if form.is_valid():
            faq_item = form.save(commit=False)
            faq_item.updated_by = request.user
            faq_item.save()

            # Log the action
            AuditLog.objects.create(
                user=request.user,
                action='CREATE' if not pk else 'UPDATE',
                content_type='FAQItem',
                object_id=faq_item.id,
                description=f'{"Created" if not pk else "Updated"} FAQ item: {faq_item.question[:50]}...',
                ip_address=request.META.get('REMOTE_ADDR')
            )

            messages.success(request, f'FAQ item {"created" if not pk else "updated"} successfully!')
            return redirect('simple_content_management')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = FAQItemForm(instance=faq_item)

    context = {
        'form': form,
        'faq_item': faq_item,
        'action': action,
    }
    return render(request, 'core/edit_faq_item.html', context)


@login_required
@requires_navigation_access('content_management')
def delete_faq_item(request, pk):
    """Delete FAQ item"""
    faq_item = get_object_or_404(FAQItem, pk=pk)

    if request.method == 'POST':
        question_text = faq_item.question
        faq_item.delete()

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='DELETE',
            content_type='FAQItem',
            object_id=pk,
            description=f'Deleted FAQ item: {question_text[:50]}...',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        messages.success(request, 'FAQ item deleted successfully!')
        return redirect('simple_content_management')

    context = {
        'faq_item': faq_item,
    }
    return render(request, 'core/delete_faq_item.html', context)


@login_required
@requires_navigation_access('content_management')
@require_POST
def toggle_faq_status(request, pk):
    """Toggle FAQ item active status via AJAX"""
    try:
        faq_item = get_object_or_404(FAQItem, pk=pk)
        faq_item.is_active = not faq_item.is_active
        faq_item.updated_by = request.user
        faq_item.save()

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='UPDATE',
            content_type='FAQItem',
            object_id=faq_item.id,
            description=f'{"Activated" if faq_item.is_active else "Deactivated"} FAQ item: {faq_item.question[:50]}...',
            ip_address=request.META.get('REMOTE_ADDR')
        )

        return JsonResponse({
            'success': True,
            'is_active': faq_item.is_active,
            'message': f'FAQ item {"activated" if faq_item.is_active else "deactivated"} successfully!'
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Error updating status: {str(e)}'
        }, status=500)


# CONTENT PREVIEW

@login_required
@requires_navigation_access('content_management')
def preview_landing_page(request):
    """Preview landing page with current content"""
    content = LandingPageContent.get_content()
    team_members = TeamMember.objects.filter(is_active=True).order_by('order')
    
    context = {
        'landing_page_content': content,
        'team_members': team_members,
        'preview_mode': True,
    }
    return render(request, 'core/preview_landing_page.html', context)


# CONTENT EXPORT/IMPORT

@login_required
@requires_navigation_access('content_management')
@role_required('RA', 'SA')
def export_content(request):
    """Export content to JSON format"""
    import json
    
    content_type = request.GET.get('type', 'all')
    
    data = {}
    
    if content_type in ['all', 'landing_page']:
        content = LandingPageContent.get_content()
        data['landing_page'] = {
            'hero_title': content.hero_title,
            'hero_subtitle': content.hero_subtitle,
            'features_title': content.features_title,
            'features_subtitle': content.features_subtitle,
            'slide1_title': content.slide1_title,
            'slide1_subtitle': content.slide1_subtitle,
            'slide1_description': content.slide1_description,
            'slide2_title': content.slide2_title,
            'slide2_subtitle': content.slide2_subtitle,
            'slide2_description': content.slide2_description,
            'slide3_title': content.slide3_title,
            'slide3_subtitle': content.slide3_subtitle,
            'slide3_description': content.slide3_description,
            'about_title': content.about_title,
            'about_description': content.about_description,
            'faq_title': content.faq_title,
            'faq_subtitle': content.faq_subtitle,
            'contact_title': content.contact_title,
            'contact_subtitle': content.contact_subtitle,
            'office_name': content.office_name,
            'office_address': content.office_address,
            'phone_number': content.phone_number,
            'email_address': content.email_address,
        }
    
    if content_type in ['all', 'team_members']:
        team_members = TeamMember.objects.all()
        data['team_members'] = [
            {
                'name': member.name,
                'role': member.role,
                'technical_skills': member.technical_skills,
                'soft_skills': member.soft_skills,
                'order': member.order,
                'is_active': member.is_active,
                'photo_url': member.photo.url if member.photo else None,
            }
            for member in team_members
        ]
    
    # Add metadata
    data['export_metadata'] = {
        'exported_by': request.user.username,
        'export_date': timezone.now().isoformat(),
        'content_type': content_type,
        'version': '1.0'
    }
    
    # Create response
    response = HttpResponse(
        json.dumps(data, indent=2),
        content_type='application/json'
    )
    response['Content-Disposition'] = f'attachment; filename=verisior_content_{content_type}_{timezone.now().strftime("%Y%m%d_%H%M%S")}.json'
    
    # Log the export
    AuditLog.objects.create(
        user=request.user,
        action='EXPORT',
        content_type='Content',
        description=f'Exported {content_type} content to JSON',
        ip_address=request.META.get('REMOTE_ADDR')
    )
    
    return response


# UTILITY FUNCTIONS

def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def log_user_action(request, action, content_type, object_id=None, description=''):
    """Helper function to create audit logs"""
    AuditLog.objects.create(
        user=request.user if request.user.is_authenticated else None,
        action=action,
        content_type=content_type,
        object_id=object_id,
        description=description,
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )


# ERROR HANDLERS

def handler404(request, exception):
    """Custom 404 error handler"""
    return render(request, 'errors/404.html', status=404)


def handler500(request):
    """Custom 500 error handler"""
    return render(request, 'errors/500.html', status=500)


def handler403(request, exception):
    """Custom 403 error handler"""
    return render(request, 'errors/403.html', status=403)


# API ENDPOINTS FOR AJAX REQUESTS

@login_required
@require_POST
def update_content_ajax(request):
    """Update content via AJAX"""
    try:
        data = json.loads(request.body)
        content_type = data.get('content_type')
        field_name = data.get('field_name')
        new_value = data.get('new_value')
        
        if content_type == 'landing_page':
            content = LandingPageContent.get_content()
            if hasattr(content, field_name):
                setattr(content, field_name, new_value)
                content.updated_by = request.user
                content.save()
                
                # Log the action
                log_user_action(
                    request=request,
                    action='UPDATE',
                    content_type='LandingPageContent',
                    object_id=content.id,
                    description=f'Updated {field_name} via AJAX'
                )
                
                return JsonResponse({
                    'success': True,
                    'message': f'{field_name} updated successfully'
                })
            else:
                return JsonResponse({
                    'success': False,
                    'error': f'Field {field_name} does not exist'
                })
        else:
            return JsonResponse({
                'success': False,
                'error': 'Invalid content type'
            })
            
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data'
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })


@login_required
def get_content_ajax(request):
    """Get content via AJAX"""
    try:
        content_type = request.GET.get('content_type')
        
        if content_type == 'landing_page':
            content = LandingPageContent.get_content()
            data = {
                'hero_title': content.hero_title,
                'hero_subtitle': content.hero_subtitle,
                'features_title': content.features_title,
                'features_subtitle': content.features_subtitle,
                'about_title': content.about_title,
                'about_description': content.about_description,
                'contact_title': content.contact_title,
                'contact_subtitle': content.contact_subtitle,
                'office_name': content.office_name,
                'office_address': content.office_address,
                'phone_number': content.phone_number,
                'email_address': content.email_address,
                'updated_at': content.updated_at.isoformat(),
            }
            
            return JsonResponse({
                'success': True,
                'data': data
            })
        elif content_type == 'team_members':
            team_members = TeamMember.objects.filter(is_active=True).order_by('order')
            data = [
                {
                    'id': member.id,
                    'name': member.name,
                    'role': member.role,
                    'technical_skills': member.technical_skills,
                    'soft_skills': member.soft_skills,
                    'photo_url': member.photo.url if member.photo else None,
                    'order': member.order,
                }
                for member in team_members
            ]
            
            return JsonResponse({
                'success': True,
                'data': data
            })
        else:
            return JsonResponse({
                'success': False,
                'error': 'Invalid content type'
            })
            
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })


# CONTENT ORDERING

@login_required
@requires_navigation_access('content_management')
@require_POST
def update_content_order(request):
    """Update content item order via AJAX"""
    try:
        import json
        
        content_type = request.POST.get('content_type')
        order_data = json.loads(request.POST.get('order_data', '[]'))
        
        if content_type == 'team_member':
            for item in order_data:
                TeamMember.objects.filter(id=item['id']).update(
                    order=item['order'],
                    updated_by=request.user
                )
            message = 'Team member order updated successfully!'
            
        else:
            return JsonResponse({'success': False, 'message': 'Invalid content type'})
        
        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='UPDATE',
            content_type=content_type,
            description=f'Updated {content_type} display order',
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        return JsonResponse({'success': True, 'message': message})
        
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Error updating order: {str(e)}'})


# BACKUP AND RESTORE HELPERS

@login_required
@requires_navigation_access('content_management')
@role_required('SA')
def backup_content(request):
    """Create a backup of all content"""
    try:
        content = LandingPageContent.get_content()
        team_members = TeamMember.objects.all()
        
        backup_data = {
            'landing_page_content': {
                'hero_title': content.hero_title,
                'hero_subtitle': content.hero_subtitle,
                'features_title': content.features_title,
                'features_subtitle': content.features_subtitle,
                'slide1_title': content.slide1_title,
                'slide1_subtitle': content.slide1_subtitle,
                'slide1_description': content.slide1_description,
                'slide2_title': content.slide2_title,
                'slide2_subtitle': content.slide2_subtitle,
                'slide2_description': content.slide2_description,
                'slide3_title': content.slide3_title,
                'slide3_subtitle': content.slide3_subtitle,
                'slide3_description': content.slide3_description,
                'about_title': content.about_title,
                'about_description': content.about_description,
                'faq_title': content.faq_title,
                'faq_subtitle': content.faq_subtitle,
                'contact_title': content.contact_title,
                'contact_subtitle': content.contact_subtitle,
                'office_name': content.office_name,
                'office_address': content.office_address,
                'phone_number': content.phone_number,
                'email_address': content.email_address,
            },
            'team_members': [
                {
                    'name': member.name,
                    'role': member.role,
                    'technical_skills': member.technical_skills,
                    'soft_skills': member.soft_skills,
                    'order': member.order,
                    'is_active': member.is_active,
                    'photo_url': member.photo.url if member.photo else None,
                }
                for member in team_members
            ],
            'backup_metadata': {
                'created_by': request.user.username,
                'created_at': timezone.now().isoformat(),
                'version': '1.0'
            }
        }
        
        # Log the backup
        log_user_action(
            request=request,
            action='BACKUP',
            content_type='Content',
            description='Created content backup'
        )
        
        return JsonResponse({
            'success': True,
            'backup_data': backup_data
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })


@login_required
@requires_navigation_access('content_management')
@role_required('SA')
@require_POST
def restore_content(request):
    """Restore content from backup"""
    try:
        data = json.loads(request.body)
        backup_data = data.get('backup_data')
        
        if not backup_data:
            return JsonResponse({
                'success': False,
                'error': 'Invalid backup data'
            })
        
        # Restore landing page content
        if 'landing_page_content' in backup_data:
            content = LandingPageContent.get_content()
            landing_page_data = backup_data['landing_page_content']
            
            # Update all fields
            for field_name, value in landing_page_data.items():
                if hasattr(content, field_name):
                    setattr(content, field_name, value)
            
            content.updated_by = request.user
            content.save()
        
        # Restore team members (optional - be careful with this)
        if 'team_members' in backup_data and data.get('restore_team_members', False):
            # This would replace all team members - use with caution
            # TeamMember.objects.all().delete()
            # for member_data in backup_data['team_members']:
            #     TeamMember.objects.create(**member_data, updated_by=request.user)
            pass
        
        # Log the restore
        log_user_action(
            request=request,
            action='RESTORE',
            content_type='Content',
            description='Restored content from backup'
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Content restored successfully'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data'
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })


# TEMPLATE CONTEXT PROCESSOR

def landing_page_content(request):
    """Context processor to make landing page content available in all templates"""
    try:
        content = LandingPageContent.get_content()
        team_members = TeamMember.objects.filter(is_active=True).order_by('order')
        faq_items = FAQItem.objects.filter(is_active=True).order_by('order')
        privacy_policy = PrivacyPolicy.get_active_policy()
        
        return {
            'landing_page_content': content,
            'team_members_display': team_members,
            'faq_items_display': faq_items,
            'privacy_policy': privacy_policy,
        }
    except Exception as e:
        # Log the error for debugging
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error in landing_page_content context processor: {str(e)}")
        
        # Return empty context if content doesn't exist yet
        return {
            'landing_page_content': None,
            'team_members_display': [],
            'faq_items_display': [],
            'privacy_policy': None,
        }
