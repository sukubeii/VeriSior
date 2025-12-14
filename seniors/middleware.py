# government/middleware.py - Automatic status checking middleware

from django.utils import timezone
from django.contrib.auth import get_user_model
from datetime import date, timedelta
import logging

logger = logging.getLogger(__name__)

class AutoStatusCheckMiddleware:
    """
    Middleware that automatically checks and updates senior citizen statuses
    every time the system is accessed by government users.
    
    This simulates a subscription-like system where status checks happen
    automatically without manual intervention.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.last_check_date = None
        
    def __call__(self, request):
        # Run automated checks before processing the request
        if self.should_run_automated_checks(request):
            self.run_automated_status_checks(request)
        
        response = self.get_response(request)
        return response
    
    def should_run_automated_checks(self, request):
        """
        Determine if automated checks should run.
        
        Runs checks if:
        1. User is authenticated and is a government user
        2. It's a new day since last check
        3. Request is for government module pages
        """
        # Only run for authenticated government users
        if not request.user.is_authenticated:
            return False
            
        if not hasattr(request.user, 'user_type') or request.user.user_type != 'GOV':
            return False
        
        # Only run for government module URLs
        if not request.path.startswith('/government/'):
            return False
        
        # Check if we've already run today
        today = date.today()
        if self.last_check_date == today:
            return False
        
        # Check if system has already been checked today by any user
        from .models import SystemStatusCheck
        today_checks = SystemStatusCheck.objects.filter(
            check_date__date=today
        ).exists()
        
        if today_checks:
            self.last_check_date = today
            return False
        
        return True
    
    def run_automated_status_checks(self, request):
        """
        Run the automated status checks for all senior citizens
        """
        try:
            from .models import SeniorCitizen, SystemStatusCheck
            
            logger.info(f"Running automated status checks triggered by user: {request.user.username}")
            
            # Get or create system user for automated actions
            User = get_user_model()
            system_user, created = User.objects.get_or_create(
                username='system_auto_check',
                defaults={
                    'first_name': 'System',
                    'last_name': 'Automated Checks',
                    'email': 'system@verisior.gov',
                    'user_type': 'GOV',
                    'role': 'SA',
                    'is_active': True,
                    'is_staff': False,
                }
            )
            
            # Run the automated checks
            results = SeniorCitizen.run_automated_checks(system_user)
            
            # Log the results
            SystemStatusCheck.objects.create(
                checked_by=request.user,
                seniors_checked=results['checked'],
                warnings_sent=results['warnings_sent'],
                deactivated_count=results['deactivated'],
                archived_count=results['archived'],
                errors_count=len(results['errors']),
                notes='; '.join(results['errors']) if results['errors'] else 'No errors'
            )
            
            # Update last check date
            self.last_check_date = date.today()
            
            logger.info(f"Automated checks completed: {results}")
            
            # Add results to request for potential display in views
            request.auto_check_results = results
            
        except Exception as e:
            logger.error(f"Error running automated status checks: {str(e)}")
            
            # Log the error
            try:
                from .models import SystemStatusCheck
                SystemStatusCheck.objects.create(
                    checked_by=request.user,
                    seniors_checked=0,
                    warnings_sent=0,
                    deactivated_count=0,
                    archived_count=0,
                    errors_count=1,
                    notes=f'System error: {str(e)}'
                )
            except:
                pass  # Don't let logging errors break the system
