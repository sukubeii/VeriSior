# accounts/security_models.py - Security Models for Login Tracking

from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta
import json
import hashlib

User = get_user_model()



class LoginAttempt(models.Model):
    """
    Logs all login attempts, successful and failed.
    Used for security monitoring and forensic analysis.
    """
    STATUS_CHOICES = [
        ('SUCCESS', 'Successful Login'),
        ('FAILED_PASSWORD', 'Failed - Wrong Password'),
        ('FAILED_USERNAME', 'Failed - Wrong Username'),
        ('FAILED_MFA', 'Failed - MFA Required/Invalid'),
        ('FAILED_DISABLED', 'Failed - Account Disabled'),
        ('LOGOUT', 'User Logout'),
    ]

    username = models.CharField(max_length=150)  # Store username even if user doesn't exist
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='login_attempts'
    )

    status = models.CharField(max_length=30, choices=STATUS_CHOICES)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    device_fingerprint = models.CharField(max_length=64)

    # Device information
    device_type = models.CharField(max_length=50, blank=True)
    browser_name = models.CharField(max_length=100, blank=True)
    browser_version = models.CharField(max_length=50, blank=True)
    os_name = models.CharField(max_length=100, blank=True)
    os_version = models.CharField(max_length=50, blank=True)

    # Location information
    country = models.CharField(max_length=100, blank=True)
    region = models.CharField(max_length=100, blank=True)
    city = models.CharField(max_length=100, blank=True)
    timezone_name = models.CharField(max_length=100, blank=True)
    isp = models.CharField(max_length=200, blank=True)

    # Additional security data
    session_key = models.CharField(max_length=40, blank=True)
    blocked_reason = models.TextField(blank=True)  # Additional details for blocked attempts

    # Timestamps
    attempted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'login_attempts'
        indexes = [
            models.Index(fields=['username', 'attempted_at']),
            models.Index(fields=['ip_address', 'attempted_at']),
            models.Index(fields=['status', 'attempted_at']),
            models.Index(fields=['user', 'attempted_at']),
        ]
        ordering = ['-attempted_at']

    def __str__(self):
        return f"{self.username} - {self.get_status_display()} from {self.ip_address}"

    def get_location_display(self):
        """Get formatted location for display"""
        location_parts = []
        if self.city:
            location_parts.append(self.city)
        if self.region:
            location_parts.append(self.region)
        if self.country:
            location_parts.append(self.country)

        return ', '.join(location_parts) if location_parts else 'Unknown Location'

    def get_device_display(self):
        """Get formatted device info for display"""
        device_parts = []
        if self.browser_name:
            browser = f"{self.browser_name}"
            if self.browser_version:
                browser += f" {self.browser_version}"
            device_parts.append(browser)

        if self.os_name:
            os_info = f"{self.os_name}"
            if self.os_version:
                os_info += f" {self.os_version}"
            device_parts.append(os_info)

        if self.device_type:
            device_parts.append(self.device_type.title())

        return ' | '.join(device_parts) if device_parts else 'Unknown Device'

    @classmethod
    def log_attempt(cls, username, user, status, request, session_key='', blocked_reason=''):
        """Convenience method to log a login attempt"""
        from .security_utils import DeviceDetector, LocationDetector

        # Get device information
        device_info = DeviceDetector.get_device_info(request)

        # Get location information (async in background if API is used)
        location_info = LocationDetector.get_location_info(
            request.META.get('REMOTE_ADDR')
        )

        # Create device fingerprint
        fingerprint = cls.generate_fingerprint(request)

        return cls.objects.create(
            username=username,
            user=user,
            status=status,
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            device_fingerprint=fingerprint,
            session_key=session_key,
            blocked_reason=blocked_reason,
            **device_info,
            **location_info,
        )

    @staticmethod
    def generate_fingerprint(request):
        """Generate device fingerprint"""
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        accept_language = request.META.get('HTTP_ACCEPT_LANGUAGE', '')
        accept_encoding = request.META.get('HTTP_ACCEPT_ENCODING', '')

        fingerprint_data = f"{user_agent}{accept_language}{accept_encoding}"
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:64]


class SecurityAlert(models.Model):
    """
    Security alerts sent to users about suspicious activities.
    """
    ALERT_TYPES = [
        ('LOGIN_BLOCKED', 'Login Attempt Blocked'),
        ('SESSION_TERMINATED', 'Session Terminated'),
        ('MULTIPLE_FAILURES', 'Multiple Failed Attempts'),
        ('SUSPICIOUS_LOCATION', 'Login from New Location'),
        ('DEVICE_CHANGE', 'Login from New Device'),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='security_alerts'
    )
    alert_type = models.CharField(max_length=30, choices=ALERT_TYPES)
    title = models.CharField(max_length=200)
    message = models.TextField()

    # Related login attempt
    login_attempt = models.ForeignKey(
        LoginAttempt,
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )

    # Alert metadata
    severity = models.CharField(
        max_length=20,
        choices=[
            ('LOW', 'Low'),
            ('MEDIUM', 'Medium'),
            ('HIGH', 'High'),
            ('CRITICAL', 'Critical')
        ],
        default='MEDIUM'
    )

    # Alert status
    is_read = models.BooleanField(default=False)
    is_acknowledged = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    read_at = models.DateTimeField(null=True, blank=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'security_alerts'
        indexes = [
            models.Index(fields=['user', 'is_read', 'created_at']),
            models.Index(fields=['alert_type', 'created_at']),
            models.Index(fields=['severity', 'is_acknowledged']),
        ]
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username} - {self.get_alert_type_display()}"

    def mark_as_read(self):
        """Mark alert as read"""
        if not self.is_read:
            self.is_read = True
            self.read_at = timezone.now()
            self.save(update_fields=['is_read', 'read_at'])

    def acknowledge(self):
        """Acknowledge the alert"""
        if not self.is_acknowledged:
            self.is_acknowledged = True
            self.acknowledged_at = timezone.now()
            self.save(update_fields=['is_acknowledged', 'acknowledged_at'])

