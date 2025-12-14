from django.db import models, transaction
from simple_history.models import HistoricalRecords
import uuid
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.db.models import Max
from datetime import date, datetime, timedelta
import re

class SeniorCitizen(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'Pending Approval'),
        ('APPROVED', 'Approved'),
        ('REJECTED', 'Rejected'),
        ('DEACTIVATED', 'Temporarily Deactivated'),
        ('ARCHIVED', 'Archived'),
        ('DELETED', 'Deleted'),  # Soft-deleted, ready for permanent deletion
    ]
    
    VACCINATION_STATUS_CHOICES = [
        ('FULL', 'Fully Vaccinated'),
        ('PARTIAL', 'Partially Vaccinated'),
        ('NONE', 'Not Vaccinated'),
    ]
    
    GENDER_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
    ]
    
    EYE_COLOR_CHOICES = [
        ('BLACK', 'Black'),
        ('BROWN', 'Brown'),
        ('BLUE', 'Blue'),
        ('GREEN', 'Green'),
        ('HAZEL', 'Hazel'),
        ('GRAY', 'Gray'),
        ('OTHER', 'Other'),
    ]

    BLOOD_TYPE_CHOICES = [
        ('A+', 'A+'),
        ('A-', 'A-'),
        ('B+', 'B+'),
        ('B-', 'B-'),
        ('AB+', 'AB+'),
        ('AB-', 'AB-'),
        ('O+', 'O+'),
        ('O-', 'O-'),
    ]
    
    ARCHIVE_REASON_CHOICES = [
        ('DECEASED', 'Senior citizen is deceased'),
        ('MOVED', 'Moved to different municipality'),
        ('DUPLICATE', 'Duplicate record'),
        ('ERROR', 'Record created in error'),
        ('REQUEST', 'Archive requested by senior citizen'),
        ('EXPIRED_NO_RENEWAL', 'ID expired and not renewed'),
        ('PROOF_OF_LIFE_FAILED', 'Failed proof of life verification'),
        ('AUTO_EXPIRED', 'Automatically archived - ID expired'),
        ('AUTO_DECEASED', 'Automatically archived - Presumed deceased'),
        ('OTHER', 'Other reason'),
    ]
    
    DEACTIVATION_REASON_CHOICES = [
        ('EXPIRED_PENDING_RENEWAL', 'ID expired - pending renewal'),
        ('PROOF_OF_LIFE_OVERDUE', 'Proof of life overdue'),
        ('ADMINISTRATIVE', 'Administrative suspension'),
    ]

    EMERGENCY_CONTACT_RELATION_CHOICES = [
        ('WIFE', 'Wife'),
        ('SON', 'Son'),
        ('DAUGHTER', 'Daughter'),
        ('SIBLING', 'Sibling'),
        ('RELATIVE', 'Relative'),
    ]

    # Barangay codes mapping
    BARANGAY_CODES = {
        '005': 'Bagbag',
        '021': 'Capri',
        '041': 'Fairview',
        '042': 'Greater Lagro',
        '043': 'Gulod',
        '047': 'Kaligayahan',
        '069': 'Nagkaisang Nayon',
        '072': 'North Fairview',
        '073': 'Novaliches Proper',
        '083': 'Pasong Putik',
        '099': 'San Agustin',
        '101': 'San Bartolome',
        '119': 'Sta. Lucia',
        '120': 'Sta. Monica',
    }
    
    # Basic information
    id_number = models.CharField(max_length=15, unique=True)  # Changed from 20 to 15
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    middle_name = models.CharField(max_length=100, blank=True, null=True)
    birth_date = models.DateField()
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES, default='M')
    address = models.TextField()
    barangay_code = models.CharField(max_length=3, blank=True, null=True)
    
    # Contact information
    mobile_number = models.CharField(max_length=20, blank=True, null=True)
    telephone_number = models.CharField(max_length=20, blank=True, null=True)
    
    # Health information
    vaccination_status = models.CharField(max_length=10, choices=VACCINATION_STATUS_CHOICES, default='NONE')
    height = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True, help_text='Height in centimeters')
    weight = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True, help_text='Weight in kilograms')
    eye_color = models.CharField(max_length=10, choices=EYE_COLOR_CHOICES, blank=True, null=True)
    blood_type = models.CharField(max_length=3, choices=BLOOD_TYPE_CHOICES, blank=True, null=True, help_text='Blood type (A+, B+, O+, etc.)')
    
    # Emergency contact information
    emergency_contact_name = models.CharField(max_length=200, blank=True, null=True)
    emergency_contact_relation = models.CharField(max_length=20, choices=EMERGENCY_CONTACT_RELATION_CHOICES, blank=True, null=True)
    emergency_contact_address = models.TextField(blank=True, null=True)
    emergency_contact_number = models.CharField(max_length=20, blank=True, null=True)

    # Files and images
    photo = models.ImageField(upload_to='senior_photos/', blank=True, null=True)
    qr_code = models.ImageField(upload_to='qr_codes/', blank=True, null=True)

    # Required documents
    birth_certificate = models.FileField(upload_to='senior_documents/birth_certificates/', blank=True, null=True, help_text='Birth certificate (PDF or JPEG)')
    certificate_of_indigency = models.FileField(upload_to='senior_documents/indigency_certificates/', blank=True, null=True, help_text='Certificate of indigency (PDF or JPEG)')
    marriage_certificate = models.FileField(upload_to='senior_documents/marriage_certificates/', blank=True, null=True, help_text='Marriage certificate (PDF or JPEG) - Optional')
    
    # Critical date fields for automation
    application_date = models.DateField(
        help_text='Date when the senior citizen applied or was registered',
        null=True, blank=True
    )
    
    expiration_date = models.DateField(
        help_text='Date when the senior citizen ID expires (10 years from application)',
        null=True, blank=True
    )
    last_renewed_date = models.DateField(
        help_text='Date when the ID was last renewed',
        null=True, blank=True
    )
    
    next_proof_of_life_date = models.DateField(
        help_text='Date when next proof of life is required (yearly from application)',
        null=True, blank=True
    )
    last_proof_of_life_date = models.DateField(
        help_text='Date when proof of life was last completed',
        null=True, blank=True
    )
    proof_of_life_overdue = models.BooleanField(
        default=False,
        help_text='True if proof of life is overdue'
    )
    
    # Automatic processing tracking
    last_auto_check_date = models.DateTimeField(
        null=True, blank=True,
        help_text='Last time automated status check was performed'
    )
    expiration_warning_sent = models.BooleanField(
        default=False,
        help_text='True if expiration warning has been sent'
    )
    proof_of_life_warning_sent = models.BooleanField(
        default=False,
        help_text='True if proof of life warning has been sent'
    )
    
    # System fields
    created_by = models.ForeignKey('accounts.CustomUser', on_delete=models.SET_NULL, null=True, related_name='created_seniors')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_by = models.ForeignKey('accounts.CustomUser', on_delete=models.SET_NULL, null=True, related_name='updated_seniors')
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='PENDING')
    
    # Deactivation fields
    deactivation_reason = models.CharField(
        max_length=30,
        choices=DEACTIVATION_REASON_CHOICES,
        blank=True,
        null=True,
        help_text='Reason for temporary deactivation'
    )
    deactivated_at = models.DateTimeField(
        blank=True,
        null=True,
        help_text='Date and time when record was deactivated'
    )
    deactivated_by = models.ForeignKey(
        'accounts.CustomUser',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='deactivated_seniors',
        help_text='User who deactivated this record (or system if automatic)'
    )
    
    # Archive-related fields
    archive_reason = models.CharField(
        max_length=25,
        choices=ARCHIVE_REASON_CHOICES, 
        blank=True, 
        null=True,
        help_text='Reason for archiving this record'
    )
    archive_notes = models.TextField(
        blank=True, 
        null=True,
        help_text='Additional notes about why this record was archived'
    )
    archived_by = models.ForeignKey(
        'accounts.CustomUser', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='archived_seniors',
        help_text='User who archived this record'
    )
    archived_at = models.DateTimeField(
        blank=True,
        null=True,
        help_text='Date and time when this record was archived'
    )
    deleted_by = models.ForeignKey(
        'accounts.CustomUser',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='deleted_seniors',
        help_text='User who deleted this archived record'
    )
    deleted_at = models.DateTimeField(
        blank=True,
        null=True,
        help_text='Date and time when this record was moved to deleted status'
    )

    history = HistoricalRecords()
    
    def __str__(self):
        return f"{self.last_name}, {self.first_name} ({self.id_number})"
    
    def save(self, *args, **kwargs):
        """Enhanced save method with automatic date calculations"""
        # Set application_date to created_at date if not provided (for new records)
        if not self.application_date and not self.pk:
            self.application_date = timezone.now().date()
        elif not self.application_date and self.pk and self.created_at:
            self.application_date = self.created_at.date()
        
        # Calculate expiration date (10 years from application date)
        if self.application_date and not self.expiration_date:
            self.expiration_date = date(
                self.application_date.year + 10,
                self.application_date.month,
                self.application_date.day
            )
        
        # Calculate next proof of life date (1 year from application or last proof)
        if not self.next_proof_of_life_date:
            if self.last_proof_of_life_date:
                # Next year from last proof of life
                self.next_proof_of_life_date = date(
                    self.last_proof_of_life_date.year + 1,
                    self.last_proof_of_life_date.month,
                    self.last_proof_of_life_date.day
                )
            elif self.application_date:
                # First proof of life - 1 year from application
                self.next_proof_of_life_date = date(
                    self.application_date.year + 1,
                    self.application_date.month,
                    self.application_date.day
                )
        
        # Extract barangay code from existing ID number if not set
        if self.id_number and not self.barangay_code:
            self.barangay_code = self.extract_barangay_code_from_id()
        
        # Generate ID number if not set
        if not self.id_number:
            self.id_number = self.generate_id_number()
        
        # Validate ID number format
        if self.id_number:
            self.validate_id_number_format()
        
        super().save(*args, **kwargs)
    
    # Status check methods
    def is_expired(self):
        """Check if the senior citizen ID is expired"""
        if not self.expiration_date:
            return False
        return date.today() > self.expiration_date
    
    def is_proof_of_life_overdue(self):
        """Check if proof of life is overdue"""
        if not self.next_proof_of_life_date:
            return False
        return date.today() > self.next_proof_of_life_date
    
    def days_until_expiration(self):
        """Get number of days until expiration"""
        if not self.expiration_date:
            return None
        delta = self.expiration_date - date.today()
        return delta.days
    
    def days_until_proof_of_life(self):
        """Get number of days until next proof of life"""
        if not self.next_proof_of_life_date:
            return None
        delta = self.next_proof_of_life_date - date.today()
        return delta.days
    
    def get_status_with_context(self):
        """Get status with additional context for expired/overdue"""
        base_status = self.get_status_display()
        
        if self.status == 'DEACTIVATED':
            if self.deactivation_reason:
                return f"{base_status} ({self.get_deactivation_reason_display()})"
        elif self.status == 'APPROVED':
            warnings = []
            if self.is_expired():
                warnings.append("EXPIRED")
            if self.is_proof_of_life_overdue():
                warnings.append("PROOF OF LIFE OVERDUE")
            
            if warnings:
                return f"{base_status} - {', '.join(warnings)}"
        
        return base_status
    
    def can_be_verified(self):
        """Check if the senior citizen can be publicly verified"""
        return (
            self.status == 'APPROVED' and 
            not self.is_archived() and 
            not self.is_expired() and 
            not self.is_proof_of_life_overdue()
        )
    
    def is_archived(self):
        """Check if the record is archived"""
        return self.status == 'ARCHIVED'
    
    def needs_expiration_warning(self):
        """Check if expiration warning should be sent (30 days before)"""
        if not self.expiration_date or self.expiration_warning_sent:
            return False
        days_until = self.days_until_expiration()
        return days_until is not None and 0 < days_until <= 30
    
    def needs_proof_of_life_warning(self):
        """Check if proof of life warning should be sent (30 days before)"""
        if not self.next_proof_of_life_date or self.proof_of_life_warning_sent:
            return False
        days_until = self.days_until_proof_of_life()
        return days_until is not None and 0 < days_until <= 30
    
    def should_auto_deactivate_expired(self):
        """Check if should be automatically deactivated due to expiration"""
        return (
            self.status == 'APPROVED' and 
            self.is_expired() and 
            self.status != 'DEACTIVATED'
        )
    
    def should_auto_deactivate_proof_of_life(self):
        """Check if should be automatically deactivated due to proof of life"""
        return (
            self.status == 'APPROVED' and 
            self.is_proof_of_life_overdue() and 
            self.status != 'DEACTIVATED'
        )
    
    def should_auto_archive_expired(self):
        """Check if should be automatically archived (30 days after expiration)"""
        if not self.expiration_date or self.status == 'ARCHIVED':
            return False
        days_since_expiration = (date.today() - self.expiration_date).days
        return (
            self.status == 'DEACTIVATED' and 
            self.deactivation_reason == 'EXPIRED_PENDING_RENEWAL' and
            days_since_expiration >= 30
        )
    
    def should_auto_archive_proof_of_life(self):
        """Check if should be automatically archived (30 days after proof of life due)"""
        if not self.next_proof_of_life_date or self.status == 'ARCHIVED':
            return False
        days_since_due = (date.today() - self.next_proof_of_life_date).days
        return (
            self.status == 'DEACTIVATED' and 
            self.deactivation_reason == 'PROOF_OF_LIFE_OVERDUE' and
            days_since_due >= 30
        )
    
    def auto_deactivate_expired(self, system_user=None):
        """Automatically deactivate due to expiration"""
        self.status = 'DEACTIVATED'
        self.deactivation_reason = 'EXPIRED_PENDING_RENEWAL'
        self.deactivated_at = timezone.now()
        self.deactivated_by = system_user
        self.last_auto_check_date = timezone.now()
        self.save()
        
        # Log the action
        from core.models import AuditLog
        AuditLog.objects.create(
            user=system_user,
            action='AUTO_DEACTIVATE',
            content_type='SeniorCitizen',
            object_id=self.id,
            description=f'Auto-deactivated expired senior citizen: {self.id_number}',
            ip_address='127.0.0.1'
        )
    
    def auto_deactivate_proof_of_life(self, system_user=None):
        """Automatically deactivate due to overdue proof of life"""
        self.status = 'DEACTIVATED'
        self.deactivation_reason = 'PROOF_OF_LIFE_OVERDUE'
        self.deactivated_at = timezone.now()
        self.deactivated_by = system_user
        self.proof_of_life_overdue = True
        self.last_auto_check_date = timezone.now()
        self.save()
        
        # Log the action
        from core.models import AuditLog
        AuditLog.objects.create(
            user=system_user,
            action='AUTO_DEACTIVATE',
            content_type='SeniorCitizen',
            object_id=self.id,
            description=f'Auto-deactivated senior citizen due to overdue proof of life: {self.id_number}',
            ip_address='127.0.0.1'
        )
    
    def auto_archive_expired(self, system_user=None):
        """Automatically archive due to expired ID not renewed"""
        self.status = 'ARCHIVED'
        self.archive_reason = 'AUTO_EXPIRED'
        self.archived_at = timezone.now()
        self.archived_by = system_user
        self.archive_notes = 'Automatically archived: ID expired and not renewed within 30-day grace period'
        self.last_auto_check_date = timezone.now()
        self.save()
        
        # Log the action
        from core.models import AuditLog
        AuditLog.objects.create(
            user=system_user,
            action='AUTO_ARCHIVE',
            content_type='SeniorCitizen',
            object_id=self.id,
            description=f'Auto-archived expired senior citizen: {self.id_number}',
            ip_address='127.0.0.1'
        )
    
    def auto_archive_proof_of_life(self, system_user=None):
        """Automatically archive due to proof of life failure (presumed deceased)"""
        self.status = 'ARCHIVED'
        self.archive_reason = 'AUTO_DECEASED'
        self.archived_at = timezone.now()
        self.archived_by = system_user
        self.archive_notes = 'Automatically archived: Proof of life not completed within 30-day grace period (presumed deceased)'
        self.last_auto_check_date = timezone.now()
        self.save()
        
        # Log the action
        from core.models import AuditLog
        AuditLog.objects.create(
            user=system_user,
            action='AUTO_ARCHIVE',
            content_type='SeniorCitizen',
            object_id=self.id,
            description=f'Auto-archived senior citizen (presumed deceased): {self.id_number}',
            ip_address='127.0.0.1'
        )
    
    def renew_id(self, renewed_by=None):
        """Renew the senior citizen ID for another 10 years"""
        today = date.today()
        self.last_renewed_date = today
        self.expiration_date = date(today.year + 10, today.month, today.day)
        self.expiration_warning_sent = False  # Reset warning flag
        
        # If deactivated due to expiration, reactivate
        if self.status == 'DEACTIVATED' and self.deactivation_reason == 'EXPIRED_PENDING_RENEWAL':
            self.status = 'APPROVED'
            self.deactivation_reason = None
            self.deactivated_at = None
            self.deactivated_by = None
        
        if renewed_by:
            self.updated_by = renewed_by
        
        self.save()
    
    def complete_proof_of_life(self, completed_by=None):
        """Complete proof of life verification"""
        today = date.today()
        self.last_proof_of_life_date = today
        self.next_proof_of_life_date = date(today.year + 1, today.month, today.day)
        self.proof_of_life_overdue = False
        self.proof_of_life_warning_sent = False  # Reset warning flag
        
        # If deactivated due to proof of life, reactivate
        if self.status == 'DEACTIVATED' and self.deactivation_reason == 'PROOF_OF_LIFE_OVERDUE':
            self.status = 'APPROVED'
            self.deactivation_reason = None
            self.deactivated_at = None
            self.deactivated_by = None
        
        if completed_by:
            self.updated_by = completed_by
            
        self.save()
    
    @classmethod
    def run_automated_checks(cls, system_user=None):
        """Run automated status checks for all active senior citizens"""
        today = date.today()
        results = {
            'checked': 0,
            'warnings_sent': 0,
            'deactivated': 0,
            'archived': 0,
            'errors': []
        }
        
        # Get all seniors that need checking (approved or deactivated)
        seniors_to_check = cls.objects.filter(
            status__in=['APPROVED', 'DEACTIVATED']
        ).exclude(
            last_auto_check_date__date=today  # Skip if already checked today
        )
        
        for senior in seniors_to_check:
            try:
                results['checked'] += 1
                
                # Check for warnings first (30 days before due dates)
                if senior.needs_expiration_warning():
                    senior.expiration_warning_sent = True
                    senior.save()
                    results['warnings_sent'] += 1
                    # Here you could send actual notifications/emails
                
                if senior.needs_proof_of_life_warning():
                    senior.proof_of_life_warning_sent = True
                    senior.save()
                    results['warnings_sent'] += 1
                    # Here you could send actual notifications/emails
                
                # Check for automatic archiving (30 days after deactivation)
                if senior.should_auto_archive_expired():
                    senior.auto_archive_expired(system_user)
                    results['archived'] += 1
                    continue
                
                if senior.should_auto_archive_proof_of_life():
                    senior.auto_archive_proof_of_life(system_user)
                    results['archived'] += 1
                    continue
                
                # Check for automatic deactivation (on due dates)
                if senior.should_auto_deactivate_expired():
                    senior.auto_deactivate_expired(system_user)
                    results['deactivated'] += 1
                    continue
                
                if senior.should_auto_deactivate_proof_of_life():
                    senior.auto_deactivate_proof_of_life(system_user)
                    results['deactivated'] += 1
                    continue
                
                # Update last check date
                senior.last_auto_check_date = timezone.now()
                senior.save()
                
            except Exception as e:
                results['errors'].append(f"Error checking {senior.id_number}: {str(e)}")
        
        return results
    
    def extract_barangay_code_from_id(self):
        """Extract barangay code from ID number"""
        if self.id_number and len(self.id_number) >= 3:
            return self.id_number[:3]
        return None
    
    def validate_id_number_format(self):
        """Validate ID number format"""
        if not self.id_number:
            return
        
        # Expected format: XXX0000ZZZZZZZZ (15 digits total)
        if not re.match(r'^\d{3}0000\d{8}$', self.id_number):
            raise ValidationError(f'Invalid ID number format: {self.id_number}. Expected format: XXX0000ZZZZZZZZ')
        
        # Validate barangay code
        barangay_code = self.id_number[:3]
        if barangay_code not in self.BARANGAY_CODES:
            raise ValidationError(f'Invalid barangay code in ID number: {barangay_code}')
    
    @classmethod
    def get_next_global_count(cls):
        """Get the next global sequential number for ID generation"""
        # Get ALL ID numbers from the database
        all_ids = cls.objects.all().values_list('id_number', flat=True)
        
        if not all_ids:
            return 1  # First senior citizen ever
        
        max_sequential = 0
        
        # Iterate through all IDs and extract the sequential part (last 8 digits)
        for id_num in all_ids:
            try:
                # Convert to string to safely extract last 8 characters
                id_str = str(id_num)
                # Extract last 8 digits
                sequential = int(id_str[-8:])
                
                # Keep track of the maximum sequential number found
                if sequential > max_sequential:
                    max_sequential = sequential
            except (ValueError, TypeError, IndexError):
                # Skip any malformed IDs
                continue
        
        # Return the next number in the sequence
        return max_sequential + 1
    
    def generate_id_number(self):
        """Generate ID number for senior citizen with format XXX0000ZZZZZZZZ"""
        if not self.barangay_code:
            raise ValidationError('Barangay code is required for ID generation')
        
        # Get next global sequential count (increments across all barangays)
        next_count = self.get_next_global_count()
        
        # Format: XXX0000ZZZZZZZZ (15 digits total)
        # XXX = barangay code (3 digits)
        # 0000 = zero placeholders (4 digits) 
        # ZZZZZZZZ = sequential number (8 digits, up to 99,999,999)
        id_number = f"{self.barangay_code}0000{next_count:08d}"
        
        # Ensure uniqueness (safety check in case of race conditions)
        while SeniorCitizen.objects.filter(id_number=id_number).exists():
            next_count += 1
            id_number = f"{self.barangay_code}0000{next_count:08d}"
        
        return id_number
    
    def get_barangay_name(self):
        """Get the barangay name from code"""
        return self.BARANGAY_CODES.get(self.barangay_code, 'Unknown Barangay')
    
    def get_age(self):
        """Calculate age from birth date"""
        if not self.birth_date:
            return None
        
        today = date.today()
        age = today.year - self.birth_date.year
        
        # Adjust if birthday hasn't occurred this year
        if today.month < self.birth_date.month or \
           (today.month == self.birth_date.month and today.day < self.birth_date.day):
            age -= 1
        
        return age
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['id_number']),
            models.Index(fields=['barangay_code']),
            models.Index(fields=['created_at']),
            models.Index(fields=['archived_at']),
            models.Index(fields=['expiration_date']),
            models.Index(fields=['next_proof_of_life_date']),
            models.Index(fields=['application_date']),
            models.Index(fields=['last_auto_check_date']),
        ]

class SeniorDocument(models.Model):
    """Model for documents uploaded for senior citizens"""
    
    senior = models.ForeignKey(SeniorCitizen, on_delete=models.CASCADE, related_name='documents')
    title = models.CharField(max_length=200)
    document = models.FileField(upload_to='senior_documents/')
    uploaded_by = models.ForeignKey('accounts.CustomUser', on_delete=models.SET_NULL, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-uploaded_at']
    
    def __str__(self):
        return f"{self.title} - {self.senior.id_number}"


class ProofOfLifeLog(models.Model):
    """Log of proof of life verifications"""
    senior = models.ForeignKey(SeniorCitizen, on_delete=models.CASCADE, related_name='proof_of_life_logs')
    verification_date = models.DateTimeField(auto_now_add=True)
    verified_by = models.ForeignKey('accounts.CustomUser', on_delete=models.SET_NULL, null=True)
    verification_method = models.CharField(
        max_length=20,
        choices=[
            ('IN_PERSON', 'In-Person Verification'),
            ('ONLINE', 'Online Verification'),
            ('PHONE', 'Phone Verification'),
            ('DOCUMENT', 'Document Submission'),
        ],
        default='IN_PERSON'
    )
    notes = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-verification_date']
        
    def __str__(self):
        return f"Proof of Life - {self.senior.id_number} - {self.verification_date.date()}"


class RenewalLog(models.Model):
    """Log of ID renewals"""
    senior = models.ForeignKey(SeniorCitizen, on_delete=models.CASCADE, related_name='renewal_logs')
    renewal_date = models.DateTimeField(auto_now_add=True)
    renewed_by = models.ForeignKey('accounts.CustomUser', on_delete=models.SET_NULL, null=True)
    previous_expiration_date = models.DateField()
    new_expiration_date = models.DateField()
    renewal_fee = models.DecimalField(max_digits=8, decimal_places=2, null=True, blank=True)
    notes = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-renewal_date']
        
    def __str__(self):
        return f"Renewal - {self.senior.id_number} - {self.renewal_date.date()}"


class SystemStatusCheck(models.Model):
    """Log of automated system status checks"""
    check_date = models.DateTimeField(auto_now_add=True)
    checked_by = models.ForeignKey('accounts.CustomUser', on_delete=models.SET_NULL, null=True, blank=True)
    seniors_checked = models.IntegerField(default=0)
    warnings_sent = models.IntegerField(default=0)
    deactivated_count = models.IntegerField(default=0)
    archived_count = models.IntegerField(default=0)
    errors_count = models.IntegerField(default=0)
    notes = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-check_date']
    
    def __str__(self):
        return f"System Check - {self.check_date.date()} - {self.seniors_checked} seniors"
