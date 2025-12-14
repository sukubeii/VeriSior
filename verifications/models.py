from django.db import models
from django.utils import timezone
import uuid

# ======================================================
# Discount Transactions
# ======================================================
class DiscountTransaction(models.Model):
    CATEGORY_CHOICES = [
        ('MEDICINE', 'Medicine'),
        ('GROCERY', 'Grocery'),
        ('TRANSPORT', 'Transport'),
        ('RESTAURANT', 'Restaurant'),
        ('UTILITY', 'Utility'),
        ('OTHER', 'Other'),
    ]

    STATUS_CHOICES = [
        ('APPLIED', 'Applied'),
        ('VOIDED', 'Voided'),
    ]

    # Transaction tracking
    transaction_number = models.CharField(max_length=20, unique=True, db_index=True, help_text='Unique transaction number', default='')

    # Senior information
    id_number = models.CharField(max_length=20, db_index=True)
    senior_name = models.CharField(max_length=255)

    # Discount details
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES)
    discount_amount = models.DecimalField(max_digits=10, decimal_places=2, help_text='Discounted amount in PHP', default=0.00)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='APPLIED')

    # Establishment information
    establishment_name = models.CharField(max_length=20, help_text='Establishment name (max 20 chars)', default='')
    establishment_contact = models.CharField(max_length=11, help_text='Contact number (11 digits)', default='')
    establishment_address = models.CharField(max_length=25, help_text='Establishment address (max 25 chars)', default='')

    # Location tracking
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    location_accuracy = models.FloatField(null=True, blank=True, help_text='GPS accuracy in meters')

    created_at = models.DateTimeField(auto_now_add=True)
    voided_at = models.DateTimeField(null=True, blank=True)

    def save(self, *args, **kwargs):
        if not self.transaction_number:
            # Generate unique transaction number: TXN-YYYYMMDD-XXXXXX
            date_str = timezone.now().strftime('%Y%m%d')
            unique_id = str(uuid.uuid4().hex[:6]).upper()
            self.transaction_number = f"TXN-{date_str}-{unique_id}"
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.senior_name} ({self.id_number}) - {self.category} [{self.status}]"

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['id_number', 'created_at']),
            models.Index(fields=['ip_address']),
        ]


# ======================================================
# Verification Requests (IDs not found)
# ======================================================
class VerificationRequest(models.Model):
    id_number = models.CharField(max_length=20, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_archived = models.BooleanField(default=False)

    def __str__(self):
        return f"Verification Request for {self.id_number} at {self.created_at.strftime('%Y-%m-%d %H:%M:%S')}"

    class Meta:
        ordering = ['-created_at']
