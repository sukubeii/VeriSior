# government/forms.py - Complete Updated Forms with Address Components and Binary Gender

from django import forms
from django.core.validators import RegexValidator, MinLengthValidator, MaxLengthValidator
from django.core.exceptions import ValidationError
from datetime import date, datetime
import re
from .models import SeniorCitizen, SeniorDocument

class SeniorCitizenForm(forms.ModelForm):
    # Barangay choices based on the provided list
    BARANGAY_CHOICES = [
        ('', 'Select Barangay'),
        ('005', 'Bagbag (005)'),
        ('021', 'Capri (021)'),
        ('041', 'Fairview (041)'),
        ('042', 'Greater Lagro (042)'),
        ('043', 'Gulod (043)'),
        ('047', 'Kaligayahan (047)'),
        ('069', 'Nagkaisang Nayon (069)'),
        ('072', 'North Fairview (072)'),
        ('073', 'Novaliches Proper (073)'),
        ('083', 'Pasong Putik (083)'),
        ('099', 'San Agustin (099)'),
        ('101', 'San Bartolome (101)'),
        ('119', 'Sta. Lucia (119)'),
        ('120', 'Sta. Monica (120)'),
    ]
    
    barangay = forms.ChoiceField(
        choices=BARANGAY_CHOICES,
        required=True,
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    
    birth_date_text = forms.DateField(
        required=True,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date',
            'max': '',  # Will be set dynamically in __init__
        }),
        label='Birth Date'
    )
    
    application_date_text = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'MM/DD/YYYY',
            'pattern': r'\d{1,2}/\d{1,2}/\d{4}',
            'title': 'Enter application date in MM/DD/YYYY format'
        }),
        label='Application Date (Optional)'
    )
    
    # Address component fields
    house_number = forms.CharField(
        required=True,
        max_length=50,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'e.g. 123, Unit 4B, Blk 5 Lot 12'
        }),
        label='House #/Unit #'
    )
    
    street = forms.CharField(
        required=True,
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'e.g. Rizal Street, Main Avenue'
        }),
        label='Street'
    )
    
    subdivision = forms.CharField(
        required=False,
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'e.g. Greenfield Village, Palm Heights Subdivision'
        }),
        label='Subdivision/Village'
    )
    
    city = forms.CharField(
        required=True,
        max_length=50,
        initial='Quezon City',
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'readonly': True,
            'value': 'Quezon City'
        }),
        label='City'
    )
    
    id_number = forms.CharField(required=False, widget=forms.HiddenInput())

    # File upload fields for documents
    birth_certificate = forms.FileField(
        required=True,
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.pdf,.jpg,.jpeg'
        }),
        label='Birth Certificate',
        help_text='Upload birth certificate (PDF or JPEG, max 10MB)'
    )

    certificate_of_indigency = forms.FileField(
        required=True,
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.pdf,.jpg,.jpeg'
        }),
        label='Certificate of Indigency',
        help_text='Upload certificate of indigency (PDF or JPEG, max 10MB)'
    )

    marriage_certificate = forms.FileField(
        required=False,
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.pdf,.jpg,.jpeg'
        }),
        label='Marriage Certificate (Optional)',
        help_text='Upload marriage certificate (PDF or JPEG, max 10MB)'
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Calculate max date for birth date (60 years ago from today)
        today = date.today()
        max_birth_date = date(today.year - 60, today.month, today.day)
        self.fields['birth_date_text'].widget.attrs['max'] = max_birth_date.strftime('%Y-%m-%d')
        
        if self.instance and self.instance.pk and self.instance.id_number:
            self.fields['id_number'].widget.attrs['readonly'] = True
            self.fields['id_number'].required = False
        else:
            self.fields['id_number'].widget = forms.HiddenInput()
            self.fields['id_number'].required = False
            
        if self.instance and self.instance.pk:
            self.fields['barangay'].initial = getattr(self.instance, 'barangay_code', '')
    
        if self.instance and self.instance.pk and self.instance.birth_date:
            self.fields['birth_date_text'].initial = self.instance.birth_date.strftime('%Y-%m-%d')
        
        if self.instance and self.instance.pk and self.instance.application_date:
            self.fields['application_date_text'].initial = self.instance.application_date.strftime('%m/%d/%Y')
        
        # Parse existing address into components for editing
        if self.instance and self.instance.pk and self.instance.address:
            self._parse_existing_address()
            
        if 'birth_date' in self.fields:
            del self.fields['birth_date']

        if 'gender' in self.fields:
            self.fields['gender'].empty_label = None
            self.fields['gender'].required = True

        # Make file uploads optional for editing existing records
        if self.instance and self.instance.pk:
            self.fields['birth_certificate'].required = False
            self.fields['certificate_of_indigency'].required = False
    
    def _parse_existing_address(self):
        """Parse existing address into component fields for editing"""
        address = self.instance.address
        if not address:
            return
        
        # Split address by commas
        parts = [part.strip() for part in address.split(',') if part.strip()]
        
        if len(parts) >= 1:
            self.fields['house_number'].initial = parts[0]
        if len(parts) >= 2:
            self.fields['street'].initial = parts[1]
        if len(parts) >= 3:
            # Check if last part is "Quezon City"
            if len(parts) >= 4 or (len(parts) == 3 and 'quezon city' not in parts[2].lower()):
                self.fields['subdivision'].initial = parts[2]
                if len(parts) >= 4:
                    self.fields['city'].initial = parts[3]
        else:
            # Third part is the city
            self.fields['city'].initial = parts[2]
    
    def clean_first_name(self):
        first_name = self.cleaned_data.get('first_name')
        if first_name is None:
            raise ValidationError('First name is required.')
        
        first_name = first_name.strip()
        if not first_name:
            raise ValidationError('First name is required.')
        
        # Only letters and spaces, 2-50 characters
        if not re.match(r'^[a-zA-Z\s]{2,50}$', first_name):
            raise ValidationError('First name must contain only letters and spaces (2-50 characters).')
        
        # Capitalize properly
        return first_name.title()
    
    def clean_last_name(self):
        last_name = self.cleaned_data.get('last_name')
        if last_name is None:
            raise ValidationError('Last name is required.')
        
        last_name = last_name.strip()
        if not last_name:
            raise ValidationError('Last name is required.')
        
        # Only letters and spaces, 2-50 characters
        if not re.match(r'^[a-zA-Z\s]{2,50}$', last_name):
            raise ValidationError('Last name must contain only letters and spaces (2-50 characters).')
        
        # Capitalize properly
        return last_name.title()
    
    def clean_middle_name(self):
        middle_name = self.cleaned_data.get('middle_name')
        if middle_name is None:
            return ''
        
        middle_name = middle_name.strip()
        if middle_name:
            # Only letters and spaces, 1-50 characters
            if not re.match(r'^[a-zA-Z\s]{1,50}$', middle_name):
                raise ValidationError('Middle name must contain only letters and spaces (1-50 characters).')
            return middle_name.title()
        return middle_name
    
    def clean_birth_date_text(self):
        birth_date = self.cleaned_data.get('birth_date_text')
        if not birth_date:
            raise ValidationError('Birth date is required.')

        # Validate age
        today = date.today()
        age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))

        # Must be at least 60 years old
        if age < 60:
            raise ValidationError(f'Person must be at least 60 years old. Current age: {age} years.')

        # Cannot be more than 120 years old (reasonable limit)
        if age > 120:
            raise ValidationError(f'Invalid birth date. Age cannot exceed 120 years. Current age: {age} years.')

        # Cannot be in the future
        if birth_date > today:
            raise ValidationError('Birth date cannot be in the future.')

        return birth_date
    
    def clean_application_date_text(self):
        application_date_text = self.cleaned_data.get('application_date_text')
        
        # If empty, return None (will default to today)
        if not application_date_text or not application_date_text.strip():
            return None
        
        application_date_text = application_date_text.strip()
        
        # Parse date formats
        application_date = None
        formats = [
            r'^(\d{1,2})/(\d{1,2})/(\d{4})$',  # MM/DD/YYYY
            r'^(\d{1,2})-(\d{1,2})-(\d{4})$',   # MM-DD-YYYY
            r'^(\d{1,2})\.(\d{1,2})\.(\d{4})$'  # MM.DD.YYYY
        ]
        
        for format_pattern in formats:
            match = re.match(format_pattern, application_date_text)
            if match:
                month, day, year = map(int, match.groups())
                try:
                    application_date = date(year, month, day)
                    break
                except ValueError:
                    continue
        
        if not application_date:
            raise ValidationError('Invalid application date format. Please use MM/DD/YYYY format.')
        
        # Validate application date
        today = date.today()
        
        # Cannot be in the future
        if application_date > today:
            raise ValidationError('Application date cannot be in the future.')
        
        # Cannot be more than 10 years ago
        ten_years_ago = date(today.year - 10, today.month, today.day)
        if application_date < ten_years_ago:
            raise ValidationError('Application date cannot be more than 10 years ago.')
        
        return application_date
    
    def clean_house_number(self):
        house_number = self.cleaned_data.get('house_number')
        if not house_number:
            raise ValidationError('House number/Unit number is required.')
        
        house_number = house_number.strip()
        if len(house_number) < 1:
            raise ValidationError('House number/Unit number is required.')
        if len(house_number) > 50:
            raise ValidationError('House number/Unit number cannot exceed 50 characters.')
        
        return house_number
    
    def clean_street(self):
        street = self.cleaned_data.get('street')
        if not street:
            raise ValidationError('Street name is required.')
        
        street = street.strip()
        if len(street) < 2:
            raise ValidationError('Street name must be at least 2 characters long.')
        if len(street) > 100:
            raise ValidationError('Street name cannot exceed 100 characters.')
        
        return street
    
    def clean_subdivision(self):
        subdivision = self.cleaned_data.get('subdivision')
        if subdivision:
            subdivision = subdivision.strip()
            if len(subdivision) > 100:
                raise ValidationError('Subdivision/Village name cannot exceed 100 characters.')
        return subdivision if subdivision else ''
    
    def clean_gender(self):
        gender = self.cleaned_data.get('gender')
        if not gender:
            raise ValidationError('Gender is required.')
        return gender
    
    def clean_mobile_number(self):
        mobile_number = self.cleaned_data.get('mobile_number')
        if mobile_number is None:
            return ''
        
        mobile_number = mobile_number.strip()
        if mobile_number:
            # Remove all non-digit characters except + and -
            cleaned_mobile = re.sub(r'[^\d+\-]', '', mobile_number)
            
            # Philippine mobile number formats:
            # +639XXXXXXXXX (13 digits with +63)
            # 639XXXXXXXXX (12 digits starting with 63)
            # 09XXXXXXXXX (11 digits starting with 09)
            
            if re.match(r'^\+639\d{9}$', cleaned_mobile):
                return cleaned_mobile
            elif re.match(r'^639\d{9}$', cleaned_mobile):
                return '+' + cleaned_mobile
            elif re.match(r'^09\d{9}$', cleaned_mobile):
                return '+63' + cleaned_mobile[1:]
            else:
                raise ValidationError('Invalid mobile number format. Use +639XXXXXXXXX or 09XXXXXXXXX format.')
        
        return mobile_number
    
    def clean_telephone_number(self):
        telephone_number = self.cleaned_data.get('telephone_number')
        if telephone_number is None:
            return ''
        
        telephone_number = telephone_number.strip()
        if telephone_number:
            # Remove all non-digit characters except + - ( ) and spaces
            cleaned_tel = re.sub(r'[^\d+\-\(\)\s]', '', telephone_number)
            
            # Basic validation - at least 7 digits for landline
            digits_only = re.sub(r'\D', '', cleaned_tel)
            if len(digits_only) < 7:
                raise ValidationError('Telephone number must have at least 7 digits.')
            if len(digits_only) > 15:
                raise ValidationError('Telephone number cannot exceed 15 digits.')
            
            return telephone_number
        
        return telephone_number
    
    def clean_height(self):
        height = self.cleaned_data.get('height')
        if height is not None:
            if height < 50 or height > 250:
                raise ValidationError('Height must be between 50 and 250 centimeters.')
        return height
    
    def clean_weight(self):
        weight = self.cleaned_data.get('weight')
        if weight is not None:
            if weight < 20 or weight > 300:
                raise ValidationError('Weight must be between 20 and 300 kilograms.')
        return weight
    
    def clean_emergency_contact_name(self):
        name = self.cleaned_data.get('emergency_contact_name')
        if name is None:
            return ''
        
        name = name.strip()
        if name:
            # Only letters, spaces, and common punctuation, 2-100 characters
            if not re.match(r'^[a-zA-Z\s\.\,\-]{2,100}$', name):
                raise ValidationError('Emergency contact name must contain only letters, spaces, and basic punctuation (2-100 characters).')
            return name.title()
        return name
    
    def clean_emergency_contact_number(self):
        contact_number = self.cleaned_data.get('emergency_contact_number')
        if contact_number is None:
            return ''
        
        contact_number = contact_number.strip()
        if contact_number:
            # Similar validation to mobile/telephone
            digits_only = re.sub(r'\D', '', contact_number)
            if len(digits_only) < 7:
                raise ValidationError('Emergency contact number must have at least 7 digits.')
            if len(digits_only) > 15:
                raise ValidationError('Emergency contact number cannot exceed 15 digits.')
        return contact_number
    
    def clean_emergency_contact_address(self):
        address = self.cleaned_data.get('emergency_contact_address')
        if address is None:
            return ''
        
        address = address.strip()
        if address:
            if len(address) < 10:
                raise ValidationError('Emergency contact address must be at least 10 characters long.')
            if len(address) > 500:
                raise ValidationError('Emergency contact address cannot exceed 500 characters.')
        return address
    
    def clean_photo(self):
        photo = self.cleaned_data.get('photo')
        if photo:
            # Check file size (max 5MB)
            if photo.size > 5 * 1024 * 1024:
                raise ValidationError('Photo file size cannot exceed 5MB.')

            # Check file extension
            allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif']
            file_extension = photo.name.lower().split('.')[-1]
            if f'.{file_extension}' not in allowed_extensions:
                raise ValidationError('Photo must be in JPG, JPEG, PNG, or GIF format.')

        return photo

    def clean_birth_certificate(self):
        birth_certificate = self.cleaned_data.get('birth_certificate')
        if birth_certificate:
            # Check file size (max 10MB)
            if birth_certificate.size > 10 * 1024 * 1024:
                raise ValidationError('Birth certificate file size cannot exceed 10MB.')

            # Check file extension
            allowed_extensions = ['.pdf', '.jpg', '.jpeg']
            file_extension = birth_certificate.name.lower().split('.')[-1]
            if f'.{file_extension}' not in allowed_extensions:
                raise ValidationError('Birth certificate must be in PDF or JPEG format.')

        return birth_certificate

    def clean_certificate_of_indigency(self):
        certificate_of_indigency = self.cleaned_data.get('certificate_of_indigency')
        if certificate_of_indigency:
            # Check file size (max 10MB)
            if certificate_of_indigency.size > 10 * 1024 * 1024:
                raise ValidationError('Certificate of indigency file size cannot exceed 10MB.')

            # Check file extension
            allowed_extensions = ['.pdf', '.jpg', '.jpeg']
            file_extension = certificate_of_indigency.name.lower().split('.')[-1]
            if f'.{file_extension}' not in allowed_extensions:
                raise ValidationError('Certificate of indigency must be in PDF or JPEG format.')

        return certificate_of_indigency

    def clean_marriage_certificate(self):
        marriage_certificate = self.cleaned_data.get('marriage_certificate')
        if marriage_certificate:
            # Check file size (max 10MB)
            if marriage_certificate.size > 10 * 1024 * 1024:
                raise ValidationError('Marriage certificate file size cannot exceed 10MB.')

            # Check file extension
            allowed_extensions = ['.pdf', '.jpg', '.jpeg']
            file_extension = marriage_certificate.name.lower().split('.')[-1]
            if f'.{file_extension}' not in allowed_extensions:
                raise ValidationError('Marriage certificate must be in PDF or JPEG format.')

        return marriage_certificate
    
    def clean_vaccination_status(self):
        vaccination_status = self.cleaned_data.get('vaccination_status')
        if not vaccination_status:
            raise ValidationError('Vaccination status is required.')
        return vaccination_status
    
    def clean_barangay(self):
        barangay = self.cleaned_data.get('barangay')
        if not barangay:
            raise ValidationError('Barangay selection is required for ID number generation.')
        return barangay
    
    def clean(self):
        cleaned_data = super().clean()
        mobile_number = cleaned_data.get('mobile_number')
        telephone_number = cleaned_data.get('telephone_number')
        barangay = cleaned_data.get('barangay')
        birth_date_text = cleaned_data.get('birth_date_text')
        application_date_text = cleaned_data.get('application_date_text')
        
        # Combine address components - ENSURE THIS ALWAYS HAPPENS
        house_number = cleaned_data.get('house_number')
        street = cleaned_data.get('street')
        subdivision = cleaned_data.get('subdivision')
        city = cleaned_data.get('city', 'Quezon City')
        
        # Build complete address - ALWAYS create an address if we have required components
        if house_number and street:
            address_parts = [house_number.strip(), street.strip()]
            
            if subdivision and subdivision.strip():
                address_parts.append(subdivision.strip())
            
            if city and city.strip():
                address_parts.append(city.strip())
            else:
                address_parts.append('Quezon City')  # Default fallback
            
            combined_address = ', '.join(address_parts)
            cleaned_data['address'] = combined_address
            print(f"Form clean: Combined address = '{combined_address}'")  # Debug line
        else:
            # If we don't have the required components, check if we already have an address
            if not cleaned_data.get('address') and self.instance and self.instance.address:
                cleaned_data['address'] = self.instance.address
                print(f"Form clean: Keeping existing address = '{self.instance.address}'")  # Debug line
        
        # Ensure at least one contact method is provided
        if not mobile_number and not telephone_number:
            self.add_error('mobile_number', 'At least one contact method (mobile or telephone) is required.')
            self.add_error('telephone_number', 'At least one contact method (mobile or telephone) is required.')
        
        # Convert birth_date_text to birth_date for the model
        if birth_date_text:
            if isinstance(birth_date_text, date):
                cleaned_data['birth_date'] = birth_date_text
            elif isinstance(birth_date_text, str):
                # Handle string date input
                try:
                    cleaned_data['birth_date'] = datetime.strptime(birth_date_text, '%Y-%m-%d').date()
                except ValueError:
                    pass
        
        # Handle application date
        if application_date_text and isinstance(application_date_text, date):
            cleaned_data['application_date'] = application_date_text
        elif not application_date_text:
            # If no application date provided, it will default to today in the model's save method
            cleaned_data['application_date'] = None
        
        # Validate that application date is not before birth date
        if birth_date_text and application_date_text:
            if isinstance(birth_date_text, date) and isinstance(application_date_text, date):
                if application_date_text < birth_date_text:
                    self.add_error('application_date_text', 'Application date cannot be before birth date.')
        
        return cleaned_data
    
    class Meta:
        model = SeniorCitizen
        fields = [
            'id_number', 'first_name', 'last_name', 'middle_name',
            'birth_date_text', 'application_date_text', 'gender',
            'house_number', 'street', 'subdivision', 'city',
            'mobile_number', 'telephone_number',
            'vaccination_status', 'height', 'weight', 'eye_color', 'blood_type',
            'emergency_contact_name', 'emergency_contact_relation', 'emergency_contact_address',
            'emergency_contact_number', 'photo',
            'birth_certificate', 'certificate_of_indigency', 'marriage_certificate'
        ]
        widgets = {
            # Personal Information
            'first_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter first name',
                'maxlength': '50',
                'required': True
            }),
            'last_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter last name',
                'maxlength': '50',
                'required': True
            }),
            'middle_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter middle name (optional)',
                'maxlength': '50'
            }),
            'gender': forms.RadioSelect(attrs={'class': 'form-check-input'}),
            
            # Contact Information
            'mobile_number': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'e.g. 09123456789',
                'maxlength': '20'
            }),
            'telephone_number': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'e.g. 8123-4567',
                'maxlength': '20'
            }),
            
            # Health Information
            'vaccination_status': forms.RadioSelect(attrs={'class': 'form-check-input'}),
            'height': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.01',
                'placeholder': 'e.g. 152',
                'min': '50',
                'max': '250'
            }),
            'weight': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.01',
                'placeholder': 'e.g. 60',
                'min': '20',
                'max': '300'
            }),
            'eye_color': forms.Select(attrs={'class': 'form-control'}),
            'blood_type': forms.Select(attrs={
                'class': 'form-control',
                'placeholder': 'Select blood type'
            }),

            # Emergency Contact Information
            'emergency_contact_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter emergency contact name',
                'maxlength': '100'
            }),
            'emergency_contact_relation': forms.Select(attrs={
                'class': 'form-control'
            }),
            'emergency_contact_address': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 2,
                'placeholder': 'Enter emergency contact address',
                'maxlength': '500'
            }),
            'emergency_contact_number': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter emergency contact number',
                'maxlength': '20'
            }),
            
            # Photo
            'photo': forms.FileInput(attrs={
                'class': 'form-control',
                'accept': 'image/*'
            }),
        }
        labels = {
            'mobile_number': 'Mobile Number',
            'telephone_number': 'Telephone Number',
            'gender': 'Gender',
            'height': 'Height (cm)',
            'weight': 'Weight (kg)',
            'eye_color': 'Eye Color',
        }

class SeniorDocumentForm(forms.ModelForm):
    def clean_title(self):
        title = self.cleaned_data.get('title')
        if title is None:
            raise ValidationError('Document title is required.')
        
        title = title.strip()
        if not title:
            raise ValidationError('Document title is required.')
        
        if len(title) < 3:
            raise ValidationError('Document title must be at least 3 characters long.')
        if len(title) > 100:
            raise ValidationError('Document title cannot exceed 100 characters.')
        
        return title

    def clean_document(self):
        document = self.cleaned_data.get('document')
        if not document:
            raise ValidationError('Document file is required.')
        
        # Check file size (max 10MB)
        if document.size > 10 * 1024 * 1024:
            raise ValidationError('Document file size cannot exceed 10MB.')
        
        # Check file extension
        allowed_extensions = ['.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png', '.gif']
        file_extension = document.name.lower().split('.')[-1]
        if f'.{file_extension}' not in allowed_extensions:
            raise ValidationError('Document must be in PDF, DOC, DOCX, JPG, JPEG, PNG, or GIF format.')
        
        return document

class Meta:
    model = SeniorDocument
    fields = ['title', 'document']
    widgets = {
        'title': forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter document title',
            'maxlength': '100'
        }),
        'document': forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.pdf,.doc,.docx,.jpg,.jpeg,.png,.gif'
        }),
    }
