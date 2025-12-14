# core/forms.py - Complete Forms with Content Management and Validation

from django import forms
from django.core.validators import FileExtensionValidator, MinLengthValidator, MaxLengthValidator, RegexValidator
from .models import LandingPageContent, TeamMember, FAQItem, PrivacyPolicy


# MAIN CONTENT MANAGEMENT FORMS

class LandingPageContentForm(forms.ModelForm):
    """Form for editing landing page content with character limits and validation"""
    
    # Phone number validator - 11 digits only
    phone_validator = RegexValidator(
        regex=r'^\d{11}$',
        message='Phone number must be exactly 11 digits (numbers only)'
    )
    
    class Meta:
        model = LandingPageContent
        fields = [
            'hero_title', 'hero_subtitle',
            'features_title', 'features_subtitle',
            'slide1_title', 'slide1_subtitle', 'slide1_description',
            'slide2_title', 'slide2_subtitle', 'slide2_description',
            'slide3_title', 'slide3_subtitle', 'slide3_description',
            'about_title', 'about_description',
            'faq_title', 'faq_subtitle',
            'contact_title', 'contact_subtitle',
            'office_name', 'office_address', 'phone_number', 'email_address'
        ]
        widgets = {
            # Hero Section
            'hero_title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter main title (3-15 characters)...',
                'minlength': '3',
                'maxlength': '15',
            }),
            'hero_subtitle': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter subtitle (10-100 characters)...',
                'minlength': '10',
                'maxlength': '100',
            }),
            
            # Features Section
            'features_title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter features title (10-50 characters)...',
                'minlength': '10',
                'maxlength': '50',
            }),
            'features_subtitle': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter features subtitle (10-100 characters)...',
                'minlength': '10',
                'maxlength': '100',
            }),
            
            # Slide 1
            'slide1_title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter slide 1 title (10-30 characters)...',
                'minlength': '10',
                'maxlength': '30',
            }),
            'slide1_subtitle': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter slide 1 subtitle (10-20 characters)...',
                'minlength': '10',
                'maxlength': '20',
            }),
            'slide1_description': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Enter slide 1 description (10-150 characters)...',
                'rows': 3,
                'minlength': '10',
                'maxlength': '150',
            }),
            
            # Slide 2
            'slide2_title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter slide 2 title (10-30 characters)...',
                'minlength': '10',
                'maxlength': '30',
            }),
            'slide2_subtitle': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter slide 2 subtitle (10-20 characters)...',
                'minlength': '10',
                'maxlength': '20',
            }),
            'slide2_description': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Enter slide 2 description (10-150 characters)...',
                'rows': 3,
                'minlength': '10',
                'maxlength': '150',
            }),
            
            # Slide 3
            'slide3_title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter slide 3 title (10-30 characters)...',
                'minlength': '10',
                'maxlength': '30',
            }),
            'slide3_subtitle': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter slide 3 subtitle (10-20 characters)...',
                'minlength': '10',
                'maxlength': '20',
            }),
            'slide3_description': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Enter slide 3 description (10-150 characters)...',
                'rows': 3,
                'minlength': '10',
                'maxlength': '150',
            }),
            
            # About Section
            'about_title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter about title (3-15 characters)...',
                'minlength': '3',
                'maxlength': '15',
            }),
            'about_description': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Enter about description (10-300 characters)...',
                'rows': 4,
                'minlength': '10',
                'maxlength': '300',
            }),
            
            # FAQ Section
            'faq_title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter FAQ title (10-30 characters)...',
                'minlength': '10',
                'maxlength': '30',
            }),
            'faq_subtitle': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter FAQ subtitle (10-100 characters)...',
                'minlength': '10',
                'maxlength': '100',
            }),
            
            # Contact Section
            'contact_title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter contact title (3-15 characters)...',
                'minlength': '3',
                'maxlength': '15',
            }),
            'contact_subtitle': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter contact subtitle (10-100 characters)...',
                'minlength': '10',
                'maxlength': '100',
            }),
            
            # Contact Information
            'office_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter office name (10-30 characters)...',
                'minlength': '10',
                'maxlength': '30',
            }),
            'office_address': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Enter office address (10-100 characters)...',
                'rows': 3,
                'minlength': '10',
                'maxlength': '100',
            }),
            'phone_number': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter 11-digit phone number (numbers only)...',
                'pattern': '[0-9]{11}',
                'minlength': '11',
                'maxlength': '11',
            }),
            'email_address': forms.EmailInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter email address (10-30 characters)...',
                'minlength': '10',
                'maxlength': '30',
            }),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Apply validators to fields with specific min/max requirements
        validation_rules = {
            'hero_title': (3, 15),
            'hero_subtitle': (10, 100),
            'features_title': (10, 50),
            'features_subtitle': (10, 100),
            'slide1_title': (10, 30),
            'slide1_subtitle': (10, 20),
            'slide1_description': (10, 150),
            'slide2_title': (10, 30),
            'slide2_subtitle': (10, 20),
            'slide2_description': (10, 150),
            'slide3_title': (10, 30),
            'slide3_subtitle': (10, 20),
            'slide3_description': (10, 150),
            'about_title': (3, 15),
            'about_description': (10, 300),
            'faq_title': (10, 30),
            'faq_subtitle': (10, 100),
            'contact_title': (3, 15),
            'contact_subtitle': (10, 100),
            'office_name': (10, 30),
            'office_address': (10, 100),
            'email_address': (10, 30),
        }
        
        for field_name, (min_len, max_len) in validation_rules.items():
            if field_name in self.fields:
                self.fields[field_name].validators.extend([
                    MinLengthValidator(min_len, f'Minimum {min_len} characters required'),
                    MaxLengthValidator(max_len, f'Maximum {max_len} characters allowed')
                ])
                self.fields[field_name].help_text = f"{min_len}-{max_len} characters"
        
        # Phone number special validation
        self.fields['phone_number'].validators.append(self.phone_validator)
        self.fields['phone_number'].help_text = "Exactly 11 digits (numbers only)"

    def clean_phone_number(self):
        """Validate phone number - must be exactly 11 digits"""
        phone = self.cleaned_data.get('phone_number', '').strip()
        
        # Remove any non-digit characters
        phone_digits = ''.join(filter(str.isdigit, phone))
        
        # Validate exactly 11 digits
        if len(phone_digits) != 11:
            raise forms.ValidationError('Phone number must be exactly 11 digits (numbers only)')
        
        # Check if it contains only digits
        if not phone_digits.isdigit():
            raise forms.ValidationError('Phone number must contain only numbers')
        
        return phone_digits

    def clean_email_address(self):
        """Validate email address length"""
        email = self.cleaned_data.get('email_address', '').strip()
        
        if len(email) < 10:
            raise forms.ValidationError('Email address must be at least 10 characters')
        
        if len(email) > 30:
            raise forms.ValidationError('Email address must not exceed 30 characters')
        
        # Basic email format validation
        if '@' not in email or '.' not in email:
            raise forms.ValidationError('Please enter a valid email address')
        
        return email.lower()


class TeamMemberForm(forms.ModelForm):
    """Form for editing team members with character limits"""
    
    class Meta:
        model = TeamMember
        fields = ['name', 'role', 'photo', 'technical_skills', 'soft_skills', 'order', 'is_active']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter full name...',
                'maxlength': '50',
                'data-max': '50'
            }),
            'role': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter role/position...',
                'maxlength': '60',
                'data-max': '60'
            }),
            'photo': forms.FileInput(attrs={
                'class': 'form-control',
                'accept': 'image/*'
            }),
            'technical_skills': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Enter technical skills...',
                'rows': 3,
                'maxlength': '300',
                'data-max': '300'
            }),
            'soft_skills': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Enter soft skills...',
                'rows': 2,
                'maxlength': '200',
                'data-max': '200'
            }),
            'order': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': '0'
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            })
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['photo'].validators = [
            FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png', 'gif'])
        ]
        self.fields['photo'].help_text = "Upload team member photo (JPG, PNG, GIF - recommended size: 200x200px)"
        self.fields['name'].help_text = "Maximum 50 characters"
        self.fields['role'].help_text = "Maximum 60 characters"
        self.fields['technical_skills'].help_text = "Maximum 300 characters"
        self.fields['soft_skills'].help_text = "Maximum 200 characters"
        self.fields['order'].help_text = "Display order (0 = first)"


class FAQItemForm(forms.ModelForm):
    """Form for editing FAQ items with character limits"""
    
    class Meta:
        model = FAQItem
        fields = ['question', 'answer', 'icon_class', 'order', 'is_active']
        widgets = {
            'question': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter FAQ question...',
                'maxlength': '120',
                'data-max': '120'
            }),
            'answer': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Enter detailed answer...',
                'rows': 4,
                'maxlength': '500',
                'data-max': '500'
            }),
            'icon_class': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'e.g., fas fa-question-circle',
                'maxlength': '50'
            }),
            'order': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': '0'
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            })
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['question'].help_text = "Maximum 120 characters"
        self.fields['answer'].help_text = "Maximum 500 characters"
        self.fields['icon_class'].help_text = "Font Awesome icon class (e.g., 'fas fa-question-circle')"
        self.fields['order'].help_text = "Display order (0 = first)"


# LEGACY FORMS (keeping for backward compatibility)

class CarouselSlideForm(forms.ModelForm):
    """Form for managing carousel slides"""
    
    class Meta:
        model = LandingPageContent
        fields = ['slide1_title', 'slide1_subtitle', 'slide1_description']
        widgets = {
            'slide1_title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter slide title',
                'maxlength': '30'
            }),
            'slide1_subtitle': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter slide subtitle',
                'maxlength': '20'
            }),
            'slide1_description': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Enter slide description',
                'rows': 4,
                'maxlength': '150'
            }),
        }


class AboutUsContentForm(forms.ModelForm):
    """Form for managing About Us content"""
    
    class Meta:
        model = LandingPageContent
        fields = ['about_title', 'about_description']
        widgets = {
            'about_title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'About Us Section Title',
                'maxlength': '15'
            }),
            'about_description': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Enter the About Us description...',
                'rows': 6,
                'maxlength': '300'
            })
        }


class ContactInformationForm(forms.ModelForm):
    """Form for managing contact information"""
    
    class Meta:
        model = LandingPageContent
        fields = ['office_name', 'office_address', 'phone_number', 'email_address']
        widgets = {
            'office_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Main office name',
                'maxlength': '30'
            }),
            'office_address': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Complete office address...',
                'rows': 3,
                'maxlength': '100'
            }),
            'phone_number': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '09XXXXXXXXX (11 digits)',
                'maxlength': '11'
            }),
            'email_address': forms.EmailInput(attrs={
                'class': 'form-control',
                'placeholder': 'email@example.com',
                'maxlength': '30'
            }),
        }


# SEARCH AND FILTER FORMS

class ContentSearchForm(forms.Form):
    """Form for searching and filtering content"""
    
    CONTENT_TYPE_CHOICES = [
        ('', 'All Content Types'),
        ('team_member', 'Team Members'),
        ('faq', 'FAQ Items'),
        ('landing_page', 'Landing Page Content'),
    ]
    
    STATUS_CHOICES = [
        ('', 'All Status'),
        ('active', 'Active'),
        ('inactive', 'Inactive'),
    ]
    
    search_query = forms.CharField(
        max_length=200,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Search content...'
        })
    )
    content_type = forms.ChoiceField(
        choices=CONTENT_TYPE_CHOICES,
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    status = forms.ChoiceField(
        choices=STATUS_CHOICES,
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['search_query'].help_text = "Search by title, name, question, or description"
        self.fields['content_type'].help_text = "Filter by content type"
        self.fields['status'].help_text = "Filter by active/inactive status"


# BULK OPERATION FORMS

class BulkContentOperationForm(forms.Form):
    """Form for bulk operations on content items"""
    
    OPERATION_CHOICES = [
        ('activate', 'Activate Selected'),
        ('deactivate', 'Deactivate Selected'),
        ('delete', 'Delete Selected'),
    ]
    
    CONTENT_TYPE_CHOICES = [
        ('team_member', 'Team Members'),
        ('faq', 'FAQ Items'),
    ]
    
    operation = forms.ChoiceField(
        choices=OPERATION_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    content_type = forms.ChoiceField(
        choices=CONTENT_TYPE_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    selected_items = forms.MultipleChoiceField(
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'form-check-input'}),
        required=True
    )
    
    def __init__(self, *args, **kwargs):
        content_type = kwargs.pop('content_type', None)
        super().__init__(*args, **kwargs)
        
        if content_type:
            if content_type == 'team_member':
                choices = [(member.id, member.name) for member in TeamMember.objects.all()]
            elif content_type == 'faq':
                choices = [(faq.id, faq.question[:50] + "...") for faq in FAQItem.objects.all()]
            else:
                choices = []
            
            self.fields['selected_items'].choices = choices


# CONTENT ORDERING FORMS

class ContentOrderForm(forms.Form):
    """Form for reordering content items"""
    
    content_type = forms.CharField(widget=forms.HiddenInput())
    order_data = forms.CharField(widget=forms.HiddenInput())
    
    def clean_order_data(self):
        """Validate and parse the order data"""
        order_data = self.cleaned_data['order_data']
        try:
            import json
            parsed_data = json.loads(order_data)
            
            if not isinstance(parsed_data, list):
                raise forms.ValidationError("Order data must be a list")
            
            for item in parsed_data:
                if not isinstance(item, dict) or 'id' not in item or 'order' not in item:
                    raise forms.ValidationError("Each item must have 'id' and 'order' fields")
                
                try:
                    int(item['id'])
                    int(item['order'])
                except (ValueError, TypeError):
                    raise forms.ValidationError("ID and order must be integers")
            
            return parsed_data
        except json.JSONDecodeError:
            raise forms.ValidationError("Invalid JSON format")


# IMPORT/EXPORT FORMS

class ContentExportForm(forms.Form):
    """Form for exporting content"""
    
    EXPORT_FORMAT_CHOICES = [
        ('json', 'JSON'),
        ('csv', 'CSV'),
        ('xml', 'XML'),
    ]
    
    CONTENT_TYPE_CHOICES = [
        ('all', 'All Content'),
        ('landing_page', 'Landing Page Content'),
        ('team_member', 'Team Members'),
        ('faq', 'FAQ Items'),
    ]
    
    content_type = forms.ChoiceField(
        choices=CONTENT_TYPE_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    export_format = forms.ChoiceField(
        choices=EXPORT_FORMAT_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    include_inactive = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['content_type'].help_text = "Select which content to export"
        self.fields['export_format'].help_text = "Choose export file format"
        self.fields['include_inactive'].help_text = "Include inactive/disabled content items"


class ContentImportForm(forms.Form):
    """Form for importing content"""
    
    IMPORT_MODE_CHOICES = [
        ('replace', 'Replace All Content'),
        ('merge', 'Merge with Existing'),
        ('append', 'Append to Existing'),
    ]
    
    import_file = forms.FileField(
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.json,.csv,.xml'
        })
    )
    import_mode = forms.ChoiceField(
        choices=IMPORT_MODE_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    validate_only = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['import_file'].help_text = "Upload JSON, CSV, or XML file containing content data"
        self.fields['import_mode'].help_text = "How to handle existing content"
        self.fields['validate_only'].help_text = "Only validate the file without importing"
    
    def clean_import_file(self):
        """Validate the uploaded file"""
        file = self.cleaned_data['import_file']
        
        if file.size > 10 * 1024 * 1024:
            raise forms.ValidationError("File size cannot exceed 10MB")
        
        valid_extensions = ['.json', '.csv', '.xml']
        if not any(file.name.lower().endswith(ext) for ext in valid_extensions):
            raise forms.ValidationError("File must be JSON, CSV, or XML format")
        
        return file


# BACKUP FORMS

class ContentBackupForm(forms.Form):
    """Form for creating content backups"""
    
    BACKUP_TYPE_CHOICES = [
        ('full', 'Full Content Backup'),
        ('selective', 'Selective Content Backup'),
    ]
    
    backup_type = forms.ChoiceField(
        choices=BACKUP_TYPE_CHOICES,
        widget=forms.RadioSelect(attrs={'class': 'form-check-input'})
    )
    include_media = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    backup_name = forms.CharField(
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Optional backup name'
        })
    )
    
    include_landing_page = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    include_team = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    include_faq = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['backup_type'].help_text = "Choose backup scope"
        self.fields['include_media'].help_text = "Include uploaded images and files"
        self.fields['backup_name'].help_text = "Optional custom name for the backup"
    
    def clean(self):
        """Validate selective backup options"""
        cleaned_data = super().clean()
        backup_type = cleaned_data.get('backup_type')
        
        if backup_type == 'selective':
            selective_fields = [
                'include_landing_page', 'include_team', 'include_faq'
            ]
            
            if not any(cleaned_data.get(field, False) for field in selective_fields):
                raise forms.ValidationError(
                    "For selective backup, you must choose at least one content type"
                )
        
        return cleaned_data


class ContentRestoreForm(forms.Form):
    """Form for restoring content from backups"""
    
    RESTORE_MODE_CHOICES = [
        ('full', 'Full Restore (Replace All)'),
        ('selective', 'Selective Restore'),
        ('merge', 'Merge with Existing'),
    ]
    
    backup_file = forms.FileField(
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.zip,.json'
        })
    )
    restore_mode = forms.ChoiceField(
        choices=RESTORE_MODE_CHOICES,
        widget=forms.RadioSelect(attrs={'class': 'form-check-input'})
    )
    create_backup_before_restore = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['backup_file'].help_text = "Upload backup file (ZIP or JSON)"
        self.fields['restore_mode'].help_text = "How to restore the content"
        self.fields['create_backup_before_restore'].help_text = "Create backup of current content before restoring"
    
    def clean_backup_file(self):
        """Validate the backup file"""
        file = self.cleaned_data['backup_file']
        
        if file.size > 50 * 1024 * 1024:
            raise forms.ValidationError("Backup file cannot exceed 50MB")
        
        valid_extensions = ['.zip', '.json']
        if not any(file.name.lower().endswith(ext) for ext in valid_extensions):
            raise forms.ValidationError("File must be ZIP or JSON format")

        return file


# PRIVACY POLICY FORM

class PrivacyPolicyForm(forms.ModelForm):
    """Form for editing privacy policy content"""

    class Meta:
        model = PrivacyPolicy
        fields = [
            'title', 'version', 'effective_date', 'is_active',
            'introduction', 'information_collected', 'information_usage',
            'information_protection', 'data_retention', 'user_rights',
            'contact_information'
        ]
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter privacy policy title...',
                'maxlength': '100',
                'data-max': '100'
            }),
            'version': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'e.g., 1.0, 1.1, 2.0',
                'maxlength': '10'
            }),
            'effective_date': forms.DateInput(attrs={
                'class': 'form-control',
                'type': 'date'
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
            'introduction': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 5,
                'placeholder': 'Enter introduction to your privacy policy...',
                'maxlength': '1000',
                'data-max': '1000'
            }),
            'information_collected': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 6,
                'placeholder': 'Describe what information you collect...',
                'maxlength': '1500',
                'data-max': '1500'
            }),
            'information_usage': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 6,
                'placeholder': 'Describe how you use the information...',
                'maxlength': '1500',
                'data-max': '1500'
            }),
            'information_protection': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 5,
                'placeholder': 'Describe how you protect user information...',
                'maxlength': '1200',
                'data-max': '1200'
            }),
            'data_retention': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Describe your data retention policy...',
                'maxlength': '800',
                'data-max': '800'
            }),
            'user_rights': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Describe user rights and choices...',
                'maxlength': '1000',
                'data-max': '1000'
            }),
            'contact_information': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Provide contact information for privacy concerns...',
                'maxlength': '500',
                'data-max': '500'
            }),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Add help text
        self.fields['title'].help_text = "The main title for your privacy policy"
        self.fields['version'].help_text = "Version number for tracking changes"
        self.fields['effective_date'].help_text = "Date when this policy becomes effective"
        self.fields['is_active'].help_text = "Only one privacy policy can be active at a time"
        self.fields['introduction'].help_text = "Brief introduction explaining your commitment to privacy"
        self.fields['information_collected'].help_text = "What personal information do you collect from users"
        self.fields['information_usage'].help_text = "How do you use the collected information"
        self.fields['information_protection'].help_text = "Security measures you have in place"
        self.fields['data_retention'].help_text = "How long you keep user data"
        self.fields['user_rights'].help_text = "What rights users have regarding their data"
        self.fields['contact_information'].help_text = "How users can contact you about privacy concerns"

    def clean_version(self):
        """Ensure version format is valid"""
        version = self.cleaned_data['version']
        if not version:
            raise forms.ValidationError("Version is required")
        return version

    def clean(self):
        """Custom validation for the form"""
        cleaned_data = super().clean()
        is_active = cleaned_data.get('is_active', False)

        # If setting this policy as active, check if another is active
        if is_active and self.instance.pk:
            # Check if there's another active policy
            other_active = PrivacyPolicy.objects.filter(
                is_active=True
            ).exclude(pk=self.instance.pk).exists()

            if other_active:
                # This will be handled by the model's activate() method
                pass

        return cleaned_data
