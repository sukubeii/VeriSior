from allauth.account.adapter import DefaultAccountAdapter

class CustomAccountAdapter(DefaultAccountAdapter):
    """
    Custom adapter for django-allauth to handle custom behavior
    """
    def save_user(self, request, user, form, commit=True):
        """
        Saves a new user instance and applies custom logic
        """
        user = super().save_user(request, user, form, commit=False)
        
        # Set must_change_password to True for new users
        user.must_change_password = True
        
        if commit:
            user.save()
        
        return user
    
    def is_open_for_signup(self, request):
        """
        Controls whether signups are allowed. In this app, we don't allow public signups.
        """
        # Disable public registration
        return False
