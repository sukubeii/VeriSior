from django.utils.deprecation import MiddlewareMixin

class SessionCleanupMiddleware(MiddlewareMixin):
    """
    Middleware to automatically clean up problematic session data
    """

    def process_request(self, request):
        """Clean up session data on each request"""
        if hasattr(request, 'session'):
            # Clean up old batch upload errors that are older than the current session
            if 'batch_upload_errors' in request.session:
                # Allow errors to persist for only one additional page load
                if request.path != '/seniors/batch-upload/':
                    # If user is not on the batch upload page, clear the errors
                    try:
                        del request.session['batch_upload_errors']
                        request.session.modified = True
                    except:
                        pass
        return None
