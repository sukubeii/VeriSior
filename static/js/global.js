/**
 * VeriSior Complete JavaScript System
 * Handles all authentication, user management, and UI functionality
 */

// ===== UTILITY FUNCTIONS =====
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

const csrftoken = getCookie('csrftoken');

function setupCSRF() {
    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            if (!(/^http:.*/.test(settings.url) || /^https:.*/.test(settings.url))) {
                xhr.setRequestHeader("X-CSRFToken", csrftoken);
            }
        }
    });
}

// ===== ALERT SYSTEM =====
function showAlert(message, type = 'info', duration = 5000, containerId = 'body') {
    const alertTypes = {
        success: { bg: '#d4edda', border: '#c3e6cb', color: '#155724', icon: 'check-circle' },
        error: { bg: '#f8d7da', border: '#f5c6cb', color: '#721c24', icon: 'exclamation-circle' },
        warning: { bg: '#fff3cd', border: '#ffeaa7', color: '#856404', icon: 'exclamation-triangle' },
        info: { bg: '#d1ecf1', border: '#bee5eb', color: '#0c5460', icon: 'info-circle' }
    };
    
    const alertStyle = alertTypes[type] || alertTypes.info;
    const alertId = 'alert-' + Date.now();
    
    const alert = $(`
        <div id="${alertId}" class="alert position-fixed alert-slide-in" style="
            background: ${alertStyle.bg};
            border: 1px solid ${alertStyle.border};
            color: ${alertStyle.color};
            top: 20px;
            right: 20px;
            z-index: 9999;
            min-width: 300px;
            border-radius: 8px;
            padding: 1rem;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        " role="alert">
            <i class="fas fa-${alertStyle.icon} me-2"></i>
            <strong>${message}</strong>
            <button type="button" class="btn-close ms-2" style="background: none; border: none; font-size: 1.2rem; cursor: pointer;" onclick="$('#${alertId}').remove()">&times;</button>
        </div>
    `);
    
    $(containerId).append(alert);
    setTimeout(() => $('#' + alertId).remove(), duration);
}

function showAlertInContainer(message, type = 'info', containerId = '#loginErrors') {
    const alertTypes = {
        success: 'alert-success',
        error: 'alert-danger',
        warning: 'alert-warning',
        info: 'alert-info'
    };
    
    const alertClass = alertTypes[type] || 'alert-info';
    const iconTypes = {
        success: 'check-circle',
        error: 'exclamation-circle', 
        warning: 'exclamation-triangle',
        info: 'info-circle'
    };
    
    const alert = $(`
        <div class="alert ${alertClass} alert-dismissible fade show" role="alert">
            <i class="fas fa-${iconTypes[type]} me-2"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `);
    
    $(containerId).html(alert);
    setTimeout(() => $(containerId).empty(), 5000);
}

// ===== LOGIN AND AUTHENTICATION SYSTEM =====

// Global variables for login management
let currentLoginState = null;

// Initialize login system on page load
$(document).ready(function() {
    // Check URL parameters for authentication states
    checkAuthenticationState();
    
    // Setup login form handlers
    setupLoginHandlers();
    
    // Setup MFA handlers
    setupMFAHandlers();
    
    // Setup password change handlers
    setupPasswordChangeHandlers();
    
    // Setup forgot password handlers
    setupForgotPasswordHandlers();
    
    // Setup user management if on user management pages
    if ($('.user-management-page').length || $('#userForm').length || $('.user-list-page').length) {
        setupUserManagement();
    }
    
    // Setup profile settings if on settings page
    if ($('.settings-page').length || $('#generalSettingsForm').length) {
        setupProfileSettings();
    }
    
    // Setup change password page
    if ($('#changePasswordForm').length && $('.change-password-page').length) {
        setupChangePasswordPage();
    }
});

function checkAuthenticationState() {
    const urlParams = new URLSearchParams(window.location.search);
    
    if (urlParams.get('need_mfa') === 'true') {
        const username = urlParams.get('username');
        showMFAVerification(username);
    } else if (urlParams.get('need_change_password') === 'true') {
        showPasswordChange();
    } else if (urlParams.get('need_mfa_setup') === 'true') {
        showMFASetup();
    }
}

// ===== LOGIN HANDLERS =====
function setupLoginHandlers() {
    // Government portal button
    window.openGovernmentLogin = function() {
        $('#loginModal').modal('show');
    };
    
    // Public portal button
    window.openPublicPortal = function() {
        window.location.href = '/verify/';
    };
    
    // Keyboard handler for public portal card
    window.handleKeyPress = function(event) {
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            openPublicPortal();
        }
    };

    // Setup when modal is shown
    $('#loginModal').on('shown.bs.modal', function() {
        // Small delay to ensure DOM is ready
        setTimeout(function() {
            // Initialize password visibility
            if (typeof setupPasswordVisibility === 'function') {
                setupPasswordVisibility();
            }
        }, 100);
    });
    
    // Login form submission
    $('#loginForm').on('submit', function(e) {
        e.preventDefault();
        
        const form = $(this);
        const submitBtn = form.find('button[type="submit"]');
        const formData = new FormData(this);
        
        setLoadingState(submitBtn, true);
        $('#loginErrors').empty();
        
        $.ajax({
            url: '/auth/',
            method: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            success: function(response) {
                if (response.need_mfa) {
                    $('#loginModal').modal('hide');
                    showMFAVerification(response.user_display_name); // Change from response.username to response.user_display_name
                } else if (response.need_change_password) {
                    $('#loginModal').modal('hide');
                    showPasswordChange();
                } else if (response.success && response.redirect_url) {
                    showAlert('Login successful! Redirecting...', 'success', 2000);
                    setTimeout(() => window.location.href = response.redirect_url, 1000);
                }
            },
            error: function(xhr) {
                const response = xhr.responseJSON || {};
                showAlertInContainer(response.error || 'Login failed. Please try again.', 'error', '#loginErrors');
            },
            complete: function() {
                setLoadingState(submitBtn, false);
            }
        });
    });
}

// ===== MFA HANDLERS =====
function setupMFAHandlers() {
    // MFA Verification Form
    $('#mfaVerifyForm').off('submit').on('submit', function(e) {
        e.preventDefault();
        e.stopImmediatePropagation(); // Prevent any other handlers
        
        const form = $(this);
        const submitBtn = form.find('button[type="submit"]');
        
        // Prevent double submission
        if (submitBtn.prop('disabled')) {
            console.log('Form already submitting, ignoring duplicate submission');
            return false;
        }
        
        const formData = new FormData(this);
        
        // Ensure CSRF token is included
        const csrfToken = getCookie('csrftoken') || $('[name=csrfmiddlewaretoken]').val();
        if (csrfToken) {
            formData.set('csrfmiddlewaretoken', csrfToken);
        }
        
        setLoadingState(submitBtn, true);
        $('#mfaVerifyErrors').empty();
        
        $.ajax({
            url: '/mfa-verify/',
            method: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            headers: { 
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRFToken': csrfToken
            },
            success: function(response) {
                if (response.need_change_password) {
                    $('#mfaVerifyModal').modal('hide');
                    showPasswordChange();
                } else if (response.success && response.redirect_url) {
                    showAlert('Authentication successful! Redirecting...', 'success', 2000);
                    // Disable form to prevent resubmission during redirect
                    submitBtn.prop('disabled', true);
                    setTimeout(() => {
                        window.location.href = response.redirect_url;
                    }, 1000);
                } else if (response.redirect_url) {
                    // Handle unauthorized redirect
                    window.location.href = response.redirect_url;
                }
            },
            error: function(xhr) {
                const response = xhr.responseJSON || {};
                if (response.redirect_url) {
                    window.location.href = response.redirect_url;
                } else {
                    showAlertInContainer(response.error || 'Invalid verification code', 'error', '#mfaVerifyErrors');
                    setLoadingState(submitBtn, false);
                }
            }
        });
        
        return false;
    });
    
    // MFA Setup Form
    $('#mfaSetupForm').on('submit', function(e) {
        e.preventDefault();
        
        const form = $(this);
        const submitBtn = form.find('button[type="submit"]');
        const formData = new FormData(this);
        
        // Ensure CSRF token is included
        const csrfToken = getCookie('csrftoken') || $('[name=csrfmiddlewaretoken]').val();
        if (csrfToken) {
            formData.set('csrfmiddlewaretoken', csrfToken);
        }
        
        setLoadingState(submitBtn, true);
        $('#mfaSetupErrors').empty();
        
        $.ajax({
            url: '/mfa-setup/',
            method: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            headers: { 
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRFToken': csrfToken
            },
            success: function(response) {
                if (response.success && response.redirect_url) {
                    showAlert('MFA setup complete! Redirecting...', 'success', 2000);
                    setTimeout(() => window.location.href = response.redirect_url, 1000);
                }
            },
            error: function(xhr) {
                const response = xhr.responseJSON || {};
                showAlertInContainer(response.error || 'Invalid verification code', 'error', '#mfaSetupErrors');
            },
            complete: function() {
                setLoadingState(submitBtn, false);
            }
        });
    });
    
    // Auto-format MFA codes
    $('#mfa_verification_code, #mfa_setup_code').on('input', function() {
        let value = $(this).val().replace(/\D/g, '');
        if (value.length > 6) value = value.slice(0, 6);
        $(this).val(value);
    });
}

function showMFAVerification(userDisplayName) {
    $('#mfaUsernameValue').text(userDisplayName || 'User');
    $('#mfaVerifyModal').modal('show');
    setTimeout(() => $('#mfa_verification_code').focus(), 500);
}

function showMFASetup() {
    // Load QR code and secret key
    $.ajax({
        url: '/mfa-setup-info/',
        method: 'GET',
        success: function(response) {
            $('#qrCodeImage').attr('src', 'data:image/png;base64,' + response.qr_code);
            $('#secretKey').val(response.secret_key);
            $('#totp_secret').val(response.secret_key);
        },
        error: function() {
            showAlert('Failed to load MFA setup information', 'error');
        }
    });
    
    $('#mfaSetupModal').modal('show');
    setTimeout(() => $('#mfa_setup_code').focus(), 500);
}

// ===== PASSWORD CHANGE HANDLERS =====
function setupPasswordChangeHandlers() {
    $('#changePasswordForm').on('submit', function(e) {
        e.preventDefault();
        
        const form = $(this);
        const submitBtn = form.find('button[type="submit"]');
        const formData = new FormData(this);
        
        // Ensure CSRF token is included
        const csrfToken = getCookie('csrftoken') || $('[name=csrfmiddlewaretoken]').val();
        if (csrfToken) {
            formData.set('csrfmiddlewaretoken', csrfToken);
        }
        
        setLoadingState(submitBtn, true);
        $('#passwordFormErrors').empty();
        
        $.ajax({
            url: '/change-password/',
            method: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            headers: { 
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRFToken': csrfToken
            },
            success: function(response) {
                if (response.need_mfa_setup) {
                    $('#changePasswordModal').modal('hide');
                    showMFASetup();
                } else if (response.success && response.redirect_url) {
                    showAlert('Password changed successfully! Redirecting...', 'success', 2000);
                    setTimeout(() => window.location.href = response.redirect_url, 1000);
                }
            },
            error: function(xhr) {
                const response = xhr.responseJSON || {};
                if (response.errors) {
                    let errorMsg = '';
                    Object.values(response.errors).forEach(errors => {
                        errorMsg += errors.join(', ') + ' ';
                    });
                    showAlertInContainer(errorMsg.trim(), 'error', '#passwordFormErrors');
                } else {
                    showAlertInContainer(response.error || 'Password change failed', 'error', '#passwordFormErrors');
                }
            },
            complete: function() {
                setLoadingState(submitBtn, false);
            }
        });
    });
}

function showPasswordChange() {
    // Ensure the modal has a fresh CSRF token
    const csrfToken = getCookie('csrftoken');
    if (csrfToken) {
        const existingToken = $('#changePasswordForm input[name="csrfmiddlewaretoken"]');
        if (existingToken.length) {
            existingToken.val(csrfToken);
        } else {
            $('#changePasswordForm').prepend(`<input type="hidden" name="csrfmiddlewaretoken" value="${csrfToken}">`);
        }
    }
    
    $('#changePasswordModal').modal('show');
    setTimeout(() => $('#current_password_change').focus(), 500);
}

// ===== FORGOT PASSWORD HANDLERS =====
function setupForgotPasswordHandlers() {
    $('#forgotPasswordLink').on('click', function(e) {
        e.preventDefault();
        $('#loginModal').modal('hide');
        $('#forgotPasswordModal').modal('show');
    });
    
    $('#forgotPasswordForm').on('submit', function(e) {
        e.preventDefault();

        const form = $(this);
        const submitBtn = form.find('button[type="submit"]');
        const formData = new FormData(this);

        setLoadingState(submitBtn, true);
        $('#forgotPasswordErrors').empty();

        $.ajax({
            url: '/auth/forgot-password/',
            method: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function(response) {
                if (response.success || response.message) {
                    showAlertInContainer('Password reset request submitted successfully! An administrator will review your request and send you a temporary password if approved.', 'success', '#forgotPasswordErrors');
                    // Clear the form
                    form[0].reset();
                    // Close modal after 3 seconds
                    setTimeout(() => $('#forgotPasswordModal').modal('hide'), 3000);
                }
            },
            error: function(xhr) {
                const response = xhr.responseJSON || {};
                showAlertInContainer(response.error || 'Failed to submit password reset request. Please try again.', 'error', '#forgotPasswordErrors');
            },
            complete: function() {
                setLoadingState(submitBtn, false);
            }
        });
    });
    
    // Password reset verification form
    $('#passwordResetVerifyForm').on('submit', function(e) {
        e.preventDefault();
        
        const form = $(this);
        const submitBtn = form.find('button[type="submit"]');
        const formData = new FormData(this);
        
        setLoadingState(submitBtn, true);
        $('#passwordResetVerifyErrors').empty();
        
        $.ajax({
            url: '/password-reset-verify/',
            method: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function(response) {
                if (response.success) {
                    showAlertInContainer('Code verified! You can now reset your password.', 'success', '#passwordResetVerifyErrors');
                    $('#passwordResetCompleteModal').modal('show');
                    $('#passwordResetVerifyModal').modal('hide');
                }
            },
            error: function(xhr) {
                const response = xhr.responseJSON || {};
                showAlertInContainer(response.error || 'Invalid verification code', 'error', '#passwordResetVerifyErrors');
            },
            complete: function() {
                setLoadingState(submitBtn, false);
            }
        });
    });
    
    // Password reset complete form
    $('#passwordResetCompleteForm').on('submit', function(e) {
        e.preventDefault();
        
        const form = $(this);
        const submitBtn = form.find('button[type="submit"]');
        const formData = new FormData(this);
        
        setLoadingState(submitBtn, true);
        $('#passwordResetCompleteErrors').empty();
        
        $.ajax({
            url: '/password-reset-complete/',
            method: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function(response) {
                if (response.success) {
                    showAlert('Password reset successfully! Please login with your new password.', 'success', 3000);
                    $('#passwordResetCompleteModal').modal('hide');
                    setTimeout(() => {
                        window.location.href = '/auth/';
                    }, 2000);
                }
            },
            error: function(xhr) {
                const response = xhr.responseJSON || {};
                showAlertInContainer(response.error || 'Password reset failed', 'error', '#passwordResetCompleteErrors');
            },
            complete: function() {
                setLoadingState(submitBtn, false);
            }
        });
    });
}

// ===== CHANGE PASSWORD PAGE SPECIFIC =====
function setupChangePasswordPage() {
    const newPasswordInput = document.getElementById('id_new_password');
    const confirmPasswordInput = document.getElementById('id_confirm_password');
    const strengthBar = document.getElementById('passwordStrengthBar');
    const strengthText = document.getElementById('passwordStrengthText');
    const passwordMatchDiv = document.getElementById('passwordMatch');
    
    // Password requirements elements
    const requirements = {
        length: document.getElementById('req-length'),
        uppercase: document.getElementById('req-uppercase'),
        lowercase: document.getElementById('req-lowercase'),
        number: document.getElementById('req-number'),
        special: document.getElementById('req-special')
    };
    
    function checkPasswordRequirements(password) {
        const checks = {
            length: password.length >= 8,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            number: /[0-9]/.test(password),
            special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
        };
        
        // Update requirement indicators
        Object.keys(checks).forEach(req => {
            const element = requirements[req];
            if (element) {
                const icon = element.querySelector('i');
                
                if (checks[req]) {
                    element.classList.remove('invalid');
                    element.classList.add('valid');
                    if (icon) icon.className = 'fas fa-check';
                } else {
                    element.classList.remove('valid');
                    element.classList.add('invalid');
                    if (icon) icon.className = 'fas fa-times';
                }
            }
        });
        
        return checks;
    }
    
    function calculatePasswordStrength(password) {
        const checks = checkPasswordRequirements(password);
        const score = Object.values(checks).filter(Boolean).length;
        
        const strengthLevels = [
            { class: '', text: '' },
            { class: 'strength-weak', text: 'Very Weak' },
            { class: 'strength-weak', text: 'Weak' },
            { class: 'strength-fair', text: 'Fair' },
            { class: 'strength-good', text: 'Good' },
            { class: 'strength-strong', text: 'Strong' }
        ];
        
        const level = strengthLevels[score];
        
        // Update strength bar
        if (strengthBar) {
            strengthBar.className = `password-strength-bar ${level.class}`;
        }
        if (strengthText) {
            strengthText.textContent = level.text ? `Password strength: ${level.text}` : '';
            strengthText.className = level.class ? `text-${level.class.split('-')[1]}` : 'text-muted';
        }
        
        return score;
    }
    
    function checkPasswordMatch() {
        if (!newPasswordInput || !confirmPasswordInput || !passwordMatchDiv) return true;
        
        const newPassword = newPasswordInput.value;
        const confirmPassword = confirmPasswordInput.value;
        
        if (confirmPassword === '') {
            passwordMatchDiv.innerHTML = '';
            return true;
        }
        
        if (newPassword === confirmPassword) {
            passwordMatchDiv.innerHTML = '<small class="text-success"><i class="fas fa-check me-1"></i>Passwords match</small>';
            return true;
        } else {
            passwordMatchDiv.innerHTML = '<small class="text-danger"><i class="fas fa-times me-1"></i>Passwords do not match</small>';
            return false;
        }
    }
    
    // Event listeners
    if (newPasswordInput) {
        newPasswordInput.addEventListener('input', function() {
            calculatePasswordStrength(this.value);
            checkPasswordMatch();
        });
    }
    
    if (confirmPasswordInput) {
        confirmPasswordInput.addEventListener('input', checkPasswordMatch);
    }
    
    // Form submission validation
    $('#changePasswordForm').on('submit', function(e) {
        if (!newPasswordInput || !confirmPasswordInput) return;
        
        const newPassword = newPasswordInput.value;
        const confirmPassword = confirmPasswordInput.value;
        
        // Check password strength
        const strengthScore = calculatePasswordStrength(newPassword);
        if (strengthScore < 4) {
            e.preventDefault();
            showAlert('Please choose a stronger password that meets all requirements.', 'warning');
            newPasswordInput.focus();
            return false;
        }
        
        // Check password match
        if (newPassword !== confirmPassword) {
            e.preventDefault();
            showAlert('Passwords do not match. Please check and try again.', 'error');
            confirmPasswordInput.focus();
            return false;
        }
        
        // Show loading state
        const submitBtn = this.querySelector('button[type="submit"]');
        setLoadingState(submitBtn, true);
        
        // Re-enable after delay in case of server validation errors
        setTimeout(() => {
            setLoadingState(submitBtn, false);
        }, 10000);
    });
}

// ===== COPY TO CLIPBOARD FUNCTIONALITY =====
window.copyToClipboard = function(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.select();
        element.setSelectionRange(0, 99999); // For mobile devices
        
        navigator.clipboard.writeText(element.value).then(() => {
            showAlert('Copied to clipboard!', 'success', 2000);
        }).catch(() => {
            // Fallback for older browsers
            document.execCommand('copy');
            showAlert('Copied to clipboard!', 'success', 2000);
        });
    }
};

// ===== PAGE TRANSITION SYSTEM =====

// Show page loader
function showPageLoader(message = 'Loading...') {
    if ($('#pageLoader').length) return;
    
    const loader = $(`
        <div id="pageLoader" class="page-loader">
            <div class="loader-content">
                <div class="loader-spinner"></div>
                <div class="loader-text">${message}</div>
            </div>
        </div>
    `);
    
    $('body').append(loader);
    
    // Force reflow to ensure smooth animation
    loader[0].offsetHeight;
}

// Hide page loader
function hidePageLoader() {
    const loader = $('#pageLoader');
    if (loader.length) {
        loader.addClass('fade-out');
        setTimeout(() => loader.remove(), 500);
    }
}

// Initialize page transitions
function initializePageTransitions() {
    // Add page loaded class after DOM is ready
    $(document).ready(function() {
        setTimeout(() => {
            $('body').addClass('page-loaded');
            hidePageLoader();
        }, 100);
    });
    
    // Handle link clicks for smooth transitions
    $(document).on('click', 'a:not([href^="#"]):not([target="_blank"]):not(.no-transition):not([data-bs-toggle])', function(e) {
        const link = $(this);
        const href = link.attr('href');
        
        // Skip if it's a javascript: link or download link
        if (!href || href.startsWith('javascript:') || link.attr('download')) {
            return;
        }
        
        // Skip if it's an external link
        if (href.startsWith('http') && !href.includes(window.location.hostname)) {
            return;
        }
        
        e.preventDefault();
        
        showPageLoader('Loading page...');
        
        // Small delay for smooth transition
        setTimeout(() => {
            window.location.href = href;
        }, 150);
    });
    
    // Handle form submissions for smooth transitions
    $(document).on('submit', 'form:not(.no-transition):not(.ajax-form)', function(e) {
        const form = $(this);
        
        // Skip if form has validation errors
        if (form.find('.is-invalid').length > 0) {
            return;
        }
        
        // Add loading state to form
        form.addClass('form-loading loading');
        
        // Show page loader after a short delay
        setTimeout(() => {
            if (form.hasClass('loading')) {
                showPageLoader('Processing...');
            }
        }, 300);
    });
}

// Enhanced setLoadingState function with better UX
function setLoadingState(element, loading = true, text = null) {
    const $el = $(element);
    
    if (loading) {
        $el.prop('disabled', true);
        $el.addClass('btn-loading');
        
        if (!$el.data('original-text')) {
            $el.data('original-text', $el.html());
        }
        
        if (text) {
            $el.html(`<i class="fas fa-spinner fa-spin me-2"></i>${text}`);
        }
    } else {
        $el.prop('disabled', false);
        $el.removeClass('btn-loading');
        
        const originalText = $el.data('original-text');
        if (originalText) {
            $el.html(originalText);
        }
    }
}

// Enhanced showAlert function with better animations
function showAlert(message, type = 'info', duration = 5000, containerId = 'body') {
    const alertTypes = {
        success: { bg: 'linear-gradient(135deg, rgba(16, 185, 129, 0.1) 0%, rgba(5, 150, 105, 0.1) 100%)', border: '#10b981', color: '#065f46', icon: 'check-circle' },
        error: { bg: 'linear-gradient(135deg, rgba(220, 53, 69, 0.1) 0%, rgba(200, 35, 51, 0.1) 100%)', border: '#dc3545', color: '#721c24', icon: 'exclamation-circle' },
        warning: { bg: 'linear-gradient(135deg, rgba(255, 193, 7, 0.1) 0%, rgba(255, 140, 0, 0.1) 100%)', border: '#ffc107', color: '#856404', icon: 'exclamation-triangle' },
        info: { bg: 'linear-gradient(135deg, rgba(66, 165, 245, 0.1) 0%, rgba(129, 212, 250, 0.1) 100%)', border: '#42a5f5', color: '#0d47a1', icon: 'info-circle' }
    };
    
    const alertStyle = alertTypes[type] || alertTypes.info;
    const alertId = 'alert-' + Date.now();
    
    const alert = $(`
        <div id="${alertId}" class="position-fixed fade-in-up" style="
            background: ${alertStyle.bg};
            border: 2px solid ${alertStyle.border};
            color: ${alertStyle.color};
            top: 20px;
            right: 20px;
            z-index: 9999;
            min-width: 350px;
            max-width: 500px;
            border-radius: 16px;
            padding: 1.25rem;
            box-shadow: 0 8px 32px rgba(13, 71, 161, 0.15);
            backdrop-filter: blur(10px);
            transform: translateX(100%);
            transition: transform 0.4s cubic-bezier(0.23, 1, 0.32, 1);
        " role="alert">
            <div class="d-flex align-items-center">
                <i class="fas fa-${alertStyle.icon} me-3" style="font-size: 1.2rem;"></i>
                <div class="flex-grow-1">
                    <strong>${message}</strong>
                </div>
                <button type="button" class="btn-close ms-3" style="
                    background: none; 
                    border: none; 
                    font-size: 1.2rem; 
                    cursor: pointer;
                    color: ${alertStyle.color};
                    opacity: 0.7;
                    transition: opacity 0.3s ease;
                " onclick="removeAlert('${alertId}')">&times;</button>
            </div>
        </div>
    `);
    
    $(containerId).append(alert);
    
    // Trigger animation
    setTimeout(() => {
        alert.css('transform', 'translateX(0)');
    }, 10);
    
    // Auto-remove after duration
    setTimeout(() => removeAlert(alertId), duration);
}

// Remove alert function
function removeAlert(alertId) {
    const alert = $('#' + alertId);
    if (alert.length) {
        alert.css('transform', 'translateX(100%)');
        setTimeout(() => alert.remove(), 400);
    }
}

// Initialize everything when document is ready
$(document).ready(function() {
    // Initialize page transitions
    initializePageTransitions();
    
    // Show initial page loader
    if (document.readyState === 'loading') {
        showPageLoader('Loading VeriSior...');
    }
    
    // Enhanced form loading states
    $('form').on('submit', function() {
        const form = $(this);
        const submitBtn = form.find('button[type="submit"]');
        
        if (!submitBtn.prop('disabled')) {
            setLoadingState(submitBtn, true, 'Processing...');
            
            // Re-enable after timeout (fallback)
            setTimeout(() => {
                setLoadingState(submitBtn, false);
            }, 10000);
        }
    });
    
    // Enhanced AJAX setup with loading states
    $(document).ajaxStart(function() {
        if (!$('#pageLoader').length) {
            showPageLoader('Processing request...');
        }
    });
    
    $(document).ajaxStop(function() {
        setTimeout(() => {
            hidePageLoader();
        }, 200);
    });
    
    // Smooth scroll for hash links
    $('a[href^="#"]').on('click', function(e) {
        e.preventDefault();
        const target = $($(this).attr('href'));
        if (target.length) {
            $('html, body').animate({
                scrollTop: target.offset().top - 100
            }, 600, 'swing');
        }
    });
    
    // Enhanced modal transitions
    $('.modal').on('show.bs.modal', function() {
        $(this).find('.modal-dialog').addClass('fade-in-up');
    });
    
    $('.modal').on('hidden.bs.modal', function() {
        $(this).find('.modal-dialog').removeClass('fade-in-up');
        // Clear any loading states
        $(this).find('.btn-loading').each(function() {
            setLoadingState($(this), false);
        });
    });
});

// Export functions for global use
window.showPageLoader = showPageLoader;
window.hidePageLoader = hidePageLoader;
window.removeAlert = removeAlert;

// ===== PASSWORD EYE ICON TOGGLE =====

$(document).ready(function() {
    function setupPasswordVisibility() {
        // Process each password field
        $('input[type="password"]').each(function() {
            const passwordField = $(this);
            
            // Skip if already processed
            if (passwordField.closest('.password-field-wrapper').length > 0) {
                return;
            }
            
            // Wrap the password field in a container
            passwordField.wrap('<div class="password-field-wrapper"></div>');
            const wrapper = passwordField.parent('.password-field-wrapper');
            
            // Create the embedded eye toggle button that fills the right side
            const eyeToggle = $(`
                <button type="button" class="password-toggle" tabindex="-1">
                    <i class="fas fa-eye"></i>
                </button>
            `);
            
            // Append the eye toggle to the wrapper
            wrapper.append(eyeToggle);
            
            // Disable browser's built-in password reveal
            passwordField.attr('autocomplete', 'current-password');
        });
        
        // Remove any existing event listeners to prevent duplicates
        $(document).off('click.passwordToggle');
        
        // Handle password toggle click
        $(document).on('click.passwordToggle', '.password-toggle', function(e) {
            e.preventDefault();
            e.stopPropagation();
            
            const toggleBtn = $(this);
            const eyeIcon = toggleBtn.find('i');
            const passwordField = toggleBtn.siblings('input');
            const currentType = passwordField.attr('type');
            
            if (currentType === 'password') {
                // Show password
                passwordField.attr('type', 'text');
                eyeIcon.removeClass('fa-eye').addClass('fa-eye-slash');
                toggleBtn.attr('title', 'Hide password');
            } else {
                // Hide password  
                passwordField.attr('type', 'password');
                eyeIcon.removeClass('fa-eye-slash').addClass('fa-eye');
                toggleBtn.attr('title', 'Show password');
            }
            
            // Maintain focus on password field
            passwordField.focus();
        });
        
        // Prevent form submission when clicking the eye
        $(document).on('click.passwordToggle', '.password-field-wrapper', function(e) {
            if ($(e.target).hasClass('password-toggle') || $(e.target).closest('.password-toggle').length) {
                e.stopPropagation();
            }
        });
    }
    
    // Initialize on page load
    setupPasswordVisibility();
    
    // Reinitialize when new content is added (for dynamic forms)
    const observer = new MutationObserver(function(mutations) {
        let shouldReinit = false;
        mutations.forEach(function(mutation) {
            if (mutation.type === 'childList') {
                const addedNodes = Array.from(mutation.addedNodes);
                if (addedNodes.some(node => 
                    node.nodeType === 1 && 
                    (node.tagName === 'INPUT' && node.type === 'password' || 
                     node.querySelector && node.querySelector('input[type="password"]'))
                )) {
                    shouldReinit = true;
                }
            }
        });
        
        if (shouldReinit) {
            setTimeout(setupPasswordVisibility, 100);
        }
    });
    
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
});

// ===== CONTACT FORM SCRIPT =====

// Global variables for form state tracking
if (typeof formHasChanges === 'undefined') {
    var formHasChanges = false;
}
if (typeof pendingNavigation === 'undefined') {
    var pendingNavigation = null;
}
if (typeof privacyPolicyScrolledToEnd === 'undefined') {
    var privacyPolicyScrolledToEnd = false;
}
if (typeof window.privacyPolicyAccepted === 'undefined') {
    window.privacyPolicyAccepted = false;
}

// Flag to prevent multiple submissions
var isSubmittingContactForm = false;

$(document).ready(function() {
    // Initialize contact form functionality only if contact form exists
    if ($('#contactForm').length > 0) {
        initializeContactForm();
        setupPrivacyPolicyModal();
        setupFormChangeDetection();
        setupNavigationInterception();
    }
});

function initializeContactForm() {
    console.log('Setting up contact form');
    
    // DISABLE SUBMIT BUTTON BY DEFAULT ON PAGE LOAD
    $('#contactSubmitBtn').prop('disabled', true);
    
    // Enhanced form validation with real-time input restrictions
    setupFieldValidation();
    setupInputRestrictions();
    setupCharacterCounters();

    // Initially disable the checkbox
    $('#privacyPolicyCheck').addClass('disabled').prop('disabled', true);

    $('#privacyPolicyCheck').on('click', function(e) {
        if (!window.privacyPolicyAccepted) {
            e.preventDefault();
            $('#privacyError').addClass('show').text('Please read and accept the Privacy Policy first');
            return false;
        }
    });

    $('#privacyPolicyCheck').on('change', function() {
        if ($(this).is(':checked')) {
            $('#privacyError').removeClass('show').text('');
            $(this).removeClass('is-invalid');
        }
        checkFormValidity();
    });

    // Track when privacy modal is opened
    $(document).on('click', '#openPrivacyModal', function(e) {
        e.preventDefault();
        $('#privacyModal').modal('show');
    });

    // Only enable checkbox when "I Accept" button is clicked
    $(document).on('click', '#acceptPrivacyBtn', function() {
        window.privacyPolicyAccepted = true;
        
        // Enable the checkbox and auto-check it
        $('#privacyPolicyCheck').removeClass('disabled').prop('disabled', false).prop('checked', true);
        $('#privacyError').removeClass('show').text('');
        
        $('#privacyModal').modal('hide');
        checkFormValidity();
    });

    // Reset if modal is closed without accepting
    $('#privacyModal').on('hidden.bs.modal', function() {
        if (!window.privacyPolicyAccepted) {
            $('#privacyPolicyCheck').addClass('disabled').prop('disabled', true).prop('checked', false);
        }
    });
    
    // Form submission - Remove any existing handlers and add only one
    $('#contactForm').off('submit').on('submit', function(e) {
        e.preventDefault();
        e.stopImmediatePropagation();
        
        // Prevent duplicate submissions
        if (isSubmittingContactForm) {
            return false;
        }
        
        let isValid = true;
        
        // Validate all fields
        const allFields = ['contactFullName', 'contactEmail', 'contactPhone', 'contactSubject', 'contactMessage'];
        allFields.forEach(fieldId => {
            if (!validateField($('#' + fieldId))) {
                isValid = false;
            }
        });
        
        // Check privacy policy
        if (!$('#privacyPolicyCheck').is(':checked')) {
            $('#privacyError').addClass('show').text('You must accept the Privacy Policy');
            $('#privacyPolicyCheck').addClass('is-invalid');
            isValid = false;
        }
        
        if (isValid) {
            submitContactForm();
        } else {
            // Scroll to first error
            const firstError = $('.contact-input.is-invalid').first();
            if (firstError.length) {
                $('html, body').animate({
                    scrollTop: firstError.offset().top - 100
                }, 300);
                firstError.focus();
            }
        }
        
        return false;
    });
}

function setupFieldValidation() {
    const allFields = ['contactFullName', 'contactEmail', 'contactPhone', 'contactSubject', 'contactMessage'];
    
    allFields.forEach(fieldId => {
        $('#' + fieldId).on('blur input change', function() {
            validateField($(this));
            checkFormValidity();
        });
    });
}

function setupInputRestrictions() {
    // Full Name - Only letters, spaces, hyphens, apostrophes, periods
    $('#contactFullName').on('input', function(e) {
        let value = $(this).val();
        // Remove invalid characters
        value = value.replace(/[^a-zA-Z\s\-'\.]/g, '');
        // Limit to 100 characters
        if (value.length > 100) {
            value = value.substring(0, 100);
        }
        $(this).val(value);
    });
    
    // Phone Number - Only digits, limit to 15
    $('#contactPhone').on('keydown', function(e) {
        // Allow: backspace, delete, tab, escape, enter
        if ($.inArray(e.keyCode, [46, 8, 9, 27, 13]) !== -1 ||
            // Allow: Ctrl+A, Ctrl+C, Ctrl+V, Ctrl+X
            (e.keyCode === 65 && e.ctrlKey === true) ||
            (e.keyCode === 67 && e.ctrlKey === true) ||
            (e.keyCode === 86 && e.ctrlKey === true) ||
            (e.keyCode === 88 && e.ctrlKey === true)) {
            return;
        }
        
        // Ensure that it is a number and stop if 15 digits already entered
        if ((e.shiftKey || (e.keyCode < 48 || e.keyCode > 57)) && (e.keyCode < 96 || e.keyCode > 105)) {
            e.preventDefault();
        }
        
        // Stop if 15 digits already entered
        if ($(this).val().length >= 15) {
            e.preventDefault();
        }
    });

    $('#contactPhone').on('input paste', function(e) {
        setTimeout(() => {
            let value = $(this).val();
            // Remove all non-digits
            value = value.replace(/\D/g, '');
            // Limit to 15 digits
            if (value.length > 15) {
                value = value.substring(0, 15);
            }
            $(this).val(value);
            
            // Trigger validation after cleaning
            $(this).trigger('blur');
        }, 1);
    });

    // Set HTML5 attributes for mobile
    $('#contactPhone').attr('inputmode', 'numeric').attr('pattern', '[0-9]*').attr('maxlength', '15');
    
    // Message - Limit to 2000 characters
    $('#contactMessage').on('input', function(e) {
        let value = $(this).val();
        if (value.length > 2000) {
            value = value.substring(0, 2000);
            $(this).val(value);
        }
    });
}

function setupCharacterCounters() {
    // Full Name counter
    $('#contactFullName').after('<small class="char-counter text-muted" id="fullNameCounter"></small>');
    $('#contactFullName').on('input', function() {
        const length = $(this).val().length;
        const counter = $('#fullNameCounter');
        counter.text(`${length}/100 characters`);
        
        if (length > 90) {
            counter.removeClass('text-muted').addClass('text-warning');
        } else {
            counter.removeClass('text-warning').addClass('text-muted');
        }
    });
    
    // Phone Number counter (only show when typing)
    $('#contactPhone').after('<small class="char-counter text-muted" id="phoneCounter" style="display: none;"></small>');
    $('#contactPhone').on('input focus', function() {
        const length = $(this).val().length;
        const counter = $('#phoneCounter');
        
        if (length > 0) {
            counter.show().text(`${length}/15 digits`);
            
            if (length >= 7 && length <= 15) {
                counter.removeClass('text-muted text-warning').addClass('text-success');
            } else if (length > 0) {
                counter.removeClass('text-muted text-success').addClass('text-warning');
            } else {
                counter.removeClass('text-warning text-success').addClass('text-muted');
            }
        } else {
            counter.hide();
        }
    });
    
    $('#contactPhone').on('blur', function() {
        if ($(this).val().length === 0) {
            $('#phoneCounter').hide();
        }
    });
    
    // Message counter
    $('#contactMessage').after('<small class="char-counter text-muted" id="messageCounter"></small>');
    $('#contactMessage').on('input', function() {
        const length = $(this).val().length;
        const counter = $('#messageCounter');
        counter.text(`${length}/2000 characters`);
        
        if (length > 1900) {
            counter.removeClass('text-muted text-warning').addClass('text-danger');
        } else if (length > 1800) {
            counter.removeClass('text-muted text-danger').addClass('text-warning');
        } else {
            counter.removeClass('text-warning text-danger').addClass('text-muted');
        }
    });
}

function validateField($field) {
    // Ensure $field is a jQuery object
    if (!$field.jquery) {
        $field = $($field);
    }
    
    const value = $field.val().trim();
    const fieldId = $field.attr('id');
    const errorId = fieldId.replace('contact', '').toLowerCase() + 'Error';
    const $error = $('#' + errorId);
    
    // Handle phone field separately (optional)
    if (fieldId === 'contactPhone') {
        if (value === '') {
            $field.removeClass('is-valid is-invalid');
            $error.removeClass('show').text('');
            return true; // Phone is optional
        } else if (value.length < 7) {
            $field.addClass('is-invalid').removeClass('is-valid');
            $error.addClass('show').text('Phone number must be at least 7 digits');
            return false;
        } else if (value.length > 15) {
            $field.addClass('is-invalid').removeClass('is-valid');
            $error.addClass('show').text('Phone number must not exceed 15 digits');
            return false;
        } else {
            $field.addClass('is-valid').removeClass('is-invalid');
            $error.removeClass('show').text('');
            return true;
        }
    }
    
    // Handle email validation
    if (fieldId === 'contactEmail') {
        if (value === '') {
            $field.addClass('is-invalid').removeClass('is-valid');
            $error.addClass('show').text('Email address is required');
            return false;
        } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
            $field.addClass('is-invalid').removeClass('is-valid');
            $error.addClass('show').text('Please enter a valid email address');
            return false;
        } else {
            $field.addClass('is-valid').removeClass('is-invalid');
            $error.removeClass('show').text('');
            return true;
        }
    }
    
    // Handle name validation
    if (fieldId === 'contactFullName') {
        if (value === '') {
            $field.addClass('is-invalid').removeClass('is-valid');
            $error.addClass('show').text('Full name is required');
            return false;
        } else if (value.length < 2) {
            $field.addClass('is-invalid').removeClass('is-valid');
            $error.addClass('show').text('Name must be at least 2 characters');
            return false;
        } else if (!/^[a-zA-Z\s\-'\.]+$/.test(value)) {
            $field.addClass('is-invalid').removeClass('is-valid');
            $error.addClass('show').text('Name contains invalid characters');
            return false;
        } else {
            $field.addClass('is-valid').removeClass('is-invalid');
            $error.removeClass('show').text('');
            return true;
        }
    }
    
    // Handle message validation
    if (fieldId === 'contactMessage') {
        if (value === '') {
            $field.addClass('is-invalid').removeClass('is-valid');
            $error.addClass('show').text('Message is required');
            return false;
        } else if (value.length < 10) {
            $field.addClass('is-invalid').removeClass('is-valid');
            $error.addClass('show').text('Message must be at least 10 characters');
            return false;
        } else if (value.length > 2000) {
            $field.addClass('is-invalid').removeClass('is-valid');
            $error.addClass('show').text('Message must not exceed 2000 characters');
            return false;
        } else {
            $field.addClass('is-valid').removeClass('is-invalid');
            $error.removeClass('show').text('');
            return true;
        }
    }
    
    // Handle other required fields
    if (value === '') {
        $field.addClass('is-invalid').removeClass('is-valid');
        $error.addClass('show').text('This field is required');
        return false;
    } else {
        $field.addClass('is-valid').removeClass('is-invalid');
        $error.removeClass('show').text('');
        return true;
    }
}

function checkFormValidity() {
    const requiredFields = ['contactFullName', 'contactEmail', 'contactSubject', 'contactMessage'];
    let allValid = true;
    
    // Validate required fields
    requiredFields.forEach(fieldId => {
        const field = $('#' + fieldId);
        const value = field.val().trim();
        
        if (fieldId === 'contactEmail') {
            if (value === '' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
                allValid = false;
            }
        } else if (value === '') {
            allValid = false;
        }
    });
    
    // Check phone field if it has value
    const phoneValue = $('#contactPhone').val().trim();
    if (phoneValue !== '' && (phoneValue.length < 7 || phoneValue.length > 15)) {
        allValid = false;
    }
    
    // Check if privacy policy is checked
    const privacyChecked = $('#privacyPolicyCheck').is(':checked');
    
    // Disable button if form is invalid OR privacy policy is not checked
    $('#contactSubmitBtn').prop('disabled', !(allValid && privacyChecked));
}

function submitContactForm() {
    const submitBtn = $('#contactSubmitBtn');
    
    // Prevent duplicate submissions
    if (isSubmittingContactForm) {
        return;
    }
    
    isSubmittingContactForm = true;
    
    // Show loading state
    setLoadingState(submitBtn, true, 'Sending...');
    
    // Collect form data
    const formData = new FormData();
    formData.append('full_name', $('#contactFullName').val().trim());
    formData.append('email', $('#contactEmail').val().trim());
    formData.append('phone', $('#contactPhone').val().trim());
    formData.append('subject', $('#contactSubject').val());
    formData.append('message', $('#contactMessage').val().trim());
    
    // Add CSRF token
    const csrfToken = getCookie('csrftoken') || $('[name=csrfmiddlewaretoken]').val();
    if (csrfToken) {
        formData.append('csrfmiddlewaretoken', csrfToken);
    }
    
    // Submit to Django backend
    $.ajax({
        url: '/contact/',
        method: 'POST',
        data: formData,
        processData: false,
        contentType: false,
        headers: { 
            'X-Requested-With': 'XMLHttpRequest',
            'X-CSRFToken': csrfToken
        },
        success: function(response) {
            isSubmittingContactForm = false;
            setLoadingState(submitBtn, false);
            
            // Clear the form
            $('#contactForm')[0].reset();
            $('.contact-input').removeClass('is-valid is-invalid');
            $('.contact-error').removeClass('show').text('');
            $('.char-counter').text('');
            $('#phoneCounter').hide();
            $('#messageCounter').text('');
            $('#fullNameCounter').text('');
            
            // Reset privacy checkbox
            $('#privacyPolicyCheck').prop('checked', false).addClass('disabled').prop('disabled', true);
            
            // Reset privacy policy state
            window.privacyPolicyAccepted = false;
            
            // Reset form state
            formHasChanges = false;
            
            // Disable submit button
            $('#contactSubmitBtn').prop('disabled', true);
            
            // Show success alert
            const alertHtml = `
                <div class="alert alert-success alert-dismissible fade show position-fixed" style="
                    top: 20px; 
                    right: 20px; 
                    z-index: 9999; 
                    min-width: 400px;
                    box-shadow: 0 8px 32px rgba(22, 163, 74, 0.3);
                ">
                    <i class="fas fa-check-circle me-2"></i>
                    <strong>Success!</strong> ${response.message || 'Your message has been sent successfully. We will get back to you soon.'}
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            `;
            
            $('body').append(alertHtml);
            
            // Auto-remove alert after 7 seconds
            setTimeout(() => {
                $('.alert-success').fadeOut(500, function() {
                    $(this).remove();
                });
            }, 7000);
            
            // Scroll to top of form
            $('html, body').animate({
                scrollTop: $('#contactForm').offset().top - 100
            }, 300);
        },
        error: function(xhr) {
            isSubmittingContactForm = false;
            setLoadingState(submitBtn, false);
            
            const response = xhr.responseJSON || {};
            const errorMessage = response.error || 'Failed to send message. Please try again.';
            
            // Show error alert
            const alertHtml = `
                <div class="alert alert-danger alert-dismissible fade show position-fixed" style="
                    top: 20px; 
                    right: 20px; 
                    z-index: 9999; 
                    min-width: 400px;
                    box-shadow: 0 8px 32px rgba(220, 53, 69, 0.3);
                ">
                    <i class="fas fa-exclamation-circle me-2"></i>
                    <strong>Error!</strong> ${errorMessage}
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            `;
            
            $('body').append(alertHtml);
            
            setTimeout(() => {
                $('.alert-danger').fadeOut(500, function() {
                    $(this).remove();
                });
            }, 7000);
        }
    });
}

// ===== PRIVACY POLICY MODAL SETUP =====
function setupPrivacyPolicyModal() {
    // Open privacy modal
    $('#openPrivacyModal').on('click', function(e) {
        e.preventDefault();
        $('#privacyModal').modal('show');
    });
    
    // Scroll detection in privacy modal
    $('#privacyModalBody').on('scroll', function() {
        const scrollTop = $(this).scrollTop();
        const scrollHeight = $(this)[0].scrollHeight;
        const clientHeight = $(this)[0].clientHeight;
        const scrolledToEnd = scrollTop + clientHeight >= scrollHeight - 50; // 50px tolerance
        
        if (scrolledToEnd && !privacyPolicyScrolledToEnd) {
            privacyPolicyScrolledToEnd = true;
            const acceptBtn = $('#acceptPrivacyBtn');
            acceptBtn.prop('disabled', false).css('opacity', '1');
            $('.modal-footer small').text('You may now accept the privacy policy');
        }
    });
    
    // Accept privacy policy
    $('#acceptPrivacyBtn').on('click', function() {
        window.privacyPolicyAccepted = true;
        $('#privacyPolicyCheck').prop('checked', true).removeClass('disabled').prop('disabled', false);
        $('#privacyError').removeClass('show').text('');
        $('#privacyPolicyCheck').removeClass('is-invalid');
        $('#privacyModal').modal('hide');
        checkFormValidity();
    });
    
    // Reset scroll state when modal is closed
    $('#privacyModal').on('hidden.bs.modal', function() {
        if (!$('#privacyPolicyCheck').prop('checked')) {
            privacyPolicyScrolledToEnd = false;
            $('#acceptPrivacyBtn').prop('disabled', true).css('opacity', '0.5');
            $('.modal-footer small').text('Please scroll to the bottom to continue');
            $('#privacyModalBody').scrollTop(0);
        }
    });
}

// ===== CONTACT US FORM CHANGE DETECTION =====
function setupFormChangeDetection() {
    // Track changes to form inputs
    $('#contactForm input, #contactForm select, #contactForm textarea').on('input change', function() {
        const currentValue = $(this).val();
        const originalValue = $(this).data('original-value') || '';
        
        if (currentValue !== originalValue) {
            formHasChanges = true;
        } else {
            // Check if any other fields have changes
            checkForAnyChanges();
        }
    });
    
    // Store original values
    $('#contactForm input, #contactForm select, #contactForm textarea').each(function() {
        $(this).data('original-value', $(this).val());
    });
    
    // Reset form changes when form is successfully submitted
    $('#contactForm').on('reset', function() {
        setTimeout(() => {
            formHasChanges = false;
            $(this).find('input, select, textarea').each(function() {
                $(this).data('original-value', $(this).val());
            });
        }, 100);
    });
}

function checkForAnyChanges() {
    let hasChanges = false;
    $('#contactForm input, #contactForm select, #contactForm textarea').each(function() {
        const currentValue = $(this).val();
        const originalValue = $(this).data('original-value') || '';
        if (currentValue !== originalValue) {
            hasChanges = true;
            return false; // Break the loop
        }
    });
    formHasChanges = hasChanges;
}

// ===== NAVIGATION INTERCEPTION =====
function setupNavigationInterception() {
    // Intercept browser back/forward/refresh
    window.addEventListener('beforeunload', function(e) {
        // ONLY show warning if we're on a page with a contact form AND there are changes
        if (formHasChanges && $('#contactForm').length > 0) {
            const message = 'You have unsaved changes in the contact form. Are you sure you want to leave?';
            e.preventDefault();
            e.returnValue = message;
            return message;
        }
    });
    
    // Intercept link clicks
    $(document).on('click', 'a:not([href^="#"]):not([target="_blank"]):not(.no-transition):not([data-bs-toggle]):not(#openPrivacyModal)', function(e) {
        if (formHasChanges && $('#contactForm').length > 0) {
            e.preventDefault();
            pendingNavigation = $(this).attr('href');
            
            // Show confirmation if exit modal exists
            if ($('#exitConfirmationModal').length) {
                $('#exitConfirmationModal').modal('show');
            } else {
                // Fallback browser confirmation
                const confirmed = confirm('You have unsaved changes in the contact form. Are you sure you want to leave?');
                if (confirmed) {
                    formHasChanges = false;
                    window.location.href = pendingNavigation;
                }
            }
        }
    });
    
    // Exit confirmation modal handlers (if modal exists)
    $('#stayOnPageBtn').on('click', function() {
        $('#exitConfirmationModal').modal('hide');
        pendingNavigation = null;
    });
    
    $('#leavePageBtn').on('click', function() {
        formHasChanges = false; // Prevent further warnings
        if (pendingNavigation) {
            window.location.href = pendingNavigation;
        }
    });
}

// ===== UTILITY FUNCTIONS =====
function setLoadingState(element, loading = true, text = null) {
    const $el = $(element);
    
    if (loading) {
        $el.prop('disabled', true);
        $el.addClass('btn-loading');
        
        if (!$el.data('original-text')) {
            $el.data('original-text', $el.html());
        }
        
        if (text) {
            $el.html(`<i class="fas fa-spinner fa-spin me-2"></i>${text}`);
        }
    } else {
        $el.prop('disabled', false);
        $el.removeClass('btn-loading');
        
        const originalText = $el.data('original-text');
        if (originalText) {
            $el.html(originalText);
        }
    }
}

// Get CSRF token from cookies
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

// ----------------

// JavaScript functions for handling the close confirmation
function confirmCloseLogin() {
    const confirmed = confirm('Are you sure you want to stop the login process? You will need to start over.');
    
    if (confirmed) {
        proceedCloseLogin();
    }
}

function proceedCloseLogin() {
    // Hide MFA modal
    $('#mfaVerifyModal').modal('hide');
    
    // Clear MFA form data
    $('#mfaVerifyForm')[0].reset();
    $('#mfaVerifyErrors').empty();
    
    // Clear login form data as well
    $('#loginForm')[0].reset();
    $('#loginErrors').empty();
    
    // Remove any validation classes
    $('#loginForm .form-control').removeClass('is-valid is-invalid');
    $('#mfaVerifyForm .form-control').removeClass('is-valid is-invalid');
    
    // Show a brief message
    showAlert('Login process cancelled', 'info', 3000);
    
    // Clear any loading states
    setLoadingState($('#loginForm button[type="submit"]'), false);
    setLoadingState($('#mfaVerifyForm button[type="submit"]'), false);
}

// Browser navigation detection
let isMFAModalOpen = false;
let mfaFormSubmitting = false; // Add this flag to track form submission

// Track when MFA modal is shown
$(document).ready(function() {
    $('#mfaVerifyModal').on('shown.bs.modal', function() {
        isMFAModalOpen = true;
        mfaFormSubmitting = false; // Reset flag when modal opens
        
        // Add beforeunload listener for browser navigation
        $(window).on('beforeunload.mfaModal', function(e) {
            // Only show warning if modal is open AND we're not submitting the form
            if (isMFAModalOpen && !mfaFormSubmitting) {
                const message = 'Are you sure you want to leave? Your login process will be cancelled.';
                e.returnValue = message;
                return message;
            }
        });
        
        // Add popstate listener for back button
        $(window).on('popstate.mfaModal', function(e) {
            if (isMFAModalOpen && !mfaFormSubmitting) {
                e.preventDefault();
                confirmCloseLogin();
            }
        });
    });
    
    // Clean up when MFA modal is hidden
    $('#mfaVerifyModal').on('hidden.bs.modal', function() {
        isMFAModalOpen = false;
        mfaFormSubmitting = false;
        // Remove event listeners
        $(window).off('beforeunload.mfaModal popstate.mfaModal');
    });
});
