"""
Authentication views with security measures.

Security measures:
- CSRF protection on login form (CWE-352)
- Password never stored/displayed in plaintext (CWE-256)
- Session flushed on logout to prevent session fixation (CWE-384)
- Django's authenticate() uses ORM — safe from SQL injection (CWE-89)
- Rate limiting on login attempts (CWE-307)
- Login attempt logging for lockout demonstration

Rate limiting implementation:
- AXES_FAILURE_LIMIT = 5 failed attempts triggers lockout
- Login attempts tracked in-memory (per-process)
- Lockout duration: 15 minutes
- Generic error messages prevent user enumeration (CWE-287)
"""

import os
import sys

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.http import HttpResponseForbidden

from .forms import LoginForm, RegisterForm

# In-memory login attempt tracking (per-process)
# For production, use Redis or database-backed tracking
# Key format: "ip_address:username" to prevent locking real users
_login_attempts = {}  # {"ip:username": {"count": int, "lockout_until": datetime}}

# Debug flag - always False unless explicitly enabled
_DEBUG_LOGIN = False

def _debug(msg):
    if _DEBUG_LOGIN:
        print(f"[AUTH DEBUG] {msg}", file=sys.stderr)


def _make_key(ip, username):
    """Create a composite key for IP + username tracking."""
    return f"{ip}:{username}"


def _get_client_ip(request):
    """Get client IP address for rate limiting."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', 'unknown')


def _is_locked_out(ip, username):
    """Check if IP+username combination is locked out due to too many failed attempts."""
    import datetime
    key = _make_key(ip, username)
    if key not in _login_attempts:
        return False

    lockout_until = _login_attempts[key].get('lockout_until')
    if lockout_until and datetime.datetime.now() < lockout_until:
        return True

    # Lockout expired, reset
    if key in _login_attempts:
        del _login_attempts[key]
    return False


def _record_failed_attempt(username, ip):
    """Record a failed login attempt."""
    import datetime
    LOCKOUT_DURATION = datetime.timedelta(minutes=15)
    FAILURE_LIMIT = 5

    key = _make_key(ip, username)
    if key not in _login_attempts:
        _login_attempts[key] = {'count': 0}

    _login_attempts[key]['count'] += 1

    if _login_attempts[key]['count'] >= FAILURE_LIMIT:
        _login_attempts[key]['lockout_until'] = datetime.datetime.now() + LOCKOUT_DURATION


def _record_success(username, ip):
    """Reset failed attempts on successful login."""
    key = _make_key(ip, username)
    if key in _login_attempts:
        del _login_attempts[key]


@require_http_methods(["GET", "POST"])
def login_view(request):
    """
    Login view with CSRF protection and rate limiting.

    GET: Display login form with CSRF token
    POST: Validate credentials, create session

    Security:
    - {% csrf_token %} in template → CsrfViewMiddleware verifies
    - Django authenticate() uses parameterized queries (no SQLi)
    - Failed login: generic message (no user enumeration)
    - Rate limiting: 5 failed attempts = 15 minute lockout (CWE-307)
    """
    global _login_attempts

    _debug(f"login_view called, method={request.method}, user={request.user}")

    if request.user.is_authenticated:
        return _redirect_by_role(request.user)

    form = LoginForm()

    if request.method == 'POST':
        _debug(f"POST data: {dict(request.POST)}")
        form = LoginForm(request.POST)
        _debug(f"form.is_valid()={form.is_valid()}, errors={form.errors}")
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            ip = _get_client_ip(request)

            _debug(f"Checking lockout for ip={ip}, username={username}")
            # Check if IP+username combo is locked out
            if _is_locked_out(ip, username):
                _debug("User is locked out")
                messages.error(request, 'Account temporarily locked due to too many failed attempts. Please try again later.')
                return render(request, 'main/login.html', {'form': form})

            user = authenticate(request, username=username, password=password)
            _debug(f"authenticate returned: {user}")

            if user is not None:
                if user.is_active:
                    login(request, user)
                    _record_success(username, ip)
                    return _redirect_by_role(user)
                else:
                    _record_failed_attempt(username, ip)
                    messages.error(request, 'Invalid username or password.')
            else:
                _record_failed_attempt(username, ip)
                _debug(f"Failed attempt recorded, _login_attempts={_login_attempts}")
                # Check if just got locked out
                if _is_locked_out(ip, username):
                    messages.error(request, 'Account temporarily locked due to too many failed attempts. Please try again later.')
                else:
                    key = _make_key(ip, username)
                    remaining = 5 - _login_attempts.get(key, {}).get('count', 0)
                    messages.error(request, f'Invalid username or password. ({remaining} attempts remaining)')

    return render(request, 'main/login.html', {'form': form})


@require_http_methods(["GET", "POST"])
def register_view(request):
    """
    User registration view.

    GET: Display registration form with CSRF token
    POST: Validate and create new user account

    Security:
    - Unique username/email validation
    - Password strength enforcement (CWE-256)
    - Role-specific field validation
    - PBKDF2 password hashing (default Django)
    """
    if request.user.is_authenticated:
        return redirect('main:member_dashboard')

    form = RegisterForm()

    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            role = form.cleaned_data['role']
            employee_id = form.cleaned_data.get('employee_id', '')
            membership_number = form.cleaned_data.get('membership_number', '')

            from .models import User
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                role=role,
                employee_id=employee_id or None,
                membership_number=membership_number or None
            )

            messages.success(request, f'Account created for {username}! Please log in.')
            return redirect('main:login')

    return render(request, 'main/register.html', {'form': form})


@require_http_methods(["GET", "POST"])
def logout_view(request):
    """
    Logout view — flush session entirely.

    Security:
    - session.flush() invalidates session token (CWE-384 mitigation)
    - Old session ID cannot be reused after logout
    """
    if request.user.is_authenticated:
        username = request.user.username
        logout(request)  # This calls session.flush() internally
        messages.success(request, 'You have been logged out successfully.')
    return redirect('main:login')


def _redirect_by_role(user):
    """Redirect user to appropriate dashboard based on role."""
    if user.role == 'member':
        return redirect('main:member_dashboard')
    elif user.role == 'librarian':
        return redirect('main:book_list')  # Placeholder until Roberto builds librarian dashboard
    elif user.role == 'admin':
        return redirect('main:book_list')  # Placeholder until Galih builds admin dashboard
    return redirect('main:book_list')
