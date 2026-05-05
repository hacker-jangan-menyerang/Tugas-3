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

import datetime
from typing import Any

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.http import HttpResponseForbidden
from django.core.cache import cache
from django.utils import timezone

from .forms import LoginForm, RegisterForm

FAILURE_LIMIT = 5
LOCKOUT_DURATION = datetime.timedelta(minutes=15)

def _get_attempts(key):
    """Get attempt data from cache for a key."""
    return cache.get(key, {'count': 0})


def _set_attempts(key, data):
    """Persist attempt data in cache."""
    cache.set(key, data, timeout=int(LOCKOUT_DURATION.total_seconds()))


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
    key = _make_key(ip, username)
    data = _get_attempts(key)
    lockout_until = data.get('lockout_until')
    if lockout_until and timezone.now() < lockout_until:
        return True

    if lockout_until:
        cache.delete(key)
    return False


def _get_lockout_remaining_seconds(ip, username):
    """Return remaining lockout time in seconds for a key."""
    key = _make_key(ip, username)
    data = _get_attempts(key)
    lockout_until = data.get('lockout_until')
    if lockout_until and timezone.now() < lockout_until:
        return max(0, int((lockout_until - timezone.now()).total_seconds()))
    return 0


def _record_failed_attempt(username, ip):
    """Record a failed login attempt."""
    key = _make_key(ip, username)
    data = _get_attempts(key)
    data['count'] = data.get('count', 0) + 1

    if data['count'] >= FAILURE_LIMIT:
        data['lockout_until'] = timezone.now() + LOCKOUT_DURATION

    _set_attempts(key, data)
    return data


def _record_success(username, ip):
    """Reset failed attempts on successful login."""
    key = _make_key(ip, username)
    cache.delete(key)


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
    if request.user.is_authenticated:
        return _redirect_by_role(request.user)

    form = LoginForm()
    context: dict[str, Any] = {'form': form}

    if request.method == 'POST':
        form = LoginForm(request.POST)
        context['form'] = form
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            ip = _get_client_ip(request)

            # Check if IP+username combo is locked out
            if _is_locked_out(ip, username):
                remaining_seconds = _get_lockout_remaining_seconds(ip, username)
                remaining_minutes = max(1, int(remaining_seconds / 60))
                messages.error(request, f'Account temporarily locked due to too many failed attempts. Try again in {remaining_minutes} minutes.')
                context['lockout_seconds'] = remaining_seconds
                return render(request, 'main/login.html', context)

            user = authenticate(request, username=username, password=password)

            if user is not None:
                if user.is_active:
                    login(request, user)
                    _record_success(username, ip)
                    return _redirect_by_role(user)
                else:
                    data = _record_failed_attempt(username, ip)
                    messages.error(request, 'Invalid username or password.')
            else:
                data = _record_failed_attempt(username, ip)
                if data.get('lockout_until') and _is_locked_out(ip, username):
                    remaining_seconds = _get_lockout_remaining_seconds(ip, username)
                    remaining_minutes = max(1, int(remaining_seconds / 60))
                    messages.error(request, f'Account temporarily locked due to too many failed attempts. Try again in {remaining_minutes} minutes.')
                    context['lockout_seconds'] = remaining_seconds
                else:
                    remaining = max(0, FAILURE_LIMIT - data.get('count', 0))
                    messages.error(request, f'Invalid username or password. ({remaining} attempts remaining)')

    return render(request, 'main/login.html', context)


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
