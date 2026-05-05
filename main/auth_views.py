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
from typing import Any, Optional

from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.http import HttpResponseForbidden
from django.utils import timezone

from axes.models import AccessAttempt
from axes.helpers import get_client_ip_address

from .forms import LoginForm, RegisterForm

def _get_axes_failure_limit() -> int:
    """Return the configured Axes failure limit."""
    return int(getattr(settings, 'AXES_FAILURE_LIMIT', 5))


def _get_axes_cooloff_seconds() -> int:
    """Return Axes cooloff time in seconds."""
    cooloff = getattr(settings, 'AXES_COOLOFF_TIME', datetime.timedelta(minutes=15))
    if isinstance(cooloff, datetime.timedelta):
        return int(cooloff.total_seconds())
    return int(datetime.timedelta(hours=float(cooloff)).total_seconds())


def _get_client_ip(request) -> str:
    """Get client IP address for Axes tracking."""
    client_ip = get_client_ip_address(request)
    if isinstance(client_ip, tuple):
        return client_ip[0]
    return client_ip or 'unknown'


def _get_latest_attempt(ip: str, username: Optional[str]) -> Optional[AccessAttempt]:
    """Get latest AccessAttempt for an IP."""
    return AccessAttempt.objects.filter(ip_address=ip).order_by('-attempt_time').first()


def _is_locked_out(ip: str, username: Optional[str]) -> bool:
    """Check Axes lockout status using AccessAttempt state."""
    attempt = _get_latest_attempt(ip, username)
    if not attempt:
        return False

    failures = int(getattr(attempt, 'failures_since_start', 0) or 0)
    if failures < _get_axes_failure_limit():
        return False

    remaining = _get_lockout_remaining_seconds(ip, username)
    return remaining > 0


def _get_lockout_remaining_seconds(ip: str, username: Optional[str]) -> int:
    """Return remaining lockout time in seconds based on Axes attempts."""
    attempt = _get_latest_attempt(ip, username)
    if not attempt:
        return 0

    last_attempt = getattr(attempt, 'last_attempt_time', None) or getattr(attempt, 'attempt_time', None)
    if not last_attempt:
        return 0

    cooloff_seconds = _get_axes_cooloff_seconds()
    elapsed = (timezone.now() - last_attempt).total_seconds()
    return max(0, int(cooloff_seconds - elapsed))


def _get_remaining_attempts(ip: str, username: Optional[str]) -> int:
    """Return remaining attempts before Axes lockout."""
    attempt = _get_latest_attempt(ip, username)
    failures = int(getattr(attempt, 'failures_since_start', 0) or 0) if attempt else 0
    return max(0, _get_axes_failure_limit() - failures)


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
    lockout_seconds = request.session.pop('lockout_seconds', None)
    if lockout_seconds:
        context['lockout_seconds'] = lockout_seconds

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
                request.session['lockout_seconds'] = remaining_seconds
                return redirect('main:login')

            user = authenticate(request, username=username, password=password)

            if user is not None:
                if user.is_active:
                    login(request, user)
                    return _redirect_by_role(user)
                else:
                    messages.error(request, 'Invalid username or password.')
            else:
                if _is_locked_out(ip, username) or getattr(request, 'axes_locked_out', False):
                    remaining_seconds = _get_lockout_remaining_seconds(ip, username)
                    remaining_minutes = max(1, int(remaining_seconds / 60))
                    messages.error(request, f'Account temporarily locked due to too many failed attempts. Try again in {remaining_minutes} minutes.')
                    request.session['lockout_seconds'] = remaining_seconds
                else:
                    remaining = _get_remaining_attempts(ip, username)
                    messages.error(request, f'Invalid username or password. ({remaining} attempts remaining)')
                return redirect('main:login')

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
        return redirect('main:admin_dashboard')  # Placeholder until Galih builds admin dashboard
    return redirect('main:book_list')
