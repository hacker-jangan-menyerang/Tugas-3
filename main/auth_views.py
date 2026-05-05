"""
Authentication views (minimal implementation).

Security measures:
- CSRF protection on login form (CWE-352)
- Password never stored/displayed in plaintext (CWE-256)
- Session flushed on logout to prevent session fixation (CWE-384)
- Django's authenticate() uses ORM — safe from SQL injection (CWE-89)

Note: Kevin will enhance with rate limiting (django-axes),
register view, and additional security hardening.
"""

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.views.decorators.http import require_http_methods

from .forms import LoginForm


@require_http_methods(["GET", "POST"])
def login_view(request):
    """
    Login view with CSRF protection.

    GET: Display login form with CSRF token
    POST: Validate credentials, create session

    Security:
    - {% csrf_token %} in template → CsrfViewMiddleware verifies
    - Django authenticate() uses parameterized queries (no SQLi)
    - Failed login: generic message (no user enumeration)
    """
    if request.user.is_authenticated:
        return _redirect_by_role(request.user)

    form = LoginForm()

    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']

            user = authenticate(request, username=username, password=password)

            if user is not None:
                if user.is_active:
                    login(request, user)
                    return _redirect_by_role(user)
                else:
                    # Generic message — don't reveal that account exists but is disabled
                    messages.error(request, 'Invalid username or password.')
            else:
                # Generic message — prevent user enumeration
                messages.error(request, 'Invalid username or password.')

    return render(request, 'main/login.html', {'form': form})


@require_http_methods(["GET", "POST"])
def logout_view(request):
    """
    Logout view — flush session entirely.

    Security:
    - session.flush() invalidates session token (CWE-384 mitigation)
    - Old session ID cannot be reused after logout
    """
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
