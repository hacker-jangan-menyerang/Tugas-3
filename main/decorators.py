"""
Role-based access control decorators.

Implements least privilege principle (CWE-285):
- Each view is restricted to specific roles only
- Unauthenticated users are redirected to login
- Users with wrong role get 403 Forbidden

Usage:
    @role_required('member')
    def member_view(request):
        ...

    @role_required('librarian', 'admin')
    def staff_view(request):
        ...
"""

from functools import wraps
from django.shortcuts import redirect
from django.http import HttpResponseForbidden


def role_required(*roles):
    """
    Decorator to restrict view access by user role.

    Enforces least privilege — only users with an explicitly
    allowed role can access the decorated view.

    Args:
        *roles: One or more role strings ('member', 'librarian', 'admin')

    Returns:
        - Redirect to login if not authenticated
        - 403 Forbidden if role doesn't match
        - Normal view response if authorized
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('main:login')
            if request.user.role not in roles:
                return HttpResponseForbidden(
                    '<h1>403 Forbidden</h1>'
                    '<p>You do not have permission to access this page.</p>'
                )
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator
