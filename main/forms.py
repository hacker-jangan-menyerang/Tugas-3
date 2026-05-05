"""
Django forms with server-side validation.

All forms use Django's built-in CSRF protection via {% csrf_token %}
in templates and CsrfViewMiddleware in settings.

Input validation prevents code injection (CWE-20, CWE-79).
"""

from django import forms
from django.core.validators import RegexValidator, MaxLengthValidator


class LoginForm(forms.Form):
    """
    Login form with input validation.

    - Username: alphanumeric + underscore only (allowlist)
    - Password: max 128 chars (prevent DoS via extremely long input)
    """
    username = forms.CharField(
        max_length=150,
        validators=[
            RegexValidator(
                regex=r'^[a-zA-Z0-9_]+$',
                message='Username can only contain letters, numbers, and underscores.'
            ),
        ],
        widget=forms.TextInput(attrs={
            'class': 'w-full px-4 py-3 rounded-lg border border-slate-300 '
                     'focus:border-red-700 focus:ring-2 focus:ring-red-700/20 '
                     'outline-none transition-all',
            'placeholder': 'Enter your username',
            'autocomplete': 'username',
            'id': 'id_username',
        })
    )
    password = forms.CharField(
        max_length=128,
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-3 rounded-lg border border-slate-300 '
                     'focus:border-red-700 focus:ring-2 focus:ring-red-700/20 '
                     'outline-none transition-all',
            'placeholder': 'Enter your password',
            'autocomplete': 'current-password',
            'id': 'id_password',
        })
    )
