"""
Django forms with server-side validation.

All forms use Django's built-in CSRF protection via {% csrf_token %}
in templates and CsrfViewMiddleware in settings.

Input validation prevents code injection (CWE-20, CWE-79).
"""

from django import forms
from django.core.validators import RegexValidator, MaxLengthValidator
from django.contrib.auth import get_user_model

User = get_user_model()


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


class RegisterForm(forms.Form):
    """
    Registration form with comprehensive validation.

    Validates:
    - Username uniqueness and format (CWE-287)
    - Password strength (CWE-256 mitigation)
    - Email format
    - Role selection
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
            'placeholder': 'Choose a username',
            'autocomplete': 'username',
            'id': 'id_username',
        })
    )
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'w-full px-4 py-3 rounded-lg border border-slate-300 '
                     'focus:border-red-700 focus:ring-2 focus:ring-red-700/20 '
                     'outline-none transition-all',
            'placeholder': 'Enter your email',
            'autocomplete': 'email',
            'id': 'id_email',
        })
    )
    password = forms.CharField(
        max_length=128,
        min_length=8,
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-3 rounded-lg border border-slate-300 '
                     'focus:border-red-700 focus:ring-2 focus:ring-red-700/20 '
                     'outline-none transition-all',
            'placeholder': 'Create a password (min 8 characters)',
            'autocomplete': 'new-password',
            'id': 'id_password1',
        })
    )
    password_confirm = forms.CharField(
        max_length=128,
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-3 rounded-lg border border-slate-300 '
                     'focus:border-red-700 focus:ring-2 focus:ring-red-700/20 '
                     'outline-none transition-all',
            'placeholder': 'Confirm your password',
            'autocomplete': 'new-password',
            'id': 'id_password2',
        })
    )
    role = forms.ChoiceField(
        choices=User.Role.choices,
        widget=forms.Select(attrs={
            'class': 'w-full px-4 py-3 rounded-lg border border-slate-300 '
                     'focus:border-red-700 focus:ring-2 focus:ring-red-700/20 '
                     'outline-none transition-all',
            'id': 'id_role',
        })
    )
    employee_id = forms.CharField(
        max_length=50,
        required=False,
        validators=[
            RegexValidator(
                regex=r'^[A-Z0-9\-]*$',
                message='Employee ID must be uppercase letters, numbers, and hyphens only.'
            ),
        ],
        widget=forms.TextInput(attrs={
            'class': 'w-full px-4 py-3 rounded-lg border border-slate-300 '
                     'focus:border-red-700 focus:ring-2 focus:ring-red-700/20 '
                     'outline-none transition-all',
            'placeholder': 'Employee ID (for Librarian only)',
            'id': 'id_employee_id',
        })
    )
    membership_number = forms.CharField(
        max_length=50,
        required=False,
        validators=[
            RegexValidator(
                regex=r'^[A-Z0-9\-]*$',
                message='Membership number must be uppercase letters, numbers, and hyphens only.'
            ),
        ],
        widget=forms.TextInput(attrs={
            'class': 'w-full px-4 py-3 rounded-lg border border-slate-300 '
                     'focus:border-red-700 focus:ring-2 focus:ring-red-700/20 '
                     'outline-none transition-all',
            'placeholder': 'Membership number (for Member only)',
            'id': 'id_membership_number',
        })
    )

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError('Username already exists.')
        return username

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError('Email already registered.')
        return email

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        password_confirm = cleaned_data.get('password_confirm')
        role = cleaned_data.get('role')

        if password and password_confirm and password != password_confirm:
            raise forms.ValidationError({'password_confirm': 'Passwords do not match.'})

        # Validate role-specific fields
        if role == 'librarian' and not cleaned_data.get('employee_id'):
            self.add_error('employee_id', 'Employee ID is required for Librarian role.')

        if role == 'member' and not cleaned_data.get('membership_number'):
            self.add_error('membership_number', 'Membership number is required for Member role.')

        return cleaned_data
