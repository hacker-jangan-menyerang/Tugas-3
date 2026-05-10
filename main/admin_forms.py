"""
Admin forms with server-side validation.

Security measures:
- Allowlist input validation for usernames and IDs.
- Role-specific field checks to prevent inconsistent data.
"""

from django import forms
from django.core.validators import RegexValidator
from django.contrib.auth import get_user_model

User = get_user_model()

_TEXT_INPUT_CLASS = (
    'w-full px-4 py-3 rounded-lg border border-slate-300 '
    'focus:border-red-700 focus:ring-2 focus:ring-red-700/20 '
    'outline-none transition-all'
)
_SELECT_INPUT_CLASS = (
    'w-full px-4 py-3 rounded-lg border border-slate-300 '
    'focus:border-red-700 focus:ring-2 focus:ring-red-700/20 '
    'outline-none transition-all'
)


class AdminUserCreateForm(forms.Form):
    """
    Admin user creation form.

    Validates:
    - Username uniqueness and format
    - Email uniqueness
    - Password minimum length
    - Role-specific required fields
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
            'class': _TEXT_INPUT_CLASS,
            'placeholder': 'Choose a username',
            'autocomplete': 'username',
            'id': 'id_username',
        })
    )
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': _TEXT_INPUT_CLASS,
            'placeholder': 'Enter email address',
            'autocomplete': 'email',
            'id': 'id_email',
        })
    )
    password = forms.CharField(
        max_length=128,
        min_length=8,
        widget=forms.PasswordInput(attrs={
            'class': _TEXT_INPUT_CLASS,
            'placeholder': 'Create a password (min 8 characters)',
            'autocomplete': 'new-password',
            'id': 'id_password1',
        })
    )
    role = forms.ChoiceField(
        choices=User.Role.choices,
        widget=forms.Select(attrs={
            'class': _SELECT_INPUT_CLASS,
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
            'class': _TEXT_INPUT_CLASS,
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
            'class': _TEXT_INPUT_CLASS,
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
        role = cleaned_data.get('role')

        if role == 'librarian' and not cleaned_data.get('employee_id'):
            self.add_error('employee_id', 'Employee ID is required for Librarian role.')

        if role == 'member' and not cleaned_data.get('membership_number'):
            self.add_error('membership_number', 'Membership number is required for Member role.')

        return cleaned_data


class AdminUserEditForm(forms.Form):
    """
    Admin user edit form (no password field).
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
            'class': _TEXT_INPUT_CLASS,
            'placeholder': 'Update username',
            'autocomplete': 'username',
            'id': 'id_username',
        })
    )
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': _TEXT_INPUT_CLASS,
            'placeholder': 'Update email address',
            'autocomplete': 'email',
            'id': 'id_email',
        })
    )
    role = forms.ChoiceField(
        choices=User.Role.choices,
        widget=forms.Select(attrs={
            'class': _SELECT_INPUT_CLASS,
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
            'class': _TEXT_INPUT_CLASS,
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
            'class': _TEXT_INPUT_CLASS,
            'placeholder': 'Membership number (for Member only)',
            'id': 'id_membership_number',
        })
    )

    def __init__(self, *args, **kwargs):
        self.user_instance = kwargs.pop('user_instance', None)
        super().__init__(*args, **kwargs)
        if self.user_instance is not None:
            self.fields['username'].initial = self.user_instance.username
            self.fields['email'].initial = self.user_instance.email
            self.fields['role'].initial = self.user_instance.role
            self.fields['employee_id'].initial = self.user_instance.employee_id or ''
            self.fields['membership_number'].initial = self.user_instance.membership_number or ''

    def clean_username(self):
        username = self.cleaned_data.get('username')
        queryset = User.objects.filter(username=username)
        if self.user_instance is not None:
            queryset = queryset.exclude(pk=self.user_instance.pk)
        if queryset.exists():
            raise forms.ValidationError('Username already exists.')
        return username

    def clean_email(self):
        email = self.cleaned_data.get('email')
        queryset = User.objects.filter(email=email)
        if self.user_instance is not None:
            queryset = queryset.exclude(pk=self.user_instance.pk)
        if queryset.exists():
            raise forms.ValidationError('Email already registered.')
        return email

    def clean(self):
        cleaned_data = super().clean()
        role = cleaned_data.get('role')

        if role == 'librarian' and not cleaned_data.get('employee_id'):
            self.add_error('employee_id', 'Employee ID is required for Librarian role.')

        if role == 'member' and not cleaned_data.get('membership_number'):
            self.add_error('membership_number', 'Membership number is required for Member role.')

        return cleaned_data
