"""
Librarian forms with Code Injection Prevention.

Roberto Eugenio Sugiarto (2406355640) — Librarian Feature Developer + Code Injection Specialist

Security measures (CWE-79, CWE-20, CWE-94):
1. Input Validation:
   - RegexValidator with allowlist patterns (only permitted characters)
   - MaxLengthValidator to prevent buffer-overflow-style attacks
   - Django's built-in form validation pipeline

2. HTML Sanitization:
   - Description fields stripped of HTML tags at form level (defense-in-depth)
   - Templates use Django auto-escaping (NO |safe on user content)

3. File Upload Security:
   - Extension allowlist: .pdf, .epub, .txt only
   - MIME type verification via python-magic (checks file header, not just extension)
   - File size limit enforcement

4. CSRF Protection:
   - All forms rendered with {% csrf_token %} in templates
   - CsrfViewMiddleware active in settings.py
"""

import re

from django import forms
from django.core.validators import RegexValidator, MaxLengthValidator

from .models import Book, Category


# ── Shared widget CSS classes (matches existing project style) ──────────

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
_TEXTAREA_CLASS = (
    'w-full px-4 py-3 rounded-lg border border-slate-300 '
    'focus:border-red-700 focus:ring-2 focus:ring-red-700/20 '
    'outline-none transition-all resize-y'
)


# ── Helpers ──────────────────────────────────────────────────────────────

def _strip_html_tags(value: str) -> str:
    """
    Strip HTML tags from a string (defense-in-depth).

    Django templates auto-escape output, so this is an *extra* layer
    that removes tags at the form-cleaning stage, before data even
    reaches the database.

    Args:
        value: Raw user input string.

    Returns:
        String with all HTML/XML tags removed.
    """
    if not value:
        return value
    return re.sub(r'<[^>]+>', '', value)


# ── Allowed file extensions and MIME types for eBook upload ─────────────

ALLOWED_EBOOK_EXTENSIONS = ('.pdf', '.epub', '.txt')
ALLOWED_EBOOK_MIMETYPES = (
    'application/pdf',
    'application/epub+zip',
    'text/plain',
)
MAX_EBOOK_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB


# ── Book Form ────────────────────────────────────────────────────────────

class BookForm(forms.Form):
    """
    Form for adding and updating books.

    Code Injection Prevention:
    - title/author: Allowlist regex — letters, numbers, common punctuation only
    - isbn: Numbers and hyphens only (CWE-20 input validation)
    - description: HTML tags stripped, max 2000 chars
    - ebook_file: Extension + MIME type + size validation
    """

    title = forms.CharField(
        max_length=255,
        validators=[
            RegexValidator(
                regex=r'^[a-zA-Z0-9\s\-\.,;:!?\'"()&#+@/]+$',
                message='Title can only contain letters, numbers, spaces, and common punctuation.'
            ),
        ],
        widget=forms.TextInput(attrs={
            'class': _TEXT_INPUT_CLASS,
            'placeholder': 'Enter book title',
            'id': 'id_title',
        })
    )

    author = forms.CharField(
        max_length=255,
        validators=[
            RegexValidator(
                regex=r'^[a-zA-Z0-9\s\-\.,;:!?\'"()&]+$',
                message='Author can only contain letters, numbers, spaces, and common punctuation.'
            ),
        ],
        widget=forms.TextInput(attrs={
            'class': _TEXT_INPUT_CLASS,
            'placeholder': 'Enter author name',
            'id': 'id_author',
        })
    )

    isbn = forms.CharField(
        max_length=20,
        validators=[
            RegexValidator(
                regex=r'^[0-9\-]+$',
                message='ISBN can only contain numbers and hyphens.'
            ),
        ],
        widget=forms.TextInput(attrs={
            'class': _TEXT_INPUT_CLASS,
            'placeholder': 'e.g. 978-0-13-468599-1',
            'id': 'id_isbn',
        })
    )

    description = forms.CharField(
        required=False,
        max_length=2000,
        validators=[MaxLengthValidator(2000)],
        widget=forms.Textarea(attrs={
            'class': _TEXTAREA_CLASS,
            'placeholder': 'Enter book description (optional)',
            'rows': 4,
            'id': 'id_description',
        })
    )

    category = forms.ModelChoiceField(
        queryset=Category.objects.all(),
        required=False,
        empty_label='-- Select Category --',
        widget=forms.Select(attrs={
            'class': _SELECT_INPUT_CLASS,
            'id': 'id_category',
        })
    )

    ebook_file = forms.FileField(
        required=False,
        widget=forms.ClearableFileInput(attrs={
            'class': _TEXT_INPUT_CLASS,
            'accept': '.pdf,.epub,.txt',
            'id': 'id_ebook_file',
        }),
        help_text='Allowed formats: PDF, EPUB, TXT (max 50 MB)'
    )

    def clean_description(self):
        """Strip HTML tags from description (defense-in-depth)."""
        description = self.cleaned_data.get('description', '')
        return _strip_html_tags(description)

    def clean_ebook_file(self):
        """
        Validate eBook file upload.

        Security checks (CWE-20, CWE-94):
        1. Extension allowlist — only .pdf, .epub, .txt
        2. MIME type verification — checks actual file content header
        3. Size limit — max 50 MB

        This prevents:
        - Uploading executables disguised as PDFs (TC-FILE-01)
        - Code injection via file upload
        """
        ebook_file = self.cleaned_data.get('ebook_file')
        if not ebook_file:
            return ebook_file

        # 1. Check file extension (allowlist)
        file_name = ebook_file.name.lower()
        if not file_name.endswith(ALLOWED_EBOOK_EXTENSIONS):
            raise forms.ValidationError(
                f'Invalid file type. Only {", ".join(ALLOWED_EBOOK_EXTENSIONS)} files are allowed.'
            )

        # 2. Check file size
        if ebook_file.size > MAX_EBOOK_SIZE_BYTES:
            raise forms.ValidationError(
                f'File too large. Maximum size is {MAX_EBOOK_SIZE_BYTES // (1024 * 1024)} MB.'
            )

        # 3. Check MIME type (verify actual content, not just extension)
        try:
            import magic
            file_content = ebook_file.read(2048)  # Read first 2KB for MIME detection
            ebook_file.seek(0)  # Reset file pointer

            mime_type = magic.from_buffer(file_content, mime=True)
            if mime_type not in ALLOWED_EBOOK_MIMETYPES:
                raise forms.ValidationError(
                    f'File content does not match allowed types. '
                    f'Detected: {mime_type}. '
                    f'Allowed: {", ".join(ALLOWED_EBOOK_MIMETYPES)}.'
                )
        except ImportError:
            # Fallback: if python-magic is not installed, rely on extension check only
            # (already validated above)
            pass

        return ebook_file


# ── Category Form ────────────────────────────────────────────────────────

class CategoryForm(forms.Form):
    """
    Form for adding and updating categories.

    Code Injection Prevention:
    - name: Allowlist regex — letters, numbers, spaces, hyphens only
    - description: HTML tags stripped, max 500 chars
    """

    name = forms.CharField(
        max_length=100,
        validators=[
            RegexValidator(
                regex=r'^[a-zA-Z0-9\s\-]+$',
                message='Category name can only contain letters, numbers, spaces, and hyphens.'
            ),
        ],
        widget=forms.TextInput(attrs={
            'class': _TEXT_INPUT_CLASS,
            'placeholder': 'Enter category name',
            'id': 'id_name',
        })
    )

    description = forms.CharField(
        required=False,
        max_length=500,
        validators=[MaxLengthValidator(500)],
        widget=forms.Textarea(attrs={
            'class': _TEXTAREA_CLASS,
            'placeholder': 'Enter category description (optional)',
            'rows': 3,
            'id': 'id_description',
        })
    )

    def clean_description(self):
        """Strip HTML tags from description (defense-in-depth)."""
        description = self.cleaned_data.get('description', '')
        return _strip_html_tags(description)
