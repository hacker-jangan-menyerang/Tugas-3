"""
Librarian feature views for Digital Library.

Roberto Eugenio Sugiarto (2406355640) — Librarian Feature Developer + Code Injection Specialist

Security measures implemented:
1. Code Injection Prevention (CWE-79, CWE-20, CWE-94):
   - All forms use Django Forms with RegexValidator + MaxLengthValidator
   - Allowlist validation for ISBN, title, author, category name
   - HTML tags stripped from description fields at form level
   - Templates use Django auto-escaping (NO |safe on user content)
   - File upload validated by extension allowlist + MIME type check

2. Audit Logging (Unauthorized Book Modification mitigation):
   - Every add/update/delete action logged to AuditLog table
   - Logs include: who did what, when, and details

3. Least Privilege:
   - All views decorated with @role_required('librarian')
   - Members and admins cannot access librarian features

4. CSRF Protection:
   - All POST forms include {% csrf_token %}
   - CsrfViewMiddleware verifies token server-side
   - No @csrf_exempt used

5. Soft Delete:
   - Books are soft-deleted (is_deleted=True), not removed from DB
   - Preserves audit trail and data integrity
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.views.decorators.http import require_http_methods, require_POST
from django.core.paginator import Paginator

from .models import Book, Category, BorrowTransaction
from .librarian_forms import BookForm, CategoryForm
from .decorators import role_required
from .audit import create_audit_log


# ── Dashboard ────────────────────────────────────────────────────────────

@role_required('librarian')
@require_http_methods(["GET"])
def librarian_dashboard(request):
    """
    Librarian dashboard — overview of books, categories, and recent transactions.

    Security:
    - @role_required('librarian') — only librarians can access
    - GET-only to prevent state changes
    - ORM-only data access (no raw SQL)
    """
    total_books = Book.objects.filter(is_deleted=False).count()
    total_deleted = Book.objects.filter(is_deleted=True).count()
    total_available = Book.objects.filter(is_deleted=False, status='available').count()
    total_borrowed = Book.objects.filter(is_deleted=False, status='not_available').count()
    total_categories = Category.objects.count()

    recent_transactions = BorrowTransaction.objects.select_related(
        'book', 'borrower'
    ).order_by('-borrow_date')[:10]

    return render(request, 'main/librarian_dashboard.html', {
        'total_books': total_books,
        'total_deleted': total_deleted,
        'total_available': total_available,
        'total_borrowed': total_borrowed,
        'total_categories': total_categories,
        'recent_transactions': recent_transactions,
    })


# ── Book Management ──────────────────────────────────────────────────────

@role_required('librarian')
@require_http_methods(["GET"])
def book_management_list(request):
    """
    List all books for management (including soft-deleted).

    Security:
    - @role_required('librarian') — only librarians
    - GET-only, no state changes
    - ORM-only queries
    """
    show_deleted = request.GET.get('show_deleted', '') == '1'

    if show_deleted:
        books = Book.objects.all().select_related('category', 'created_by').order_by('-created_at')
    else:
        books = Book.objects.filter(is_deleted=False).select_related(
            'category', 'created_by'
        ).order_by('-created_at')

    paginator = Paginator(books, 20)
    page_obj = paginator.get_page(request.GET.get('page'))

    return render(request, 'main/librarian_book_list.html', {
        'page_obj': page_obj,
        'show_deleted': show_deleted,
    })


@role_required('librarian')
@require_http_methods(["GET", "POST"])
def add_book(request):
    """
    Add a new book to the library.

    GET: Display book form with CSRF token
    POST: Validate input (Code Injection Prevention) and create book

    Security:
    - BookForm validates all fields with RegexValidator + MaxLengthValidator
    - ISBN: numbers + hyphens only (allowlist)
    - Title/Author: letters, numbers, punctuation only (allowlist)
    - Description: HTML tags stripped (defense-in-depth)
    - eBook file: extension + MIME type + size validation
    - CSRF token required for POST
    - Audit log created for accountability
    """
    if request.method == 'POST':
        form = BookForm(request.POST, request.FILES)
        if form.is_valid():
            book = Book.objects.create(
                title=form.cleaned_data['title'],
                author=form.cleaned_data['author'],
                isbn=form.cleaned_data['isbn'],
                description=form.cleaned_data.get('description', ''),
                category=form.cleaned_data.get('category'),
                ebook_file=form.cleaned_data.get('ebook_file'),
                status='available',
                created_by=request.user,
            )

            # Audit log — accountability for book addition
            create_audit_log(
                'book_added',
                request.user,
                f'Added book: "{book.title}" (ISBN: {book.isbn})',
            )

            messages.success(request, f'Book "{book.title}" added successfully.')
            return redirect('main:book_management_list')
    else:
        form = BookForm()

    return render(request, 'main/librarian_book_form.html', {
        'form': form,
        'form_title': 'Add Book',
        'submit_label': 'Add Book',
    })


@role_required('librarian')
@require_http_methods(["GET", "POST"])
def update_book(request, book_id):
    """
    Update an existing book.

    GET: Display form pre-filled with current book data
    POST: Validate and update book

    Security:
    - Same input validation as add_book (Code Injection Prevention)
    - CSRF token required for POST
    - Audit log tracks what changed
    """
    book = get_object_or_404(Book, id=book_id, is_deleted=False)

    if request.method == 'POST':
        form = BookForm(request.POST, request.FILES)
        if form.is_valid():
            old_title = book.title
            book.title = form.cleaned_data['title']
            book.author = form.cleaned_data['author']
            book.isbn = form.cleaned_data['isbn']
            book.description = form.cleaned_data.get('description', '')
            book.category = form.cleaned_data.get('category')

            new_file = form.cleaned_data.get('ebook_file')
            if new_file:
                book.ebook_file = new_file

            book.save()

            # Audit log — accountability for book modification
            create_audit_log(
                'book_updated',
                request.user,
                f'Updated book: "{old_title}" → "{book.title}" (ID: {book.id})',
            )

            messages.success(request, f'Book "{book.title}" updated successfully.')
            return redirect('main:book_management_list')
    else:
        form = BookForm(initial={
            'title': book.title,
            'author': book.author,
            'isbn': book.isbn,
            'description': book.description,
            'category': book.category,
        })

    return render(request, 'main/librarian_book_form.html', {
        'form': form,
        'form_title': f'Update Book: {book.title}',
        'submit_label': 'Update Book',
        'book': book,
    })


@role_required('librarian')
@require_POST
def delete_book(request, book_id):
    """
    Soft-delete a book (set is_deleted=True).

    Security:
    - POST-only to prevent CSRF via GET
    - Soft delete preserves data integrity and audit trail
    - Audit log tracks who deleted what
    - Book not physically removed from database
    """
    book = get_object_or_404(Book, id=book_id, is_deleted=False)

    book.is_deleted = True
    book.save(update_fields=['is_deleted'])

    # Audit log — accountability for book deletion
    create_audit_log(
        'book_deleted',
        request.user,
        f'Soft-deleted book: "{book.title}" (ID: {book.id}, ISBN: {book.isbn})',
    )

    messages.success(request, f'Book "{book.title}" has been deleted (soft delete).')
    return redirect('main:book_management_list')


# ── Category Management ──────────────────────────────────────────────────

@role_required('librarian')
@require_http_methods(["GET"])
def category_list(request):
    """
    List all categories.

    Security:
    - @role_required('librarian') — only librarians
    - GET-only, no state changes
    """
    categories = Category.objects.all().order_by('name')

    return render(request, 'main/librarian_category_list.html', {
        'categories': categories,
    })


@role_required('librarian')
@require_http_methods(["GET", "POST"])
def add_category(request):
    """
    Add a new category.

    Security:
    - CategoryForm validates name with RegexValidator (allowlist)
    - Description has HTML tags stripped
    - CSRF token required
    - Audit log for accountability
    """
    if request.method == 'POST':
        form = CategoryForm(request.POST)
        if form.is_valid():
            category = Category.objects.create(
                name=form.cleaned_data['name'],
                description=form.cleaned_data.get('description', ''),
            )

            create_audit_log(
                'category_added',
                request.user,
                f'Added category: "{category.name}"',
            )

            messages.success(request, f'Category "{category.name}" added successfully.')
            return redirect('main:category_list')
    else:
        form = CategoryForm()

    return render(request, 'main/librarian_category_form.html', {
        'form': form,
        'form_title': 'Add Category',
        'submit_label': 'Add Category',
    })


@role_required('librarian')
@require_http_methods(["GET", "POST"])
def update_category(request, category_id):
    """
    Update an existing category.

    Security:
    - Same validation as add_category
    - CSRF token required
    - Audit log tracks changes
    """
    category = get_object_or_404(Category, id=category_id)

    if request.method == 'POST':
        form = CategoryForm(request.POST)
        if form.is_valid():
            old_name = category.name
            category.name = form.cleaned_data['name']
            category.description = form.cleaned_data.get('description', '')
            category.save()

            create_audit_log(
                'category_updated',
                request.user,
                f'Updated category: "{old_name}" → "{category.name}"',
            )

            messages.success(request, f'Category "{category.name}" updated successfully.')
            return redirect('main:category_list')
    else:
        form = CategoryForm(initial={
            'name': category.name,
            'description': category.description,
        })

    return render(request, 'main/librarian_category_form.html', {
        'form': form,
        'form_title': f'Update Category: {category.name}',
        'submit_label': 'Update Category',
        'category': category,
    })


@role_required('librarian')
@require_POST
def delete_category(request, category_id):
    """
    Delete a category.

    Security:
    - POST-only to prevent CSRF via GET
    - Audit log for accountability
    - Books in this category will have category set to NULL (on_delete=SET_NULL)
    """
    category = get_object_or_404(Category, id=category_id)
    category_name = category.name

    category.delete()

    create_audit_log(
        'category_deleted',
        request.user,
        f'Deleted category: "{category_name}" (ID: {category_id})',
    )

    messages.success(request, f'Category "{category_name}" has been deleted.')
    return redirect('main:category_list')


# ── Report Generation ────────────────────────────────────────────────────

@role_required('librarian')
@require_http_methods(["GET"])
def generate_report(request):
    """
    Generate borrowing transaction report.

    Displays a filtered list of all borrow transactions.

    Security:
    - @role_required('librarian') — only librarians
    - GET-only, read-only report
    - ORM-only queries
    """
    status_filter = request.GET.get('status', '').strip()
    valid_statuses = {'borrowed', 'returned'}

    transactions = BorrowTransaction.objects.select_related(
        'book', 'borrower'
    ).all()

    if status_filter in valid_statuses:
        transactions = transactions.filter(status=status_filter)
    else:
        status_filter = ''

    transactions = transactions.order_by('-borrow_date')

    paginator = Paginator(transactions, 25)
    page_obj = paginator.get_page(request.GET.get('page'))

    total_borrowed = BorrowTransaction.objects.filter(status='borrowed').count()
    total_returned = BorrowTransaction.objects.filter(status='returned').count()

    create_audit_log(
        'report_generated',
        request.user,
        f'Generated borrow report (status_filter={status_filter or "all"}).',
    )

    return render(request, 'main/librarian_report.html', {
        'page_obj': page_obj,
        'status_filter': status_filter,
        'total_borrowed': total_borrowed,
        'total_returned': total_returned,
    })
