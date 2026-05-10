"""
Member feature views for Digital Library.

Benedictus Lucky Win Ziraluo (2406355174) — Member Feature Developer + CSRF Specialist

Security measures implemented:
1. CSRF Protection (CWE-352):
   - All POST forms include {% csrf_token %}
   - CsrfViewMiddleware verifies token server-side
   - No @csrf_exempt used anywhere

2. IDOR Prevention (CWE-639):
   - Borrow history filtered by request.user (ownership check)
   - Return only allowed by the borrower themselves

3. Server-side Timestamping (Repudiation mitigation):
   - borrow_date uses auto_now_add (set by server)
   - return_date set by timezone.now() on server
   - User cannot manipulate timestamps

4. Least Privilege:
   - All views decorated with @role_required('member')
   - Members cannot access librarian/admin features

5. Input Validation:
   - Book ID validated as integer by Django URL converter
   - Status checks prevent double-borrow / double-return
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.utils import timezone
from django.views.decorators.http import require_http_methods, require_POST
from datetime import timedelta

from .models import Book, BorrowTransaction
from .decorators import role_required
from .audit import create_audit_log


@role_required('member')
@require_http_methods(["GET"])
def member_dashboard(request):
    """
    Member dashboard — shows available books for borrowing.

    Security:
    - @role_required('member') — only members can access
    - Books filtered via ORM (no raw SQL)
    """
    books = Book.objects.filter(
        is_deleted=False
    ).select_related('category').order_by('title')

    # Get member's active borrows to show which books they already borrowed
    active_borrows = BorrowTransaction.objects.filter(
        borrower=request.user,
        status='borrowed'
    ).values_list('book_id', flat=True)

    return render(request, 'main/member_dashboard.html', {
        'books': books,
        'active_borrows': list(active_borrows),
    })


@role_required('member')
@require_http_methods(["GET", "POST"])
def borrow_book(request, book_id):
    """
    Borrow an eBook.

    GET: Show confirmation page with CSRF token in form
    POST: Process borrow (CSRF token verified by middleware)

    Business Logic (from OCL Tugas 1):
    - AvailabilityCheck: Book.status must be 'available'
    - AccountabilityMemberTracked: membership_number recorded in transaction
    - Server-side timestamping: borrow_date = auto_now_add, due_date = now + 14 days

    Security:
    - CSRF token required for POST (CWE-352)
    - @role_required('member') — least privilege
    - Book existence verified via get_object_or_404
    """
    book = get_object_or_404(Book, id=book_id, is_deleted=False)

    if request.method == 'POST':
        # Check book availability (OCL: AvailabilityCheck)
        if book.status != 'available':
            messages.error(request, 'This book is not available for borrowing.')
            return redirect('main:member_dashboard')

        # Check if user already has an active borrow for this book
        existing = BorrowTransaction.objects.filter(
            book=book,
            borrower=request.user,
            status='borrowed'
        ).exists()

        if existing:
            messages.warning(request, 'You have already borrowed this book.')
            return redirect('main:member_dashboard')

        # Create transaction with server-side timestamps
        # borrow_date: auto_now_add=True (server timestamp, not user input)
        # due_date: server calculates now + 14 days
        transaction = BorrowTransaction.objects.create(
            book=book,
            borrower=request.user,
            membership_number=request.user.membership_number,  # AccountabilityMemberTracked
            due_date=timezone.now() + timedelta(days=14),  # Server-side calculation
            status='borrowed'
        )

        # Update book status (OCL: Book.status = 'Not Available')
        book.status = 'not_available'
        book.save(update_fields=['status'])

        create_audit_log(
            'book_borrowed',
            request.user,
            f'Borrowed "{book.title}" (book_id={book.id}, txn={transaction.id}).',
        )

        messages.success(request, f'Successfully borrowed "{book.title}".')
        return redirect('main:borrow_history')

    # GET — show confirmation page with CSRF token
    return render(request, 'main/borrow_confirm.html', {'book': book})


@role_required('member')
@require_http_methods(["GET", "POST"])
def return_book(request, transaction_id):
    """
    Return a borrowed eBook.

    GET: Show confirmation page with CSRF token
    POST: Process return (CSRF token verified by middleware)

    Business Logic (from OCL Tugas 1):
    - ValidStatusIntegrity: transaction.status must be 'borrowed' before return
    - Server-side timestamping: return_date = timezone.now()

    Security:
    - CSRF token required for POST (CWE-352)
    - Ownership check: transaction.borrower == request.user (IDOR prevention, CWE-639)
    - @role_required('member') — least privilege
    """
    # Ownership check — IDOR prevention
    # Only the borrower can return their own book
    transaction = get_object_or_404(
        BorrowTransaction,
        id=transaction_id,
        borrower=request.user  # CRITICAL: ownership check
    )

    if request.method == 'POST':
        # ValidStatusIntegrity: can only return books that are currently borrowed
        if transaction.status != 'borrowed':
            messages.error(request, 'This book has already been returned.')
            return redirect('main:borrow_history')

        # Server-side timestamp — user cannot manipulate return_date
        transaction.return_date = timezone.now()
        transaction.status = 'returned'
        transaction.save(update_fields=['return_date', 'status'])

        # Update book status back to available
        transaction.book.status = 'available'
        transaction.book.save(update_fields=['status'])

        create_audit_log(
            'book_returned',
            request.user,
            f'Returned "{transaction.book.title}" (book_id={transaction.book.id}, txn={transaction.id}).',
        )

        messages.success(request, f'Successfully returned "{transaction.book.title}".')
        return redirect('main:borrow_history')

    # GET — show confirmation page
    return render(request, 'main/return_confirm.html', {'transaction': transaction})


@role_required('member')
@require_http_methods(["GET"])
def borrow_history(request):
    """
    View borrowing history — OWN transactions only.

    Security:
    - IDOR Prevention (CWE-639): filtered by borrower=request.user
    - Member A cannot see Member B's history
    - No user ID in URL — always uses request.user (session-based)
    """
    # IDOR Prevention: ONLY show transactions belonging to the logged-in user
    transactions = BorrowTransaction.objects.filter(
        borrower=request.user  # Ownership check — prevents IDOR
    ).select_related('book', 'book__category').order_by('-borrow_date')

    return render(request, 'main/borrow_history.html', {
        'transactions': transactions,
    })


@role_required('member')
@require_http_methods(["GET"])
def read_online(request, book_id):
    """
    Read a book online (simple reader page).

    Security:
    - @role_required('member') — only authenticated members
    - Ownership check: user must have an active borrow for this book
    - Book content rendered safely (no |safe filter on user content)
    """
    book = get_object_or_404(Book, id=book_id, is_deleted=False)

    # Check if user has an active borrow for this book
    has_access = BorrowTransaction.objects.filter(
        book=book,
        borrower=request.user,
        status='borrowed'
    ).exists()

    if not has_access:
        messages.error(request, 'You need to borrow this book first to read it online.')
        return redirect('main:member_dashboard')

    create_audit_log(
        'book_read_online',
        request.user,
        f'Opened online reader for "{book.title}" (book_id={book.id}).',
    )

    return render(request, 'main/read_online.html', {'book': book})
