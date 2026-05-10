from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.db.models import Q
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError

from .models import Book


def search_books(request):
    """
    Search books using Django ORM (SQL Injection safe).
    Uses Q objects for safe query construction.

    Public endpoint - anyone can search.
    Returns JSON only when Accept: application/json header is set.
    """
    query = request.GET.get('q', '').strip()

    # Using Django ORM Q objects - SAFE from SQL injection
    books = Book.objects.filter(
        Q(title__icontains=query) |
        Q(author__icontains=query) |
        Q(isbn__icontains=query),
        is_deleted=False,
        status='available'
    ).select_related('category')[:20]

    results = [
        {
            'id': book.id,
            'title': book.title,
            'author': book.author,
            'isbn': book.isbn,
            'status': book.status,
            'category': book.category.name if book.category else None
        }
        for book in books
    ]

    # Only return JSON when explicitly requested via Accept header
    if request.headers.get('Accept') == 'application/json':
        return JsonResponse({'books': results, 'count': len(results)})

    # Otherwise return HTML template
    return render(request, 'main/search_results.html', {
        'books': books,
        'query': query,
        'count': len(results)
    })


def book_list(request):
    """
    List all available books.
    Public endpoint - anyone can view the book catalog.
    """
    books = Book.objects.filter(is_deleted=False, status='available').select_related('category')

    if request.headers.get('Accept') == 'application/json':
        return JsonResponse({
            'books': [
                {
                    'id': b.id,
                    'title': b.title,
                    'author': b.author,
                    'isbn': b.isbn,
                    'status': b.status,
                    'category': b.category.name if b.category else None
                }
                for b in books
            ]
        })

    return render(request, 'main/book_list.html', {'books': books})


def book_detail(request, book_id):
    """
    View book details.
    Public endpoint - anyone can view book details.
    """
    book = get_object_or_404(Book, id=book_id, is_deleted=False)

    if request.headers.get('Accept') == 'application/json':
        return JsonResponse({
            'book': {
                'id': book.id,
                'title': book.title,
                'author': book.author,
                'isbn': book.isbn,
                'description': book.description,
                'status': book.status,
                'category': book.category.name if book.category else None
            }
        })

    return render(request, 'main/book_detail.html', {'book': book})