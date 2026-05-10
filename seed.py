"""
Seed data script for Digital Library database.
Run with: python manage.py shell < seed.py
Or: python seed.py (using Django's execute_from_command_line)
"""

import os
import sys
import django

# Setup Django
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'elibrary.settings')
django.setup()

from main.models import User, Category, Book, BorrowTransaction
from django.utils import timezone
from datetime import timedelta


def seed():
    print("Seeding database...")

    # Create Categories
    categories_data = [
        {'name': 'Programming', 'description': 'Books about programming languages and software development'},
        {'name': 'Database', 'description': 'Books about database design and management'},
        {'name': 'Networking', 'description': 'Books about computer networks and communications'},
        {'name': 'Security', 'description': 'Books about cybersecurity and information security'},
        {'name': 'Web Development', 'description': 'Books about web technologies and frameworks'},
    ]

    categories = []
    for cat_data in categories_data:
        cat, created = Category.objects.get_or_create(
            name=cat_data['name'],
            defaults={'description': cat_data['description']}
        )
        categories.append(cat)
        print(f"  Category: {cat.name} {'(created)' if created else '(exists)'}")

    # Create Users
    users_data = [
        {
            'username': 'admin',
            'email': 'admin@library.com',
            'role': 'admin',
            'employee_id': None,
            'membership_number': None,
            'password': 'admin123'
        },
        {
            'username': 'librarian1',
            'email': 'librarian1@library.com',
            'role': 'librarian',
            'employee_id': 'EMP001',
            'membership_number': None,
            'password': 'librarian123'
        },
        {
            'username': 'librarian2',
            'email': 'librarian2@library.com',
            'role': 'librarian',
            'employee_id': 'EMP002',
            'membership_number': None,
            'password': 'librarian123'
        },
        {
            'username': 'member1',
            'email': 'member1@library.com',
            'role': 'member',
            'employee_id': None,
            'membership_number': 'MBR001',
            'password': 'member123'
        },
        {
            'username': 'member2',
            'email': 'member2@library.com',
            'role': 'member',
            'employee_id': None,
            'membership_number': 'MBR002',
            'password': 'member123'
        },
    ]

    users = []
    for user_data in users_data:
        password = user_data.pop('password')
        user, created = User.objects.get_or_create(
            username=user_data['username'],
            defaults=user_data
        )
        if created:
            user.set_password(password)
            user.save()
        users.append(user)
        print(f"  User: {user.username} ({user.role}) {'(created)' if created else '(exists)'}")

    # Create Books
    books_data = [
        {'title': 'Python for Data Science', 'author': 'John Smith', 'isbn': '978-0-13-468599-1', 'category': categories[0]},
        {'title': 'Django Web Development', 'author': 'Jane Doe', 'isbn': '978-0-13-468599-2', 'category': categories[0]},
        {'title': 'JavaScript Complete Guide', 'author': 'Bob Wilson', 'isbn': '978-0-13-468599-3', 'category': categories[4]},
        {'title': 'Database Design Principles', 'author': 'Alice Brown', 'isbn': '978-0-13-468599-4', 'category': categories[1]},
        {'title': 'SQL Mastery', 'author': 'Charlie Davis', 'isbn': '978-0-13-468599-5', 'category': categories[1]},
        {'title': 'Computer Networks Fundamentals', 'author': 'David Lee', 'isbn': '978-0-13-468599-6', 'category': categories[2]},
        {'title': 'Network Security Essentials', 'author': 'Eve Johnson', 'isbn': '978-0-13-468599-7', 'category': categories[3]},
        {'title': 'Ethical Hacking Guide', 'author': 'Frank Miller', 'isbn': '978-0-13-468599-8', 'category': categories[3]},
        {'title': 'Web Application Security', 'author': 'Grace Chen', 'isbn': '978-0-13-468599-9', 'category': categories[3]},
        {'title': 'React Development', 'author': 'Henry Taylor', 'isbn': '978-0-13-468599-10', 'category': categories[4]},
        {'title': 'Machine Learning Basics', 'author': 'Ivy Wang', 'isbn': '978-0-13-468599-11', 'category': categories[0]},
        {'title': 'Deep Learning Essentials', 'author': 'Jack Robinson', 'isbn': '978-0-13-468599-12', 'category': categories[0]},
    ]

    librarian = users[1]  # librarian1

    for i, book_data in enumerate(books_data):
        book, created = Book.objects.get_or_create(
            isbn=book_data['isbn'],
            defaults={
                'title': book_data['title'],
                'author': book_data['author'],
                'category': book_data['category'],
                'status': 'available',
                'created_by': librarian
            }
        )
        print(f"  Book: {book.title} {'(created)' if created else '(exists)'}")

    # Create some borrow transactions
    member1 = users[3]  # member1
    all_books = Book.objects.filter(is_deleted=False)[:3]

    for i, book in enumerate(all_books):
        transaction, created = BorrowTransaction.objects.get_or_create(
            book=book,
            borrower=member1,
            defaults={
                'employee_id': librarian.employee_id,
                'membership_number': member1.membership_number,
                'due_date': timezone.now() + timedelta(days=14),
                'status': 'borrowed' if i < 2 else 'returned',
                'return_date': timezone.now() if i < 2 else None
            }
        )
        print(f"  Transaction: {book.title} - {member1.username} ({transaction.status}) {'(created)' if created else '(exists)'}")

    print("\nSeeding completed!")
    print(f"  Users: {User.objects.count()}")
    print(f"  Categories: {Category.objects.count()}")
    print(f"  Books: {Book.objects.count()}")
    print(f"  Transactions: {BorrowTransaction.objects.count()}")


if __name__ == '__main__':
    seed()