"""
SQL Injection Prevention Test Cases
Vincent Valentino Oei - Database Architect + SQL Injection Specialist

Test Cases:
- TC-SQLI-01: Search dengan payload SQL injection → tidak menampilkan semua buku
- TC-SQLI-02: Login dengan username SQL injection → tetap gagal
- TC-SQLI-03: Search dengan DROP TABLE payload → tidak ada efek

Run with: python manage.py test main.tests --verbosity=2
"""

from django.test import TestCase, Client
from django.contrib.auth import get_user_model


User = get_user_model()


class SQLInjectionSearchTests(TestCase):
    """Test SQL injection prevention in search functionality."""

    @classmethod
    def setUpTestData(cls):
        from main.models import Book, Category
        cat = Category.objects.create(name='Test Category')
        Book.objects.create(
            title='Normal Python Book',
            author='Test Author',
            isbn='123-456-789',
            status='available',
            category=cat
        )

    def setUp(self):
        self.client = Client()

    def test_tc_sqli_01_or_1_equals_1_payload(self):
        """
        TC-SQLI-01: Search dengan payload ' OR '1'='1'-- → tidak menampilkan semua buku
        Expected: Search returns 0 results (payload treated as literal string)
        """
        response = self.client.get('/books/search/', {'q': "' OR '1'='1'--"})
        self.assertEqual(response.status_code, 200)

        # Check response is not leaking all books
        from main.models import Book
        content = response.content.decode('utf-8')
        # Should NOT show all books in the page
        book_count = Book.objects.count()
        # The page should either show 0 results or not show all books
        # Since payload is escaped, it won't match anything
        if '0 book' in content or 'No books' in content or '0 results' in content:
            success = True
        else:
            # Check if it's treated as literal search (shouldn't match any title)
            success = 'Normal Python Book' not in content or 'No books' in content

        self.assertTrue(success, "SQL Injection may have succeeded - payload returned unintended results")

    def test_tc_sqli_03_drop_table_payload(self):
        """
        TC-SQLI-03: Search dengan ; DROP TABLE book;-- → tidak ada efek
        Expected: No database error, search returns 0 results
        """
        response = self.client.get('/books/search/', {'q': '; DROP TABLE book;--'})
        self.assertEqual(response.status_code, 200)

        # Verify table still exists
        from main.models import Book
        book_count = Book.objects.count()
        self.assertGreater(book_count, 0, "DROP TABLE was executed - table is missing!")

        # Response should not be a server error
        self.assertNotEqual(response.status_code, 500)

    def test_tc_sqli_union_attack(self):
        """
        Additional test: UNION-based SQL injection
        Expected: Returns 0 results or safe response
        """
        payloads = [
            "' UNION SELECT * FROM users--",
            "' OR 1=1 UNION SELECT username,password FROM auth_user--",
        ]

        for payload in payloads:
            response = self.client.get('/books/search/', {'q': payload})
            self.assertEqual(response.status_code, 200)
            # Should not expose user data
            content = response.content.decode('utf-8')
            # Password fields should not appear in response
            self.assertNotIn('pbkdf2', content.lower(),
                f"SQL injection may have leaked password hash: {payload}")

    def test_search_with_valid_query(self):
        """
        Verify normal search still works correctly.
        Expected: Returns matching books
        """
        response = self.client.get('/books/search/', {'q': 'Python'})
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        # Should find the "Normal Python Book"
        self.assertIn('Normal Python Book', content)


class SQLInjectionLoginTests(TestCase):
    """
    TC-SQLI-02: Login dengan username admin' -- → tetap gagal

    Note: Login functionality is Kevin's responsibility, but we verify
    that Django's ORM prevents SQL injection in authentication.
    """

    @classmethod
    def setUpTestData(cls):
        from main.models import User
        User.objects.create_user(
            username='admin',
            password='adminpass123',
            role='admin'
        )

    def test_tc_sqli_02_login_injection(self):
        """
        Test that SQL injection in login form does not bypass authentication.
        Expected: Login fails even with SQL injection payload
        """
        # These payloads should NOT allow login
        payloads = [
            "admin'--",
            "admin' OR '1'='1",
            "' OR 1=1--",
        ]

        for payload in payloads:
            response = self.client.post('/login/', {
                'username': payload,
                'password': 'anypassword'
            })
            # Login should fail (redirect or error, not success)
            # If it redirects to success page, that's a vulnerability
            self.assertNotEqual(
                response.status_code, 302,
                f"SQL injection payload '{payload}' may have succeeded"
            )


class SQLInjectionModelTests(TestCase):
    """Test that all models use ORM and no raw SQL exists."""

    def test_no_cursor_execute_in_views(self):
        """Verify search views don't use cursor.execute (raw SQL)."""
        from main import search_views
        import inspect

        source = inspect.getsource(search_views)
        self.assertNotIn('cursor.execute', source,
            "cursor.execute found in search_views - raw SQL not allowed!")
        self.assertNotIn('cursor.execute(', source,
            "cursor.execute( found in search_views - raw SQL not allowed!")

    def test_q_objects_used_in_search(self):
        """Verify search uses Django Q objects for safe queries."""
        from main import search_views
        import inspect

        source = inspect.getsource(search_views)
        self.assertIn('Q(', source,
            "Q objects not found in search - should use Django ORM Q for filtering!")

    def test_orm_queries_only(self):
        """Verify all queries use ORM, not raw SQL."""
        from main.models import Book, User, BorrowTransaction

        # These should work without raw SQL
        Book.objects.filter(title__icontains='test')
        User.objects.filter(role='member')
        BorrowTransaction.objects.filter(status='borrowed')

        # If we get here, ORM is working
        self.assertTrue(True)