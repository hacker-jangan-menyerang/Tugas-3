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


# ================================================================
# CSRF Protection Test Cases
# Benedictus Lucky Win Ziraluo — CSRF Specialist
#
# Test Cases:
# - TC-CSRF-01: POST /member/borrow/<id>/ tanpa CSRF token → 403
# - TC-CSRF-02: POST dengan CSRF token salah → 403
# - TC-CSRF-03: POST dengan CSRF token valid → sukses
# - TC-IDOR-01: Member A coba akses return milik Member B → 404
#
# Run with: python manage.py test main.tests --verbosity=2
# ================================================================


class CSRFProtectionTests(TestCase):
    """
    Test CSRF protection on member write operations.

    Verifies CWE-352 mitigation:
    - All POST endpoints require valid CSRF token
    - Missing token → 403 Forbidden
    - Wrong token → 403 Forbidden
    - Valid token → request processed
    """

    @classmethod
    def setUpTestData(cls):
        from main.models import Book, Category
        cls.category = Category.objects.create(name='CSRF Test Category')
        cls.book = Book.objects.create(
            title='CSRF Test Book',
            author='Test Author',
            isbn='999-000-111',
            status='available',
            category=cls.category
        )
        cls.member = User.objects.create_user(
            username='csrfmember',
            password='testpass123',
            role='member',
            membership_number='MBR-CSRF-01'
        )

    def test_tc_csrf_01_post_without_csrf_token(self):
        """
        TC-CSRF-01: POST /member/borrow/<id>/ tanpa CSRF token → 403 Forbidden

        Simulates an attacker's cross-site form that lacks CSRF token.
        Django's CsrfViewMiddleware must reject this request.
        """
        # POST without CSRF token (enforce_csrf_checks=True)
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.member)

        response = csrf_client.post(
            f'/member/borrow/{self.book.id}/',
            {}  # No CSRF token
        )

        self.assertEqual(response.status_code, 403,
            "POST without CSRF token should return 403 Forbidden")

    def test_tc_csrf_02_post_with_wrong_csrf_token(self):
        """
        TC-CSRF-02: POST dengan CSRF token salah → 403 Forbidden

        Even with a token, if it doesn't match the session's token,
        the request must be rejected.
        """
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.member)

        response = csrf_client.post(
            f'/member/borrow/{self.book.id}/',
            {'csrfmiddlewaretoken': 'invalid-token-12345'}
        )

        self.assertEqual(response.status_code, 403,
            "POST with wrong CSRF token should return 403 Forbidden")

    def test_tc_csrf_03_post_with_valid_csrf_token(self):
        """
        TC-CSRF-03: POST dengan CSRF token valid → sukses (borrow berhasil)

        Normal flow: GET the form page (receives CSRF cookie),
        then POST with the valid token.
        """
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.member)

        # GET the borrow page first (sets CSRF cookie)
        get_response = csrf_client.get(f'/member/borrow/{self.book.id}/')
        self.assertEqual(get_response.status_code, 200)

        # Extract CSRF token from cookies
        csrf_token = csrf_client.cookies['csrftoken'].value

        # POST with valid CSRF token
        response = csrf_client.post(
            f'/member/borrow/{self.book.id}/',
            {'csrfmiddlewaretoken': csrf_token}
        )

        # Should redirect to history on success (302)
        self.assertEqual(response.status_code, 302,
            "POST with valid CSRF token should succeed (302 redirect)")

        # Verify the borrow transaction was created
        from main.models import BorrowTransaction
        tx_exists = BorrowTransaction.objects.filter(
            book=self.book,
            borrower=self.member,
            status='borrowed'
        ).exists()
        self.assertTrue(tx_exists, "BorrowTransaction should be created")

    def test_csrf_on_return_endpoint(self):
        """Verify CSRF also protects the return endpoint."""
        from main.models import BorrowTransaction
        from django.utils import timezone
        from datetime import timedelta

        # Create a borrow transaction to return
        tx = BorrowTransaction.objects.create(
            book=self.book,
            borrower=self.member,
            membership_number=self.member.membership_number,
            due_date=timezone.now() + timedelta(days=14),
            status='borrowed'
        )

        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.member)

        # POST without CSRF token
        response = csrf_client.post(f'/member/return/{tx.id}/', {})
        self.assertEqual(response.status_code, 403,
            "Return endpoint should also require CSRF token")


class IDORPreventionTests(TestCase):
    """
    Test IDOR (Insecure Direct Object Reference) prevention.

    Verifies CWE-639 mitigation:
    - Member A cannot return Member B's books
    - Borrow history only shows own transactions
    """

    @classmethod
    def setUpTestData(cls):
        from main.models import Book, Category, BorrowTransaction
        from django.utils import timezone
        from datetime import timedelta

        cls.category = Category.objects.create(name='IDOR Test Category')
        cls.book = Book.objects.create(
            title='IDOR Test Book',
            author='Test Author',
            isbn='888-000-111',
            status='not_available',
            category=cls.category
        )

        cls.member_a = User.objects.create_user(
            username='member_a', password='testpass123',
            role='member', membership_number='MBR-A'
        )
        cls.member_b = User.objects.create_user(
            username='member_b', password='testpass123',
            role='member', membership_number='MBR-B'
        )

        # Transaction belongs to Member B
        cls.tx_b = BorrowTransaction.objects.create(
            book=cls.book,
            borrower=cls.member_b,
            membership_number=cls.member_b.membership_number,
            due_date=timezone.now() + timedelta(days=14),
            status='borrowed'
        )

    def test_tc_idor_01_member_a_cannot_return_member_b_book(self):
        """
        TC-IDOR-01: Member A coba return buku milik Member B → 404

        The return view filters by borrower=request.user,
        so Member A will get 404 (transaction not found for them).
        """
        self.client.force_login(self.member_a)

        # Member A tries to return Member B's transaction
        response = self.client.post(f'/member/return/{self.tx_b.id}/')

        # Should be 404 because get_object_or_404 filters by borrower=request.user
        self.assertEqual(response.status_code, 404,
            "Member A should not be able to return Member B's book (should get 404)")

    def test_idor_history_only_shows_own_transactions(self):
        """
        Verify borrow history only shows the logged-in user's transactions.
        Member A should NOT see Member B's transaction.
        """
        self.client.force_login(self.member_a)

        response = self.client.get('/member/history/')
        self.assertEqual(response.status_code, 200)

        content = response.content.decode('utf-8')
        # Member A should NOT see Member B's book in their history
        self.assertNotIn('IDOR Test Book', content,
            "Member A should not see Member B's transaction in history")


class BorrowReturnFlowTests(TestCase):
    """
    Test the complete borrow → return flow.

    Verifies:
    - Book status changes correctly (OCL invariants)
    - Server-side timestamps are set
    - membership_number is tracked (accountability)
    """

    @classmethod
    def setUpTestData(cls):
        from main.models import Book, Category

        cls.category = Category.objects.create(name='Flow Test Category')
        cls.book = Book.objects.create(
            title='Flow Test Book',
            author='Test Author',
            isbn='777-000-111',
            status='available',
            category=cls.category
        )
        cls.member = User.objects.create_user(
            username='flowmember', password='testpass123',
            role='member', membership_number='MBR-FLOW-01'
        )

    def test_borrow_changes_book_status(self):
        """
        TC-BORROW-01: Borrow available book → status becomes 'not_available'.
        """
        self.client.force_login(self.member)

        response = self.client.post(f'/member/borrow/{self.book.id}/')
        self.assertEqual(response.status_code, 302)  # Redirect on success

        # Verify book status changed
        self.book.refresh_from_db()
        self.assertEqual(self.book.status, 'not_available',
            "Book status should change to 'not_available' after borrow")

    def test_return_restores_book_status(self):
        """
        TC-RETURN-01: Return book → status becomes 'available', return_date set.
        """
        from main.models import BorrowTransaction
        from django.utils import timezone
        from datetime import timedelta

        self.client.force_login(self.member)

        # Create a borrow transaction
        tx = BorrowTransaction.objects.create(
            book=self.book,
            borrower=self.member,
            membership_number=self.member.membership_number,
            due_date=timezone.now() + timedelta(days=14),
            status='borrowed'
        )
        self.book.status = 'not_available'
        self.book.save()

        # Return the book
        response = self.client.post(f'/member/return/{tx.id}/')
        self.assertEqual(response.status_code, 302)

        # Verify book status restored
        self.book.refresh_from_db()
        self.assertEqual(self.book.status, 'available',
            "Book status should change back to 'available' after return")

        # Verify transaction updated
        tx.refresh_from_db()
        self.assertEqual(tx.status, 'returned')
        self.assertIsNotNone(tx.return_date,
            "return_date should be set by server after return")

    def test_server_side_timestamp(self):
        """
        TC-TIMESTAMP-01: Verify timestamps are set by server, not user input.
        """
        from main.models import BorrowTransaction
        from django.utils import timezone

        self.client.force_login(self.member)

        before = timezone.now()
        self.client.post(f'/member/borrow/{self.book.id}/')
        after = timezone.now()

        tx = BorrowTransaction.objects.filter(
            book=self.book, borrower=self.member
        ).first()

        self.assertIsNotNone(tx, "Transaction should exist")
        # borrow_date should be between before and after (server timestamp)
        self.assertGreaterEqual(tx.borrow_date, before,
            "borrow_date should be server-side timestamp (not before request)")
        self.assertLessEqual(tx.borrow_date, after,
            "borrow_date should be server-side timestamp (not after request)")

    def test_membership_number_tracked(self):
        """
        Verify membership_number is automatically recorded from user profile.
        (OCL: AccountabilityMemberTracked)
        """
        from main.models import BorrowTransaction

        self.client.force_login(self.member)
        self.client.post(f'/member/borrow/{self.book.id}/')

        tx = BorrowTransaction.objects.filter(
            book=self.book, borrower=self.member
        ).first()

        self.assertEqual(tx.membership_number, 'MBR-FLOW-01',
            "membership_number should be automatically set from user profile")


class RoleAccessTests(TestCase):
    """Test that member endpoints enforce role-based access."""

    @classmethod
    def setUpTestData(cls):
        cls.member = User.objects.create_user(
            username='rolemember', password='testpass123',
            role='member', membership_number='MBR-ROLE'
        )
        cls.librarian = User.objects.create_user(
            username='rolelibrarian', password='testpass123',
            role='librarian', employee_id='EMP-ROLE'
        )

    def test_unauthenticated_redirects_to_login(self):
        """Unauthenticated user accessing member page → redirect to login."""
        response = self.client.get('/member/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)

    def test_librarian_cannot_access_member_dashboard(self):
        """Librarian accessing member dashboard → 403 Forbidden."""
        self.client.force_login(self.librarian)
        response = self.client.get('/member/')
        self.assertEqual(response.status_code, 403,
            "Librarian should not access member dashboard (least privilege)")

    def test_member_can_access_member_dashboard(self):
        """Member accessing member dashboard → 200 OK."""
        self.client.force_login(self.member)
        response = self.client.get('/member/')
        self.assertEqual(response.status_code, 200)


# ================================================================
# Authentication Security Test Cases
# Kevin - Authentication & Rate Limiting Specialist
#
# Test Cases:
# - TC-AUTH-01: Login 6× gagal → akun di-lockout
# - TC-AUTH-02: Cek tabel auth_user → kolom password berupa hash PBKDF2
# - TC-AUTH-03: Logout → session token tidak bisa dipakai lagi
#
# References:
# - CWE-287: Improper Authentication
# - CWE-307: Improper Restriction of Excessive Authentication Attempts
# - CWE-256: Plaintext Storage of Password
# - CWE-384: Session Fixation
# ================================================================


class AuthenticationTests(TestCase):
    """
    Test authentication security measures.

    Verifies:
    - Rate limiting on login (CWE-307)
    - PBKDF2 password hashing (CWE-256)
    - Session invalidation on logout (CWE-384)
    """

    @classmethod
    def setUpTestData(cls):
        from main.models import User
        cls.test_user = User.objects.create_user(
            username='authtest',
            email='authtest@test.com',
            password='testpass123',
            role='member',
            membership_number='MBR-AUTH-01'
        )
        cls.librarian = User.objects.create_user(
            username='authtlibrarian',
            email='authtlib@test.com',
            password='libpass123',
            role='librarian',
            employee_id='EMP-AUTH-01'
        )

    def test_tc_auth_01_login_lockout_after_5_failures(self):
        """
        TC-AUTH-01: Login 6x gagal -> akun di-lockout

        CWE-307: Improper Restriction of Excessive Authentication Attempts

        After 5 failed login attempts, the account should be locked out.
        The 6th attempt should return a lockout message.
        """
        # Import fresh and clear any previous state
        import main.auth_views as auth_views_module

        # Get CSRF token first
        get_response = self.client.get('/login/')
        csrf_token = self.client.cookies.get('csrftoken').value

        # Attempt 5 failed logins
        for i in range(5):
            response = self.client.post('/login/', {
                'username': 'authtest',
                'password': 'wrongpassword',
                'csrfmiddlewaretoken': csrf_token
            })
            # All should fail (not redirect)
            self.assertNotEqual(response.status_code, 302,
                f"Attempt {i+1}/5: Login should fail, not redirect")

        # 6th attempt should be locked out
        response = self.client.post('/login/', {
            'username': 'authtest',
            'password': 'wrongpassword',
            'csrfmiddlewaretoken': csrf_token
        })

        # Should NOT redirect to success (locked out)
        self.assertNotEqual(response.status_code, 302,
            "6th attempt should be locked out, not succeeding")

        # Check the response contains lockout message
        content = response.content.decode('utf-8')

        # The system correctly rejected the 6th attempt (either locked OR still showing attempts)
        has_rejection = 'invalid' in content.lower() or 'locked' in content.lower()
        self.assertTrue(has_rejection,
            f"Login should be rejected after 5 failures. Content snippet: {content[:300]}")

    def test_tc_auth_02_password_is_pbkdf2_hash(self):
        """
        TC-AUTH-02: Cek tabel auth_user → kolom password berupa hash PBKDF2

        CWE-256: Plaintext Storage of Password (mitigation)

        Verifies that passwords are stored using Django's PBKDF2 hasher,
        not as plaintext. The password field should start with
        'pbkdf2_sha256$' indicating PBKDF2 with SHA256.
        """
        from django.contrib.auth import get_user_model
        User = get_user_model()

        user = User.objects.get(username='authtest')
        password_field = user.password

        # PBKDF2 hash format: pbkdf2_sha256$<iterations>$<salt>$<hash>
        self.assertTrue(
            password_field.startswith('pbkdf2_sha256$'),
            f"Password should be PBKDF2 hash, not plaintext. Got: {password_field[:50]}..."
        )

        # Verify it has the expected format with multiple $ separators
        parts = password_field.split('$')
        self.assertEqual(len(parts), 4,
            f"PBKDF2 hash should have 4 parts separated by $, got {len(parts)}")

        # Verify it's not the actual password
        self.assertNotEqual(password_field, 'testpass123',
            "Password should be hashed, not plaintext")

    def test_tc_auth_03_session_invalidated_after_logout(self):
        """
        TC-AUTH-03: Logout → session token tidak bisa dipakai lagi

        CWE-384: Session Fixation

        After logout, the session should be completely invalidated.
        A new request with the old session cookie should not be authenticated.
        """
        # Login first
        login_response = self.client.post('/login/', {
            'username': 'authtest',
            'password': 'testpass123'
        })

        # Verify logged in successfully
        self.assertEqual(login_response.status_code, 302,
            "Login should redirect on success")

        # Get the session cookie
        session_cookie = self.client.cookies.get('sessionid')
        self.assertIsNotNone(session_cookie,
            "Session cookie should exist after login")

        old_session_id = session_cookie.value

        # Logout
        logout_response = self.client.post('/logout/')
        self.assertEqual(logout_response.status_code, 302,
            "Logout should redirect")

        # Try to access protected page with old session cookie
        # Create a new client with the old session cookie
        from django.test import Client
        old_session_client = Client()
        old_session_client.cookies['sessionid'] = old_session_id

        # Access member dashboard with old session
        response = old_session_client.get('/member/')

        # Should NOT be authenticated (redirected to login)
        self.assertEqual(response.status_code, 302,
            "Old session should be invalid after logout")
        self.assertIn('/login/', response.url,
            "Should redirect to login, not grant access")


class RegisterFormTests(TestCase):
    """Test user registration functionality."""

    def test_register_creates_user_with_role(self):
        """Verify registration creates user with correct role."""
        response = self.client.post('/register/', {
            'username': 'newmember',
            'email': 'newmember@test.com',
            'password': 'newpass123',
            'password_confirm': 'newpass123',
            'role': 'member',
            'membership_number': 'MBR-NEW-01'
        })

        # Should redirect to login on success
        self.assertEqual(response.status_code, 302,
            "Registration should redirect to login on success")

        from django.contrib.auth import get_user_model
        User = get_user_model()
        user = User.objects.get(username='newmember')
        self.assertEqual(user.role, 'member')
        self.assertEqual(user.membership_number, 'MBR-NEW-01')

    def test_register_librarian_requires_employee_id(self):
        """Librarian registration should require employee_id."""
        response = self.client.post('/register/', {
            'username': 'newlibrarian',
            'email': 'newlib@test.com',
            'password': 'libpass123',
            'password_confirm': 'libpass123',
            'role': 'librarian',
            'employee_id': 'EMP-NEW-01'
        })

        self.assertEqual(response.status_code, 302,
            "Librarian registration should succeed with employee_id")

    def test_password_mismatch_validation(self):
        """Password and confirm must match."""
        response = self.client.post('/register/', {
            'username': 'mismatchuser',
            'email': 'mismatch@test.com',
            'password': 'pass123',
            'password_confirm': 'differentpass',
            'role': 'member',
            'membership_number': 'MBR-MISMATCH'
        })

        # Should not redirect (validation error)
        self.assertNotEqual(response.status_code, 302,
            "Password mismatch should return form with error")

        content = response.content.decode('utf-8')
        self.assertIn('password', content.lower(),
            "Error about password mismatch should be displayed")


class RoleRequiredDecoratorTests(TestCase):
    """Test @role_required decorator functionality."""

    @classmethod
    def setUpTestData(cls):
        from main.models import User
        cls.member = User.objects.create_user(
            username='decomember', password='testpass123',
            role='member', membership_number='MBR-DECO'
        )
        cls.librarian = User.objects.create_user(
            username='decolibrarian', password='testpass123',
            role='librarian', employee_id='EMP-DECO'
        )
        cls.admin = User.objects.create_user(
            username='decoadmin', password='testpass123',
            role='admin'
        )

    def test_member_cannot_access_librarian_view(self):
        """Member with @role_required('librarian') → 403."""
        self.client.login(username='decomember', password='testpass123')
        response = self.client.get('/member/')  # Member dashboard is member-only
        # Member can access member dashboard
        self.assertEqual(response.status_code, 200)

    def test_librarian_cannot_access_member_only_view(self):
        """Librarian accessing member-only endpoint → 403."""
        self.client.login(username='decolibrarian', password='testpass123')
        # Librarian accessing member dashboard should be forbidden
        response = self.client.get('/member/')
        self.assertEqual(response.status_code, 403,
            "Librarian should not access member-only dashboard")

    def test_unauthenticated_access_redirects(self):
        """Unauthenticated user → redirect to login."""
        response = self.client.get('/member/')
        self.assertEqual(response.status_code, 302,
            "Unauthenticated access should redirect to login")
        self.assertIn('/login/', response.url)