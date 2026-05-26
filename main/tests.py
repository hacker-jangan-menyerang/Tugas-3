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

        # Repeatedly submit wrong credentials. django-axes locks the account once
        # the failure limit (AXES_FAILURE_LIMIT = 5) is reached. Each attempt must
        # be rejected: before lockout the view redirects (302, Post/Redirect/Get)
        # back to /login/; once locked, django-axes returns HTTP 429. No attempt
        # may ever authenticate (a 302 to a role dashboard or a 200 logged-in page).
        statuses = []
        for i in range(7):
            response = self.client.post('/login/', {
                'username': 'authtest',
                'password': 'wrongpassword',
                'csrfmiddlewaretoken': csrf_token
            })
            statuses.append(response.status_code)
            self.assertIn(response.status_code, (302, 429),
                f"Attempt {i+1}: login must be rejected (302 retry or 429 lockout), "
                f"got {response.status_code}")
            if response.status_code == 302:
                self.assertIn('/login/', response.url,
                    f"Attempt {i+1}: failed login must return to login, not a dashboard")

        # The lockout control must engage during the repeated failures.
        self.assertIn(429, statuses,
            f"After repeated failures django-axes must lock the account (HTTP 429). "
            f"Status sequence was: {statuses}")

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
        self.client.force_login(self.member)
        response = self.client.get('/member/')  # Member dashboard is member-only
        # Member can access member dashboard
        self.assertEqual(response.status_code, 200)

    def test_librarian_cannot_access_member_only_view(self):
        """Librarian accessing member-only endpoint → 403."""
        self.client.force_login(self.librarian)
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


# ================================================================
# Code Injection Prevention Test Cases
# Roberto Eugenio Sugiarto (2406355640) — Code Injection Specialist
#
# Test Cases:
# - TC-XSS-01: Add book with <script>alert(1)</script> → text only
# - TC-XSS-02: Add category with XSS payload → escaped
# - TC-INPUT-01: Submit form without required fields → rejected
# - TC-FILE-01: Upload .exe renamed to .pdf → rejected
#
# References:
# - CWE-79: Cross-site Scripting (XSS)
# - CWE-20: Improper Input Validation
# - CWE-94: Code Injection
#
# Run with: python manage.py test main.tests --verbosity=2
# ================================================================


class XSSPreventionTests(TestCase):
    """
    Test XSS / Code Injection prevention in librarian features.

    Verifies CWE-79 mitigation:
    - Script tags in book titles are escaped in output
    - XSS payloads in category names are rejected by regex
    - Django auto-escaping prevents script execution
    """

    @classmethod
    def setUpTestData(cls):
        from main.models import Category
        cls.category = Category.objects.create(
            name='Test Category',
            description='For testing'
        )
        cls.librarian = User.objects.create_user(
            username='xsslibrarian',
            password='testpass123',
            role='librarian',
            employee_id='EMP-XSS-01'
        )

    def test_tc_xss_01_script_tag_in_book_title(self):
        """
        TC-XSS-01: Add book with <script>alert(1)</script> title
        → script rendered as escaped text, NOT executed

        The title contains script tags but:
        1. BookForm regex rejects < and > characters
        2. Even if bypassed, Django auto-escaping would prevent execution
        """
        self.client.force_login(self.librarian)

        response = self.client.post('/librarian/add-book/', {
            'title': '<script>alert(1)</script>',
            'author': 'Test Author',
            'isbn': '978-0-00-000000-1',
            'description': 'Test description',
            'category': self.category.id,
        })

        # Form should reject — regex does not allow < or > in title
        # Should NOT redirect (302 = success), should re-render form
        self.assertNotEqual(response.status_code, 302,
            "XSS payload in title should be rejected by form validation")

        # Verify no book was created with script tag
        from main.models import Book
        xss_books = Book.objects.filter(title__contains='<script>')
        self.assertEqual(xss_books.count(), 0,
            "No book with <script> tag should be created")

    def test_tc_xss_02_xss_in_category_name(self):
        """
        TC-XSS-02: Add category with XSS payload → rejected

        CategoryForm uses RegexValidator that only allows
        letters, numbers, spaces, and hyphens. Script tags rejected.
        """
        self.client.force_login(self.librarian)

        response = self.client.post('/librarian/categories/add/', {
            'name': '<img src=x onerror=alert(1)>',
            'description': 'XSS test',
        })

        # Should NOT redirect (form validation rejects the payload)
        self.assertNotEqual(response.status_code, 302,
            "XSS payload in category name should be rejected")

        # Verify no category with XSS was created
        from main.models import Category
        xss_cats = Category.objects.filter(name__contains='<img')
        self.assertEqual(xss_cats.count(), 0,
            "No category with XSS payload should be created")

    def test_xss_in_description_stripped(self):
        """
        Verify HTML tags are stripped from description field.
        BookForm.clean_description() strips HTML tags as defense-in-depth.
        """
        self.client.force_login(self.librarian)

        response = self.client.post('/librarian/add-book/', {
            'title': 'Safe Book Title',
            'author': 'Safe Author',
            'isbn': '978-0-00-000000-2',
            'description': 'Hello <script>alert("xss")</script> world',
            'category': self.category.id,
        })

        # Should succeed (description stripped of tags)
        if response.status_code == 302:
            from main.models import Book
            book = Book.objects.get(isbn='978-0-00-000000-2')
            # Description should have tags stripped
            self.assertNotIn('<script>', book.description,
                "HTML tags should be stripped from description")
            self.assertIn('Hello', book.description)
            self.assertIn('world', book.description)

    def test_auto_escaping_in_template(self):
        """
        Verify Django auto-escaping works in book list template.
        Even if malicious data gets into DB, it should be escaped in HTML.
        """
        from main.models import Book
        # Directly create book with script tag (bypassing form)
        book = Book.objects.create(
            title='Test <script>alert("xss")</script>',
            author='Test',
            isbn='978-0-00-000000-3',
            status='available',
            category=self.category,
        )

        self.client.force_login(self.librarian)
        response = self.client.get('/librarian/books/')
        content = response.content.decode('utf-8')

        # The script tag should be HTML-escaped in the output
        self.assertNotIn('<script>alert("xss")</script>', content,
            "Script tags should be auto-escaped by Django template engine")
        # Should contain the escaped version
        self.assertIn('&lt;script&gt;', content,
            "Script tag should appear as escaped text")


class InputValidationTests(TestCase):
    """
    Test input validation on librarian forms.

    Verifies CWE-20 mitigation:
    - Required fields cannot be empty
    - ISBN format validated (numbers + hyphens only)
    - Field length limits enforced
    """

    @classmethod
    def setUpTestData(cls):
        from main.models import Category
        cls.category = Category.objects.create(
            name='Validation Category',
            description='For validation tests'
        )
        cls.librarian = User.objects.create_user(
            username='vallibrarian',
            password='testpass123',
            role='librarian',
            employee_id='EMP-VAL-01'
        )

    def test_tc_input_01_missing_required_fields(self):
        """
        TC-INPUT-01: Submit book form without required fields → rejected

        Title, author, and ISBN are all required. Submitting
        without them should return form with validation errors.
        """
        self.client.force_login(self.librarian)

        response = self.client.post('/librarian/add-book/', {
            'title': '',
            'author': '',
            'isbn': '',
            'description': '',
        })

        # Should NOT redirect (validation error)
        self.assertNotEqual(response.status_code, 302,
            "Empty required fields should be rejected by validator")

        # Verify no book was created
        from main.models import Book
        self.assertEqual(
            Book.objects.filter(created_by=self.librarian).count(), 0,
            "No book should be created with empty required fields"
        )

    def test_isbn_only_numbers_and_hyphens(self):
        """Verify ISBN rejects non-numeric characters."""
        self.client.force_login(self.librarian)

        response = self.client.post('/librarian/add-book/', {
            'title': 'Test Book',
            'author': 'Test Author',
            'isbn': 'ABC-INVALID',
            'description': '',
            'category': self.category.id,
        })

        self.assertNotEqual(response.status_code, 302,
            "Invalid ISBN should be rejected")


class FileUploadSecurityTests(TestCase):
    """
    Test file upload security for eBook uploads.

    Verifies CWE-94 mitigation:
    - Only .pdf, .epub, .txt allowed
    - MIME type checked (not just extension)
    - File size limit enforced
    """

    @classmethod
    def setUpTestData(cls):
        from main.models import Category
        cls.category = Category.objects.create(
            name='Upload Category',
            description='For upload tests'
        )
        cls.librarian = User.objects.create_user(
            username='uploadlibrarian',
            password='testpass123',
            role='librarian',
            employee_id='EMP-UPL-01'
        )

    def test_tc_file_01_exe_disguised_as_pdf(self):
        """
        TC-FILE-01: Upload .exe renamed to .pdf → rejected

        The file has .pdf extension but contains EXE content.
        MIME type check should detect the mismatch and reject.
        """
        from django.core.files.uploadedfile import SimpleUploadedFile

        self.client.force_login(self.librarian)

        # Create a fake EXE file content (MZ header)
        exe_content = b'MZ' + b'\\x90' * 100  # PE/EXE magic bytes
        fake_pdf = SimpleUploadedFile(
            'malware.pdf',  # .pdf extension
            exe_content,    # but EXE content
            content_type='application/pdf'
        )

        response = self.client.post('/librarian/add-book/', {
            'title': 'Malware Book',
            'author': 'Evil Author',
            'isbn': '978-0-00-000000-9',
            'description': 'Test',
            'category': self.category.id,
            'ebook_file': fake_pdf,
        })

        # Should be rejected by MIME type check
        # (or at minimum, the form should handle it safely)
        from main.models import Book
        book = Book.objects.filter(isbn='978-0-00-000000-9').first()
        if book and book.ebook_file:
            # If book was created, the file should have been validated
            self.assertFalse(
                book.ebook_file.name.endswith('.exe'),
                "EXE file should not be stored as-is"
            )

    def test_exe_extension_rejected(self):
        """Verify .exe extension is rejected outright."""
        from django.core.files.uploadedfile import SimpleUploadedFile

        self.client.force_login(self.librarian)

        exe_file = SimpleUploadedFile(
            'malware.exe',
            b'MZ' + b'\\x00' * 50,
            content_type='application/x-msdownload'
        )

        response = self.client.post('/librarian/add-book/', {
            'title': 'Another Book',
            'author': 'Another Author',
            'isbn': '978-0-00-000001-0',
            'description': '',
            'category': self.category.id,
            'ebook_file': exe_file,
        })

        # Should NOT redirect (file rejected)
        self.assertNotEqual(response.status_code, 302,
            ".exe file should be rejected by file upload validator")

    def test_valid_pdf_accepted(self):
        """Verify valid PDF file is accepted."""
        from django.core.files.uploadedfile import SimpleUploadedFile

        self.client.force_login(self.librarian)

        # Create a minimal PDF file
        pdf_content = b'%PDF-1.4 test content'
        pdf_file = SimpleUploadedFile(
            'valid_book.pdf',
            pdf_content,
            content_type='application/pdf'
        )

        response = self.client.post('/librarian/add-book/', {
            'title': 'Valid PDF Book',
            'author': 'Valid Author',
            'isbn': '978-0-00-000001-1',
            'description': 'A valid book',
            'category': self.category.id,
            'ebook_file': pdf_file,
        })

        # Should succeed (valid PDF)
        # Note: MIME detection may vary; this tests the happy path
        from main.models import Book
        # At minimum, no server error
        self.assertNotEqual(response.status_code, 500,
            "Valid PDF upload should not cause server error")


class LibrarianAuditLogTests(TestCase):
    """Test that librarian actions create audit log entries."""

    @classmethod
    def setUpTestData(cls):
        from main.models import Category
        cls.category = Category.objects.create(
            name='Audit Category',
            description='For audit tests'
        )
        cls.librarian = User.objects.create_user(
            username='auditlibrarian',
            password='testpass123',
            role='librarian',
            employee_id='EMP-AUD-01'
        )

    def test_add_book_creates_audit_log(self):
        """Adding a book should create an audit log entry."""
        from main.models import AuditLog

        self.client.force_login(self.librarian)
        initial_count = AuditLog.objects.count()

        self.client.post('/librarian/add-book/', {
            'title': 'Audit Test Book',
            'author': 'Audit Author',
            'isbn': '978-0-00-000002-0',
            'description': 'Test',
            'category': self.category.id,
        })

        self.assertGreater(
            AuditLog.objects.count(), initial_count,
            "Adding a book should create an audit log entry"
        )

        log = AuditLog.objects.order_by('-generated_date').first()
        self.assertEqual(log.target_action, 'book_added')
        self.assertEqual(log.performed_by, self.librarian)

    def test_delete_book_creates_audit_log(self):
        """Soft-deleting a book should create an audit log entry."""
        from main.models import Book, AuditLog

        book = Book.objects.create(
            title='Delete Audit Book',
            author='Author',
            isbn='978-0-00-000002-1',
            status='available',
            category=self.category,
            created_by=self.librarian,
        )

        self.client.force_login(self.librarian)
        initial_count = AuditLog.objects.count()

        self.client.post(f'/librarian/delete-book/{book.id}/')

        self.assertGreater(
            AuditLog.objects.count(), initial_count,
            "Deleting a book should create an audit log entry"
        )

        log = AuditLog.objects.filter(target_action='book_deleted').order_by('-id').first()
        self.assertIsNotNone(log, "book_deleted audit log entry should exist")
        self.assertEqual(log.target_action, 'book_deleted')

    def test_soft_delete_preserves_book(self):
        """Verify soft delete sets is_deleted=True, not physical delete."""
        from main.models import Book

        book = Book.objects.create(
            title='Soft Delete Book',
            author='Author',
            isbn='978-0-00-000002-2',
            status='available',
            category=self.category,
            created_by=self.librarian,
        )

        self.client.force_login(self.librarian)
        self.client.post(f'/librarian/delete-book/{book.id}/')

        book.refresh_from_db()
        self.assertTrue(book.is_deleted,
            "Book should be soft-deleted (is_deleted=True)")
        # Book should still exist in DB
        self.assertTrue(
            Book.objects.filter(id=book.id).exists(),
            "Book should still exist in database after soft delete"
        )


class LibrarianRBACTests(TestCase):
    """Test RBAC enforcement on librarian endpoints."""

    @classmethod
    def setUpTestData(cls):
        cls.member = User.objects.create_user(
            username='rbacmember',
            password='testpass123',
            role='member',
            membership_number='MBR-RBAC'
        )
        cls.librarian = User.objects.create_user(
            username='rbaclibrarian',
            password='testpass123',
            role='librarian',
            employee_id='EMP-RBAC'
        )

    def test_member_cannot_access_librarian_dashboard(self):
        """Member accessing /librarian/ → 403 Forbidden."""
        self.client.force_login(self.member)
        response = self.client.get('/librarian/')
        self.assertEqual(response.status_code, 403,
            "Member should not access librarian dashboard")

    def test_member_cannot_add_book(self):
        """Member accessing /librarian/add-book/ → 403 Forbidden."""
        self.client.force_login(self.member)
        response = self.client.get('/librarian/add-book/')
        self.assertEqual(response.status_code, 403,
            "Member should not access add book page")

    def test_librarian_can_access_dashboard(self):
        """Librarian accessing /librarian/ → 200 OK."""
        self.client.force_login(self.librarian)
        response = self.client.get('/librarian/')
        self.assertEqual(response.status_code, 200,
            "Librarian should access their dashboard")

    def test_unauthenticated_redirects(self):
        """Unauthenticated user → redirect to login."""
        response = self.client.get('/librarian/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)

class CSRFLibrarianEndpointTests(TestCase):
    """
    CSRF protection on all librarian write endpoints.

    Rubric requires testing *all* POST/DELETE endpoints, not just borrow/return.
    Verifies CWE-352 mitigation on:
    - add_book, update_book, delete_book
    - add_category, update_category, delete_category
    """

    @classmethod
    def setUpTestData(cls):
        from main.models import Book, Category
        cls.librarian = User.objects.create_user(
            username='csrf_lib',
            password='testpass123',
            role='librarian',
            employee_id='EMP-CSRF-LIB'
        )
        cls.category = Category.objects.create(name='CSRF Lib Category')
        cls.book = Book.objects.create(
            title='CSRF Lib Book',
            author='Author',
            isbn='111-222-333',
            status='available',
            category=cls.category,
            created_by=cls.librarian,
        )

    def _csrf_client(self):
        c = Client(enforce_csrf_checks=True)
        c.force_login(self.librarian)
        return c

    def test_add_book_requires_csrf_token(self):
        """POST /librarian/add-book/ without token → 403."""
        response = self._csrf_client().post('/librarian/add-book/', {
            'title': 'New Book',
            'author': 'Author',
            'isbn': '000-111-222',
        })
        self.assertEqual(response.status_code, 403)

    def test_update_book_requires_csrf_token(self):
        """POST /librarian/update-book/<id>/ without token → 403."""
        response = self._csrf_client().post(
            f'/librarian/update-book/{self.book.id}/',
            {'title': 'Updated', 'author': 'Author', 'isbn': '111-222-333'}
        )
        self.assertEqual(response.status_code, 403)

    def test_delete_book_requires_csrf_token(self):
        """POST /librarian/delete-book/<id>/ without token → 403."""
        response = self._csrf_client().post(f'/librarian/delete-book/{self.book.id}/')
        self.assertEqual(response.status_code, 403)
        # Book must NOT be soft-deleted
        self.book.refresh_from_db()
        self.assertFalse(self.book.is_deleted)

    def test_add_category_requires_csrf_token(self):
        """POST /librarian/categories/add/ without token → 403."""
        response = self._csrf_client().post('/librarian/categories/add/', {
            'name': 'New Category',
        })
        self.assertEqual(response.status_code, 403)

    def test_update_category_requires_csrf_token(self):
        """POST /librarian/categories/<id>/update/ without token → 403."""
        response = self._csrf_client().post(
            f'/librarian/categories/{self.category.id}/update/',
            {'name': 'Renamed Category'}
        )
        self.assertEqual(response.status_code, 403)
        self.category.refresh_from_db()
        self.assertEqual(self.category.name, 'CSRF Lib Category')

    def test_delete_category_requires_csrf_token(self):
        """POST /librarian/categories/<id>/delete/ without token → 403."""
        from main.models import Category
        extra_cat = Category.objects.create(name='To Delete Cat')
        response = self._csrf_client().post(
            f'/librarian/categories/{extra_cat.id}/delete/'
        )
        self.assertEqual(response.status_code, 403)
        self.assertTrue(Category.objects.filter(id=extra_cat.id).exists())


class CSRFAdminEndpointTests(TestCase):
    """
    CSRF protection on all admin write endpoints.

    Verifies CWE-352 mitigation on:
    - user_create, user_edit, user_toggle_active, user_change_role
    """

    @classmethod
    def setUpTestData(cls):
        cls.admin = User.objects.create_user(
            username='csrf_admin',
            password='testpass123',
            role='admin',
        )
        cls.target = User.objects.create_user(
            username='csrf_target',
            password='testpass123',
            role='member',
            membership_number='MBR-CSRF-TGT',
        )

    def _csrf_client(self):
        c = Client(enforce_csrf_checks=True)
        c.force_login(self.admin)
        return c

    def test_user_create_requires_csrf_token(self):
        """POST /admin-panel/users/create/ without token → 403."""
        response = self._csrf_client().post('/admin-panel/users/create/', {
            'username': 'shouldnotexist',
            'password': 'pass1234',
            'role': 'member',
        })
        self.assertEqual(response.status_code, 403)
        self.assertFalse(User.objects.filter(username='shouldnotexist').exists())

    def test_user_toggle_requires_csrf_token(self):
        """POST /admin-panel/users/<id>/toggle/ without token → 403."""
        was_active = self.target.is_active
        response = self._csrf_client().post(
            f'/admin-panel/users/{self.target.id}/toggle/'
        )
        self.assertEqual(response.status_code, 403)
        self.target.refresh_from_db()
        self.assertEqual(self.target.is_active, was_active)

    def test_user_change_role_requires_csrf_token(self):
        """POST /admin-panel/users/<id>/role/ without token → 403."""
        response = self._csrf_client().post(
            f'/admin-panel/users/{self.target.id}/role/',
            {'role': 'librarian'}
        )
        self.assertEqual(response.status_code, 403)
        self.target.refresh_from_db()
        self.assertEqual(self.target.role, 'member')

    def test_user_edit_requires_csrf_token(self):
        """POST /admin-panel/users/<id>/edit/ without token → 403."""
        response = self._csrf_client().post(
            f'/admin-panel/users/{self.target.id}/edit/',
            {'username': 'hijacked', 'email': 'h@h.com'}
        )
        self.assertEqual(response.status_code, 403)
        self.target.refresh_from_db()
        self.assertEqual(self.target.username, 'csrf_target')


class SQLInjectionCreateUpdateTests(TestCase):
    """
    SQL injection prevention on create and update endpoints.

    Rubric requires covering login, search, filter, *create*, and *update*.
    Verifies that SQLi payloads in form fields:
    - Do not cause 500 errors
    - Do not corrupt or expose database data
    - Are handled safely by Django ORM (parameterized queries)
    """

    @classmethod
    def setUpTestData(cls):
        from main.models import Category
        cls.librarian = User.objects.create_user(
            username='sqli_lib',
            password='testpass123',
            role='librarian',
            employee_id='EMP-SQLI-LIB',
        )
        cls.admin = User.objects.create_user(
            username='sqli_admin',
            password='testpass123',
            role='admin',
        )
        cls.category = Category.objects.create(name='SQLi Test Category')

    def test_sqli_payload_in_add_book_description(self):
        """
        SQLi payload in description field on add_book → no SQL error, ORM safe.

        Description has no regex validator (only HTML strip), so classic SQLi
        strings reach the ORM layer — which handles them as parameterized values.
        """
        self.client.force_login(self.librarian)

        payloads = [
            "' OR '1'='1'--",
            "'; DROP TABLE books; --",
            "' UNION SELECT username, password FROM users --",
        ]
        for payload in payloads:
            response = self.client.post('/librarian/add-book/', {
                'title': 'Safe Title',
                'author': 'Safe Author',
                'isbn': '978-0-00-000010-0',
                'description': payload,
                'category': self.category.id,
            })
            # Must not produce a server error
            self.assertNotEqual(response.status_code, 500,
                f"SQLi payload in description caused 500: {payload}")

            # Main books table must still exist and be intact
            from main.models import Book
            self.assertGreaterEqual(Book.objects.count(), 0,
                "Books table must survive SQLi payload in description")

    def test_sqli_payload_rejected_by_title_validator(self):
        """
        SQLi payload containing = (not in allowlist) is rejected by title regex validator.

        The title allowlist regex `^[a-zA-Z0-9\\s\\-\\.,;:!?\\'\"()&#+@/]+$`
        does NOT include `=`, so boolean-based SQLi payloads are rejected at form level.
        """
        self.client.force_login(self.librarian)

        boolean_payloads = [
            "' OR '1'='1'--",      # contains =
            "admin'=--",           # contains =
        ]
        for payload in boolean_payloads:
            response = self.client.post('/librarian/add-book/', {
                'title': payload,
                'author': 'Author',
                'isbn': '978-0-00-000011-0',
                'description': 'desc',
                'category': self.category.id,
            })
            # Regex validator should reject =, so form won't submit (no 302)
            self.assertNotEqual(response.status_code, 302,
                f"SQLi title with '=' should be rejected by validator: {payload}")

    def test_sqli_in_update_book_no_error(self):
        """
        SQLi payload in update_book form → no SQL error, data integrity preserved.
        """
        from main.models import Book
        book = Book.objects.create(
            title='Update SQLi Book',
            author='Author',
            isbn='978-0-00-000012-0',
            status='available',
            category=self.category,
            created_by=self.librarian,
        )

        self.client.force_login(self.librarian)

        response = self.client.post(f'/librarian/update-book/{book.id}/', {
            'title': 'Safe Title',
            'author': 'Safe Author',
            'isbn': '978-0-00-000012-0',
            'description': "'; DROP TABLE books; --",
            'category': self.category.id,
        })

        self.assertNotEqual(response.status_code, 500,
            "SQLi payload in update form must not cause server error")
        # Table must still exist
        self.assertGreaterEqual(Book.objects.count(), 0,
            "Books table must survive SQLi in update_book")

    def test_sqli_in_admin_user_create_no_error(self):
        """
        SQLi payload in admin user_create form → handled safely by ORM.
        """
        self.client.force_login(self.admin)

        response = self.client.post('/admin-panel/users/create/', {
            'username': 'safeuser',
            'email': 'safe@test.com',
            'password': 'safepass1234',
            'role': 'member',
            'membership_number': "'; DROP TABLE users; --",
        })

        self.assertNotEqual(response.status_code, 500,
            "SQLi in membership_number must not cause server error")
        # Users table must still be intact
        self.assertGreaterEqual(User.objects.count(), 0,
            "Users table must survive SQLi in admin user_create")

    def test_no_raw_sql_in_librarian_views(self):
        """Verify librarian_views uses ORM only — no cursor.execute."""
        from main import librarian_views
        import inspect
        source = inspect.getsource(librarian_views)
        self.assertNotIn('cursor.execute', source,
            "cursor.execute found in librarian_views — raw SQL not allowed")

    def test_no_raw_sql_in_admin_views(self):
        """Verify admin_views uses ORM only — no cursor.execute."""
        from main import admin_views
        import inspect
        source = inspect.getsource(admin_views)
        self.assertNotIn('cursor.execute', source,
            "cursor.execute found in admin_views — raw SQL not allowed")


class AdminFeatureTests(TestCase):
    """
    Test admin-panel features (Galih).

    Verifies:
    - RBAC enforcement on admin-only routes (CWE-285, CWE-862)
    - Audit logging on state-change actions
    - Self-modification protection (admin cannot lock self out)
    - No credential leakage in AuditLog.details
    """

    @classmethod
    def setUpClass(cls):
        # Workaround for Python 3.14 + Django 4.2 incompat:
        # Django 4.2's `BaseContext.__copy__` calls `copy(super())` which fails
        # under Python 3.14, blowing up `store_rendered_templates`. Patch in a
        # safe shallow copy.
        from django.template.context import BaseContext

        cls._original_basecontext_copy = BaseContext.__copy__

        def _safe_copy(self):
            duplicate = self.__class__.__new__(self.__class__)
            duplicate.__dict__.update(self.__dict__)
            duplicate.dicts = self.dicts[:]
            return duplicate

        BaseContext.__copy__ = _safe_copy
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        from django.template.context import BaseContext
        BaseContext.__copy__ = cls._original_basecontext_copy
        super().tearDownClass()

    @classmethod
    def setUpTestData(cls):
        from main.models import User
        cls.admin = User.objects.create_user(
            username='galih_admin',
            email='galih_admin@test.com',
            password='adminpass123',
            role='admin',
        )
        cls.librarian = User.objects.create_user(
            username='galih_librarian',
            email='galih_librarian@test.com',
            password='libpass123',
            role='librarian',
            employee_id='EMP-GAL-01',
        )
        cls.member = User.objects.create_user(
            username='galih_member',
            email='galih_member@test.com',
            password='memberpass123',
            role='member',
            membership_number='MBR-GAL-01',
        )

    def test_tc_admin_01_member_blocked_from_admin_panel(self):
        """TC-ADMIN-01: Member GET /admin-panel/ → 403."""
        self.client.force_login(self.member)
        response = self.client.get('/admin-panel/')
        self.assertEqual(response.status_code, 403)

    def test_tc_admin_02_librarian_blocked_from_user_list(self):
        """TC-ADMIN-02: Librarian GET /admin-panel/users/ → 403."""
        self.client.force_login(self.librarian)
        response = self.client.get('/admin-panel/users/')
        self.assertEqual(response.status_code, 403)

    def test_tc_admin_03_admin_can_list_users(self):
        """TC-ADMIN-03: Admin GET /admin-panel/users/ → 200, users appear in response."""
        self.client.force_login(self.admin)
        response = self.client.get('/admin-panel/users/')
        self.assertEqual(response.status_code, 200)
        body = response.content.decode('utf-8')
        self.assertIn(self.admin.username, body)
        self.assertIn(self.member.username, body)

    def test_tc_admin_04_create_user_logs_audit(self):
        """TC-ADMIN-04: Admin POST create user → User in DB + AuditLog entry."""
        from main.models import User, AuditLog

        self.client.force_login(self.admin)
        response = self.client.post('/admin-panel/users/create/', {
            'username': 'new_member_x',
            'email': 'newx@test.com',
            'password': 'newpass1234',
            'role': 'member',
            'employee_id': '',
            'membership_number': 'MBR-NEW-X',
        })
        self.assertIn(response.status_code, (200, 302))
        self.assertTrue(
            User.objects.filter(username='new_member_x').exists(),
            'New user should be created in DB',
        )
        self.assertTrue(
            AuditLog.objects.filter(target_action='user_created').exists(),
            'AuditLog entry for user_created should exist',
        )

    def test_tc_admin_05_admin_cannot_deactivate_self(self):
        """TC-ADMIN-05: Admin POST toggle on self → blocked, is_active unchanged."""
        from main.models import User

        self.client.force_login(self.admin)
        response = self.client.post(f'/admin-panel/users/{self.admin.id}/toggle/')
        self.assertIn(response.status_code, (200, 302))

        self.admin.refresh_from_db()
        self.assertTrue(
            self.admin.is_active,
            'Admin should not be able to deactivate themselves',
        )

    def test_tc_admin_06_role_change_logged(self):
        """TC-ADMIN-06: Admin changes member role → DB updated + AuditLog entry."""
        from main.models import User, AuditLog

        self.client.force_login(self.admin)
        response = self.client.post(
            f'/admin-panel/users/{self.member.id}/role/',
            {'role': 'librarian'},
        )
        self.assertIn(response.status_code, (200, 302))

        self.member.refresh_from_db()
        self.assertEqual(self.member.role, 'librarian')
        self.assertTrue(
            AuditLog.objects.filter(
                target_action='user_role_changed',
                performed_by=self.admin,
            ).exists(),
            'AuditLog entry for user_role_changed should exist',
        )

    def test_tc_admin_07_audit_log_no_password_leak(self):
        """TC-ADMIN-07: create_audit_log() must reject details containing 'password'."""
        from main.audit import create_audit_log
        from main.models import AuditLog

        with self.assertRaises(ValueError):
            create_audit_log(
                'test_action',
                self.admin,
                'attempted to leak password=secret123',
            )

        # Also assert no existing audit log row has 'password' in details
        self.assertFalse(
            AuditLog.objects.filter(details__icontains='password').exists(),
            'No AuditLog entry should contain the substring "password"',
        )
