# Digital Library Management System

**Kelompok: hacker-jangan-menyerang**
**Repo: PKPL26_68_hacker-jangan-menyerang**

Sistem Informasi Perpustakaan Digital dengan fokus pada 4 mitigasi keamanan:
- SQL Injection Prevention
- Broken Authentication Prevention
- CSRF Protection
- Code Injection (XSS) Prevention

---

## Entity Relationship Diagram (ERD)
ERD dapat dilihat di sini:
https://dbdiagram.io/d/69f8c2f6ddb9320fdccf8b33

### Database Schema

| Table | Description |
|-------|-------------|
| `users` | User accounts dengan role (member/librarian/admin), employee_id, membership_number |
| `books` | Book catalog dengan soft delete, status (available/not_available) |
| `categories` | Book categories |
| `borrow_transactions` | Transaction tracking dengan employee_id & membership_number untuk accountability |
| `audit_logs` | Audit trail dengan report_id unique dan generated_date |

### OCL Invariants

| Invariant | Implementation |
|-----------|---------------|
| `ValidStatusIntegrity` | Book.status ∈ {'available', 'not_available'} |
| `ValidTransactionStatus` | BorrowTransaction.status ∈ {'borrowed', 'returned'} |
| `AccountabilityEmployeeTracked` | employee_id NOT NULL |
| `AccountabilityMemberTracked` | membership_number NOT NULL |
| `AccountabilityAuditLogged` | report_id UNIQUE, generated_date NOT NULL |

---

## SQL Injection Prevention (Vincent Valentino Oei)

### Implementation

Search Book menggunakan Django ORM dengan Q objects — **tidak ada raw SQL**.

```python
# VULNERABLE ( DON'T DO THIS )
# query = f"SELECT * FROM books WHERE title LIKE '%{search_term}%'"
# cursor.execute(query)

# SAFE - Using Django ORM Q objects
from django.db.models import Q
books = Book.objects.filter(
    Q(title__icontains=query) |
    Q(author__icontains=query) |
    Q(isbn__icontains=query),
    is_deleted=False,
    status='available'
)
```

### Test Cases

| TC | Description | Expected |
|----|-------------|----------|
| TC-SQLI-01 | Search `' OR '1'='1'--` | Returns 0 results (payload escaped) |
| TC-SQLI-02 | Login `admin' --` | Login fails |
| TC-SQLI-03 | Search `; DROP TABLE book;--` | No effect, table intact |

### Running Tests

```bash
python manage.py test main.tests --verbosity=2
```

**Result:** 8 tests passed

---

## Setup

```bash
# 1. Create virtual environment
python -m venv venv

# 2. Activate
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run migrations
python manage.py migrate

# 5. Seed database
python seed.py

# 6. Run server
python manage.py runserver
```

### Default Users (from seed.py)

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | admin |
| librarian1 | librarian123 | librarian |
| librarian2 | librarian123 | librarian |
| member1 | member123 | member |
| member2 | member123 | member |

---

## Project Structure

```
PKPL26_68_hacker-jangan-menyerang/
├── elibrary/              # Django project settings
├── main/
│   ├── models.py         # User, Book, Category, BorrowTransaction, AuditLog
│   ├── views.py          # Health check endpoint
│   ├── auth_views.py     # Login, logout, register (with rate limiting)
│   ├── search_views.py   # Book list, search, detail (SQL injection safe)
│   ├── member_views.py   # Member dashboard and borrow/return
│   ├── urls.py           # URL routing
│   ├── admin.py          # Admin panel
│   ├── decorators.py     # @role_required decorator
│   ├── forms.py          # LoginForm, RegisterForm
│   ├── tests.py          # All test cases (SQLi, CSRF, Auth, RBAC)
│   └── templates/main/   # HTML templates with 하자메 design
├── docs/
│   └── erd_diagram.md    # ERD documentation
├── assets/images/
│   └── sqli-erd-diagram.png
├── static/css/
│   └── style.css         # 하자메 design system
├── seed.py               # Database seeding
├── requirements.txt
└── db.sqlite3            # SQLite database (committed as per spec)
```

---

## Security Mitigations

| Category | Implementation |
|----------|----------------|
| **SQL Injection** | Django ORM Q objects, no raw SQL |
| **XSS** | Django auto-escape, no `|safe` filters |
| **CSRF** | CsrfViewMiddleware enabled, all forms use `{% csrf_token %}` |
| **Broken Auth** | PBKDF2 password hashing, rate limiting (5 attempts = 15 min lockout) |
| **RBAC** | @role_required decorators for least privilege |
| **Soft Delete** | `is_deleted` flag on Book model |

---

## Broken Authentication Mitigation (Kevin)

### Overview

Authentication system implements multiple security measures to prevent:
- **CWE-287**: Improper Authentication (password hashing, session management)
- **CWE-307**: Brute Force (rate limiting, account lockout)
- **CWE-256**: Plaintext Storage of Password (PBKDF2 hashing)
- **CWE-384**: Session Fixation (session flush on logout)

### Rate Limiting Login Attempts

**Lockout Duration:** 15 minutes after 5 failed attempts

**Before (Vulnerable - No Rate Limiting):**
```python
# VULNERABLE: No protection against brute force
def login_view(request):
    user = authenticate(username=username, password=password)
    if user:
        login(request, user)
        return redirect('dashboard')
    # Always returns same error, no lockout
    messages.error(request, 'Invalid credentials')
```

**After (Mitigated - Rate Limiting with Lockout):**
```python
# SAFE: Rate limiting with 5-attempt lockout (15 minutes)
def login_view(request):
    # Check if locked out first
    if is_locked_out(username):
        messages.error(request, 'Account temporarily locked.')
        return render(request, 'login.html', {'form': form})

    user = authenticate(username=username, password=password)
    if user:
        login(request, user)
        _reset_failed_attempts(username)  # Clear lockout on success
        return redirect('dashboard')

    _record_failed_attempt(username)  # Track failures
    remaining = 5 - get_failure_count(username)
    messages.error(request, f'Invalid credentials. ({remaining} attempts remaining)')
```

### Password Hashing (PBKDF2)

**Before (Vulnerable - Plaintext Storage):**
```python
# VULNERABLE: Password stored in plaintext
def create_user(username, password):
    user = User(username=username, password=password)  # Plaintext!
    user.save()
```

**After (Mitigated - PBKDF2 Default Django):**
```python
# SAFE: Django's set_password uses PBKDF2 by default
def create_user(username, password):
    user = User.objects.create_user(
        username=username,
        password=password  # Automatically hashed with PBKDF2
    )
    # Password field will be: pbkdf2_sha256$iterations$salt$hash
```

**Verification in Database:**
```bash
# Check password hash format in database
sqlite3 db.sqlite3 "SELECT password FROM users WHERE username='admin';"
# Result: pbkdf2_sha256$600000$salt$hash (not plaintext)
```

### Session Management

**Before (Vulnerable - Session Fixation):**
```python
# VULNERABLE: Session ID not regenerated on login
def login_view(request):
    user = authenticate(username=username, password=password)
    if user:
        login(request, user)  # Session ID unchanged - vulnerable!
```

**After (Mitigated - Session Flush):**
```python
# SAFE: Session invalidated on logout
def logout_view(request):
    logout(request)  # Internally calls session.flush()
    # Old session ID cannot be reused
    return redirect('login')

# Session configuration in settings.py:
SESSION_COOKIE_HTTPONLY = True    # Prevent JavaScript access
SESSION_COOKIE_SAMESITE = 'Lax'   # CSRF protection
SESSION_COOKIE_AGE = 3600         # 1 hour expiration
```

### User Role Enforcement (@role_required)

**Decorator Implementation:**
```python
def role_required(*roles):
    """Decorator to restrict view access by user role."""
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('main:login')
            if request.user.role not in roles:
                return HttpResponseForbidden('403 Forbidden')
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator

# Usage:
@role_required('librarian')
def add_book(request):
    # Only librarians can access this view
    ...
```

---

## CSRF Protection & Member Features (Benedictus Lucky Win Ziraluo)

### Overview

Implementasi CSRF (Cross-Site Request Forgery) protection pada seluruh fitur member, serta pencegahan IDOR (Insecure Direct Object Reference) pada akses data transaksi.

**Vulnerability yang dimitigasi:**
- **CWE-352** (Cross-Site Request Forgery): Attacker membuat form di situs lain yang mengirim POST request ke aplikasi atas nama user yang sedang login
- **CWE-639** (Insecure Direct Object Reference): User mengakses data milik user lain dengan memanipulasi ID di URL
- **Repudiation**: User memanipulasi timestamp transaksi untuk menyangkal aktivitas

### 1. CSRF Token pada Semua Form POST

**Before (Vulnerable — Tanpa CSRF Token):**
```html
<!-- VULNERABLE: Form tanpa CSRF token -->
<!-- Attacker bisa buat form ini di situs lain dan submit atas nama korban -->
<form method="post" action="/member/borrow/1/">
    <button type="submit">Borrow Book</button>
</form>
```

**After (Secure — Dengan CSRF Token):**
```html
<!-- SECURE: Django generates unique token per session -->
<!-- CsrfViewMiddleware verifies token sebelum proses request -->
<form method="post" action="/member/borrow/1/">
    {% csrf_token %}
    <!-- Renders: <input type="hidden" name="csrfmiddlewaretoken" value="unique-token"> -->
    <button type="submit">Borrow Book</button>
</form>
```

**Konfigurasi di `settings.py`:**
```python
MIDDLEWARE = [
    ...
    'django.middleware.csrf.CsrfViewMiddleware',  # Aktif — verifikasi setiap POST
    ...
]
```

**Tidak ada `@csrf_exempt` di seluruh project** — semua endpoint POST dilindungi CSRF.

### 2. IDOR Prevention pada Borrow History & Return

**Before (Vulnerable — Tanpa Ownership Check):**
```python
# VULNERABLE: User bisa akses transaksi milik user lain
def return_book(request, transaction_id):
    transaction = get_object_or_404(BorrowTransaction, id=transaction_id)
    # Siapapun yang tahu ID bisa return buku orang lain!
    transaction.status = 'returned'
    transaction.save()

def borrow_history(request, user_id):
    # VULNERABLE: URL pakai user_id → Member A bisa lihat history Member B
    transactions = BorrowTransaction.objects.filter(borrower_id=user_id)
```

**After (Secure — Ownership Check):**
```python
# SECURE: Filter by request.user → hanya bisa akses data sendiri
def return_book(request, transaction_id):
    # Ownership check: hanya borrower yang bisa return
    transaction = get_object_or_404(
        BorrowTransaction,
        id=transaction_id,
        borrower=request.user  # CRITICAL: cegah IDOR
    )
    transaction.return_date = timezone.now()  # Server-side timestamp
    transaction.status = 'returned'
    transaction.save()

def borrow_history(request):
    # SECURE: Tidak ada user_id di URL, selalu pakai request.user
    transactions = BorrowTransaction.objects.filter(
        borrower=request.user  # Ownership check
    )
```

### 3. Server-side Timestamping (Repudiation Mitigation)

```python
# Semua timestamp diisi oleh SERVER, bukan input user
BorrowTransaction.objects.create(
    book=book,
    borrower=request.user,
    membership_number=request.user.membership_number,  # Auto dari profil
    due_date=timezone.now() + timedelta(days=14),       # Server hitung
    status='borrowed'
    # borrow_date: auto_now_add=True → diisi Django saat create
)

# Return: timestamp juga dari server
transaction.return_date = timezone.now()  # Bukan dari request.POST
```

### Fitur Member yang Diimplementasi

| Fitur | URL | Method | CSRF | IDOR Check |
|-------|-----|--------|------|------------|
| Member Dashboard | `/member/` | GET | — | `@role_required('member')` |
| Borrow eBook | `/member/borrow/<id>/` | GET, POST | ✅ `{% csrf_token %}` | Book availability check |
| Return eBook | `/member/return/<id>/` | GET, POST | ✅ `{% csrf_token %}` | ✅ `borrower=request.user` |
| Borrow History | `/member/history/` | GET | — | ✅ `borrower=request.user` |
| Read Online | `/member/read/<id>/` | GET | — | ✅ Active borrow check |

### Test Cases

| TC | Description | Expected | Status |
|----|-------------|----------|--------|
| **TC-CSRF-01** | POST `/member/borrow/<id>/` tanpa CSRF token | 403 Forbidden | ✅ Pass |
| **TC-CSRF-02** | POST dengan CSRF token salah/invalid | 403 Forbidden | ✅ Pass |
| **TC-CSRF-03** | POST dengan CSRF token valid | Borrow berhasil (302 redirect) | ✅ Pass |
| **TC-CSRF-04** | POST `/member/return/<id>/` tanpa CSRF token | 403 Forbidden | ✅ Pass |
| **TC-IDOR-01** | Member A coba return buku Member B | 404 Not Found | ✅ Pass |
| **TC-IDOR-02** | Borrow history hanya tampilkan transaksi sendiri | Member A tidak lihat data Member B | ✅ Pass |
| **TC-BORROW-01** | Borrow buku available | Book status → `not_available` | ✅ Pass |
| **TC-RETURN-01** | Return buku borrowed | Book status → `available`, return_date terisi | ✅ Pass |
| **TC-TIMESTAMP-01** | Verifikasi borrow_date dari server | Timestamp antara before/after request | ✅ Pass |
| **TC-ROLE-01** | Unauthenticated akses `/member/` | Redirect ke login | ✅ Pass |
| **TC-ROLE-02** | Librarian akses `/member/` | 403 Forbidden | ✅ Pass |

### Running Tests

```bash
python manage.py test main.tests -v 2
```

### Screenshot Aplikasi

#### Member Dashboard
<!-- TODO: Tambahkan screenshot member dashboard -->
> 📸 `[Screenshot: Member Dashboard — tampilan grid buku dengan tombol Borrow/Read]`

#### Borrow Confirmation
<!-- TODO: Tambahkan screenshot halaman konfirmasi borrow -->
> 📸 `[Screenshot: Borrow Confirm — form dengan CSRF token visible di view source]`

#### Borrow History
<!-- TODO: Tambahkan screenshot borrow history -->
> 📸 `[Screenshot: Borrow History — tabel riwayat peminjaman milik member]`

#### Return Confirmation
<!-- TODO: Tambahkan screenshot halaman return -->
> 📸 `[Screenshot: Return Confirm — form POST dengan CSRF token]`

#### Read Online
<!-- TODO: Tambahkan screenshot halaman read online -->
> 📸 `[Screenshot: Read Online — halaman baca buku]`

### Screenshot Hasil Test Case

#### TC-CSRF-01: POST tanpa CSRF Token → 403
<!-- TODO: Tambahkan screenshot curl/Postman POST tanpa token → 403 -->
> 📸 `[Screenshot: curl -X POST /member/borrow/1/ tanpa CSRF token → 403 Forbidden]`

#### TC-CSRF-03: POST dengan CSRF Token Valid → Sukses
<!-- TODO: Tambahkan screenshot borrow berhasil -->
> 📸 `[Screenshot: Borrow berhasil dengan CSRF token valid → redirect ke history]`

#### TC-IDOR-01: Member A Return Buku Member B → 404
<!-- TODO: Tambahkan screenshot IDOR test -->
> 📸 `[Screenshot: Member A coba return buku Member B → 404 Not Found]`

#### TC-CSRF & TC-IDOR Test Output
<!-- TODO: Tambahkan screenshot output python manage.py test -->
> 📸 `[Screenshot: Output terminal — semua TC-CSRF dan TC-IDOR pass]`

---

## CWE References

| CWE | Name | Mitigation Implemented |
|-----|------|------------------------|
| **CWE-89** | SQL Injection | Django ORM Q objects, no raw SQL |
| **CWE-79** | XSS (Code Injection) | Django auto-escape, allowlist validation |
| **CWE-352** | CSRF | CsrfViewMiddleware, {% csrf_token %} in forms |
| **CWE-287** | Broken Authentication | PBKDF2 hashing, session management |
| **CWE-307** | Brute Force | Rate limiting (5 attempts = 15 min lockout) |
| **CWE-256** | Plaintext Storage | Django's default PBKDF2 password hasher |
| **CWE-384** | Session Fixation | session.flush() on logout, secure cookies |
| **CWE-639** | IDOR (Insecure Direct Object Reference) | Ownership check `borrower=request.user` pada return & history |