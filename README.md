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
│   ├── search_views.py   # Book list, search, detail (SQL injection safe)
│   ├── urls.py           # URL routing
│   ├── admin.py          # Admin panel
│   ├── tests.py          # 8 SQL injection test cases
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
| **XSS** | Django auto-escape, no `\|safe` filters |
| **CSRF** | CsrfViewMiddleware enabled, all forms use `{% csrf_token %}` |
| **Broken Auth** | PBKDF2 password hashing, rate limiting via django-axes (Kevin) |
| **RBAC** | @role_required decorators (Kevin) |
| **Soft Delete** | `is_deleted` flag on Book model |

---

## CWE References

- **CWE-89**: SQL Injection
- **CWE-79**: XSS (Code Injection)
- **CWE-352**: CSRF
- **CWE-287**: Broken Authentication
- **CWE-307**: Brute Force
- **CWE-256**: Plaintext Storage
- **CWE-384**: Session Fixation