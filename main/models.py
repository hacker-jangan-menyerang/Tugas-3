from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.validators import RegexValidator


class User(AbstractUser):
    """Custom user model with role-based access."""

    class Role(models.TextChoices):
        MEMBER = 'member', 'Member'
        LIBRARIAN = 'librarian', 'Librarian'
        ADMIN = 'admin', 'Admin'

    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.MEMBER
    )
    employee_id = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        help_text="Employee ID for Librarian role"
    )
    membership_number = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        help_text="Membership number for Member role"
    )

    class Meta:
        db_table = 'users'

    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"


class Category(models.Model):
    """Book category model."""

    name = models.CharField(
        max_length=100,
        validators=[RegexValidator(
            regex=r'^[a-zA-Z0-9\s\-]+$',
            message='Category name can only contain letters, numbers, spaces, and hyphens'
        )]
    )
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'categories'
        verbose_name_plural = 'Categories'

    def __str__(self):
        return self.name


class Book(models.Model):
    """Book model with soft delete support."""

    class Status(models.TextChoices):
        AVAILABLE = 'available', 'Available'
        NOT_AVAILABLE = 'not_available', 'Not Available'

    title = models.CharField(max_length=255)
    author = models.CharField(max_length=255)
    isbn = models.CharField(
        max_length=20,
        validators=[RegexValidator(
            regex=r'^[0-9\-]+$',
            message='ISBN can only contain numbers and hyphens'
        )]
    )
    description = models.TextField(blank=True)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.AVAILABLE
    )
    ebook_file = models.FileField(
        upload_to='ebooks/',
        blank=True,
        null=True
    )
    category = models.ForeignKey(
        Category,
        on_delete=models.SET_NULL,
        null=True,
        related_name='books'
    )
    is_deleted = models.BooleanField(default=False)
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='books_created'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'books'

    def __str__(self):
        return f"{self.title} by {self.author}"


class BorrowTransaction(models.Model):
    """Borrow transaction model tracking book loans."""

    class Status(models.TextChoices):
        BORROWED = 'borrowed', 'Borrowed'
        RETURNED = 'returned', 'Returned'

    book = models.ForeignKey(
        Book,
        on_delete=models.CASCADE,
        related_name='transactions'
    )
    borrower = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='borrow_transactions'
    )
    employee_id = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        help_text="Employee ID of librarian who processed the transaction"
    )
    membership_number = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        help_text="Membership number of member"
    )
    borrow_date = models.DateTimeField(auto_now_add=True)
    due_date = models.DateTimeField()
    return_date = models.DateTimeField(null=True, blank=True)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.BORROWED
    )

    class Meta:
        db_table = 'borrow_transactions'

    def __str__(self):
        return f"{self.book.title} - {self.borrower.username} ({self.get_status_display()})"


class AuditLog(models.Model):
    """Audit log for tracking system actions."""

    report_id = models.CharField(max_length=100, unique=True)
    generated_date = models.DateTimeField(auto_now_add=True)
    target_action = models.CharField(max_length=255)
    performed_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='audit_logs'
    )
    details = models.TextField(blank=True)

    class Meta:
        db_table = 'audit_logs'
        ordering = ['-generated_date']

    def __str__(self):
        return f"{self.report_id} - {self.target_action}"