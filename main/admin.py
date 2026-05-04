from django.contrib import admin
from .models import User, Category, Book, BorrowTransaction, AuditLog


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'role', 'employee_id', 'membership_number', 'is_active')
    list_filter = ('role', 'is_active')
    search_fields = ('username', 'email', 'employee_id', 'membership_number')


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_at')
    search_fields = ('name',)


@admin.register(Book)
class BookAdmin(admin.ModelAdmin):
    list_display = ('title', 'author', 'isbn', 'status', 'category', 'is_deleted')
    list_filter = ('status', 'category', 'is_deleted')
    search_fields = ('title', 'author', 'isbn')


@admin.register(BorrowTransaction)
class BorrowTransactionAdmin(admin.ModelAdmin):
    list_display = ('book', 'borrower', 'status', 'borrow_date', 'due_date', 'return_date')
    list_filter = ('status', 'borrow_date')
    search_fields = ('book__title', 'borrower__username', 'employee_id', 'membership_number')


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('report_id', 'target_action', 'performed_by', 'generated_date')
    list_filter = ('generated_date',)
    search_fields = ('report_id', 'target_action', 'performed_by__username')