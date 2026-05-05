from django.contrib import admin, messages

from axes.models import AccessAttempt
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


try:
    admin.site.unregister(AccessAttempt)
except admin.sites.NotRegistered:
    pass


@admin.action(description='Clear selected IP lockouts')
def clear_ip_lockouts(modeladmin, request, queryset):
    ip_addresses = list(queryset.values_list('ip_address', flat=True).distinct())
    AccessAttempt.objects.filter(ip_address__in=ip_addresses).delete()
    messages.success(request, f'Cleared lockouts for {len(ip_addresses)} IP(s).')


@admin.register(AccessAttempt)
class AccessAttemptAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'username', 'attempt_time', 'failures_since_start')
    list_filter = ('ip_address', 'username')
    search_fields = ('ip_address', 'username')
    actions = [clear_ip_lockouts]