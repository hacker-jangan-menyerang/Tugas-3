"""
Admin feature views for Digital Library.

Security measures implemented:
1. Role-based access control (CWE-285) via @role_required('admin')
2. HTTP method restrictions to reduce attack surface
3. ORM-only queries (no raw SQL)
"""

from datetime import date
from urllib.parse import urlencode

from django.contrib import messages
from django.core.paginator import Paginator
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_http_methods, require_POST

from .admin_forms import AdminUserCreateForm, AdminUserEditForm
from .audit import create_audit_log
from .decorators import role_required
from .models import AuditLog, Book, BorrowTransaction, User


@role_required('admin')
@require_http_methods(["GET"])
def admin_dashboard(request):
    """
    Admin dashboard with system overview and recent activity.

    Security:
    - @role_required('admin') ensures only admins can access.
    - GET-only to prevent state changes.
    - ORM-only data access.
    """
    total_users = User.objects.count()
    total_members = User.objects.filter(role='member').count()
    total_librarians = User.objects.filter(role='librarian').count()
    total_admins = User.objects.filter(role='admin').count()

    total_books_active = Book.objects.filter(is_deleted=False).count()
    total_books_deleted = Book.objects.filter(is_deleted=True).count()

    total_active_borrows = BorrowTransaction.objects.filter(status='borrowed').count()
    total_returned = BorrowTransaction.objects.filter(status='returned').count()

    total_audit_logs = AuditLog.objects.count()
    recent_activity = AuditLog.objects.select_related('performed_by').order_by('-generated_date')[:5]

    return render(request, 'main/admin_dashboard.html', {
        'total_users': total_users,
        'total_members': total_members,
        'total_librarians': total_librarians,
        'total_admins': total_admins,
        'total_books_active': total_books_active,
        'total_books_deleted': total_books_deleted,
        'total_active_borrows': total_active_borrows,
        'total_returned': total_returned,
        'total_audit_logs': total_audit_logs,
        'recent_activity': recent_activity,
    })


@role_required('admin')
@require_http_methods(["GET"])
def user_list(request):
    """
    List users with role filtering, search, and pagination.

    Security:
    - @role_required('admin') ensures only admins can access.
    - GET-only; no state changes.
    - ORM-only queries.
    """
    query = request.GET.get('q', '').strip()
    selected_role = request.GET.get('role', '').strip()
    valid_roles = {choice[0] for choice in User.Role.choices}

    users = User.objects.all().order_by('username')
    if selected_role in valid_roles:
        users = users.filter(role=selected_role)
    else:
        selected_role = ''

    if query:
        users = users.filter(username__icontains=query)

    paginator = Paginator(users, 20)
    page_obj = paginator.get_page(request.GET.get('page'))

    query_params = {}
    if query:
        query_params['q'] = query
    if selected_role:
        query_params['role'] = selected_role

    return render(request, 'main/admin_user_list.html', {
        'page_obj': page_obj,
        'query': query,
        'selected_role': selected_role,
        'role_choices': User.Role.choices,
        'query_string': urlencode(query_params),
    })


@role_required('admin')
@require_http_methods(["GET", "POST"])
def user_create(request):
    """
    Create a new user account.

    Security:
    - @role_required('admin') limits access to admins.
    - CSRF protection in template for POST.
    - Uses User.objects.create_user for password hashing.
    - Audit logging without secrets.
    """
    if request.method == 'POST':
        form = AdminUserCreateForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            role = form.cleaned_data['role']
            employee_id = form.cleaned_data.get('employee_id') or None
            membership_number = form.cleaned_data.get('membership_number') or None

            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                role=role,
                employee_id=employee_id,
                membership_number=membership_number,
            )

            create_audit_log(
                'user_created',
                request.user,
                f'Created user {user.username} with role {user.role}.',
            )
            messages.success(request, f'User {user.username} created successfully.')
            return redirect('main:user_detail', user_id=user.id)
    else:
        form = AdminUserCreateForm()

    return render(request, 'main/admin_user_form.html', {
        'form': form,
        'form_title': 'Create User',
        'submit_label': 'Create User',
    })


@role_required('admin')
@require_http_methods(["GET"])
def user_detail(request, user_id):
    """
    Show user details and recent activity.

    Security:
    - @role_required('admin') ensures only admins can access.
    - Read-only view with ORM-only access.
    """
    target_user = get_object_or_404(User, id=user_id)
    user_logs = AuditLog.objects.filter(
        performed_by=target_user
    ).order_by('-generated_date')[:10]

    return render(request, 'main/admin_user_detail.html', {
        'target_user': target_user,
        'user_logs': user_logs,
        'role_choices': User.Role.choices,
        'is_self': target_user.id == request.user.id,
    })


@role_required('admin')
@require_http_methods(["GET", "POST"])
def user_edit(request, user_id):
    """
    Edit an existing user's profile (no password change here).

    Security:
    - @role_required('admin') restricts access to admins.
    - CSRF protection in template for POST.
    - Self cannot demote own role to non-admin.
    - Audit logging records before/after role and updated username.
    """
    target_user = get_object_or_404(User, id=user_id)
    is_self = target_user.id == request.user.id

    if request.method == 'POST':
        form = AdminUserEditForm(request.POST, user_instance=target_user)
        if form.is_valid():
            new_role = form.cleaned_data['role']
            if is_self and new_role != 'admin':
                messages.error(request, 'You cannot change your own role to non-admin.')
                return redirect('main:user_edit', user_id=target_user.id)

            old_username = target_user.username
            old_role = target_user.role

            target_user.username = form.cleaned_data['username']
            target_user.email = form.cleaned_data['email']
            target_user.role = new_role
            target_user.employee_id = form.cleaned_data.get('employee_id') or None
            target_user.membership_number = form.cleaned_data.get('membership_number') or None
            target_user.save(update_fields=[
                'username', 'email', 'role', 'employee_id', 'membership_number',
            ])

            create_audit_log(
                'user_edited',
                request.user,
                (
                    f'Edited user {old_username} (id={target_user.id}); '
                    f'role {old_role}->{target_user.role}.'
                ),
            )
            messages.success(request, f'User {target_user.username} updated successfully.')
            return redirect('main:user_detail', user_id=target_user.id)
    else:
        form = AdminUserEditForm(user_instance=target_user)

    return render(request, 'main/admin_user_form.html', {
        'form': form,
        'form_title': f'Edit User: {target_user.username}',
        'submit_label': 'Save Changes',
    })


@role_required('admin')
@require_POST
def user_toggle_active(request, user_id):
    """
    Activate or deactivate a user account.

    Security:
    - POST-only to prevent CSRF via GET.
    - Prevents self-deactivation.
    - Audit logging for accountability.
    """
    target_user = get_object_or_404(User, id=user_id)

    if target_user.id == request.user.id:
        messages.error(request, 'You cannot deactivate your own account.')
        return redirect('main:user_detail', user_id=target_user.id)

    target_user.is_active = not target_user.is_active
    target_user.save(update_fields=['is_active'])

    action = 'user_activated' if target_user.is_active else 'user_deactivated'
    create_audit_log(
        action,
        request.user,
        f'Set is_active={target_user.is_active} for {target_user.username}.',
    )

    status_label = 'activated' if target_user.is_active else 'deactivated'
    messages.success(request, f'User {target_user.username} {status_label}.')
    return redirect('main:user_detail', user_id=target_user.id)


@role_required('admin')
@require_POST
def user_change_role(request, user_id):
    """
    Change a user's role.

    Security:
    - POST-only to prevent CSRF via GET.
    - Prevents self-demotion from admin role.
    - Audit logging for accountability.
    """
    target_user = get_object_or_404(User, id=user_id)
    new_role = request.POST.get('role', '').strip()
    valid_roles = {choice[0] for choice in User.Role.choices}

    if new_role not in valid_roles:
        messages.error(request, 'Invalid role selected.')
        return redirect('main:user_detail', user_id=target_user.id)

    if target_user.id == request.user.id and new_role != 'admin':
        messages.error(request, 'You cannot change your own role to non-admin.')
        return redirect('main:user_detail', user_id=target_user.id)

    old_role = target_user.role
    if new_role == old_role:
        messages.info(request, 'Selected role is already applied to this user.')
        return redirect('main:user_detail', user_id=target_user.id)

    target_user.role = new_role
    target_user.save(update_fields=['role'])

    create_audit_log(
        'user_role_changed',
        request.user,
        f'Changed role for {target_user.username} from {old_role} to {new_role}.',
    )
    messages.success(request, f'Role updated for {target_user.username}.')
    return redirect('main:user_detail', user_id=target_user.id)


@role_required('admin')
@require_http_methods(["GET"])
def audit_log_list(request):
    """
    List audit log entries with filters.

    Security:
    - @role_required('admin') ensures only admins can access.
    - GET-only; logs are read-only.
    - ORM-only queries.
    """
    action = request.GET.get('action', '').strip()
    user_id = request.GET.get('user_id', '').strip()
    date_from_raw = request.GET.get('date_from', '').strip()
    date_to_raw = request.GET.get('date_to', '').strip()

    logs = AuditLog.objects.select_related('performed_by').all()

    if action:
        logs = logs.filter(target_action__icontains=action)

    selected_user_id = None
    if user_id:
        if user_id.isdigit():
            selected_user_id = int(user_id)
            logs = logs.filter(performed_by_id=selected_user_id)
        else:
            messages.error(request, 'Invalid user filter value.')
            user_id = ''

    date_from = None
    if date_from_raw:
        try:
            date_from = date.fromisoformat(date_from_raw)
        except ValueError:
            messages.error(request, 'Invalid start date format.')

    date_to = None
    if date_to_raw:
        try:
            date_to = date.fromisoformat(date_to_raw)
        except ValueError:
            messages.error(request, 'Invalid end date format.')

    if date_from:
        logs = logs.filter(generated_date__date__gte=date_from)
    if date_to:
        logs = logs.filter(generated_date__date__lte=date_to)

    logs = logs.order_by('-generated_date')

    paginator = Paginator(logs, 50)
    page_obj = paginator.get_page(request.GET.get('page'))
    users = User.objects.all().order_by('username')

    query_params = {}
    if action:
        query_params['action'] = action
    if user_id:
        query_params['user_id'] = user_id
    if date_from_raw:
        query_params['date_from'] = date_from_raw
    if date_to_raw:
        query_params['date_to'] = date_to_raw

    return render(request, 'main/admin_audit_log.html', {
        'page_obj': page_obj,
        'users': users,
        'action': action,
        'selected_user_id': selected_user_id,
        'date_from': date_from_raw,
        'date_to': date_to_raw,
        'query_string': urlencode(query_params),
    })
