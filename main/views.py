import datetime

from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.db import connection
from django.conf import settings
from django.contrib import messages
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from axes.models import AccessAttempt

from .decorators import role_required
from .models import Book, BorrowTransaction, Category


def landing(request):
    stats = {
        'total_books': Book.objects.filter(is_deleted=False).count(),
        'total_available': Book.objects.filter(
            is_deleted=False,
            status=Book.Status.AVAILABLE
        ).count(),
        'total_categories': Category.objects.count(),
        'total_active_borrows': BorrowTransaction.objects.filter(
            status=BorrowTransaction.Status.BORROWED
        ).count(),
    }
    return render(request, 'main/landing.html', stats)


def health_check(request):
    """Health check endpoint that verifies DB connectivity."""
    db_status = 'healthy'
    db_message = 'Database connection successful'

    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
    except Exception as e:
        db_status = 'unhealthy'
        db_message = str(e)

    if request.headers.get('Accept') == 'application/json':
        return JsonResponse({
            'status': db_status,
            'database': db_status,
            'message': db_message,
        })

    return render(request, 'main/health.html', {
        'db_status': db_status,
        'db_message': db_message,
        'checked_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    })


def _axes_cooloff_seconds() -> int:
    cooloff = getattr(settings, 'AXES_COOLOFF_TIME', datetime.timedelta(minutes=15))
    if isinstance(cooloff, datetime.timedelta):
        return int(cooloff.total_seconds())
    return int(datetime.timedelta(hours=float(cooloff)).total_seconds())


def _axes_failure_limit() -> int:
    return int(getattr(settings, 'AXES_FAILURE_LIMIT', 5))


def _remaining_lockout_seconds(attempt: AccessAttempt) -> int:
    last_attempt = getattr(attempt, 'last_attempt_time', None) or getattr(attempt, 'attempt_time', None)
    if not last_attempt:
        return 0

    elapsed = (timezone.now() - last_attempt).total_seconds()
    return max(0, int(_axes_cooloff_seconds() - elapsed))


@role_required('admin')
@require_http_methods(["GET", "POST"])
def lockout_admin(request):
    if request.method == 'POST':
        ip_address = request.POST.get('ip_address', '').strip()
        if ip_address:
            deleted, _ = AccessAttempt.objects.filter(ip_address=ip_address).delete()
            messages.success(request, f'Cleared lockout records for {ip_address}.')
        else:
            messages.error(request, 'Missing IP address to clear.')
        return redirect('main:lockout_admin')

    attempts = AccessAttempt.objects.order_by('-attempt_time')
    by_ip = {}
    for attempt in attempts:
        if attempt.ip_address not in by_ip:
            by_ip[attempt.ip_address] = attempt

    lockout_limit = _axes_failure_limit()
    lockouts = []
    for attempt in by_ip.values():
        failures = int(getattr(attempt, 'failures_since_start', 0) or 0)
        remaining_seconds = _remaining_lockout_seconds(attempt)
        if failures >= lockout_limit and remaining_seconds > 0:
            lockouts.append({
                'ip_address': attempt.ip_address,
                'username': attempt.username,
                'failures': failures,
                'last_attempt': getattr(attempt, 'last_attempt_time', None) or attempt.attempt_time,
                'remaining_minutes': max(1, int((remaining_seconds + 59) / 60)),
            })

    return render(request, 'main/lockout_admin.html', {
        'lockouts': lockouts,
        'failure_limit': lockout_limit,
    })
