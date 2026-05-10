"""
Audit logging helpers for admin and security events.

Security measures:
- Enforces ORM-only writes (no raw SQL).
- Blocks credential-like keywords in details (e.g., password, token).
- Centralizes audit creation to reduce logging drift.
"""

import datetime
import uuid

from django.utils import timezone

from .models import AuditLog


_SENSITIVE_MARKERS = ('password', 'token')


def _contains_sensitive_data(details: str) -> bool:
    return any(marker in details.lower() for marker in _SENSITIVE_MARKERS)


def create_audit_log(action, performed_by, details=''):
    """
    Create a single audit log entry with a unique report ID.

    Security:
    - Blocks credential-like keywords in details to avoid secret leakage.
    - Uses Django ORM only (no raw SQL).

    Args:
        action: Short action string (e.g., 'user_created').
        performed_by: User instance performing the action (nullable allowed).
        details: Optional human-readable details (must not include secrets).

    Returns:
        AuditLog instance (saved).
    """
    if not action or not str(action).strip():
        raise ValueError('action must be a non-empty string')

    safe_details = details or ''
    if _contains_sensitive_data(safe_details):
        raise ValueError('AuditLog.details cannot contain credential-like terms')

    timestamp = timezone.now().strftime('%Y%m%d%H%M%S')
    report_id = f'AUD-{timestamp}-{uuid.uuid4().hex[:4]}'

    return AuditLog.objects.create(
        report_id=report_id,
        target_action=str(action).strip(),
        performed_by=performed_by,
        details=safe_details,
    )


def get_audit_logs(filter_action=None, filter_user_id=None, days=None):
    """
    Fetch audit logs with optional filters.

    Security:
    - Uses ORM only.
    - Filters are allowlisted and applied server-side.

    Args:
        filter_action: Substring to match on target_action (case-insensitive).
        filter_user_id: User ID to match performed_by.
        days: If provided, limits logs to the last N days.

    Returns:
        QuerySet of AuditLog entries ordered by newest first.
    """
    queryset = AuditLog.objects.select_related('performed_by')

    if filter_action:
        queryset = queryset.filter(target_action__icontains=filter_action.strip())

    if filter_user_id:
        queryset = queryset.filter(performed_by_id=filter_user_id)

    if days is not None:
        try:
            days = int(days)
        except (TypeError, ValueError):
            days = 0

        if days > 0:
            since = timezone.now() - datetime.timedelta(days=days)
            queryset = queryset.filter(generated_date__gte=since)

    return queryset.order_by('-generated_date')
