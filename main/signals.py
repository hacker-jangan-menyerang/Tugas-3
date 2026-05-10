"""
Authentication signal handlers for audit logging.

Hooks into Django's auth signals to record login, logout, and failed-login
events into AuditLog. Credentials values are never stored — only the
attempted username string is referenced.

Security:
- No password or token is read from signal kwargs.
- Audit failures are swallowed so authentication flows are never broken
  by a logging issue (logs go to stderr instead).
"""

import logging

from django.contrib.auth.signals import (
    user_logged_in,
    user_logged_out,
    user_login_failed,
)
from django.dispatch import receiver

from .audit import create_audit_log


logger = logging.getLogger(__name__)


def _safe_audit(action, performed_by, details):
    try:
        create_audit_log(action, performed_by, details)
    except Exception as exc:
        logger.warning('Audit logging failed for %s: %s', action, exc)


@receiver(user_logged_in)
def _on_user_logged_in(sender, request, user, **kwargs):
    _safe_audit('user_logged_in', user, f'User {user.username} logged in.')


@receiver(user_logged_out)
def _on_user_logged_out(sender, request, user, **kwargs):
    if user is None:
        return
    _safe_audit('user_logged_out', user, f'User {user.username} logged out.')


@receiver(user_login_failed)
def _on_user_login_failed(sender, credentials, request, **kwargs):
    attempted_username = ''
    if credentials:
        attempted_username = str(credentials.get('username', '')).strip()
    label = attempted_username or '(unknown)'
    _safe_audit(
        'user_login_failed',
        None,
        f'Failed login attempt for username {label}.',
    )
