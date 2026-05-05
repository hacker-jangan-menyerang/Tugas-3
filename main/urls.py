from django.urls import path
from . import views
from . import search_views
from . import auth_views
from . import member_views
from . import admin_views

app_name = 'main'

urlpatterns = [
    # Health check
    path('health/', views.health_check, name='health_check'),

    # App admin (role: admin)
    path('admin-panel/lockouts/', views.lockout_admin, name='lockout_admin'),

    # Auth (minimal — Kevin will enhance with rate limiting etc.)
    path('login/', auth_views.login_view, name='login'),
    path('logout/', auth_views.logout_view, name='logout'),
    path('register/', auth_views.register_view, name='register'),

    # Public book views (Vincent)
    path('books/', search_views.book_list, name='book_list'),
    path('books/search/', search_views.search_books, name='search_books'),
    path('books/<int:book_id>/', search_views.book_detail, name='book_detail'),

    # Member features (Lucky) — all protected by @role_required('member')
    path('member/', member_views.member_dashboard, name='member_dashboard'),
    path('member/borrow/<int:book_id>/', member_views.borrow_book, name='borrow_book'),
    path('member/return/<int:transaction_id>/', member_views.return_book, name='return_book'),
    path('member/history/', member_views.borrow_history, name='borrow_history'),
    path('member/read/<int:book_id>/', member_views.read_online, name='read_online'),

    # Admin dashboard (Galih)
    path('admin-panel/', admin_views.admin_dashboard, name='admin_dashboard'),

    # Admin user management (Galih)
    path('admin-panel/users/', admin_views.user_list, name='user_list'),
    path('admin-panel/users/create/', admin_views.user_create, name='user_create'),
    path('admin-panel/users/<int:user_id>/', admin_views.user_detail, name='user_detail'),
    path('admin-panel/users/<int:user_id>/toggle/', admin_views.user_toggle_active, name='user_toggle_active'),
    path('admin-panel/users/<int:user_id>/role/', admin_views.user_change_role, name='user_change_role'),

    # Audit log view (Galih)
    path('admin-panel/audit-log/', admin_views.audit_log_list, name='audit_log_list'),
]
