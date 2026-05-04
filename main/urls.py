from django.urls import path
from . import views
from . import search_views

app_name = 'main'

urlpatterns = [
    path('health/', views.health_check, name='health_check'),
    path('books/', search_views.book_list, name='book_list'),
    path('books/search/', search_views.search_books, name='search_books'),
    path('books/<int:book_id>/', search_views.book_detail, name='book_detail'),
]
