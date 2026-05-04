from django.http import JsonResponse
from django.shortcuts import render
from django.db import connection
from datetime import datetime


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
        'checked_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    })
