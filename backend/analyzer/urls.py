from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='dashboard'),
    path('connect-email/', views.connect_email, name='connect_email'),
    path('update-settings/', views.update_settings, name='update_settings'),
    path(
        'disconnect-email/',
        views.disconnect_email,
        name='disconnect_email'
    ),
    path(
    "get-latest-emails/",
    views.get_latest_emails,
    name="get_latest_emails"
),
]