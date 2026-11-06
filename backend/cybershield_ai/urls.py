from django.contrib import admin
from django.urls import path, include
from analyzer import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('analyzer.urls')),
    path("connect-email/", views.connect_email, name="connect_email"),
    path(
    "get-latest-emails/",
    views.get_latest_emails,
    name="get_latest_emails"
),
]
