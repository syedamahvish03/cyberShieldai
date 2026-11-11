from django.contrib import admin
from django.urls import path, include
from analyzer.auth_views import EmailLoginView

urlpatterns = [
    path('admin/', admin.site.urls),
    path("accounts/login/", EmailLoginView.as_view(), name="login"),
    path("accounts/", include("django.contrib.auth.urls")),
    path('', include('analyzer.urls')),
]
