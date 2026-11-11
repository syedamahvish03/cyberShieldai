from django.contrib.auth.views import LoginView
from .forms import EmailLoginForm


class EmailLoginView(LoginView):
    authentication_form = EmailLoginForm
    template_name = "registration/login.html"
