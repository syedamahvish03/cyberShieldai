from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import MultipleObjectsReturned

User = get_user_model()


class EmailAuthenticationBackend(ModelBackend):
    """
    Authenticate users by email address only.

    The standard Django User model still stores an internal username, but
    that username is never accepted as a login identifier.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        email = username or kwargs.get("email")
        if not email or not password or "@" not in email:
            return None

        try:
            user = User.objects.get(email__iexact=email.strip())
        except (User.DoesNotExist, MultipleObjectsReturned):
            # Run a password hash check to reduce timing differences.
            User().set_password(password)
            return None

        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None

    def user_can_authenticate(self, user):
        return getattr(user, "is_active", True)
