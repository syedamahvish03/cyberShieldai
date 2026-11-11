from django.contrib.auth import get_user_model
from django.core.exceptions import MultipleObjectsReturned

User = get_user_model()


class EmailOrUsernameBackend:
    """
    Authenticate by email address, while retaining username login for
    existing accounts that have not yet added an email address.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        identifier = username or kwargs.get("email")
        if not identifier or not password:
            return None

        user = None
        try:
            if "@" in identifier:
                user = User.objects.get(email__iexact=identifier)
            else:
                user = User.objects.get(username__iexact=identifier)
        except (User.DoesNotExist, MultipleObjectsReturned):
            # Run a password hash check to reduce timing differences.
            User().set_password(password)
            return None

        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None

    def user_can_authenticate(self, user):
        return getattr(user, "is_active", True)
