from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import AuthenticationForm

User = get_user_model()


class EmailRegistrationForm(forms.Form):
    email = forms.EmailField(
        max_length=150,
        widget=forms.EmailInput(attrs={
            "autocomplete": "email",
            "placeholder": "you@example.com",
        }),
    )

    def clean_email(self):
        email = self.cleaned_data["email"].strip()
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return email

    def save(self):
        email = self.cleaned_data["email"].strip()

        # Django's default user model requires an internal username.
        # It is generated automatically and is never used for sign-in.
        base = email.split("@", 1)[0][:140] or "user"
        username = base
        suffix = 1
        while User.objects.filter(username__iexact=username).exists():
            username = f"{base[:140-len(str(suffix))-1]}_{suffix}"
            suffix += 1

        user = User(
            username=username,
            email=email,
            is_active=False,
        )
        # Do not let the person registering choose a password before
        # proving control of the email inbox.
        user.set_unusable_password()
        user.save()
        return user


class EmailLoginForm(AuthenticationForm):
    username = forms.EmailField(
        label="Email address",
        widget=forms.EmailInput(attrs={
            "autofocus": True,
            "autocomplete": "username",
            "placeholder": "you@example.com",
        }),
    )
