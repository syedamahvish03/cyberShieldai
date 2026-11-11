from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm

User = get_user_model()


class EmailRegistrationForm(UserCreationForm):
    email = forms.EmailField(
        max_length=150,
        widget=forms.EmailInput(attrs={
            "autocomplete": "email",
            "placeholder": "you@example.com",
        }),
    )

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ("email",)

    def clean_email(self):
        email = self.cleaned_data["email"].strip()
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return email

    def save(self, commit=True):
        user = super().save(commit=False)
        email = self.cleaned_data["email"].strip()
        user.email = email

        # Keep Django's required username field, generated from the email.
        base = email.split("@", 1)[0][:140] or "user"
        username = base
        suffix = 1
        while User.objects.filter(username__iexact=username).exists():
            username = f"{base[:140-len(str(suffix))-1]}_{suffix}"
            suffix += 1
        user.username = username

        if commit:
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

