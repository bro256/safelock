from django import forms
from . import models

class PasswordEntryForm(forms.ModelForm):
    class Meta:
        model = models.PasswordEntry
        fields = ('owner', 'title', 'username', 'encrypted_password', 'website', 'is_in_bookmarks')
        widgets = {
            'owner' : forms.HiddenInput(),
        }