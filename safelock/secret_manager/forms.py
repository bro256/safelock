from django import forms
from . import models

class PasswordEntryForm(forms.ModelForm):
   
    # Cutomizing password input widget 
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = models.PasswordEntry
        fields = ('title', 'username', 'password', 'website', 'is_in_bookmarks')
        widgets = {
            'owner' : forms.HiddenInput(),
        }

class PasswordEntryUpdateForm(forms.ModelForm):
    password = forms.CharField(widget=forms.TextInput)

    class Meta:
        model = models.PasswordEntry
        fields = ('title', 'username', 'password', 'website', 'is_in_bookmarks')
        widgets = {
            'owner': forms.HiddenInput(),
            'encrypted_password': forms.HiddenInput(),
            'encryption_iv': forms.HiddenInput(),
            'auth_tag': forms.HiddenInput(),
        }

