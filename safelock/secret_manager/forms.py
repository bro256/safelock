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