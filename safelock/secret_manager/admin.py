from django.contrib import admin
from. import models

class PasswordEntryAdmin(admin.ModelAdmin):
    list_display = ('id', 'owner', 'title', 'username', 'encrypted_password', 'encryption_iv', 'auth_tag', 'website', 'is_in_bookmarks', 'is_in_trash')

admin.site.register(models.PasswordEntry, PasswordEntryAdmin)
