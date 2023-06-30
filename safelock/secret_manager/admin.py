from django.contrib import admin
from. import models

class PasswordEntryAdmin(admin.ModelAdmin):
    list_display = ('id', 'owner', 'title', 'username', 'encrypted_password', 'encryption_iv', 'website', 'is_in_bookmarks', 'created_at')

admin.site.register(models.PasswordEntry, PasswordEntryAdmin)
