from django.contrib import admin
from. import models

class PasswordEntryAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'username', 'encrypted_password', 'encryption_iv', 'website', 'is_in_bookmarks')

admin.site.register(models.PasswordEntry, PasswordEntryAdmin)
