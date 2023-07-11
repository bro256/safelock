from datetime import date, datetime
from django.contrib.auth import get_user_model
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.urls import reverse


User = get_user_model()


class PasswordEntry(models.Model):
    owner = models.ForeignKey(
        User,
        verbose_name=_("owner"),
        on_delete=models.CASCADE,
        related_name='password_entries',
        null=True, blank=True,
    )
    title = models.CharField(_('title'), max_length=50)
    username = models.CharField(_('username'), max_length=50)
    encrypted_password = models.BinaryField(_('encrypted password'), max_length=50)
    encryption_iv = models.BinaryField(max_length=32)
    auth_tag = models.BinaryField(max_length=16, null=True, blank=True)  # Assuming a 16-byte tag size for AES-GCM
    website = models.CharField(_('website'), max_length=250)

    created_at = models.DateTimeField(_("Created"), auto_now_add=True)
    updated_at = models.DateTimeField(_("Updated"), auto_now=True)
    is_in_bookmarks = models.BooleanField(default=False)
    is_in_trash = models.BooleanField(default=False)

    class Meta:
        ordering = ['website', '-is_in_bookmarks', 'title']
        verbose_name = _("password entry")
        verbose_name_plural = _("password entries")

    def toggle_bookmark(self):
        self.is_in_bookmarks = not self.is_in_bookmarks
        self.save()

    def toggle_trash(self):
        self.is_in_trash = not self.is_in_trash
        self.save()

    def __str__(self):
        return f"{self.website}: {self.encrypted_password}"

    def get_absolute_url(self):
        return reverse("password_detail", kwargs={"pk": self.pk})
    