from datetime import date, datetime
from django.contrib.auth import get_user_model
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.urls import reverse


User = get_user_model()


class Password(models.Model):
    owner = models.ForeignKey(
        User,
        verbose_name=_("owner"),
        on_delete=models.CASCADE,
        related_name='passwords',
        null=True, blank=True,
    )
    title = models.CharField(_('title'), max_length=50)
    username = models.CharField(_('username'), max_length=50)
    encrypted_password = models.CharField(_('password'), max_length=50)
    encryption_iv = models.BinaryField(max_length=256)
    website = models.CharField(_('website'), max_length=250)

    created_at = models.DateTimeField(_("Created"), auto_now_add=True)
    updated_at = models.DateTimeField(_("Updated"), auto_now=True)
    is_in_favourites = models.BooleanField(default=False)
    is_in_trash = models.BooleanField(default=False)

    class Meta:
        ordering = ['is_in_favourites', 'website']
        verbose_name = _("password")
        verbose_name_plural = _("passwords")

    def add_to_favourites(password):
        password.is_in_favourites = True
        password.save()

    def move_to_trash(password):
        password.is_in_trash = True
        password.save()

    def __str__(self):
        return f"{self.website}: {self.encrypted_password}"

    def get_absolute_url(self):
        return reverse("password_detail", kwargs={"pk": self.pk})
    