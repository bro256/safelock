from django.shortcuts import render
from django.db.models import Q
from django.views import generic
from . models import PasswordEntry
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.urls import reverse, reverse_lazy
from typing import Any, Dict
from django.contrib import messages
from django.utils.translation import gettext_lazy as _
from . forms import PasswordEntryForm

from django.contrib.auth import authenticate, login
from django.contrib.auth.views import LoginView
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from django.shortcuts import redirect, render
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
from django.contrib.auth.views import PasswordChangeView

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from django.http import HttpResponse


def index(request):
    context = {
        'test' : 'test',
    }
    return render(request, 'secret_manager/index.html', context)


def derive_key(username, password):
    # Hash the username
    username_hash = hashlib.sha256(username.encode()).digest()

    # PBKDF2 parameters
    salt = username_hash[:16]  # Extract the first 16 bytes (128 bits) as the salt
    iterations = 100000
    key_length = 32
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations
    )

    # PBKDF2 to get derived key
    derived_key = kdf.derive(password.encode('utf-8'))

    ### USE FOR DEBUG ONLY!!!
    print("Salt: ", salt)
    print("Derived key type: ", type(derived_key))
    print("Derived key in HEX: ", derived_key.hex())

    return derived_key.hex()


class CustomLoginView(LoginView):
    def form_valid(self, form):
        # Authenticate the user
        self.user = form.get_user()

        # Get the entered password
        password = form.cleaned_data['password']

        # Get the logged in user and username
        username = self.user.username
        derived_key = derive_key(username, password)
        self.request.session['derived_key'] = derived_key

        ### USE FOR DEBUG ONLY!!!
        print("User: ", username, " Derived key:", derived_key)
        print("Pass: ", password)

        return super().form_valid(form)


class PasswordEntryListView(generic.ListView):
    model = PasswordEntry
    # paginate_by = 10
    template_name = "secret_manager/password_entry_list.html"
    
    def get_queryset(self):
        return self.model.objects.filter(owner=self.request.user)
    

class PasswordEntryCreateView(LoginRequiredMixin, UserPassesTestMixin, generic.CreateView):
    model = PasswordEntry
    form_class = PasswordEntryForm
    template_name = 'secret_manager/password_entry_form.html'
    success_url = reverse_lazy('password_entry_list')

    def get(self, request):
        form = self.form_class()
        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password']
            key_in_hex = self.request.session.get('derived_key')
            key = bytes.fromhex(key_in_hex)
            iv = os.urandom(12)

            # Encrypt the password using AES-GCM mode
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(password.encode()) + encryptor.finalize()

            # Retrieve the authentication tag from the encryptor
            auth_tag = encryptor.tag

            # Save the encrypted password, IV, and tag to the model instance
            entry = form.save(commit=False)
            entry.owner = request.user
            entry.encrypted_password = ciphertext
            entry.encryption_iv = iv
            entry.auth_tag = auth_tag
            entry.save()

            return redirect(self.success_url)

        return render(request, self.template_name, {'form': form})

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        return context
    
    def get_initial(self) -> Dict[str, Any]:
        initial = super().get_initial()
        initial['owner'] = self.request.user
        return initial

    def form_valid(self, form):
        form.instance.owner = self.request.user
        messages.success(self.request, _('Password entry created successfully!'))
        return super().form_valid(form)
    
    def get_form(self, form_class=None):
        form = super().get_form(form_class)
        return form

    # Checks that the user passes the given test
    def test_func(self):
        return self.request.user.is_authenticated


class PasswordEntryDetailView(generic.DetailView):
    model = PasswordEntry
    template_name = "secret_manager/password_entry_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Retrieve the encrypted password, IV, and tag from the model instance
        encrypted_password = self.object.encrypted_password
        iv = self.object.encryption_iv
        auth_tag = self.object.auth_tag

        # Retrieve the derived key from the session
        derived_key_in_hex = self.request.session.get('derived_key')
        derived_key = bytes.fromhex(derived_key_in_hex)

        # Create the AES-GCM cipher with the derived key, IV, and tag
        cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, auth_tag))
        decryptor = cipher.decryptor()

        # Decrypt the password
        decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()

        # Convert the decrypted password to a string
        decrypted_password_str = decrypted_password.decode('utf-8')

        # Add the decrypted password to the context
        context['decrypted_password'] = decrypted_password_str

        return context


def reencrypt_passwords(user, old_password, new_password):
    # Derive the old and new keys
    old_key = derive_key(user.username, old_password)
    new_key = derive_key(user.username, new_password)

    # Retrieve all the encrypted passwords associated with the user
    entries = PasswordEntry.objects.filter(owner=user)

    # Iterate over each entry and re-encrypt the password
    for entry in entries:
        # Decrypt the password using the old key and IV
        cipher = Cipher(algorithms.AES(old_key), modes.GCM(entry.encryption_iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_password = decryptor.update(entry.encrypted_password) + decryptor.finalize()

        # Encrypt the decrypted password using the new key and IV
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(new_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_password = encryptor.update(decrypted_password) + encryptor.finalize()

        # Update the entry with the new encrypted password and IV
        entry.encrypted_password = encrypted_password
        entry.encryption_iv = iv
        entry.save()


# class CustomPasswordResetConfirmView(PasswordResetConfirmView):
#     success_url = reverse_lazy('password_reset_complete')

#     def form_valid(self, form):
#         # Call the parent form_valid method to reset the user's password
#         response = super().form_valid(form)

#         # Re-encrypt passwords for the user
#         reencrypt_passwords(self.user, self.user.password, form.cleaned_data['new_password1'])
#         print("User: ", self.user)
#         print(self.user.password)
#         print(form.cleaned_data['new_password1'])

#         return response
    
class CustomPasswordChangeView(PasswordChangeView):
    # template_name = 'password_change.html'
    success_url = '/password_change_done/'

    def form_valid(self, form):
        # Change the user's password
        response = super().form_valid(form)

        # Reencrypt passwords with the new password
        reencrypt_passwords(self.request.user, form.cleaned_data['old_password'], form.cleaned_data['new_password2'])

        return response

    def get_success_url(self):
        return self.success_url