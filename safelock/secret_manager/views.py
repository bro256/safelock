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

    def post(self, request):
        form = self.form_class(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password']

            backend = default_backend()
            # key = os.urandom(32)
            # key = self.request.session['derived_key'].encode('utf-8')
            key_in_hex = self.request.session.get('derived_key')
            key = bytes.fromhex(key_in_hex)

            ### USE FOR DEBUG ONLY
            print("KEY in hex: ", key_in_hex)
            print("KEY: ", key)
            print("PASSWORD TYPE: ", type(password))
            print("PASSWORD: ", password)
            
            # key = request.session.get('derived_key')
            iv = os.urandom(16)
            
            # Create a PKCS7 padding object with the block size
            block_size = algorithms.AES.block_size // 8
            padder = padding.PKCS7(block_size * 8).padder()

            # Pad the password
            padded_password = padder.update(password.encode()) + padder.finalize()
            print("CREATE VIEW PADDED PASSWORD", padded_password)

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
            encryptor = cipher.encryptor()
            encrypted_password = encryptor.update(padded_password) + encryptor.finalize()

            entry = form.save(commit=False)
            entry.owner = request.user
            entry.encrypted_password = encrypted_password
            entry.encryption_iv = iv
            print("IV used for encryption and stored to database", iv)
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

        # Retrieve the encrypted password and IV from the model instance
        encrypted_password = self.object.encrypted_password
        iv = self.object.encryption_iv

        # Retrieve the derived key from the session
        derived_key_in_hex = self.request.session.get('derived_key')
        derived_key = bytes.fromhex(derived_key_in_hex)

        # Create the cipher with the derived key and IV
        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
        print("IV retreived from database and used for decryption", iv)
        decryptor = cipher.decryptor()

        # Decrypt the password
        decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()

        # Remove padding from the decrypted password
        print("DETAIL VIEW PADDED PASSWORD", decrypted_password)
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_password = unpadder.update(decrypted_password) + unpadder.finalize()

        # Convert the decrypted password to a string
        decrypted_password_str = unpadded_password.decode('utf-8')

        # Use the decrypted password as needed
        print("Decrypted Password:", decrypted_password_str)

        # Add the decrypted password to the context
        context['decrypted_password'] = unpadded_password.decode('utf-8')

        return context