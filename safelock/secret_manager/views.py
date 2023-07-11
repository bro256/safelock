from . forms import PasswordEntryForm, PasswordEntryUpdateForm
from . models import PasswordEntry
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.views import LoginView, PasswordChangeView
from django.db.models import Q
from django.shortcuts import redirect, render, get_object_or_404, redirect
from django.urls import reverse, reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views import generic, View
from django.views.generic.edit import UpdateView, DeleteView
from typing import Any, Dict

# from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib
import os

from django.utils.crypto import get_random_string

from django.http import HttpRequest, JsonResponse
import random
import string



def index(request):
    context = {
        'test' : 'test',
    }
    return render(request, 'secret_manager/index.html', context)


# def generate_password(request):
#     password = get_random_string(length=16)  # Generate a random password
#     return JsonResponse({'password': password})

# def generate_password(request: HttpRequest, length: int = 16, symbols: bool = True) -> JsonResponse:
#     characters = string.ascii_letters + string.digits
#     if symbols:
#         characters += string.punctuation

#     password = ''.join(random.choice(characters) for _ in range(length))  # Generate the random password

#     return JsonResponse({'password': password})

# def generate_password(request: HttpRequest) -> JsonResponse:
#     length = int(request.GET.get('length', 16))
#     symbols = request.GET.get('symbols', 'true').lower() == 'true'

#     characters = string.ascii_letters + string.digits
#     if symbols:
#         characters += string.punctuation

#     password = ''.join(random.choice(characters) for _ in range(length))

#     return JsonResponse({'password': password})

def generate_password(request: HttpRequest) -> JsonResponse:
    length = int(request.GET.get('length', 16))
    letters = request.GET.get('letters', 'true').lower() == 'true'
    numbers = request.GET.get('numbers', 'true').lower() == 'true'
    symbols = request.GET.get('symbols', 'true').lower() == 'true'

    characters = ''
    if letters:
        characters += string.ascii_letters
    if numbers:
        characters += string.digits
    if symbols:
        characters += string.punctuation

    password = ''.join(random.choice(characters) for _ in range(length))

    return JsonResponse({'password': password})


def derive_key(username, password):
    # Hash the username
    username_hash = hashlib.sha256(username.encode()).digest()

    # PBKDF2 parameters
    salt = username_hash[:16]  # Extract the first 16 bytes (128 bits) as the salt
    iterations = 600000
    key_length = 32
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations
    )

    # PBKDF2 to get derived key
    derived_key = kdf.derive(password.encode('utf-8'))

    ### FOR DEBUG ONLY!!!
    print(f"KEY DERIVATION FUNCTION. Username: {username} Pass:{password} Salt: {salt} Derived key: {derived_key} Derived key in HEX (return): {derived_key.hex()}")

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

        return super().form_valid(form)


class PasswordEntryListView(generic.ListView):
    model = PasswordEntry
    paginate_by = 10
    template_name = "secret_manager/password_entry_list.html"
    
    def get_queryset(self):
        return self.model.objects.filter(owner=self.request.user, is_in_trash=False)
    

class PasswordEntryListTrashView(generic.ListView):
    model = PasswordEntry
    paginate_by = 10
    template_name = "secret_manager/password_entry_list_trash.html"
    
    def get_queryset(self):
        return self.model.objects.filter(owner=self.request.user, is_in_trash=True)


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
            messages.success(self.request, _('Password entry created successfully!'))

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
        return super().form_valid(form)
    
    def get_form(self, form_class=None):
        form = super().get_form(form_class)
        return form

    # Checks that the user passes the given test
    def test_func(self):
        return self.request.user.is_authenticated


class PasswordEntryDetailView(UserPassesTestMixin,generic.DetailView):
    model = PasswordEntry
    template_name = "secret_manager/password_entry_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # # Retrieve the encrypted password, IV, and tag from the model instance
        # encrypted_password = self.object.encrypted_password
        # iv = self.object.encryption_iv
        # auth_tag = self.object.auth_tag

        # Retrieve the derived key from the session
        derived_key_in_hex = self.request.session.get('derived_key')
        derived_key = bytes.fromhex(derived_key_in_hex)

        # # Create the AES-GCM cipher with the derived key, IV, and tag
        # cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, auth_tag))
        # decryptor = cipher.decryptor()

        # # Decrypt the password
        # decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()

        # # Convert the decrypted password to a string
        # decrypted_password_str = decrypted_password.decode('utf-8')

        # # Add the decrypted password to the context

        # Retrieve the current PasswordEntry object
        password_entry = self.get_object()

        # Call the decrypt_password function to decrypt the password
        decrypted_password_str = decrypt_password(password_entry, derived_key)

        context['decrypted_password'] = decrypted_password_str

        return context
    
    def test_func(self):
        obj = self.get_object()
        return obj.owner == self.request.user


def reencrypt_all_passwords(user, old_password, new_password):
    # Derive the old and new keys
    old_key = derive_key(user.username, old_password)
    new_key = derive_key(user.username, new_password)

    ### FOR DEBUG ONLY!!!
    print(f"REENCRYPT FUNCTION. Old key bytes: {bytes.fromhex(old_key)} New key bytes: {bytes.fromhex(new_key)}")

    # Retrieve all the encrypted passwords associated with the user
    entries = PasswordEntry.objects.filter(owner=user)

    # Iterate over each entry and re-encrypt the password
    for entry in entries:
        # Decrypt the password using the old key and IV
        cipher = Cipher(algorithms.AES(bytes.fromhex(old_key)), modes.GCM(entry.encryption_iv, entry.auth_tag))
        decryptor = cipher.decryptor()
        decrypted_password = decryptor.update(entry.encrypted_password) + decryptor.finalize()
        decrypted_password_str = decrypted_password.decode('utf-8')

        ### FOR DEBUG ONLY!!!
        print(f"DECRYPTION. ID: Encrypted pass: {entry.encrypted_password} iv: {entry.encryption_iv} tag: {entry.auth_tag} decrypted pass: {decrypted_password} decrypted pass str: {decrypted_password_str}") 

        # Encrypt the decrypted password using the new key and IV
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(bytes.fromhex(new_key)), modes.GCM(iv))
        encryptor = cipher.encryptor()
        encrypted_password = encryptor.update(decrypted_password) + encryptor.finalize()
        auth_tag = encryptor.tag
        
        ### FOR DEBUG ONLY!!!
        print(f"ENCRYPTION. Encrypted pass: {encrypted_password} iv: {iv} Tag: {auth_tag} decrypted pass: {decrypted_password} decrypted pass str: {decrypted_password_str}") 

        # Update the entry with the new encrypted password and IV
        entry.encrypted_password = encrypted_password
        entry.encryption_iv = iv
        entry.auth_tag = auth_tag
        entry.save()

    
class CustomPasswordChangeView(PasswordChangeView):

    def form_valid(self, form):
        # Change the user's password
        response = super().form_valid(form)

        # Reencrypt passwords with the new password
        reencrypt_all_passwords(self.request.user, form.cleaned_data['old_password'], form.cleaned_data['new_password2'])
        
        # Log out the user to get new PBKDF2 derived key
        logout(self.request)

        return response

    def get_success_url(self):
        return self.success_url


def decrypt_password(password_entry, derived_key):
    # Retrieve the encrypted password, IV, and tag from the model instance
    encrypted_password = password_entry.encrypted_password
    iv = password_entry.encryption_iv
    tag = password_entry.auth_tag

    # Create the AES-GCM cipher with the derived key, IV, and tag
    decryptor = Cipher(
        algorithms.AES(derived_key),
        modes.GCM(iv, tag),
    ).decryptor()

    # Decrypt the password
    decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()

    # Convert the decrypted password to a string
    decrypted_password_str = decrypted_password.decode('utf-8')

    return decrypted_password_str


class PasswordEntryUpdateView(UserPassesTestMixin, UpdateView):
    model = PasswordEntry
    form_class = PasswordEntryUpdateForm
    template_name = 'secret_manager/password_entry_form.html'
    success_url = 'password_entry_list'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Retrieve the derived key from the session
        derived_key_in_hex = self.request.session.get('derived_key')
        derived_key = bytes.fromhex(derived_key_in_hex)
        decrypted_value = decrypt_password(self.object, derived_key)

        # Add the decrypted password to the context
        context['password'] = decrypted_value
        print(context)

        # Set the decrypted password value in the form field initial data
        context['form'].initial['password'] = decrypted_value

        return context

    def form_valid(self, form):
        # Operations before saving
        instance = form.save(commit=False)
        
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
        instance = form.save(commit=False)
        instance.encrypted_password = ciphertext
        instance.encryption_iv = iv
        instance.auth_tag = auth_tag
        instance.save()
        messages.success(self.request, _('Password entry updated successfully!'))
        return redirect(self.get_success_url())
    
    def test_func(self):
        obj = self.get_object()
        return obj.owner == self.request.user


class PasswordEntryDeleteView(LoginRequiredMixin, UserPassesTestMixin, DeleteView):
    model = PasswordEntry
    template_name = 'secret_manager/password_entry_delete.html'
    success_url = reverse_lazy('password_entry_list_trash')

    def form_valid(self, form):
        messages.success(self.request, _('Password entry deleted successfully!'))
        return super().form_valid(form)
    
    def test_func(self):
        return self.request.user == self.get_object().owner


class PasswordEntriesDelete(View):
    def get(self, request):
        return render(request, 'secret_manager/password_entries_delete.html')
    
    def post(self, request):
        user = request.user
        PasswordEntry.objects.filter(owner=user, is_in_trash=True).delete()

        messages.success(request, "Password entries deleted successfully!")
        return redirect('password_entry_list_trash')


class PasswordEntryToggleTrashView(View):
    def get(self, request, pk):
        # Retrieve the PasswordEntry object if it belongs to the current user
        password_entry = get_object_or_404(PasswordEntry, pk=pk, owner=request.user)

        # Toggle the is_in_trash value
        password_entry.is_in_trash = not password_entry.is_in_trash
        password_entry.save()
    
        # Determine the redirect URL based on the new value
        if password_entry.is_in_trash:
            redirect_url = reverse('password_entry_list')  # Redirect to trash list
            messages.success(request, _('Password entry moved to trash successfully!'))
        else:
            redirect_url = reverse('password_entry_list_trash')
            messages.success(request, _('Password entry restored successfully!'))
        
        return redirect(redirect_url)


class PasswordEntryToggleBookmarksView(View):
    def get(self, request, pk):
        # Retrieve the PasswordEntry object
        password_entry = get_object_or_404(PasswordEntry, pk=pk, owner=request.user)

        # Toggle the is_in_trash value
        password_entry.is_in_bookmarks = not password_entry.is_in_bookmarks
        password_entry.save()
    
        # Rredirect URL based on the new value
        redirect_url = reverse('password_entry_list') 
        if password_entry.is_in_bookmarks:
            messages.success(self.request, _('Password entry added to Bookmarks successfully!'))
        else:
            messages.success(self.request, _('Password entry removed from Bookmarks successfully!'))
        return redirect(redirect_url)
    

# class GeneratePasswordView(View):
#     template_name = 'secret_manager/password_generator.html'

#     def generate_password(self, length=16, symbols=False):
#         characters = string.ascii_letters + string.digits
#         if symbols:
#             characters += string.punctuation

#         password = ''.join(random.choice(characters) for _ in range(length))
#         return password

#     def get(self, request):
#         length = int(request.GET.get('length', 16))
#         symbols = bool(request.GET.get('symbols', False))

#         password = self.generate_password(length, symbols)

#         return render(request, self.template_name, {'password': password})
    

class GeneratePasswordView(View):
    template_name = 'secret_manager/password_generator.html'

    def generate_password(self, length=16, letters=True, numbers=True, symbols=False):
        characters = ''
        if letters:
            characters += string.ascii_letters
        if numbers:
            characters += string.digits
        if symbols:
            characters += string.punctuation

        password = ''.join(random.choice(characters) for _ in range(length))
        return password

    def get(self, request):
        length = int(request.GET.get('length', 16))
        letters = bool(request.GET.get('letters', True))
        numbers = bool(request.GET.get('numbers', True))
        symbols = bool(request.GET.get('symbols', False))

        password = self.generate_password(length, letters, numbers, symbols)

        return render(request, self.template_name, {'password': password})
