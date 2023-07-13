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

import random
import string

# All cryptography related functions located in cryptography.py file
from .cryptography import generate_password, derive_key, reencrypt_all_passwords, encrypt_password, decrypt_password


def index(request):
    context = {
        'test' : 'test',
    }
    return render(request, 'secret_manager/index.html', context)


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
    

class PasswordEntryTrashListView(generic.ListView):
    model = PasswordEntry
    paginate_by = 10
    template_name = "secret_manager/password_entry_trash_list.html"
    
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
            password_bytes = form.cleaned_data['password'].encode()
            key_in_hex = self.request.session.get('derived_key')

            # Calling password encryption function
            encryption_data = encrypt_password(password_bytes, key_in_hex)

            encrypted_password, encryption_iv, auth_tag = encryption_data

            # Save the encrypted password, IV, and tag to the model instance
            instance = form.save(commit=False)
            instance.owner = request.user
            instance.encrypted_password = encrypted_password
            instance.encryption_iv = encryption_iv
            instance.auth_tag = auth_tag
            instance.save()
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

        # Retrieve the derived key from the session
        derived_key_in_hex = self.request.session.get('derived_key')
        # derived_key = bytes.fromhex(derived_key_in_hex)

        # Retrieve the current PasswordEntry object
        password_entry = self.get_object()

        # Call the decrypt_password function to decrypt the password
        decrypted_password_byte_string = decrypt_password(password_entry, derived_key_in_hex)

        # Convert the decrypted password to a string
        decrypted_password = decrypted_password_byte_string.decode('utf-8')

        context['decrypted_password'] = decrypted_password

        return context
    
    def test_func(self):
        obj = self.get_object()
        return obj.owner == self.request.user

    
class CustomPasswordChangeView(PasswordChangeView):

    def form_valid(self, form):
        # Change the user's password
        response = super().form_valid(form)

        # Reencrypt passwords with the new password
        reencrypt_all_passwords(self.request.user, form.cleaned_data['old_password'], form.cleaned_data['new_password2'])
        
        # Log out the user to get new PBKDF2 derived key
        logout(self.request)
        messages.success(self.request, _('Password changed successfuly!'))

        return response

    def get_success_url(self):
        return self.success_url


class PasswordEntryUpdateView(UserPassesTestMixin, UpdateView):
    model = PasswordEntry
    form_class = PasswordEntryUpdateForm
    template_name = 'secret_manager/password_entry_form.html'
    success_url = 'password_entry_list'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Retrieve the derived key from the session
        derived_key_in_hex = self.request.session.get('derived_key')
        # derived_key = bytes.fromhex(derived_key_in_hex)
        decrypted_password_byte_string = decrypt_password(self.object, derived_key_in_hex)
        
        # Convert the decrypted password to a string
        decrypted_password = decrypted_password_byte_string.decode('utf-8')

        # Add the decrypted password to the context
        context['password'] = decrypted_password
        print(context)

        # Set the decrypted password value in the form field initial data
        context['form'].initial['password'] = decrypted_password

        return context

    def form_valid(self, form):
        # Operations before saving
        instance = form.save(commit=False)
        
        password_bytes = form.cleaned_data['password'].encode()
        key_in_hex = self.request.session.get('derived_key')
        
        # Calling password encryption function
        encryption_data = encrypt_password(password_bytes, key_in_hex)

        encrypted_password, encryption_iv, auth_tag = encryption_data

        # Save the encrypted password, IV, and tag to the model instance
        instance = form.save(commit=False)
        instance.encrypted_password = encrypted_password
        instance.encryption_iv = encryption_iv
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
       

class PasswordGeneratorView(View):
    template_name = 'secret_manager/password_generator.html'

    # def generate_password(self, length=16, letters=True, numbers=True, symbols=False):
    #     characters = ''
    #     if letters:
    #         characters += string.ascii_letters
    #     if numbers:
    #         characters += string.digits
    #     if symbols:
    #         characters += string.punctuation

    #     password = ''.join(random.choice(characters) for _ in range(length))
    #     return password

    # def get(self, request):
    #     length = int(request.GET.get('length', 16))
    #     letters = bool(request.GET.get('letters', True))
    #     numbers = bool(request.GET.get('numbers', True))
    #     symbols = bool(request.GET.get('symbols', False))

    #     password = self.generate_password(length, letters, numbers, symbols)

    #     return render(request, self.template_name, {'password': password})
    
    def get(self, request):
        return render(request, self.template_name)
