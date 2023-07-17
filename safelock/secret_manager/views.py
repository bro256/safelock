import csv
from . forms import PasswordEntryForm, PasswordEntryUpdateForm
from . models import PasswordEntry
from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.views import LoginView, PasswordChangeView
from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import redirect, render, get_object_or_404, redirect
from django.urls import reverse, reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views import generic, View
from django.views.generic.edit import UpdateView, DeleteView
from io import StringIO
from typing import Any, Dict

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

        # Derive key
        derived_key = derive_key(username, password)
        self.request.session['derived_key'] = derived_key

        return super().form_valid(form)


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
    

class PasswordEntryListView(LoginRequiredMixin, generic.ListView):
    model = PasswordEntry
    paginate_by = 10
    template_name = "secret_manager/password_entry_list.html"
    is_favorites_page = False  # Default value for is_favorites_page

    def get_queryset(self):
        qs = self.model.objects.filter(owner=self.request.user, is_in_trash=False)

        if self.is_favorites_page:
            qs = qs.filter(is_in_bookmarks=True)

        query = self.request.GET.get('query')
        if query:
            qs = qs.filter(
                Q(website__icontains=query) |
                Q(title__icontains=query)
            )
        return qs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['is_favorites_page'] = self.is_favorites_page
        return context
    

class PasswordEntryTrashListView(LoginRequiredMixin, generic.ListView):
    model = PasswordEntry
    paginate_by = 10
    template_name = "secret_manager/password_entry_trash_list.html"
    
    def get_queryset(self):
        return self.model.objects.filter(owner=self.request.user, is_in_trash=True)


class PasswordEntryCreateView(LoginRequiredMixin, generic.CreateView):
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
            derived_key_hex = self.request.session.get('derived_key')

            # Encrypt password and get encryption data
            encryption_data = encrypt_password(password_bytes, derived_key_hex)
            encrypted_password, encryption_iv, auth_tag = encryption_data

            # Save the encrypted password, IV, and auth-tag to the model instance
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


class PasswordEntryDetailView(LoginRequiredMixin, UserPassesTestMixin, generic.DetailView):
    model = PasswordEntry
    template_name = "secret_manager/password_entry_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Retrieve the derived key
        derived_key_hex = self.request.session.get('derived_key')

        # Decrypt the password
        decrypted_password_byte_string = decrypt_password(self.object, derived_key_hex)

        # Convert the decrypted password to a string
        decrypted_password = decrypted_password_byte_string.decode('utf-8')

        context['decrypted_password'] = decrypted_password

        return context
    
    def test_func(self):
        obj = self.get_object()
        return obj.owner == self.request.user


class PasswordEntryUpdateView(LoginRequiredMixin, UserPassesTestMixin, UpdateView):
    model = PasswordEntry
    form_class = PasswordEntryUpdateForm
    template_name = 'secret_manager/password_entry_form.html'
    success_url = 'password_entry_list'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Retrieve the derived key
        derived_key_hex = self.request.session.get('derived_key')

        # derived_key = bytes.fromhex(derived_key_hex)
        decrypted_password_byte_string = decrypt_password(self.object, derived_key_hex)
        
        # Convert the decrypted password to a string
        decrypted_password = decrypted_password_byte_string.decode('utf-8')

        # Add the decrypted password to the context
        context['password'] = decrypted_password

        # Set the decrypted password value in the form field initial data
        context['form'].initial['password'] = decrypted_password

        return context

    def form_valid(self, form):

        # Create database instance without saving to database immediately
        instance = form.save(commit=False)
        
        # Convert the password to bytes
        password_bytes = form.cleaned_data['password'].encode()

        # Retrieve the derived key
        derived_key_hex = self.request.session.get('derived_key')
        
        # Encrypt password
        encryption_data = encrypt_password(password_bytes, derived_key_hex)

        # Get encryption data
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


class PasswordEntriesDelete(LoginRequiredMixin, View):
    def get(self, request):
        return render(request, 'secret_manager/password_entries_delete.html')
    
    def post(self, request):
        user = request.user
        PasswordEntry.objects.filter(owner=user, is_in_trash=True).delete()
        messages.success(request, "Password entries deleted successfully!")
        return redirect('password_entry_list_trash')


class PasswordEntryToggleTrashView(LoginRequiredMixin, View):
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


class PasswordEntryToggleBookmarksView(LoginRequiredMixin, View):
    def get(self, request, pk):

        # Retrieve the PasswordEntry object if it belongs to the current user
        password_entry = get_object_or_404(PasswordEntry, pk=pk, owner=request.user)

        # Toggle the is_in_trash value
        password_entry.is_in_bookmarks = not password_entry.is_in_bookmarks
        password_entry.save()
    
        # Rredirect URL based on the new value
        redirect_url = reverse('password_entry_list') 

        return redirect(redirect_url)
       

class PasswordGeneratorView(LoginRequiredMixin, View):
    template_name = 'secret_manager/password_generator.html'
    
    def get(self, request):
        return render(request, self.template_name)
    

class PasswordEntriesExportView(LoginRequiredMixin, View):
    def get(self, request):

        # Retrieve the encrypted passwords from the database
        password_entries = PasswordEntry.objects.filter(owner=request.user, is_in_trash=False)

        # Create the CSV data
        csv_data = StringIO()
        writer = csv.writer(csv_data)
        writer.writerow(['Title', 'Username', 'Website', 'Password'])  # CSV header

        # Retrieve the derived key
        derived_key_hex = request.session.get('derived_key')

        # Decrypt and write each password entry to the CSV
        for entry in password_entries:
            decrypted_password_byte_string = decrypt_password(entry, derived_key_hex)

            # Convert the decrypted password to a string
            decrypted_password = decrypted_password_byte_string.decode('utf-8')
            writer.writerow([entry.title, entry.username, entry.website, decrypted_password])

        # Create the HttpResponse object with CSV content type
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="safelock_passwords.csv"'

        # Write the CSV data to the response
        response.write(csv_data.getvalue())

        return response


class PasswordEntriesImportView(LoginRequiredMixin, View):
    def post(self, request):
        csv_file = request.FILES.get('csv_file')

        # Check if the file has a valid format
        if not csv_file.name.endswith('.csv'):
            messages.warning(request, 'Invalid file format. Please upload a CSV file.')
            return redirect('profile')

        try:
            # Read the CSV file data
            csv_data = csv_file.read().decode('utf-8')

            # Parse the CSV data
            reader = csv.reader(csv_data.splitlines())
            header = next(reader)  # Skip the header row

            # Retrieve the derived key
            derived_key_hex = request.session.get('derived_key')

            # Process the CSV data and import the password entries
            for row in reader:

                # Extract the relevant data from each row (record)
                title = row[0]  # First column of the row
                username = row[1]  # Second column of the row
                website = row[2]  # Third column of the row
                password_bytes = row[3].encode()  # Fourth column of the row
                
                encryption_data = encrypt_password(password_bytes, derived_key_hex)
                encrypted_password, encryption_iv, auth_tag = encryption_data

                # Create and save the PasswordEntry object with encrypted password
                password_entry = PasswordEntry(
                    owner=request.user,
                    title=title,
                    username=username,
                    encrypted_password=encrypted_password,
                    encryption_iv=encryption_iv,
                    auth_tag=auth_tag, 
                    website=website,    
                )
                password_entry.save()
            
            messages.success(request, 'CSV file imported successfully.')
            return redirect('profile')
        
        except csv.Error as e:
            messages.error(request, 'Error processing CSV file: {}'.format(str(e)))
            return redirect('profile')
