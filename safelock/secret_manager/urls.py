from django.urls import path
from . import views

from .views import generate_password

urlpatterns = [
    path('', views.index, name='index'),
    path('password_entries/', views.PasswordEntryListView.as_view(), name='password_entry_list'),
    path('password_entries/favorites/', views.PasswordEntryListView.as_view(is_favorites_page=True), name='password_entry_list_favorites'),
    path('password_entries/trash/', views.PasswordEntryTrashListView.as_view(), name='password_entry_list_trash'),
    path('password_entries/delete/', views.PasswordEntriesDelete.as_view(), name='password_entries_delete'),
    path('password_entries/import/', views.PasswordEntriesImportView.as_view(), name='password_entries_import'),
    path('password_entries/export/', views.PasswordEntriesExportView.as_view(), name='password_entries_to_csv'),
    path('password_entry/<int:pk>/', views.PasswordEntryDetailView.as_view(), name='password_entry_detail'),
    path('password_entry/create/', views.PasswordEntryCreateView.as_view(), name='password_entry_create'),
    path('password_entry/update/<int:pk>/', views.PasswordEntryUpdateView.as_view(), name='password_entry_update'),
    path('password_entry/delete/<int:pk>/', views.PasswordEntryDeleteView.as_view(), name='password_entry_delete'),
    path('password_entry/toggle_trash/<int:pk>/', views.PasswordEntryToggleTrashView.as_view(), name='password_entry_toggle_trash'),
    path('password_entry/toggle_bookmarks/<int:pk>/', views.PasswordEntryToggleBookmarksView.as_view(), name='password_entry_to_bookmarks'),
    path('accounts/login/', views.CustomLoginView.as_view(), name='login'),
    path('accounts/password_change/', views.CustomPasswordChangeView.as_view(template_name='registration/password_change.html'), name='password_change'),
    path('password_generator/', views.PasswordGeneratorView.as_view(), name='password_generator'),
    path('generate-password/', generate_password, name='generate_password'),
]
