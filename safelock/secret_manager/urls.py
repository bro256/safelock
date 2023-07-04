from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('passwords/', views.PasswordEntryListView.as_view(), name='password_entry_list'),
    path('passwords/trash/', views.PasswordEntryListTrashView.as_view(), name='password_entry_list_trash'),
    path('password_entry/create/', views.PasswordEntryCreateView.as_view(), name='password_entry_create'),
    path('password_entry/<int:pk>/', views.PasswordEntryDetailView.as_view(), name='password_entry_detail'),
    path('password_entry/update/<int:pk>/', views.PasswordEntryUpdateView.as_view(), name='password_entry_update'),
    path('password_entry/delete/<int:pk>/', views.PasswordEntryDeleteView.as_view(), name='password_entry_delete'),
    path('password_entry/toggle_to_trash/<int:pk>/', views.PasswordEntryToggleTrashView.as_view(), name='password_entry_to_trash'),
    path('password_entry/toggle_to_bookmarks/<int:pk>/', views.PasswordEntryToggleBookmarksView.as_view(), name='password_entry_to_bookmarks'),
    path('accounts/login/', views.CustomLoginView.as_view(), name='login'),
    path('accounts/password_change/', views.CustomPasswordChangeView.as_view(), name='password_change'),

    # path('secrets/', views.SecretListView.as_view(), name='secret_list'),
]