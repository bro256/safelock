from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('passwords/', views.PasswordEntryListView.as_view(), name='password_entry_list'),
    path('password_entry/create/', views.PasswordEntryCreateView.as_view(), name='password_entry_create'),
    path('password_entry/<int:pk>/', views.PasswordEntryDetailView.as_view(), name='password_entry_detail'),
    # path('derived_key/', views.DerivedKeyView, name='derived_key'),
    path('accounts/login/', views.CustomLoginView.as_view(), name='login'),

    # path('secrets/', views.SecretListView.as_view(), name='secret_list'),
]