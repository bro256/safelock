from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('derived_key/', views.DerivedKeyView, name='derived_key'),
    path('accounts/login/', views.CustomLoginView.as_view(), name='login'),

    # path('secrets/', views.SecretListView.as_view(), name='secret_list'),
]