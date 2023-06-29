from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    # path('secrets/', views.SecretListView.as_view(), name='secret_list'),
]