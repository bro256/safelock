from django.urls import path
from . import views
from .views import ProfileView

urlpatterns = [
    path('signup/', views.signup, name='signup'),
    path('profile/', ProfileView.as_view(), name='profile'),
]
    