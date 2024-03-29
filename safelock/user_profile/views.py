from django.contrib.auth import get_user_model
from django.contrib import messages
from django.shortcuts import render, get_object_or_404, redirect
from django.views.decorators.csrf import csrf_protect

from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView

User = get_user_model()

# @csrf_protect
def signup(request):
    if request.user.is_authenticated:
        messages.info(request, 'In order to sign up, you need to logout first')
        return redirect('index')
    if request.method == "POST":
        error = False
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        password_confirm = request.POST.get('password_confirm')
        if not username or len(username) < 5 or User.objects.filter(username=username).exists():
            error = True
            messages.error(request, 'Username is too short or already exists.')
        if not email or len(email) < 5 or User.objects.filter(email=email).exists():
            error = True
            messages.error(request, 'Email is invalid or user with this email already exists.')
        if not password or not password_confirm or password != password_confirm or len(password) < 8:
            error = True
            messages.error(request, "Password must be at least 8 characters long and match.")
        if not error:
            user = User.objects.create(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
            )
            user.set_password(password)
            user.save()
            messages.success(request, "User registration successful!")
            return redirect('login')
    return render(request, 'user_profile/signup.html')



class ProfileView(LoginRequiredMixin, TemplateView):
    template_name = 'user_profile/profile.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['user'] = self.request.user
        return context
    
