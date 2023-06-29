from django.shortcuts import render
from django.views import generic

def index(request):
    context = {
        'test' : 'test',
    }
    return render(request, 'secret_manager/index.html', context)

