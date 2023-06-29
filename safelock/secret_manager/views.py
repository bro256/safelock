from django.shortcuts import render

def index(request):
    context = {
        'test' : 'test',
    }
    return render(request, 'secret_manager/index.html', context)