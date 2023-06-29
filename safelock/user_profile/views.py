from django.shortcuts import render

from django.contrib.auth import authenticate, login
from django.contrib.auth.views import LoginView
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from django.shortcuts import redirect, render

from django.http import HttpResponse

# Create your views here.

