from django.shortcuts import render

def home(request):
    return render(request, 'index.html') 

from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages

def register(request):
    return render(request, "register.html")

def signin(request):
    return render(request, 'signIn.html')

def about(request):
    return render(request, 'about.html')