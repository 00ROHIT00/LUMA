from django.shortcuts import render, redirect
from django.contrib import messages
from .models import User
from django.urls import reverse
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

def home(request):
    return render(request, 'index.html')

from django.contrib.auth import authenticate, login

def signin(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('chat')
        else:
            messages.error(request, "Invalid Username or Password")
            return render(request, 'signin.html')

    return render(request, 'signin.html')

from django.contrib.auth import logout

def logout_view(request):
    logout(request)
    return redirect('home')

def about(request):
    return render(request, 'about.html')

def register(request):
    if request.method == 'POST':
        first_name = request.POST.get('firstname')
        last_name = request.POST.get('lastname')
        email = request.POST.get('email')
        username = request.POST.get('username')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if password != confirm_password:
            messages.error(request, "Passwords do not match")
            return render(request, 'register.html')

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken")
            return render(request, 'register.html')

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already registered")
            return render(request, 'register.html')

        user = User.objects.create(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name
        )

        user.set_password(password)
        user.save()

        messages.success(request, "Account created successfully")
        return redirect('signin')

    return render(request, 'register.html')

from django.contrib.auth.decorators import login_required

@login_required
def chat_view(request):
    return render(request, 'chat.html')

@login_required
def check_notifications(request):
    pass

@csrf_exempt
def search_user(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        username = data.get('username')

        try:
            user = User.objects.get(username=username)
            return JsonResponse({
                'status': 'success',
                'first_name': user.first_name,
                'last_name': user.last_name
            })
        except User.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'User not found'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})
