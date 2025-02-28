from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from .models import User
from django.urls import reverse



def home(request):
    return render(request, 'index.html') 


def signin(request):
    return render(request, 'signIn.html')

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

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name
        )
        user.save()
        messages.success(request, "Account created successfully")
        return render(request, 'register.html', {'redirect_url': reverse('signin')})  # Pass redirect URL to template

    return render(request, 'register.html')






