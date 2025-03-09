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

# @csrf_exempt
# def search_user(request):
#     if request.method == 'POST':
#         data = json.loads(request.body)
#         username = data.get('username')

#         try:
#             user = User.objects.get(username=username)
#             return JsonResponse({
#                 'status': 'success',
#                 'first_name': user.first_name,
#                 'last_name': user.last_name
#             })
#         except User.DoesNotExist:
#             return JsonResponse({'status': 'error', 'message': 'User not found'})
#     return JsonResponse({'status': 'error', 'message': 'Invalid request method'})


from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from .models import User
import json

@csrf_exempt
def search_user(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')

            if not username:
                return JsonResponse({'status': 'error', 'message': 'Username is required'})

            user = User.objects.get(username=username)
            return JsonResponse({
                'status': 'success',
                'first_name': user.first_name,
                'last_name': user.last_name
            })
        except User.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'User not found'})
        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})


from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages

def admin_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            if user.is_admin:
                login(request, user)
                return redirect('admin_dashboard')  # Ensure 'admin_dashboard' is mapped correctly in your urls.py
            else:
                messages.error(request, 'You are not authorized to access the admin area.')
        else:
            messages.error(request, 'Invalid username or password.')

    return render(request, 'admin_login.html')

def admin_dashboard(request):
    return render(request, 'admin_dashboard.html')

from django.http import JsonResponse
from .models import User

def user_count(request):
    user_count = User.objects.count()
    return JsonResponse({'user_count': user_count})


from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from .models import User

@login_required
def manage_users(request):
    users = User.objects.all()
    return render(request, 'admin_users.html', {'users': users})

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import User

@login_required
def delete_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.delete()
    messages.success(request, 'User has been deleted successfully.')
    return redirect('manage_users')

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import User

@login_required
def edit_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    return render(request, 'admin_userEdit.html', {'user': user})

@login_required
def update_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    if request.method == 'POST':
        user.username = request.POST['username']
        user.first_name = request.POST['first_name']
        user.last_name = request.POST['last_name']
        user.email = request.POST['email']
        user.is_active = 'is_active' in request.POST
        user.is_admin = 'is_admin' in request.POST
        user.save()
        messages.success(request, f"{user.first_name}'s details have been updated successfully.")
        return redirect('manage_users')
    return render(request, 'admin_userEdit.html', {'user': user})

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import User

@login_required
def profile(request):
    if request.method == 'POST':
        user = request.user
        user.first_name = request.POST['first_name']
        user.last_name = request.POST['last_name']
        user.username = request.POST['username']
        user.email = request.POST['email']
        user.save()
        messages.success(request, 'Your profile was successfully updated!')
        return redirect('profile')
    
    return render(request, 'profile.html')

@login_required
def delete_account(request):
    if request.method == 'POST':
        user = request.user
        user.delete()
        messages.success(request, 'Your account was successfully deleted!')
        return redirect('home')
    
    return render(request, 'delete_account.html')
