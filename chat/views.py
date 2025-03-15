from django.shortcuts import render, redirect
from django.contrib import messages
from .models import User
from django.urls import reverse
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from django.db import models
from django.utils import timezone

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
            return redirect('chat_list')
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
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.db.models import Q
import json
from datetime import datetime
from .models import User, Chat, Message, Report

@login_required
def chat_list(request):
    print(f"Current user: {request.user.username}")
    print(f"User ID: {request.user.id}")
    
    # Get all chats where the current user is either sender or recipient
    chats = Chat.objects.filter(
        Q(sender=request.user) | Q(recipient=request.user)
    ).order_by('-updated_at')
    
    # Debug print statements
    print(f"Number of chats found: {chats.count()}")
    
    # Print all chats in the database for debugging
    all_chats = Chat.objects.all()
    print(f"Total chats in database: {all_chats.count()}")
    for chat in all_chats:
        print(f"Chat ID: {chat.id}")
        print(f"Sender: {chat.sender.username} (ID: {chat.sender.id})")
        print(f"Recipient: {chat.recipient.username} (ID: {chat.recipient.id})")
        print("---")
    
    # Print user's chats
    print("\nUser's chats:")
    # FOR DEBUGGING
    for chat in chats:
        print(f"Chat ID: {chat.id}")
        print(f"Sender: {chat.sender.username}")
        print(f"Recipient: {chat.recipient.username}")
        print(f"Latest message: {chat.messages.last().content if chat.messages.exists() else 'No messages'}")
        print("---")
    
    return render(request, 'chat.html', {
        'chats': chats,
        'active_chat': None,
        'current_user': request.user
    })

@login_required
def chat_detail(request, chat_id):
    # Get the requested chat
    chat = get_object_or_404(Chat, id=chat_id)
    
    # Security check - ensure the user is part of this chat
    if request.user != chat.sender and request.user != chat.recipient:
        return redirect('chat_list')
    
    # Get all chats for the sidebar
    chats = Chat.objects.filter(
        Q(sender=request.user) | Q(recipient=request.user)
    ).order_by('-updated_at')
    
    # Get messages for this chat
    messages = Message.objects.filter(chat=chat).order_by('sent_at')
    
    return render(request, 'chat.html', {
        'chats': chats,
        'active_chat': chat,
        'active_chat_id': chat.id,
        'messages': messages
    })

@login_required
@require_POST
def search_user(request):
    try:
        data = json.loads(request.body)
        username = data.get('username')
        
        if not username:
            return JsonResponse({'status': 'error', 'message': 'Username is required'})
        
        # Don't let users search for themselves
        if username == request.user.username:
            return JsonResponse({'status': 'error', 'message': 'You cannot chat with yourself'})
        
        try:
            user = User.objects.get(username=username)
            return JsonResponse({
                'status': 'success',
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'profile_picture': user.profile_picture.url if user.profile_picture else None,
                'initials': f"{user.first_name[0]}{user.last_name[0]}"
            })
        except User.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'User not found'})
    except json.JSONDecodeError:
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})

@login_required
@require_POST
def start_chat(request):
    data = json.loads(request.body)
    username = data.get('username')
    
    print(f"Starting chat with username: {username}")
    print(f"Request user: {request.user.username}")
    
    if not username:
        return JsonResponse({'status': 'error', 'message': 'Username is required'})
    
    try:
        recipient = User.objects.get(username=username)
        print(f"Found recipient: {recipient.username}")
        
        # Don't allow starting chat with yourself
        if recipient == request.user:
            return JsonResponse({'status': 'error', 'message': 'You cannot start a chat with yourself'})
        
        # Check if chat already exists
        existing_chat = Chat.objects.filter(
            (Q(sender=request.user) & Q(recipient=recipient)) |
            (Q(sender=recipient) & Q(recipient=request.user))
        ).first()
        
        if existing_chat:
            print(f"Found existing chat with ID: {existing_chat.id}")
            # Update the chat's timestamp to bring it to top
            existing_chat.updated_at = timezone.now()
            existing_chat.save()
            
            return JsonResponse({
                'status': 'success',
                'chat_id': existing_chat.id,
                'message': 'Existing chat opened',
                'recipient': {
                    'first_name': recipient.first_name,
                    'last_name': recipient.last_name,
                    'profile_picture': recipient.profile_picture.url if recipient.profile_picture else None
                }
            })
        
        # Create new chat
        chat = Chat.objects.create(sender=request.user, recipient=recipient)
        print(f"Created new chat with ID: {chat.id}")
        return JsonResponse({
            'status': 'success',
            'chat_id': chat.id,
            'message': 'New chat created',
            'recipient': {
                'first_name': recipient.first_name,
                'last_name': recipient.last_name,
                'profile_picture': recipient.profile_picture.url if recipient.profile_picture else None
            }
        })
    
    except User.DoesNotExist:
        print(f"User not found: {username}")
        return JsonResponse({'status': 'error', 'message': 'User not found'})
    except Exception as e:
        print(f"Error creating chat: {str(e)}")
        return JsonResponse({'status': 'error', 'message': str(e)})

@login_required
@require_POST
def send_message(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        chat_id = data.get('chat_id')
        message_content = data.get('message')
        
        try:
            chat = Chat.objects.get(id=chat_id)
            message = Message.objects.create(
                chat=chat,
                sender=request.user,
                content=message_content,
                sent_at=timezone.now()
            )
            chat.updated_at = timezone.now()
            chat.save()
            
            return JsonResponse({
                'status': 'success',
                'message': message.content,
                'message_id': message.id,
                'sent_at': timezone.localtime(message.sent_at).strftime('%I:%M %p')
            })
        except Chat.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Chat not found'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

@login_required
def check_notifications(request):
    pass

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
    user = request.user
    print(f"Profile picture URL: {user.profile_picture.url if user.profile_picture else 'None'}")
    print(f"Profile picture path: {user.profile_picture.path if user.profile_picture else 'None'}")
    
    if request.method == 'POST':
        if 'profile_picture' in request.FILES:
            user.profile_picture = request.FILES['profile_picture']
            user.save()
            return redirect('profile')
        
        user.first_name = request.POST.get('first_name', user.first_name)
        user.last_name = request.POST.get('last_name', user.last_name)
        user.username = request.POST.get('username', user.username)
        user.email = request.POST.get('email', user.email)
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

@login_required
@require_POST
def report_message(request):
    try:
        data = json.loads(request.body)
        message_id = data.get('message_id')
        
        if not message_id:
            return JsonResponse({'status': 'error', 'message': 'Message ID is required'})
        
        try:
            message = Message.objects.get(id=message_id)
            
            # Check if user has already reported this message
            if Report.objects.filter(message=message, reporter=request.user).exists():
                return JsonResponse({
                    'status': 'error',
                    'message': 'You have already reported this message'
                })
            
            # Create the report
            Report.objects.create(
                message=message,
                reporter=request.user
            )
            
            return JsonResponse({
                'status': 'success',
                'message': 'Message has been reported'
            })
            
        except Message.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Message not found'
            })
            
    except json.JSONDecodeError:
        return JsonResponse({
            'status': 'error',
            'message': 'Invalid JSON data'
        })
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        })
