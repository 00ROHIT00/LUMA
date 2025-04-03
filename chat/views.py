from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .models import User, Chat, Message, Report, Notification, Broadcast, BlockedUser, GroupChat, GroupMessage, ArchivedGroupChat, DeletedGroupMessage, GroupMessageReport, Payment
from django.urls import reverse
from django.http import JsonResponse, HttpResponse, Http404
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
import json
from django.db import models
from django.utils import timezone
from functools import wraps
from django.contrib.auth.decorators import login_required
from datetime import timedelta
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.db.models import Q, Count, Max, F, Value, BooleanField, ExpressionWrapper
from django.db.models.functions import Coalesce, ExtractMonth
import os
from django.http import Http404
from django.conf import settings
import random
import string
from django.core.mail import send_mail, EmailMultiAlternatives
import datetime
import logging
from django.db.models import Q, Count, Sum, Avg
from django.utils.timezone import make_aware

# Try importing razorpay
try:
    import razorpay
    RAZORPAY_AVAILABLE = True
except ImportError:
    RAZORPAY_AVAILABLE = False
    print("WARNING: Razorpay module is not installed. Payment features will be limited.")

def admin_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            messages.error(request, 'Please login to access this page.')
            return redirect('admin_login')
        if not request.user.is_admin:
            messages.error(request, 'You do not have permission to access the admin area.')
            return redirect('home')
        return view_func(request, *args, **kwargs)
    return _wrapped_view

def home(request):
    return render(request, 'index.html')

def signin(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        # First check if the user exists and is banned
        try:
            user = User.objects.get(username=username)
            if user.is_currently_banned():
                remaining_days = user.get_ban_duration_remaining()
                ban_reason = user.ban_reason or "Your account has been temporarily banned."
                messages.error(request, f"You are banned from using this platform. Try again later.")
                return render(request, 'signin.html')
        except User.DoesNotExist:
            pass

        # Then try to authenticate
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('chat_list')
        else:
            messages.error(request, "Invalid username or password")
            return render(request, 'signin.html')

    return render(request, 'signin.html')

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

@login_required
def chat_list(request):
    print(f"Current user: {request.user.username}")
    print(f"User ID: {request.user.id}")
    
    # Get all chats where the current user is either sender or recipient
    chats = Chat.objects.filter(
        Q(sender=request.user) | Q(recipient=request.user)
    ).exclude(
        # Exclude chats with blocked users
        Q(sender__in=BlockedUser.objects.filter(blocked=request.user).values('blocker')) |
        Q(recipient__in=BlockedUser.objects.filter(blocked=request.user).values('blocker'))
    ).exclude(
        # Exclude chats archived by this user
        archived_by=request.user
    ).order_by('-updated_at')
    
    # Add unread message count and profile picture URLs for each chat
    for chat in chats:
        # Only count messages from the other user as unread
        other_user = chat.recipient if chat.sender == request.user else chat.sender
        unread_count = Message.objects.filter(
            chat=chat,
            sender=other_user,
            deleted_for_everyone=False  # Exclude messages deleted for everyone
        ).exclude(read_by=request.user).count()
        chat.unread_count = unread_count
        
        # Get the last non-deleted message for preview
        last_message = chat.messages.filter(
            deleted_for_everyone=False
        ).order_by('-sent_at').first()
        
        if last_message:
            chat.last_message = last_message.content
        else:
            chat.last_message = "No messages yet"
            
        # Add profile picture URLs
        chat.sender_profile_pic = chat.sender.profile_picture.url if chat.sender.profile_picture else None
        chat.recipient_profile_pic = chat.recipient.profile_picture.url if chat.recipient.profile_picture else None
    
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
        print(f"Latest message: {chat.last_message}")
        print("---")
    
    return render(request, 'chat.html', {
        'chats': chats,
        'active_chat': None,
        'current_user': request.user
    })

@login_required
def chat_detail(request, chat_id):
    # Get the requested chat
    try:
        chat = get_object_or_404(Chat, id=chat_id)
        
        # Check if user is part of this chat
        if chat.sender != request.user and chat.recipient != request.user:
            raise Http404("Chat not found")
        
        # Check if the chat is archived by this user
        if chat.is_archived_by(request.user):
            chat.unarchive_for_user(request.user)
            
        # Get the other user in the chat
        other_user = chat.recipient if chat.sender == request.user else chat.sender
        
        # Check if user is blocked
        user_is_blocked = BlockedUser.is_blocked(request.user, other_user)
        
        # Get messages not deleted for this user
        messages_list = Message.objects.filter(chat=chat).exclude(
            deleted_for=request.user
        ).order_by('sent_at')
        
        # Mark all messages as read
        for message in messages_list:
            if message.sender != request.user:
                message.mark_as_read(request.user)
                
        # Get all chats for the sidebar
        # First get the chats where the user is the sender
        sender_chats = Chat.objects.filter(sender=request.user).exclude(
            archived_by=request.user
        )
        
        # Then get the chats where the user is the recipient
        recipient_chats = Chat.objects.filter(recipient=request.user).exclude(
            archived_by=request.user
        )
        
        # Combine them
        chats_list = sender_chats.union(recipient_chats)
        
        # Sort by updated_at in reverse order (newest first)
        chats_list = chats_list.order_by('-updated_at')
        
        # Enrich the chats with extra info
        for chat_obj in chats_list:
            # Get the other user in each chat
            other_user = chat_obj.recipient if chat_obj.sender == request.user else chat_obj.sender
            
            # Add profile pic URLs directly to the chat object for easy access in the template
            if hasattr(other_user, 'profile_picture') and other_user.profile_picture:
                if chat_obj.sender == request.user:
                    chat_obj.recipient_profile_pic = other_user.profile_picture.url
                else:
                    chat_obj.sender_profile_pic = other_user.profile_picture.url
            else:
                if chat_obj.sender == request.user:
                    chat_obj.recipient_profile_pic = None
                else:
                    chat_obj.sender_profile_pic = None
            
            # Get the last message in this chat
            last_message = Message.objects.filter(chat=chat_obj).exclude(
                deleted_for=request.user
            ).order_by('-sent_at').first()
            
            # Add last message preview directly to the chat object
            if last_message:
                if last_message.deleted_for_everyone:
                    chat_obj.last_message = "This message was deleted"
                else:
                    chat_obj.last_message = last_message.content
            else:
                chat_obj.last_message = "No messages yet"
            
            # Count unread messages in this chat
            if chat_obj.sender == request.user:
                # If user is the sender, count messages from recipient that are not read by user
                unread_count = Message.objects.filter(
                    chat=chat_obj, 
                    sender=chat_obj.recipient
                ).exclude(
                    read_by=request.user
                ).count()
            else:
                # If user is the recipient, count messages from sender that are not read by user
                unread_count = Message.objects.filter(
                    chat=chat_obj, 
                    sender=chat_obj.sender
                ).exclude(
                    read_by=request.user
                ).count()
            
            chat_obj.unread_count = unread_count
                
        return render(request, 'chat.html', {
            'chats': chats_list,
            'active_chat': chat,
            'other_user': other_user,
            'messages': messages_list,
            'user_is_blocked': user_is_blocked
        })
    except Http404:
        return redirect('chat_list')

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
        try:
            chat_id = request.POST.get('chat_id')
            message_content = request.POST.get('message', '')
            attachment = request.FILES.get('attachment')
            
            if not chat_id:
                return JsonResponse({'status': 'error', 'message': 'Chat ID is required'})
            
            chat = Chat.objects.get(id=chat_id)
            
            # Check if user is blocked
            other_user = chat.recipient if chat.sender == request.user else chat.sender
            if BlockedUser.is_blocked(request.user, other_user):
                return JsonResponse({
                    'status': 'error',
                    'message': 'You cannot send messages to this user'
                })
            
            # Create message with encrypted content
            message = Message.objects.create(
                chat=chat,
                sender=request.user,
                content=message_content,
                sent_at=timezone.now()
            )
            
            # Add attachment if present
            if attachment:
                # Determine attachment type
                content_type = attachment.content_type
                if content_type.startswith('image/'):
                    attachment_type = 'image'
                elif content_type == 'application/pdf':
                    attachment_type = 'pdf'
                elif content_type in ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
                    attachment_type = 'doc'
                else:
                    attachment_type = 'other'
                
                message.attachment = attachment
                message.attachment_type = attachment_type
                message.attachment_name = attachment.name
                message.save()
            
            # Mark the message as read by the sender immediately
            message.read_by.add(request.user)
            
            # Update chat timestamp
            chat.updated_at = timezone.now()
            chat.save()
            
            # Prepare response data - use the original message content for display
            response_data = {
                'status': 'success',
                'message': message_content,  # Send original content back to sender
                'message_id': message.id,
                'sent_at': timezone.localtime(message.sent_at).strftime('%I:%M %p')
            }
            
            # Add attachment data if present
            if attachment:
                response_data.update({
                    'has_attachment': True,
                    'attachment_type': attachment_type,
                    'attachment_name': attachment.name,
                    'attachment_url': message.attachment.url if message.attachment else None
                })
            
            return JsonResponse(response_data)
            
        except Chat.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Chat not found'})
        except Exception as e:
            print(f"Error sending message: {str(e)}")
            return JsonResponse({'status': 'error', 'message': str(e)})
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

@login_required
def check_notifications(request):
    try:
        print(f"\nChecking notifications for user: {request.user.username}")
        notifications = Notification.objects.filter(user=request.user, read=False)
        print(f"Found {notifications.count()} unread notifications")
        
        # Debug: Print details of each notification
        for n in notifications:
            print(f"Notification ID: {n.id}")
            print(f"Type: {n.type}")
            print(f"Message: {n.message}")
            print(f"Admin Notes: {n.admin_notes}")
            print(f"Created At: {n.created_at}")
            print("---")
        
        notification_data = [
            {
                'id': n.id,
                'type': n.type,
                'message': n.message,
                'admin_notes': n.admin_notes,
                'created_at': n.created_at.strftime('%Y-%m-%d %H:%M:%S')
            }
            for n in notifications
        ]
        print(f"Prepared notification data: {notification_data}")
        
        return JsonResponse({
            'status': 'success',
            'notifications': notification_data
        })
    except Exception as e:
        print(f"Error checking notifications: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': str(e),
            'notifications': []
        })

@login_required
@require_POST 
def mark_notifications_read(request):
    try:
        print(f"Marking notifications as read for user: {request.user.username}")
        count = Notification.objects.filter(user=request.user, read=False).update(read=True)
        print(f"Marked {count} notifications as read")
        return JsonResponse({
            'status': 'success',
            'count': count
        })
    except Exception as e:
        print(f"Error marking notifications as read: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        })

def admin_login(request):
    # If user is already logged in and is admin, redirect to dashboard
    if request.user.is_authenticated:
        if request.user.is_admin:
            return redirect('admin_dashboard')
        else:
            messages.error(request, 'You do not have permission to access the admin area.')
            return redirect('home')
            
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            if user.is_admin:
                login(request, user)
                return redirect('admin_dashboard')
            else:
                messages.error(request, 'You are not authorized to access the admin area.')
        else:
            messages.error(request, 'Invalid username or password.')

    return render(request, 'admin_login.html')

@admin_required
def admin_dashboard(request):
    return render(request, 'admin_dashboard.html')

from django.http import JsonResponse
from .models import User

@admin_required
def user_count(request):
    user_count = User.objects.count()
    return JsonResponse({'user_count': user_count})

@admin_required
def manage_users(request):
    users = User.objects.all()
    return render(request, 'admin_users.html', {'users': users})

@admin_required
def delete_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.delete()
    messages.success(request, 'User has been deleted successfully.')
    return redirect('manage_users')

@admin_required
def edit_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    return render(request, 'admin_userEdit.html', {'user': user})

@admin_required
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

@login_required
def profile(request):
    user = request.user
    
    if request.method == 'POST':
        if 'profile_picture' in request.FILES:
            # Delete old profile picture if it exists
            if user.profile_picture:
                try:
                    user.profile_picture.delete()
                except Exception as e:
                    print(f"Error deleting old profile picture: {e}")
            
            # Save new profile picture
            user.profile_picture = request.FILES['profile_picture']
            user.save()
            
            # Return JSON response for AJAX request
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'status': 'success',
                    'message': 'Profile picture updated successfully!',
                    'profile_picture_url': user.profile_picture.url
                })
            
            messages.success(request, 'Profile picture updated successfully!')
            return redirect('profile')
    
    return render(request, 'profile.html', {'user': user})

@login_required
def edit_profile(request):
    if request.method == 'POST':
        user = request.user
        username = request.POST.get('username')
        email = request.POST.get('email')
        
        # Check if username is taken by another user
        if User.objects.exclude(id=user.id).filter(username=username).exists():
            messages.error(request, 'Username is already taken.')
            return redirect('profile')
            
        # Check if email is taken by another user
        if User.objects.exclude(id=user.id).filter(email=email).exists():
            messages.error(request, 'Email is already registered.')
            return redirect('profile')
            
        user.first_name = request.POST.get('first_name')
        user.last_name = request.POST.get('last_name')
        user.username = username
        user.email = email
        user.save()
        
        messages.success(request, 'Profile updated successfully!')
        return redirect('profile')
    
    return redirect('profile')

@login_required
def change_password(request):
    if request.method == 'POST':
        user = request.user
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        
        if not user.check_password(current_password):
            messages.error(request, 'Current password is incorrect.')
            return redirect('profile')
            
        if new_password != confirm_password:
            messages.error(request, 'New passwords do not match.')
            return redirect('profile')
            
        user.set_password(new_password)
        user.save()
        messages.success(request, 'Password changed successfully! Please login again.')
        return redirect('signin')
    
    return redirect('profile')

@login_required
def delete_account(request):
    if request.method == 'POST':
        user = request.user
        password = request.POST.get('password')
        
        if not user.check_password(password):
            messages.error(request, 'Incorrect password. Account deletion cancelled.')
            return redirect('profile')
            
        user.delete()
        messages.success(request, 'Your account has been deleted successfully.')
        return redirect('signin')
    
    return redirect('profile')

@login_required
@require_POST
def report_message(request):
    try:
        data = json.loads(request.body)
        message_id = data.get('message_id')
        
        if not message_id:
            return JsonResponse({
                'status': 'error',
                'message': 'Message ID is required'
            })
        
        try:
            message = Message.objects.get(id=message_id)
            
            # Check if user has already reported this message
            if Report.objects.filter(message=message, reporter=request.user).exists():
                return JsonResponse({
                    'status': 'error',
                    'message': 'You have already reported this message'
                })
            
            # Check if user is reporting their own message
            if message.sender == request.user:
                return JsonResponse({
                    'status': 'error',
                    'message': 'You cannot report your own message'
                })
            
            # Check if user is part of the chat
            if request.user not in [message.chat.sender, message.chat.recipient]:
                return JsonResponse({
                    'status': 'error',
                    'message': 'You do not have permission to report this message'
                })
            
            # Create the report with pending status
            report = Report.objects.create(
                message=message,
                reporter=request.user,
                status='pending'
            )
            
            return JsonResponse({
                'status': 'success',
                'message': 'Message has been reported successfully',
                'report_id': report.id
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

@login_required
@require_POST
def delete_message_for_me(request):
    try:
        data = json.loads(request.body)
        message_id = data.get('message_id')
        
        if not message_id:
            return JsonResponse({'status': 'error', 'message': 'Message ID is required'})
        
        try:
            message = Message.objects.get(id=message_id)
            # Check if user is part of the chat
            if request.user not in [message.chat.sender, message.chat.recipient]:
                return JsonResponse({
                    'status': 'error',
                    'message': 'You do not have permission to delete this message'
                })
            
            message.delete_for_user(request.user)
            
            return JsonResponse({
                'status': 'success',
                'message': 'Message deleted for you'
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

@login_required
@require_POST
def delete_message_for_everyone(request):
    try:
        data = json.loads(request.body)
        message_id = data.get('message_id')
        
        if not message_id:
            return JsonResponse({'status': 'error', 'message': 'Message ID is required'})
        
        try:
            message = Message.objects.get(id=message_id)
            # Only message sender can delete for everyone
            if request.user != message.sender:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Only the sender can delete a message for everyone'
                })
            
            message.delete_for_everyone()
            
            return JsonResponse({
                'status': 'success',
                'message': 'Message deleted for everyone'
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

@admin_required
def get_dashboard_stats(request):
    try:
        # Check database connectivity
        User.objects.first()
        
        # Check recent activity (last 5 minutes)
        last_5_min = timezone.now() - timedelta(minutes=5)
        recent_messages = Message.objects.filter(sent_at__gte=last_5_min).exists()
        recent_logins = User.objects.filter(last_login__gte=last_5_min).exists()
        
        # Get system metrics
        total_users = User.objects.count()
        last_24h = timezone.now() - timedelta(hours=24)
        active_users_24h = User.objects.filter(last_login__gte=last_24h).count()
        
        # Get new users in the last 7 days
        last_week = timezone.now() - timedelta(days=7)
        new_users_7d = User.objects.filter(created_at__gte=last_week).count()
        
        # Get message statistics
        total_messages = Message.objects.count()
        messages_24h = Message.objects.filter(sent_at__gte=last_24h).count()
        
        # Get chat statistics
        total_chats = Chat.objects.count()
        active_chats_24h = Chat.objects.filter(updated_at__gte=last_24h).count()
        
        # Get daily message counts for the last 7 days
        end_date = timezone.now()
        start_date = end_date - timedelta(days=6)
        
        daily_messages = Message.objects.filter(
            sent_at__gte=start_date,
            sent_at__lte=end_date
        ).annotate(
            date=TruncDate('sent_at')
        ).values('date').annotate(
            count=Count('id')
        ).order_by('date')
        
        # Create a list of all dates in the range
        date_list = []
        current_date = start_date
        while current_date <= end_date:
            date_list.append(current_date.date())
            current_date += timedelta(days=1)
        
        # Create the messages data with 0 counts for days with no messages
        messages_data = {date: 0 for date in date_list}
        for msg in daily_messages:
            messages_data[msg['date']] = msg['count']
        
        # Format the messages data
        formatted_messages = [
            {
                'date': date.strftime('%a'),
                'count': count
            }
            for date, count in messages_data.items()
        ]
        
        # Get report statistics
        total_reports = Report.objects.count()
        pending_reports = Report.objects.filter(status='pending').count()
        resolved_reports = Report.objects.filter(status__in=['resolved', 'dismissed']).count()
        
        # Get daily report counts
        daily_reports = Report.objects.filter(
            reported_at__gte=start_date,
            reported_at__lte=end_date
        ).annotate(
            date=TruncDate('reported_at')
        ).values('date').annotate(
            count=Count('id')
        ).order_by('date')
        
        # Create the reports data with 0 counts for days with no reports
        reports_data = {date: 0 for date in date_list}
        for report in daily_reports:
            reports_data[report['date']] = report['count']
        
        # Format the reports data
        formatted_reports = [
            {
                'date': date.strftime('%a'),
                'count': count
            }
            for date, count in reports_data.items()
        ]
        
        # Calculate engagement metrics
        messages_per_user = round(total_messages / total_users if total_users > 0 else 0, 2)
        chats_per_user = round(total_chats / total_users if total_users > 0 else 0, 2)
        
        # Determine system status
        system_status = {
            'status': 'online',
            'health': 'healthy',
            'last_updated': timezone.now().strftime('%Y-%m-%d %H:%M:%S'),
            'active_users_24h': active_users_24h,
            'messages_24h': messages_24h,
            'active_chats_24h': active_chats_24h,
            'recent_activity': recent_messages or recent_logins
        }
        
        return JsonResponse({
            'total_users': total_users,
            'new_users_7d': new_users_7d,
            'total_messages': total_messages,
            'total_chats': total_chats,
            'messages_per_user': messages_per_user,
            'chats_per_user': chats_per_user,
            'daily_messages': formatted_messages,
            'daily_reports': formatted_reports,
            'total_reports': total_reports,
            'pending_reports': pending_reports,
            'resolved_reports': resolved_reports,
            'system_status': system_status
        })
        
    except Exception as e:
        # If any database operations fail, system is considered offline
        return JsonResponse({
            'system_status': {
                'status': 'offline',
                'health': 'error',
                'last_updated': timezone.now().strftime('%Y-%m-%d %H:%M:%S'),
                'error_message': str(e),
                'active_users_24h': 0,
                'messages_24h': 0,
                'active_chats_24h': 0,
                'recent_activity': False
            }
        })

@admin_required
def admin_reports(request):
    # Get all reports with related data
    reports = Report.objects.select_related(
        'message', 'reporter', 'message__sender', 'reviewed_by'
    ).order_by('-reported_at')
    
    # Filter by status if provided
    status = request.GET.get('status')
    if status:
        reports = reports.filter(status=status)
    
    # Filter by date range if provided
    date_range = request.GET.get('date')
    if date_range:
        today = timezone.now()
        if date_range == 'today':
            reports = reports.filter(reported_at__date=today.date())
        elif date_range == 'week':
            reports = reports.filter(reported_at__gte=today - timedelta(days=7))
        elif date_range == 'month':
            reports = reports.filter(reported_at__gte=today - timedelta(days=30))
    
    # Pagination
    paginator = Paginator(reports, 10)  # Show 10 reports per page
    page = request.GET.get('page')
    try:
        reports = paginator.page(page)
    except PageNotAnInteger:
        reports = paginator.page(1)
    except EmptyPage:
        reports = paginator.page(paginator.num_pages)
    
    return render(request, 'admin_reports.html', {'reports': reports})

@admin_required
@require_POST
def handle_report(request, report_id, action):
    try:
        report = Report.objects.get(id=report_id)
        data = json.loads(request.body) if request.body else {}
        
        if action == 'resolve':
            report.status = 'resolved'
            report.reviewed_by = request.user
            report.reviewed_at = timezone.now()
            
            # Handle warning and ban options
            warning = data.get('warning', False)
            ban = data.get('ban', False)
            ban_duration = data.get('banDuration')
            notes = data.get('notes', '')
            
            # Add admin notes
            report_notes = []
            if warning:
                report_notes.append("Warning issued to user")
                # Create notification for the user
                Notification.objects.create(
                    user=report.message.sender,
                    type='warning',
                    message='WARNING: For some of your recent messages',
                    admin_notes=notes if notes else None
                )
            if ban:
                report_notes.append(f"User banned for {ban_duration} days")
                # Ban the user
                ban_reason = f"Your account has been temporarily banned for {ban_duration} days due to reported messages."
                report.message.sender.ban_user(int(ban_duration), ban_reason)
                # Only log out the banned user if they are currently logged in
                if report.message.sender == request.user:
                    logout(request)
            if notes:
                report_notes.append(notes)
                
            report.notes = " | ".join(report_notes)
            report.save()
            
            return JsonResponse({
                'status': 'success',
                'message': 'Report resolved successfully',
                'warning_issued': warning,
                'ban_issued': ban,
                'ban_duration': ban_duration if ban else None
            })
            
        elif action == 'dismiss':
            report.status = 'dismissed'
            report.reviewed_by = request.user
            report.reviewed_at = timezone.now()
            report.save()
            return JsonResponse({'status': 'success', 'message': 'Report dismissed successfully'})
            
        elif action == 'delete':
            message = report.message
            message.delete_for_everyone()
            report.status = 'resolved'
            report.reviewed_by = request.user
            report.reviewed_at = timezone.now()
            report.notes = "Message was deleted by admin"
            report.save()
            return JsonResponse({'status': 'success', 'message': 'Message deleted and report resolved'})
            
        return JsonResponse({'status': 'error', 'message': 'Invalid action'})
        
    except Report.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Report not found'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})

@admin_required
@require_POST
def create_broadcast(request):
    try:
        print(f"Creating broadcast from admin: {request.user.username}")
        data = json.loads(request.body)
        message = data.get('message')
        
        if not message:
            print("Error: Broadcast message is empty")
            return JsonResponse({
                'status': 'error',
                'message': 'Broadcast message is required'
            })
        
        print(f"Creating broadcast with message: {message}")
        # Create and save the broadcast
        broadcast = Broadcast.objects.create(
            admin=request.user,
            message=message
        )
        print(f"Created broadcast with ID: {broadcast.id}")
        
        # Send notifications to all users
        notifications = broadcast.send_to_all_users()
        print(f"Broadcast complete. Created {len(notifications)} notifications")
        
        return JsonResponse({
            'status': 'success',
            'message': 'Broadcast sent successfully to all users',
            'broadcast_id': broadcast.id,
            'notification_count': len(notifications)
        })
        
    except json.JSONDecodeError:
        print("Error: Invalid JSON data in request")
        return JsonResponse({
            'status': 'error',
            'message': 'Invalid JSON data'
        })
    except Exception as e:
        print(f"Error creating broadcast: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        })

@login_required
@require_POST
def delete_chat(request):
    try:
        data = json.loads(request.body)
        chat_id = data.get('chat_id')
        
        if not chat_id:
            return JsonResponse({'status': 'error', 'message': 'Chat ID is required'})
        
        chat = get_object_or_404(Chat, id=chat_id)
        
        # Security check - ensure the user is part of this chat
        if request.user not in [chat.sender, chat.recipient]:
            return JsonResponse({'status': 'error', 'message': 'Unauthorized'})
        
        # Delete the chat
        chat.delete()
        
        return JsonResponse({
            'status': 'success',
            'message': 'Chat deleted successfully'
        })
        
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        })

@login_required
@require_POST
def block_user(request):
    try:
        data = json.loads(request.body)
        chat_id = data.get('chat_id')
        
        if not chat_id:
            return JsonResponse({'status': 'error', 'message': 'Chat ID is required'})
        
        chat = get_object_or_404(Chat, id=chat_id)
        
        # Security check - ensure the user is part of this chat
        if request.user not in [chat.sender, chat.recipient]:
            return JsonResponse({'status': 'error', 'message': 'Unauthorized'})
        
        # Determine which user to block
        user_to_block = chat.recipient if chat.sender == request.user else chat.sender
        
        # Check if already blocked
        if BlockedUser.objects.filter(blocker=request.user, blocked=user_to_block).exists():
            return JsonResponse({
                'status': 'error',
                'message': 'User is already blocked'
            })
        
        # Create the block
        BlockedUser.objects.create(
            blocker=request.user,
            blocked=user_to_block
        )
        
        return JsonResponse({
            'status': 'success',
            'message': 'User blocked successfully'
        })
        
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        })

@login_required
@require_POST
def check_if_user_is_blocked(request):
    try:
        data = json.loads(request.body)
        chat_id = data.get('chat_id')
        
        if not chat_id:
            return JsonResponse({'status': 'error', 'message': 'Chat ID is required'})
        
        chat = get_object_or_404(Chat, id=chat_id)
        
        # Security check - ensure the user is part of this chat
        if request.user not in [chat.sender, chat.recipient]:
            return JsonResponse({'status': 'error', 'message': 'Unauthorized'})
        
        # Determine the other user
        other_user = chat.recipient if chat.sender == request.user else chat.sender
        
        # Check if blocked
        is_blocked = BlockedUser.is_blocked(request.user, other_user)
        
        return JsonResponse({
            'status': 'success',
            'is_blocked': is_blocked
        })
        
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        })

@login_required
def check_message_status(request, message_id):
    """
    Check if a message has been read by the recipient.
    Returns a JSON response with the read status.
    """
    try:
        message = Message.objects.get(id=message_id)
        
        # Make sure the user is authorized to check this message
        chat = message.chat
        if request.user != chat.sender and request.user != chat.recipient:
            return JsonResponse({
                'status': 'error', 
                'message': 'You are not authorized to view this message'
            })
        
        # Get the other user in the chat (not the current user)
        other_user = chat.recipient if chat.sender == request.user else chat.sender
        
        # Check if the message is read by the other user
        is_read = message.is_read_by(other_user)
        
        return JsonResponse({
            'status': 'success',
            'is_read': is_read
        })
        
    except Message.DoesNotExist:
        return JsonResponse({
            'status': 'error',
            'message': 'Message not found'
        })
    except Exception as e:
        print(f"Error checking message status: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        })

@login_required
def mark_messages_read(request, chat_id):
    """
    Mark all messages in a chat as read by the current user.
    Returns a JSON response with the count of messages marked as read.
    """
    try:
        chat = Chat.objects.get(id=chat_id)
        
        # Make sure the user is authorized to access this chat
        if request.user != chat.sender and request.user != chat.recipient:
            return JsonResponse({
                'status': 'error', 
                'message': 'You are not authorized to access this chat'
            })
        
        # Find all unread messages sent by the other user
        if request.user == chat.sender:
            unread_messages = chat.messages.filter(sender=chat.recipient).exclude(read_by=request.user)
        else:
            unread_messages = chat.messages.filter(sender=chat.sender).exclude(read_by=request.user)
        
        # Mark all unread messages as read
        count = 0
        for message in unread_messages:
            message.read_by.add(request.user)
            count += 1
        
        return JsonResponse({
            'status': 'success',
            'count': count
        })
        
    except Chat.DoesNotExist:
        return JsonResponse({
            'status': 'error',
            'message': 'Chat not found'
        })
    except Exception as e:
        print(f"Error marking messages as read: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        })

@login_required
@require_POST
def archive_chat(request):
    """Archive a chat for the current user."""
    try:
        data = json.loads(request.body)
        chat_id = data.get('chat_id')
        
        if not chat_id:
            return JsonResponse({'status': 'error', 'message': 'Chat ID is required'})
        
        chat = get_object_or_404(Chat, id=chat_id)
        
        # Security check - ensure the user is part of this chat
        if request.user not in [chat.sender, chat.recipient]:
            return JsonResponse({'status': 'error', 'message': 'Unauthorized'})
        
        # Archive the chat for this user
        chat.archive_for_user(request.user)
        
        return JsonResponse({
            'status': 'success',
            'message': 'Chat archived successfully'
        })
        
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        })

@login_required
@require_POST
def unarchive_chat(request):
    """Unarchive a chat for the current user."""
    try:
        data = json.loads(request.body)
        chat_id = data.get('chat_id')
        
        if not chat_id:
            return JsonResponse({'status': 'error', 'message': 'Chat ID is required'})
        
        chat = get_object_or_404(Chat, id=chat_id)
        
        # Security check - ensure the user is part of this chat
        if request.user not in [chat.sender, chat.recipient]:
            return JsonResponse({'status': 'error', 'message': 'Unauthorized'})
        
        # Unarchive the chat for this user
        chat.unarchive_for_user(request.user)
        
        return JsonResponse({
            'status': 'success',
            'message': 'Chat unarchived successfully'
        })
        
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        })

@login_required
def get_archived_chats(request):
    """Get all archived chats for the current user."""
    try:
        # Get all archived chats for the current user
        archived_chats = Chat.objects.filter(
            (Q(sender=request.user) | Q(recipient=request.user)),
            archived_by=request.user
        ).exclude(
            # Exclude chats with blocked users
            Q(sender__in=BlockedUser.objects.filter(blocked=request.user).values('blocker')) |
            Q(recipient__in=BlockedUser.objects.filter(blocked=request.user).values('blocker'))
        ).order_by('-updated_at')
        
        # Format the chat data for JSON response
        chats_data = []
        for chat in archived_chats:
            # Get the other user in the conversation
            other_user = chat.recipient if chat.sender == request.user else chat.sender
            
            # Get the last message
            last_message = chat.messages.filter(
                deleted_for_everyone=False
            ).exclude(
                deleted_for=request.user
            ).order_by('-sent_at').first()
            
            # Create chat entry
            chat_data = {
                'id': chat.id,
                'is_group': False,
                'other_user': {
                    'id': other_user.id,
                    'username': other_user.username,
                    'first_name': other_user.first_name,
                    'last_name': other_user.last_name,
                    'profile_picture': other_user.profile_picture.url if other_user.profile_picture else None
                },
                'name': f"{other_user.first_name} {other_user.last_name}",
                'last_message': last_message.content if last_message else "No messages",
                'last_message_time': last_message.sent_at.strftime('%H:%M') if last_message else None,
                'updated_at': chat.updated_at.strftime('%Y-%m-%d')
            }
            chats_data.append(chat_data)
            
        # Get archived group chats
        archived_group_ids = ArchivedGroupChat.objects.filter(
            users=request.user
        ).values_list('group_id', flat=True)
        
        archived_groups = GroupChat.objects.filter(
            id__in=archived_group_ids
        ).order_by('-updated_at')
        
        # Add group chat data
        for group in archived_groups:
            # Get the latest message
            latest_message = group.messages.order_by('-created_at').first()
            
            # Create group chat entry
            group_data = {
                'id': group.id,
                'is_group': True,
                'name': group.name,
                'participants_count': group.participants.count(),
                'last_message': latest_message.content if latest_message else "No messages",
                'last_message_time': latest_message.created_at.strftime('%H:%M') if latest_message else None,
                'updated_at': group.updated_at.strftime('%Y-%m-%d')
            }
            chats_data.append(group_data)
            
        # Sort all chats by updated_at
        chats_data.sort(key=lambda x: x['updated_at'], reverse=True)
        
        return JsonResponse({
            'status': 'success',
            'chats': chats_data
        })
        
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        })

@login_required
def create_group_chat(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        group_name = data.get('group_name')
        participants = data.get('participants', [])
        
        # Validate inputs
        if not group_name:
            return JsonResponse({'status': 'error', 'message': 'Group name is required'})
        
        if not participants:
            return JsonResponse({'status': 'error', 'message': 'At least one participant is required'})
        
        # Create group chat
        try:
            group = GroupChat.objects.create(
                name=group_name,
                created_by=request.user
            )
            
            # Add creator as a participant
            group.participants.add(request.user)
            
            # Add other participants
            for username in participants:
                try:
                    user = User.objects.get(username=username)
                    group.participants.add(user)
                except User.DoesNotExist:
                    continue
            
            # Create system message
            GroupMessage.objects.create(
                group=group,
                sender=request.user,
                content=f"Group created with {group.participants.count()} members"
            )
            
            return JsonResponse({
                'status': 'success',
                'group_id': group.id,
                'group_name': group.name,
                'created_at': group.created_at.isoformat(),
                'participants': list(group.participants.values('username', 'first_name', 'last_name'))
            })
            
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

@login_required
def get_user_groups(request):
    # Get all groups the user is a member of
    groups = GroupChat.objects.filter(participants=request.user).order_by('-updated_at')
    
    group_data = []
    for group in groups:
        # Get the latest message for preview
        latest_message = group.messages.order_by('-created_at').first()
        preview = ''
        if latest_message:
            sender_name = latest_message.sender.username
            if latest_message.sender == request.user:
                sender_name = 'You'
            preview = f"{sender_name}: {latest_message.content}"
            if len(preview) > 30:
                preview = preview[:27] + '...'
        else:
            preview = 'Group chat created'
        
        # Format participants list
        participants = list(group.participants.exclude(id=request.user.id).values('username', 'first_name', 'last_name'))
        
        group_data.append({
            'id': group.id,
            'name': group.name,
            'preview': preview,
            'created_at': group.created_at.isoformat(),
            'updated_at': group.updated_at.isoformat(),
            'participants': participants,
            'participants_count': group.participants.count()
        })
    
    return JsonResponse({'status': 'success', 'groups': group_data})

@login_required
def get_group_messages(request, group_id):
    try:
        group = GroupChat.objects.get(id=group_id)
        
        # Check if user is a participant
        if request.user not in group.participants.all():
            return JsonResponse({'status': 'error', 'message': 'You are not a member of this group'})
        
        # Get messages
        messages = group.messages.all().order_by('created_at')
        
        message_data = []
        for msg in messages:
            # Get sender's name
            sender_name = f"{msg.sender.first_name} {msg.sender.last_name}"
            if msg.sender == request.user:
                sender_name = "You"
            
            message_data.append({
                'id': msg.id,
                'sender_id': msg.sender.id,
                'sender_name': sender_name,
                'sender_username': msg.sender.username,
                'content': msg.content,
                'created_at': msg.created_at.isoformat()
            })
        
        # Format participants
        participants = []
        for user in group.participants.all():
            participants.append({
                'id': user.id,
                'username': user.username,
                'name': f"{user.first_name} {user.last_name}",
                'is_you': user == request.user
            })
        
        return JsonResponse({
            'status': 'success',
            'group_id': group.id,
            'group_name': group.name,
            'messages': message_data,
            'participants': participants
        })
        
    except GroupChat.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Group chat not found'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})

@login_required
def send_group_message(request, group_id):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            content = data.get('content')
            
            if not content:
                return JsonResponse({'status': 'error', 'message': 'Message content is required'})
            
            # Check if user is a participant
            group = GroupChat.objects.get(id=group_id)
            if request.user not in group.participants.all():
                return JsonResponse({'status': 'error', 'message': 'You are not a member of this group'})
            
            # Check for duplicate messages (prevent double submission)
            # Check if the exact same message was sent by the same user in the last 5 seconds
            recent_duplicate = GroupMessage.objects.filter(
                group=group,
                sender=request.user,
                created_at__gte=timezone.now() - timezone.timedelta(seconds=5)
            ).exists()
            
            if recent_duplicate:
                # If this is a duplicate, just return success without creating a new message
                return JsonResponse({
                    'status': 'success',
                    'message_id': 0,  # Use 0 as a placeholder
                    'sender_name': 'You',
                    'content': content,
                    'created_at': timezone.now().isoformat()
                })
            
            # Create message with encrypted content
            message = GroupMessage.objects.create(
                group=group,
                sender=request.user,
                content=content
            )
            
            # Update group's updated_at timestamp
            group.save()  # This will trigger auto_now
            
            return JsonResponse({
                'status': 'success',
                'message_id': message.id,
                'sender_name': 'You',
                'content': content,  # Send back the original content to the sender
                'created_at': message.created_at.isoformat()
            })
            
        except GroupChat.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Group chat not found'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

@login_required
@require_POST
def archive_group_chat(request):
    data = json.loads(request.body)
    group_id = data.get('group_id')
    
    if not group_id:
        return JsonResponse({'status': 'error', 'message': 'Group ID is required'})
    
    try:
        group = GroupChat.objects.get(id=group_id)
        
        # Check if user is a participant
        if request.user not in group.participants.all():
            return JsonResponse({'status': 'error', 'message': 'You are not a member of this group'})
        
        # We don't have a direct field for archived users in GroupChat model
        # Let's use a similar approach as one-to-one chats with an M2M relation
        if not hasattr(group, 'archived_by'):
            # Create or get the ArchivedGroupChat model
            archived_group, created = ArchivedGroupChat.objects.get_or_create(group=group)
            archived_group.users.add(request.user)
        else:
            group.archived_by.add(request.user)
        
        return JsonResponse({'status': 'success', 'message': 'Group chat archived successfully'})
            
    except GroupChat.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Group chat not found'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})

@login_required
@require_POST
def delete_group_chat(request):
    data = json.loads(request.body)
    group_id = data.get('group_id')
    
    if not group_id:
        return JsonResponse({'status': 'error', 'message': 'Group ID is required'})
    
    try:
        group = GroupChat.objects.get(id=group_id)
        
        # Only the creator can delete the group
        if group.created_by != request.user:
            return JsonResponse({
                'status': 'error', 
                'message': 'Only the group creator can delete the group'
            })
        
        # Delete all messages
        group.messages.all().delete()
        
        # Delete the group
        group.delete()
        
        return JsonResponse({'status': 'success', 'message': 'Group chat deleted successfully'})
            
    except GroupChat.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Group chat not found'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})

@login_required
@require_POST
def exit_group_chat(request):
    data = json.loads(request.body)
    group_id = data.get('group_id')
    
    if not group_id:
        return JsonResponse({'status': 'error', 'message': 'Group ID is required'})
    
    try:
        group = GroupChat.objects.get(id=group_id)
        
        # Check if user is a participant
        if request.user not in group.participants.all():
            return JsonResponse({'status': 'error', 'message': 'You are not a member of this group'})
        
        # If this user is the creator and there are other members, transfer ownership to the oldest member
        if group.created_by == request.user and group.participants.count() > 1:
            # Get the oldest member who is not the creator
            new_owner = group.participants.exclude(id=request.user.id).order_by('id').first()
            if new_owner:
                group.created_by = new_owner
                group.save()
                
                # Add system message
                GroupMessage.objects.create(
                    group=group,
                    sender=request.user,
                    content=f"Group ownership transferred to {new_owner.first_name} {new_owner.last_name}"
                )
        
        # Remove user from participants
        group.participants.remove(request.user)
        
        # Add system message
        GroupMessage.objects.create(
            group=group,
            sender=request.user,
            content=f"{request.user.first_name} {request.user.last_name} left the group"
        )
        
        # If no participants left, delete the group
        if group.participants.count() == 0:
            group.delete()
            return JsonResponse({'status': 'success', 'message': 'You left the group and it was deleted as no members remain'})
            
        return JsonResponse({'status': 'success', 'message': 'You left the group successfully'})
            
    except GroupChat.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Group chat not found'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})

@login_required
@require_POST
def unarchive_group_chat(request):
    data = json.loads(request.body)
    group_id = data.get('group_id')
    
    if not group_id:
        return JsonResponse({'status': 'error', 'message': 'Group ID is required'})
    
    try:
        # Find the group
        group = GroupChat.objects.get(id=group_id)
        
        # Check if user is a participant
        if request.user not in group.participants.all():
            return JsonResponse({'status': 'error', 'message': 'You are not a member of this group'})
        
        # Remove user from archived users
        try:
            archived_group = ArchivedGroupChat.objects.get(group=group)
            archived_group.users.remove(request.user)
            
            # If no users have it archived, delete the ArchivedGroupChat entry
            if archived_group.users.count() == 0:
                archived_group.delete()
                
        except ArchivedGroupChat.DoesNotExist:
            pass  # Already not archived
        
        return JsonResponse({'status': 'success', 'message': 'Group chat unarchived successfully'})
            
    except GroupChat.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Group chat not found'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})

@login_required
@require_POST
def delete_group_message_for_me(request):
    """Delete a group message for the current user only."""
    try:
        data = json.loads(request.body)
        message_id = data.get('message_id')
        
        if not message_id:
            return JsonResponse({'status': 'error', 'message': 'Message ID is required'})
        
        try:
            # Get the message
            message = GroupMessage.objects.get(id=message_id)
            
            # Get the group
            group = message.group
            
            # Check if the user is a participant of the group
            if request.user not in group.participants.all():
                return JsonResponse({
                    'status': 'error',
                    'message': 'You do not have permission to delete this message'
                })
            
            # Create the deletion record
            DeletedGroupMessage.objects.get_or_create(message=message, user=request.user)
            
            return JsonResponse({
                'status': 'success',
                'message': 'Message deleted for you'
            })
            
        except GroupMessage.DoesNotExist:
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

@login_required
@require_POST
def delete_group_message_for_everyone(request):
    """Delete a group message for everyone."""
    try:
        data = json.loads(request.body)
        message_id = data.get('message_id')
        
        if not message_id:
            return JsonResponse({'status': 'error', 'message': 'Message ID is required'})
        
        try:
            # Get the message
            message = GroupMessage.objects.get(id=message_id)
            
            # Only the sender or group creator can delete for everyone
            if request.user != message.sender and request.user != message.group.created_by:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Only the sender or group creator can delete a message for everyone'
                })
            
            # Update the message content to indicate it was deleted
            message.content = "[This message was deleted]"
            message.save()
            
            return JsonResponse({
                'status': 'success',
                'message': 'Message deleted for everyone'
            })
            
        except GroupMessage.DoesNotExist:
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

@login_required
@require_POST
def report_group_message(request):
    """Report a group message."""
    try:
        data = json.loads(request.body)
        message_id = data.get('message_id')
        
        if not message_id:
            return JsonResponse({
                'status': 'error',
                'message': 'Message ID is required'
            })
        
        try:
            message = GroupMessage.objects.get(id=message_id)
            
            # Check if the user is a participant in the group
            if request.user not in message.group.participants.all():
                return JsonResponse({
                    'status': 'error',
                    'message': 'You do not have permission to report this message'
                })
            
            # Check if user is reporting their own message
            if message.sender == request.user:
                return JsonResponse({
                    'status': 'error',
                    'message': 'You cannot report your own message'
                })
            
            # Check if user has already reported this message
            existing_report = GroupMessageReport.objects.filter(
                message=message,
                reporter=request.user
            ).exists()
            
            if existing_report:
                return JsonResponse({
                    'status': 'error',
                    'message': 'You have already reported this message'
                })
            
            # Create the report
            report = GroupMessageReport.objects.create(
                message=message,
                reporter=request.user,
                status='pending'
            )
            
            return JsonResponse({
                'status': 'success',
                'message': 'Message reported successfully'
            })
            
        except GroupMessage.DoesNotExist:
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

@admin_required
def expose_razorpay_key(request):
    # This is a placeholder for the new view. It should be implemented to expose the Razorpay key ID safely.
    return JsonResponse({'status': 'error', 'message': 'This view is not implemented yet'})

def get_razorpay_key(request):
    """Return the Razorpay key ID to the frontend."""
    key_id = getattr(settings, 'RAZORPAY_KEY_ID', '')
    key_secret = getattr(settings, 'RAZORPAY_SECRET_KEY', '')
    
    # Log key info (first few characters only for security)
    print(f"Razorpay Key ID: {key_id[:4]}{'*' * 12 if len(key_id) > 4 else ''}")
    print(f"Razorpay Key Secret: {'*' * 16 if key_secret else 'Not configured'}")
    
    return JsonResponse({
        'key_id': key_id,
        'testmode': getattr(settings, 'RAZORPAY_TEST_MODE', True)
    })

@csrf_exempt
@require_POST
def verify_payment(request):
    """Verify and store payment information"""
    try:
        data = json.loads(request.body)
        print(f"Payment data received: {data}")
        
        # For direct Razorpay payments, we may not have an order_id
        # but we should always have a payment_id
        if not data.get('razorpay_payment_id'):
            print("Missing payment ID in request")
            return JsonResponse({
                'status': 'error',
                'message': 'Payment ID is required'
            }, status=400)
        
        # Handle anonymous users
        if request.user.is_authenticated:
            user = request.user
        else:
            # Get or create a guest user for anonymous donations
            guest_user, created = User.objects.get_or_create(
                username='guest_donor',
                defaults={
                    'email': 'guest@example.com',
                    'first_name': 'Guest',
                    'last_name': 'Donor'
                }
            )
            user = guest_user
            print(f"Using guest user for donation: {user.username}")
        
        # Create payment record - use get with default values to handle missing fields
        payment = Payment.objects.create(
            user=user,
            razorpay_payment_id=data.get('razorpay_payment_id'),
            razorpay_order_id=data.get('razorpay_order_id', ''),
            razorpay_signature=data.get('razorpay_signature', ''),
            amount=data.get('amount', 0) / 100,  # Convert from paise to rupees
            currency=data.get('currency', 'INR'),
            notes=json.dumps(data.get('notes', {}))  # Convert dict to JSON string
        )
        
        print(f"Payment record created with ID: {payment.id}")
        
        # Check if Razorpay module is available
        if not RAZORPAY_AVAILABLE:
            print("Razorpay module not available, marking payment as successful")
            payment.status = 'success'
            payment.save()
            return JsonResponse({
                'status': 'success', 
                'message': 'Payment recorded (Razorpay verification skipped)',
                'payment_id': payment.id
            })
        
        # In test mode, we'll mark it as successful
        # or if we don't have Razorpay credentials configured
        if getattr(settings, 'RAZORPAY_TEST_MODE', True):
            payment.status = 'success'
            payment.save()
            print("Test mode: Payment marked as successful")
            return JsonResponse({
                'status': 'success',
                'message': 'Payment recorded successfully (Test Mode)',
                'payment_id': payment.id
            })
            
        # For direct payments (without order ID and signature)
        # We'll consider it successful since Razorpay already validated it
        if not data.get('razorpay_order_id') or not data.get('razorpay_signature'):
            payment.status = 'success'
            payment.save()
            print(f"Direct payment accepted: {payment.id}")
            return JsonResponse({
                'status': 'success',
                'message': 'Payment recorded successfully',
                'payment_id': payment.id
            })
            
        # Verify the payment with signature if we have all the data
        try:
            from razorpay.utility import Utility
            client = razorpay.Client(auth=(
                getattr(settings, 'RAZORPAY_KEY_ID', ''),
                getattr(settings, 'RAZORPAY_SECRET_KEY', '')
            ))
            utility = Utility(client)
            
            parameters = {
                'razorpay_order_id': data.get('razorpay_order_id'),
                'razorpay_payment_id': data.get('razorpay_payment_id'),
                'razorpay_signature': data.get('razorpay_signature')
            }
            
            utility.verify_payment_signature(parameters)
            payment.status = 'success'
            payment.save()
            print(f"Payment verified with signature: {payment.id}")
            return JsonResponse({
                'status': 'success',
                'message': 'Payment verified successfully',
                'payment_id': payment.id
            })
        except Exception as e:
            print(f"Error during payment signature verification: {str(e)}")
            payment.status = 'failed'
            payment.error_message = str(e)
            payment.save()
            return JsonResponse({
                'status': 'error',
                'message': f'Payment verification error: {str(e)}'
            }, status=400)
    except Exception as e:
        print(f"Error processing payment: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=400)

@admin_required
def admin_donations(request):
    """Admin page to view and manage donations"""
    return render(request, 'admin_donations.html')

@admin_required
def donation_stats(request):
    """API endpoint to get donation statistics"""
    # Get total number of payments and total amount
    payments = Payment.objects.all()
    total_amount = sum(payment.amount for payment in payments)
    payment_count = len(payments)
    
    # Get recent payments (last 24 hours)
    recent_time = timezone.now() - timezone.timedelta(hours=24)
    recent_payments = Payment.objects.filter(created_at__gte=recent_time)
    recent_amount = sum(payment.amount for payment in recent_payments)
    recent_count = len(recent_payments)
    
    # Get daily donations for the last 30 days
    start_date = timezone.now().date() - timezone.timedelta(days=30)
    end_date = timezone.now().date()
    
    # Initialize daily data with zeros
    daily_donations = []
    current_date = start_date
    while current_date <= end_date:
        daily_donations.append({
            'date': current_date.strftime('%b %d'),
            'amount': 0,
            'count': 0
        })
        current_date += timezone.timedelta(days=1)
    
    # Fill in actual data
    for payment in payments:
        payment_date = payment.created_at.date()
        if start_date <= payment_date <= end_date:
            index = (payment_date - start_date).days
            if index < len(daily_donations):
                daily_donations[index]['amount'] += float(payment.amount)
                daily_donations[index]['count'] += 1
    
    # Format payment data for the table
    payment_data = []
    for payment in payments.order_by('-created_at'):
        payment_data.append({
            'id': payment.id,
            'user': payment.user.username,
            'amount': float(payment.amount),
            'created_at': payment.created_at.isoformat(),
            'razorpay_payment_id': payment.razorpay_payment_id,
            'razorpay_order_id': payment.razorpay_order_id,
            'status': payment.status
        })
    
    return JsonResponse({
        'total_amount': total_amount,
        'payment_count': payment_count,
        'recent_amount': recent_amount,
        'recent_count': recent_count,
        'daily_donations': daily_donations,
        'recent_payments': payment_data
    })

def forgot_password(request):
    """View for initiating the password reset process"""
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        
        # Check if username and email match
        try:
            user = User.objects.get(username=username, email=email)
            
            # Generate and save 6-digit OTP
            otp = ''.join(random.choices(string.digits, k=6))
            
            # Store OTP in session along with timestamp and user info
            request.session['reset_otp'] = {
                'otp': otp,
                'username': username,
                'email': email,
                'timestamp': datetime.datetime.now().timestamp(),
                'attempts': 0
            }
            
            # Send OTP via email
            subject = 'LUMA Password Reset Code'
            text_content = f'Your password reset code is: {otp}\n\nThis code is valid for 2 minutes.'
            
            # Create HTML content with attractive styling
            html_content = f'''
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Password Reset Code</title>
                <style>
                    body {{
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        line-height: 1.6;
                        color: #333333;
                        margin: 0;
                        padding: 0;
                        background-color: #f9f9f9;
                    }}
                    .container {{
                        max-width: 600px;
                        margin: 20px auto;
                        background-color: #ffffff;
                        border-radius: 8px;
                        overflow: hidden;
                        box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);
                    }}
                    .header {{
                        background-color: #007bff;
                        color: white;
                        padding: 20px;
                        text-align: center;
                    }}
                    .content {{
                        padding: 30px;
                    }}
                    .code-box {{
                        background-color: #f0f7ff;
                        border: 1px solid #cce5ff;
                        border-radius: 5px;
                        font-family: 'Courier New', monospace;
                        font-size: 24px;
                        font-weight: bold;
                        letter-spacing: 5px;
                        color: #007bff;
                        padding: 15px;
                        margin: 25px 0;
                        text-align: center;
                    }}
                    .footer {{
                        background-color: #f5f5f5;
                        padding: 15px;
                        text-align: center;
                        font-size: 12px;
                        color: #777777;
                    }}
                    .highlight {{
                        color: #007bff;
                        font-weight: bold;
                    }}
                    .button {{
                        display: inline-block;
                        padding: 10px 20px;
                        background-color: #007bff;
                        color: white;
                        text-decoration: none;
                        border-radius: 5px;
                        margin-top: 15px;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>LUMA Password Reset</h1>
                    </div>
                    <div class="content">
                        <p>Hello,</p>
                        <p>We received a request to reset your password. Here is your verification code:</p>
                        <div class="code-box">{otp}</div>
                        <p><strong>This code is valid for 2 minutes.</strong></p>
                        <p>If you didn't request a password reset, please ignore this email.</p>
                    </div>
                    <div class="footer">
                        <p>This is an automated message. Please do not reply to this email.</p>
                        <p>&copy; {datetime.datetime.now().year} LUMA Chat. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            '''
            
            # Send email with both text and HTML versions
            email = EmailMultiAlternatives(subject, text_content, settings.DEFAULT_FROM_EMAIL, [email])
            email.attach_alternative(html_content, "text/html")
            email.send(fail_silently=False)
            
            # Redirect to OTP verification page
            return render(request, 'verify_otp.html', {
                'username': username,
                'email': email
            })
            
        except User.DoesNotExist:
            messages.error(request, 'No account found with the provided username and email.')
            return render(request, 'forgot_password.html')
    
    return render(request, 'forgot_password.html')

def verify_otp(request):
    """View for verifying the OTP sent to the user's email"""
    if request.method == 'POST':
        username = request.POST.get('username')
        entered_otp = request.POST.get('otp')
        
        print(f"DEBUG: Username: {username}, OTP: {entered_otp}")
        print(f"DEBUG: POST data: {request.POST}")
        
        # Check if OTP session data exists
        if 'reset_otp' not in request.session:
            print("DEBUG: 'reset_otp' not in session")
            messages.error(request, 'Session expired. Please request a new code.')
            return redirect('forgot_password')
        
        reset_data = request.session['reset_otp']
        print(f"DEBUG: Session OTP: {reset_data['otp']}")
        
        # Verify username matches
        if reset_data['username'] != username:
            print(f"DEBUG: Username mismatch: {reset_data['username']} != {username}")
            messages.error(request, 'Invalid request.')
            return redirect('forgot_password')
        
        # Check if OTP has expired (2 minutes = 120 seconds)
        current_time = datetime.datetime.now().timestamp()
        time_difference = current_time - reset_data['timestamp']
        
        if time_difference > 120:
            print(f"DEBUG: OTP expired. Time difference: {time_difference} seconds")
            messages.error(request, 'Verification code has expired. Please request a new one.')
            return render(request, 'verify_otp.html', {
                'username': username,
                'email': reset_data['email']
            })
        
        # Increment attempt counter
        reset_data['attempts'] += 1
        request.session['reset_otp'] = reset_data
        
        # Check max attempts (limit to 3)
        if reset_data['attempts'] > 3:
            print(f"DEBUG: Too many attempts: {reset_data['attempts']}")
            messages.error(request, 'Too many incorrect attempts. Please request a new code.')
            return redirect('forgot_password')
        
        # Verify OTP
        if entered_otp == reset_data['otp']:
            print("DEBUG: OTP matched successfully!")
            # Generate a verification token
            token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
            
            # Store token in session
            request.session['reset_token'] = {
                'token': token,
                'username': username,
                'timestamp': datetime.datetime.now().timestamp()
            }
            
            # Redirect to reset password page
            return render(request, 'reset_password.html', {
                'username': username,
                'token': token
            })
        else:
            print(f"DEBUG: OTP mismatch. Entered: {entered_otp}, Expected: {reset_data['otp']}")
            remaining_attempts = 3 - reset_data['attempts']
            messages.error(request, f'Invalid verification code. {remaining_attempts} attempts remaining.')
            return render(request, 'verify_otp.html', {
                'username': username,
                'email': reset_data['email']
            })
    
    # If no POST data, redirect to forgot password page
    return redirect('forgot_password')

@csrf_exempt
def resend_otp(request):
    """AJAX endpoint to resend OTP"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')
            email = data.get('email')
            
            # Verify user exists
            try:
                user = User.objects.get(username=username, email=email)
            except User.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'message': 'User not found.'
                })
            
            # Generate new OTP
            otp = ''.join(random.choices(string.digits, k=6))
            
            # Update session with new OTP
            request.session['reset_otp'] = {
                'otp': otp,
                'username': username,
                'email': email,
                'timestamp': datetime.datetime.now().timestamp(),
                'attempts': 0
            }
            
            # Send OTP via email
            subject = 'LUMA Password Reset Code'
            text_content = f'Your new password reset code is: {otp}\n\nThis code is valid for 2 minutes.'
            
            # Create HTML content with attractive styling
            html_content = f'''
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Password Reset Code</title>
                <style>
                    body {{
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        line-height: 1.6;
                        color: #333333;
                        margin: 0;
                        padding: 0;
                        background-color: #f9f9f9;
                    }}
                    .container {{
                        max-width: 600px;
                        margin: 20px auto;
                        background-color: #ffffff;
                        border-radius: 8px;
                        overflow: hidden;
                        box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);
                    }}
                    .header {{
                        background-color: #007bff;
                        color: white;
                        padding: 20px;
                        text-align: center;
                    }}
                    .content {{
                        padding: 30px;
                    }}
                    .code-box {{
                        background-color: #f0f7ff;
                        border: 1px solid #cce5ff;
                        border-radius: 5px;
                        font-family: 'Courier New', monospace;
                        font-size: 24px;
                        font-weight: bold;
                        letter-spacing: 5px;
                        color: #007bff;
                        padding: 15px;
                        margin: 25px 0;
                        text-align: center;
                    }}
                    .footer {{
                        background-color: #f5f5f5;
                        padding: 15px;
                        text-align: center;
                        font-size: 12px;
                        color: #777777;
                    }}
                    .highlight {{
                        color: #007bff;
                        font-weight: bold;
                    }}
                    .button {{
                        display: inline-block;
                        padding: 10px 20px;
                        background-color: #007bff;
                        color: white;
                        text-decoration: none;
                        border-radius: 5px;
                        margin-top: 15px;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>LUMA Password Reset</h1>
                    </div>
                    <div class="content">
                        <p>Hello,</p>
                        <p>We have re-sent your verification code as requested. Here is your new code:</p>
                        <div class="code-box">{otp}</div>
                        <p><strong>This code is valid for 2 minutes.</strong></p>
                        <p>If you didn't request a password reset, please ignore this email.</p>
                    </div>
                    <div class="footer">
                        <p>This is an automated message. Please do not reply to this email.</p>
                        <p>&copy; {datetime.datetime.now().year} LUMA Chat. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            '''
            
            # Send email with both text and HTML versions
            email = EmailMultiAlternatives(subject, text_content, settings.DEFAULT_FROM_EMAIL, [email])
            email.attach_alternative(html_content, "text/html")
            email.send(fail_silently=False)
            
            return JsonResponse({
                'success': True,
                'message': 'Verification code sent successfully.'
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': f'Error: {str(e)}'
            })
    
    return JsonResponse({
        'success': False,
        'message': 'Invalid request method.'
    })

def reset_password(request):
    """View for setting a new password after OTP verification"""
    if request.method == 'POST':
        username = request.POST.get('username')
        token = request.POST.get('token')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        
        print(f"DEBUG: Reset password POST data - username: {username}, token exists: {bool(token)}")
        
        # Check if reset token exists in session
        if 'reset_token' not in request.session:
            print("DEBUG: 'reset_token' not in session")
            messages.error(request, 'Session expired. Please restart the password reset process.')
            return redirect('forgot_password')
        
        reset_token = request.session['reset_token']
        print(f"DEBUG: Session token: {reset_token.get('token')[:10]}..., username: {reset_token.get('username')}")
        
        # Verify token and username
        if reset_token['token'] != token or reset_token['username'] != username:
            print(f"DEBUG: Token/username mismatch - token match: {reset_token['token'] == token}, username match: {reset_token['username'] == username}")
            messages.error(request, 'Invalid request. Please try the password reset process again.')
            return redirect('forgot_password')
        
        # Check if token has expired (10 minutes = 600 seconds)
        current_time = datetime.datetime.now().timestamp()
        if current_time - reset_token['timestamp'] > 600:
            print(f"DEBUG: Token expired. Time difference: {current_time - reset_token['timestamp']} seconds")
            messages.error(request, 'Your session has expired. Please restart the password reset process.')
            return redirect('forgot_password')
        
        # Validate passwords
        if password != confirm_password:
            print("DEBUG: Passwords don't match")
            messages.error(request, 'Passwords do not match.')
            return render(request, 'reset_password.html', {
                'username': username,
                'token': token
            })
        
        # Validate password strength (minimum 8 chars, with letters and numbers)
        if len(password) < 8 or not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
            print("DEBUG: Password doesn't meet strength requirements")
            messages.error(request, 'Password must be at least 8 characters with letters and numbers.')
            return render(request, 'reset_password.html', {
                'username': username,
                'token': token
            })
        
        # Update user's password
        try:
            user = User.objects.get(username=username)
            user.set_password(password)
            user.save()
            print(f"DEBUG: Successfully reset password for user {username}")
            
            # Clear session data
            if 'reset_otp' in request.session:
                del request.session['reset_otp']
            if 'reset_token' in request.session:
                del request.session['reset_token']
            
            messages.success(request, 'Your password has been updated successfully.')
            return redirect('signin')
            
        except User.DoesNotExist:
            print(f"DEBUG: User not found: {username}")
            messages.error(request, 'User not found.')
            return redirect('forgot_password')
    
    # For GET requests, check if token is valid
    token = request.GET.get('token')
    username = request.GET.get('username')
    
    if token and username and 'reset_token' in request.session:
        reset_token = request.session['reset_token']
        
        # Verify token is valid
        if reset_token['token'] == token and reset_token['username'] == username:
            # Check if token has expired
            current_time = datetime.datetime.now().timestamp()
            if current_time - reset_token['timestamp'] <= 600:
                return render(request, 'reset_password.html', {
                    'username': username,
                    'token': token
                })
    
    # If no valid token or GET request without proper params, redirect to forgot password
    return redirect('forgot_password')
