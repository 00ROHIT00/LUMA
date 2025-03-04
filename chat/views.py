from django.shortcuts import render, redirect
from django.contrib import messages
from .models import User
from django.urls import reverse



def home(request):
    return render(request, 'index.html') 


from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.shortcuts import render, redirect

def signin(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)  # Use authenticate()

        if user is not None:
            login(request, user)  # Log the user in
            return redirect('chat')  # Redirect to chat page
        else:
            messages.error(request, "Invalid Username or Password")
            return render(request, 'signin.html')

    return render(request, 'signin.html')



from django.contrib import messages
from django.contrib.auth import logout

def logout_view(request):
    logout(request)
    return redirect('home')

def about(request):
    return render(request, 'about.html')

from django.contrib import messages
from django.shortcuts import render, redirect
from django.urls import reverse
from .models import User

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

        # Create user instance
        user = User.objects.create(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name
        )

        # Hash and set password
        user.set_password(password)
        user.save()

        messages.success(request, "Account created successfully")
        return redirect('signin')  # Redirect to signin page after successful registration

    return render(request, 'register.html')


from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import Friendship, User

@login_required
def chat_view(request):
    user = request.user
    
    # Get all friends of the logged-in user
    friends = Friendship.objects.filter(user=user).select_related('friend')
    friend_ids = friends.values_list('friend__id', flat=True)
    
    # Exclude logged-in user and already added friends from the users list
    available_users = User.objects.exclude(id__in=friend_ids).exclude(id=user.id)
    
    return render(request, 'chat.html', {'friends': friends, 'available_users': available_users})



from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

@csrf_exempt
@login_required
def add_friend(request, username):
    if request.method == "POST":
        try:
            friend = User.objects.get(username=username)
            Friendship.objects.create(user=request.user, friend=friend)
            return JsonResponse({"status": "success", "message": f"{username} added!"})
        except User.DoesNotExist:
            return JsonResponse({"status": "error", "message": "User not found"})
    return JsonResponse({"status": "error", "message": "Invalid request"})



from django.http import JsonResponse
from .models import User, FriendRequest
from django.contrib.auth.decorators import login_required

@login_required
def send_friend_request(request):
    username = request.GET.get("username")
    if not username:
        return JsonResponse({"message": "Invalid request"})
    
    try:
        sender = request.user
        receiver = User.objects.get(username=username)
        
        if sender == receiver:
            return JsonResponse({"message": "You can't send friend request to yourself"})
        
        if FriendRequest.objects.filter(sender=sender, receiver=receiver).exists():
            return JsonResponse({"message": "Friend request already sent"})
        
        FriendRequest.objects.create(sender=sender, receiver=receiver)
        return JsonResponse({"message": f"Friend request sent to {username}"})
    except User.DoesNotExist:
        return JsonResponse({"message": "User not found"})
    except Exception as e:
        return JsonResponse({"message": f"Something went wrong: {str(e)}"})
    

@login_required
def view_friend_requests(request):
    user = request.user
    pending_requests = FriendRequest.objects.filter(receiver=user, is_accepted=False)
    
    return render(request, 'friend_requests.html', {
        'pending_requests': pending_requests
    })


@login_required
def get_friend_requests(request):
    try:
        user = request.user
        pending_requests = FriendRequest.objects.filter(receiver=user, is_accepted=False)
        
        requests_data = []
        for req in pending_requests:
            requests_data.append({
                "id": req.id,
                "sender": req.sender.username,
                "timestamp": req.timestamp.strftime("%Y-%m-%d %H:%M")
            })
        
        return JsonResponse({"requests": requests_data})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

from .models import Friendship

@login_required
def respond_to_friend_request(request):
    request_id = request.GET.get("request_id")
    accept = request.GET.get("accept") == "true"
    
    if not request_id:
        return JsonResponse({"message": "Invalid request"}, status=400)
    
    try:
        user = request.user
        friend_request = FriendRequest.objects.get(id=request_id, receiver=user)
        
        if accept:
            friend_request.is_accepted = True
            friend_request.save()
            
            # Create Friendship entries for both users
            Friendship.objects.create(user=friend_request.sender, friend=user)
            Friendship.objects.create(user=user, friend=friend_request.sender)

            return JsonResponse({"message": f"You are now friends with {friend_request.sender.username}"})
        
        else:
            friend_request.delete()  # Optional: You can mark it as rejected instead
            return JsonResponse({"message": "Friend request declined"})
            
    except FriendRequest.DoesNotExist:
        return JsonResponse({"message": "Friend request not found"}, status=404)
    except Exception as e:
        return JsonResponse({"message": f"Something went wrong: {str(e)}"}, status=500)

    
@login_required
def check_notifications(request):
    try:
        user = request.user
        # Check if there are any pending friend requests
        has_notifications = FriendRequest.objects.filter(
            receiver=user, 
            is_accepted=False
        ).exists()
        
        return JsonResponse({"has_notifications": has_notifications})
    except Exception:
        return JsonResponse({"has_notifications": False})