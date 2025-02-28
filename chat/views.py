from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from .models import User
from django.urls import reverse



def home(request):
    return render(request, 'index.html') 


from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from chat.models import User  # Import your custom user model

def signin(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            user = None

        if user is not None and user.check_password(password):
            login(request, user)
            request.session['is_logged_in'] = True
            request.session['username'] = user.username
            return redirect('chat')
        else:
            messages.error(request, "Invalid Username or Password")
            return render(request, 'signin.html')

    return render(request, 'signin.html')


from django.contrib import messages
from django.contrib.auth import logout

def logout_view(request):
    logout(request)
    request.session.flush()
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

def chat(request):
    return render(request, 'chat.html')

from django.http import JsonResponse
from .models import User, FriendRequest
from django.contrib.auth.decorators import login_required

def send_friend_request(request):
    if not request.session.get('is_logged_in'):
        return JsonResponse({"message": "You must be logged in"}, status=401)
    
    username = request.GET.get("username")
    if not username:
        return JsonResponse({"message": "Invalid request"})
    
    try:
        sender = User.objects.get(username=request.session.get('username'))
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
    

    # Add this after your other view functions in views.py
def view_friend_requests(request):
    if not request.session.get('is_logged_in'):
        return redirect('signin')
    
    user = User.objects.get(username=request.session.get('username'))
    pending_requests = FriendRequest.objects.filter(receiver=user, is_accepted=False)
    
    return render(request, 'friend_requests.html', {
        'pending_requests': pending_requests
    })



def get_friend_requests(request):
    if not request.session.get('is_logged_in'):
        return JsonResponse({"error": "Authentication required"}, status=401)
    
    try:
        user = User.objects.get(username=request.session.get('username'))
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

def respond_to_friend_request(request):
    if not request.session.get('is_logged_in'):
        return JsonResponse({"message": "Authentication required"}, status=401)
    
    request_id = request.GET.get("request_id")
    accept = request.GET.get("accept") == "true"
    
    if not request_id:
        return JsonResponse({"message": "Invalid request"}, status=400)
    
    try:
        user = User.objects.get(username=request.session.get('username'))
        friend_request = FriendRequest.objects.get(id=request_id, receiver=user)
        
        if accept:
            friend_request.is_accepted = True
            friend_request.save()
            # Here you could also create a "Friendship" model entry if you want to track friendships
            return JsonResponse({"message": f"You are now friends with {friend_request.sender.username}"})
        else:
            friend_request.delete()  # Optional: you might want to just mark as rejected instead
            return JsonResponse({"message": "Friend request declined"})
            
    except FriendRequest.DoesNotExist:
        return JsonResponse({"message": "Friend request not found"}, status=404)
    except Exception as e:
        return JsonResponse({"message": f"Something went wrong: {str(e)}"}, status=500)
    

def check_notifications(request):
    if not request.session.get('is_logged_in'):
        return JsonResponse({"has_notifications": False})
    
    try:
        user = User.objects.get(username=request.session.get('username'))
        # Check if there are any pending friend requests
        has_notifications = FriendRequest.objects.filter(
            receiver=user, 
            is_accepted=False
        ).exists()
        
        return JsonResponse({"has_notifications": has_notifications})
    except Exception:
        return JsonResponse({"has_notifications": False})