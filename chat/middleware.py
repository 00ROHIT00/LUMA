from django.shortcuts import redirect
from django.contrib import messages
from django.urls import reverse
from django.contrib.auth import logout

class BanCheckMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated and request.user.is_currently_banned():
            # Log out the user
            logout(request)
            # Add ban message
            remaining_days = request.user.get_ban_duration_remaining()
            ban_reason = request.user.ban_reason or "Your account has been temporarily banned."
            messages.error(request, f"{ban_reason} Your ban will expire in {remaining_days} days.")
            # Redirect to login page
            return redirect('signin')
        
        response = self.get_response(request)
        return response 