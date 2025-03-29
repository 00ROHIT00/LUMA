'from django.conf import settings' 
'def about(request):' 
'    return render(request, "about.html", {"razorpay_key_id": settings.RAZORPAY_KEY_ID})' 
