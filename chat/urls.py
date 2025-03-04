from django.urls import path
from . import views
from .views import *

urlpatterns = [
    path('', home, name='home'),
    path('register/', views.register, name='register'),
    path('signin/', views.signin, name='signin'),
    path("about/", about, name="about"),
    path('chats/', chat_view, name='chat'),
    path('add_friend/<str:username>/', add_friend, name='add_friend'),
    path('logout/', views.logout_view, name='logout'),
    path('send_friend_request/', views.send_friend_request, name='send_friend_request'),
    path('friend_requests/', views.view_friend_requests, name='view_friend_requests'),
    path('get_friend_requests/', views.get_friend_requests, name='get_friend_requests'),
    path('respond_to_friend_request/', views.respond_to_friend_request, name='respond_to_friend_request'),
    path('check_notifications/', views.check_notifications, name='check_notifications'),
]
