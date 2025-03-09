from django.urls import path
from . import views
from .views import *

urlpatterns = [
    path('', home, name='home'),
    path('register/', views.register, name='register'),
    path('signin/', views.signin, name='signin'),
    path("about/", about, name="about"),
    path('chats/', chat_view, name='chat'),
    path('logout/', views.logout_view, name='logout'),
    path('check_notifications/', views.check_notifications, name='check_notifications'),
    path('search_user/', views.search_user, name='search_user'),
    path('api/user-count/', user_count, name='user-count'),
    path('admin-login/', admin_login, name='admin_login'),
    path('admin-dashboard/', admin_dashboard, name='admin_dashboard'),
]

