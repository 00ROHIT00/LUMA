from django.urls import path
from . import views
from .views import *

urlpatterns = [
    path('', home, name='home'),
    path('register/', views.register, name='register'),
    path('signin/', views.signin, name='signin'),
    path("about/", about, name="about"),
    # path('chats/', chat_view, name='chat'),
    path('logout/', views.logout_view, name='logout'),
    path('check_notifications/', views.check_notifications, name='check_notifications'),
    path('api/user-count/', user_count, name='user-count'),
    path('admin-login/', admin_login, name='admin_login'),
    path('admin-dashboard/', admin_dashboard, name='admin_dashboard'),
    path('admin-dashboard/manage-users/', manage_users, name='manage_users'),
    path('admin-dashboard/delete-user/<int:user_id>/', delete_user, name='delete_user'),
    path('admin-dashboard/edit-user/<int:user_id>/', edit_user, name='edit_user'),
    path('admin-dashboard/update-user/<int:user_id>/', update_user, name='update_user'),
    path('profile/', views.profile, name='profile'),
    path('delete_account/', views.delete_account, name='delete_account'),
    path('chats/', views.chat_list, name='chat_list'),
    path('chats/<int:chat_id>/', views.chat_detail, name='chat_detail'),
    path('search_user/', views.search_user, name='search_user'),
    path('start_chat/', views.start_chat, name='start_chat'),
    path('send_message/', views.send_message, name='send_message'),
]

