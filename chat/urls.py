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
    path('admin-dashboard/manage-users/', manage_users, name='manage_users'),
    path('admin-dashboard/delete-user/<int:user_id>/', delete_user, name='delete_user'),
    path('admin-dashboard/edit-user/<int:user_id>/', edit_user, name='edit_user'),
    path('admin-dashboard/update-user/<int:user_id>/', update_user, name='update_user'),  # Add this line
]

