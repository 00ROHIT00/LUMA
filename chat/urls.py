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
    path('mark_notifications_read/', views.mark_notifications_read, name='mark_notifications_read'),
    path('api/user-count/', user_count, name='user-count'),
    path('api/dashboard-stats/', get_dashboard_stats, name='dashboard-stats'),
    path('admin-login/', admin_login, name='admin_login'),
    path('admin-dashboard/', admin_dashboard, name='admin_dashboard'),
    path('admin-dashboard/manage-users/', manage_users, name='manage_users'),
    path('admin-dashboard/delete-user/<int:user_id>/', delete_user, name='delete_user'),
    path('admin-dashboard/edit-user/<int:user_id>/', edit_user, name='edit_user'),
    path('admin-dashboard/update-user/<int:user_id>/', update_user, name='update_user'),
    path('profile/', views.profile, name='profile'),
    path('edit_profile/', views.edit_profile, name='edit_profile'),
    path('change_password/', views.change_password, name='change_password'),
    path('delete_account/', views.delete_account, name='delete_account'),
    path('chats/', views.chat_list, name='chat_list'),
    path('chats/<int:chat_id>/', views.chat_detail, name='chat_detail'),
    path('search_user/', views.search_user, name='search_user'),
    path('start_chat/', views.start_chat, name='start_chat'),
    path('send_message/', views.send_message, name='send_message'),
    path('report_message/', views.report_message, name='report_message'),
    path('delete_message_for_me/', views.delete_message_for_me, name='delete_message_for_me'),
    path('delete_message_for_everyone/', views.delete_message_for_everyone, name='delete_message_for_everyone'),
    path('admin-dashboard/reports/', admin_reports, name='admin_reports'),
    path('api/reports/<int:report_id>/<str:action>/', handle_report, name='handle_report'),
]

