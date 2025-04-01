from django.urls import path
from . import views
from .views import *

urlpatterns = [
    path('', home, name='home'),
    path('register/', views.register, name='register'),
    path('signin/', views.signin, name='signin'),
    path("about/", about, name="about"),
    path('get_razorpay_key/', views.get_razorpay_key, name='get_razorpay_key'),
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
    path('api/broadcast/', create_broadcast, name='create_broadcast'),
    path('delete_chat/', views.delete_chat, name='delete_chat'),
    path('block_user/', views.block_user, name='block_user'),
    path('check_if_user_is_blocked/', views.check_if_user_is_blocked, name='check_if_user_is_blocked'),
    path('check_message_status/<int:message_id>/', views.check_message_status, name='check_message_status'),
    path('mark_messages_read/<int:chat_id>/', views.mark_messages_read, name='mark_messages_read'),
    path('archive_chat/', views.archive_chat, name='archive_chat'),
    path('unarchive_chat/', views.unarchive_chat, name='unarchive_chat'),
    path('get_archived_chats/', views.get_archived_chats, name='get_archived_chats'),
    path('create_group_chat/', views.create_group_chat, name='create_group_chat'),
    path('get_user_groups/', views.get_user_groups, name='get_user_groups'),
    path('group/<int:group_id>/messages/', views.get_group_messages, name='get_group_messages'),
    path('group/<int:group_id>/send_message/', views.send_group_message, name='send_group_message'),
    path('archive_group_chat/', views.archive_group_chat, name='archive_group_chat'),
    path('delete_group_chat/', views.delete_group_chat, name='delete_group_chat'),
    path('exit_group_chat/', views.exit_group_chat, name='exit_group_chat'),
    path('unarchive_group_chat/', views.unarchive_group_chat, name='unarchive_group_chat'),
    path('delete_group_message_for_me/', views.delete_group_message_for_me, name='delete_group_message_for_me'),
    path('delete_group_message_for_everyone/', views.delete_group_message_for_everyone, name='delete_group_message_for_everyone'),
    path('report_group_message/', views.report_group_message, name='report_group_message'),
    path('verify-payment/', views.verify_payment, name='verify_payment'),
    path('admin-dashboard/donations/', views.admin_donations, name='admin_donations'),
    path('api/donation-stats/', views.donation_stats, name='donation_stats'),
]

